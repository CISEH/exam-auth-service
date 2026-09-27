import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { query, withTransaction } from '../db/pool.js';
import { env } from '../config/env.js';
import { resolvePortal, requireAuth } from '../middleware/requireAuth.js';
import { issueAccessToken } from '../services/tokens.js';
import {
  createSession, rotateSession, revokeByRefreshToken, revokeSession, revokeUserSessions, listActiveSessions,
} from '../services/sessions.js';
import { assertNotLocked, recordAttempt } from '../services/loginGuard.js';
import { findLoginCandidate, loadUser, denialReason, normalizeIdentifier, toPublicUser } from '../services/users.js';
import { HttpError, badRequest, forbidden, notFound } from '../utils/httpError.js';
import { clientMeta, bearerToken, setRefreshCookie, clearRefreshCookie, readRefreshCookie } from '../utils/request.js';
import { validate, z } from '../utils/validate.js';

const router = Router();

// Same cost as real hashes so "unknown user" and "wrong password" take the same time.
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 10);
const BCRYPT_ROUNDS = 10;

const DENIAL_MESSAGES = {
  role_not_allowed: (cfg) => `This account can't sign in to the ${cfg.name}.`,
  account_not_activated: () => 'Your account has not been activated yet.',
  account_disabled: () => 'Your account is disabled. Contact your administrator.',
  college_inactive: () => 'Your college account is not active. Contact your administrator.',
};

async function auditLogin(db, req, user, portal, sessionId) {
  await db.query(
    `INSERT INTO audit_logs (actor_id, college_id, action, entity_type, entity_id, changes, ip_address)
     VALUES ($1, $2, 'login', 'user', $1, $3, $4::inet)`,
    [user.id, user.collegeId ?? null, JSON.stringify({ portal, sessionId }), clientMeta(req).ip]
  );
}

/** Build the token response. In cookie mode the refresh token is only sent as an HttpOnly cookie. */
function tokenResponse(res, portal, { access, refreshToken, refreshTokenExpiresAt, sessionId, user, cfg }) {
  setRefreshCookie(res, portal, refreshToken, refreshTokenExpiresAt);
  return {
    tokenType: 'Bearer',
    accessToken: access.accessToken,
    expiresIn: access.expiresIn,
    expiresAt: access.expiresAt,
    ...(env.cookie.enabled ? {} : { refreshToken }),
    refreshTokenExpiresAt,
    sessionId,
    portal,
    user: toPublicUser(user, cfg),
  };
}

// ---------------------------------------------------------------------------------
// POST /api/:portal/login   body: { username | email | phone, password }
// ---------------------------------------------------------------------------------
const loginSchema = z
  .object({
    username: z.string().trim().min(1).max(200).optional(),
    email: z.string().trim().min(1).max(200).optional(),
    phone: z.string().trim().min(1).max(40).optional(),
    password: z.string().min(1, 'Password is required').max(200),
  })
  .refine((b) => b.username || b.email || b.phone, { message: 'username, email or phone is required' });

router.post('/:portal/login', resolvePortal, async (req, res) => {
  const { portal, portalCfg: cfg } = req;
  const body = validate(loginSchema, req.body);
  const ident = normalizeIdentifier(body.email || body.username || body.phone);
  if (!ident.value) throw badRequest('Enter an email address or phone number');
  const meta = clientMeta(req);

  await assertNotLocked(ident.value, meta.ip);

  const candidate = await findLoginCandidate(ident);
  const passwordOk = await bcrypt.compare(body.password, candidate?.passwordHash || DUMMY_HASH);
  if (!candidate || !passwordOk) {
    await recordAttempt({
      identifier: ident.value, portal, ip: meta.ip, userId: candidate?.id,
      succeeded: false, reason: candidate ? 'bad_password' : 'unknown_user',
    });
    throw new HttpError(401, 'Invalid username/phone or password.', { reason: 'invalid_credentials' });
  }

  const user = await loadUser(candidate.id);
  const denied = denialReason(user, cfg);
  if (denied) {
    await recordAttempt({ identifier: ident.value, portal, ip: meta.ip, userId: user.id, succeeded: false, reason: denied });
    throw new HttpError(403, DENIAL_MESSAGES[denied]?.(cfg) ?? 'Sign-in not allowed.', { reason: denied });
  }

  const session = await withTransaction(async (db) => {
    const s = await createSession(db, { userId: user.id, portal, ...meta });
    await db.query('UPDATE users SET last_login_at = now() WHERE id = $1', [user.id]);
    await auditLogin(db, req, user, portal, s.sessionId);
    return s;
  });
  await recordAttempt({ identifier: ident.value, portal, ip: meta.ip, userId: user.id, succeeded: true });

  const access = await issueAccessToken({ user, portal, sessionId: session.sessionId });
  res.json({
    ...tokenResponse(res, portal, { access, ...session, user, cfg }),
    ...(session.replacedSessions ? { notice: 'You were signed out of your other device.' } : {}),
  });
});

// ---------------------------------------------------------------------------------
// POST /api/:portal/refresh   body: { refreshToken }  (or the HttpOnly cookie)
// Rotates the refresh token and returns a new access token.
// ---------------------------------------------------------------------------------
router.post('/:portal/refresh', resolvePortal, async (req, res) => {
  const { portal, portalCfg: cfg } = req;
  const token = req.body?.refreshToken || readRefreshCookie(req, portal);
  if (!token) throw new HttpError(401, 'Refresh token is required', { reason: 'missing_refresh_token' });

  // Errors are returned from the transaction (not thrown) so revocations get committed.
  const result = await withTransaction(async (db) => {
    const r = await rotateSession(db, token, portal, clientMeta(req));
    if (!r.ok) return r;
    const user = await loadUser(r.session.userId, db);
    const denied = denialReason(user, cfg);
    if (denied) {
      await revokeSession(db, r.session.id, denied);
      return { ok: false, error: new HttpError(401, DENIAL_MESSAGES[denied]?.(cfg) ?? 'Sign-in not allowed.', { reason: denied }) };
    }
    return { ...r, user };
  });

  if (!result.ok) {
    clearRefreshCookie(res, portal);
    throw result.error;
  }
  const access = await issueAccessToken({ user: result.user, portal, sessionId: result.session.id });
  res.json(tokenResponse(res, portal, {
    access, refreshToken: result.refreshToken, refreshTokenExpiresAt: result.refreshTokenExpiresAt,
    sessionId: result.session.id, user: result.user, cfg,
  }));
});

// ---------------------------------------------------------------------------------
// POST /api/:portal/logout   body: { refreshToken } (or cookie) — or just the Bearer access token
// Always 200, so it never reveals whether a token was valid.
// ---------------------------------------------------------------------------------
router.post('/:portal/logout', resolvePortal, async (req, res) => {
  const { portal } = req;
  const refresh = req.body?.refreshToken || readRefreshCookie(req, portal);
  let revoked = null;
  if (refresh) {
    revoked = await withTransaction((db) => revokeByRefreshToken(db, refresh, portal, 'logout'));
  } else if (bearerToken(req)) {
    // Access-token logout: verify it properly first
    try {
      await requireAuth(req, res, () => {});
      await revokeSession(undefined, req.auth.session.id, 'logout');
      revoked = req.auth.session.id;
    } catch { /* invalid token: nothing to revoke */ }
  }
  clearRefreshCookie(res, portal);
  res.json({ message: 'Signed out', revoked: !!revoked });
});

// ---------------------------------------------------------------------------------
// Authenticated (Bearer access token for this portal)
// ---------------------------------------------------------------------------------

/** GET /api/:portal/me */
router.get('/:portal/me', resolvePortal, requireAuth, (req, res) => {
  const { session, user, payload } = req.auth;
  res.json({
    data: toPublicUser(user, req.portalCfg),
    session: { id: session.id, createdAt: session.createdAt, expiresAt: session.expiresAt, absoluteExpiresAt: session.absoluteExpiresAt },
    token: { expiresAt: new Date(payload.exp * 1000).toISOString(), roles: payload.roles },
  });
});

/** GET /api/:portal/sessions — the user's active sessions on this portal */
router.get('/:portal/sessions', resolvePortal, requireAuth, async (req, res) => {
  const rows = await listActiveSessions(req.auth.user.id, req.portal);
  res.json({ data: rows.map((s) => ({ ...s, current: s.id === req.auth.session.id })) });
});

/** DELETE /api/:portal/sessions/:id — sign out one of your own sessions */
router.delete('/:portal/sessions/:id', resolvePortal, requireAuth, async (req, res) => {
  const { id } = validate(z.object({ id: z.string().uuid() }), { id: req.params.id });
  const { rowCount } = await query(
    `UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'signed_out_remotely'
      WHERE id = $1 AND user_id = $2 AND portal = $3 AND revoked_at IS NULL`,
    [id, req.auth.user.id, req.portal]
  );
  if (!rowCount) throw notFound('Session not found');
  res.json({ message: 'Session signed out' });
});

/** POST /api/:portal/logout-all  body: { keepCurrent?: boolean, allPortals?: boolean } */
router.post('/:portal/logout-all', resolvePortal, requireAuth, async (req, res) => {
  const body = validate(z.object({ keepCurrent: z.boolean().default(false), allPortals: z.boolean().default(false) }), req.body);
  const ids = await revokeUserSessions(undefined, req.auth.user.id, {
    portal: body.allPortals ? null : req.portal,
    exceptId: body.keepCurrent ? req.auth.session.id : null,
    reason: 'logout_all',
  });
  if (!body.keepCurrent) clearRefreshCookie(res, req.portal);
  res.json({ message: `${ids.length} session(s) signed out`, revoked: ids.length });
});

/** POST /api/:portal/change-password  body: { currentPassword, newPassword } — signs out every other session */
router.post('/:portal/change-password', resolvePortal, requireAuth, async (req, res) => {
  const body = validate(
    z.object({
      currentPassword: z.string().min(1),
      newPassword: z.string().min(8, 'New password must be at least 8 characters').max(200),
    }).refine((b) => b.currentPassword !== b.newPassword, { message: 'New password must be different', path: ['newPassword'] }),
    req.body
  );
  const { rows: [row] } = await query('SELECT password_hash FROM users WHERE id = $1', [req.auth.user.id]);
  if (!(await bcrypt.compare(body.currentPassword, row.passwordHash))) {
    throw forbidden('Current password is incorrect');
  }
  const hash = await bcrypt.hash(body.newPassword, BCRYPT_ROUNDS);
  const revoked = await withTransaction(async (db) => {
    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.auth.user.id]);
    await db.query(
      `INSERT INTO audit_logs (actor_id, college_id, action, entity_type, entity_id, changes, ip_address)
       VALUES ($1, $2, 'update', 'user', $1, '{"password":"changed"}', $3::inet)`,
      [req.auth.user.id, req.auth.user.collegeId ?? null, clientMeta(req).ip]
    );
    return revokeUserSessions(db, req.auth.user.id, { exceptId: req.auth.session.id, reason: 'password_changed' });
  });
  res.json({ message: 'Password updated. Other sessions were signed out.', revokedSessions: revoked.length });
});

export default router;
