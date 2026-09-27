/**
 * Refresh-token sessions.
 *
 * Refresh token format: "<session uuid>.<43-char random secret>"
 * Only sha256(secret) is stored. Every refresh rotates the secret; presenting an
 * already-rotated secret again means the token was copied, so the whole session is
 * revoked (refresh-token reuse detection). A 15-second grace window avoids false
 * alarms when two browser tabs refresh at the same moment.
 */
import crypto from 'node:crypto';
import { query, queryOne } from '../db/pool.js';
import { PORTALS } from '../config/portals.js';
import { HttpError } from '../utils/httpError.js';

const REUSE_GRACE_SECONDS = 15;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const newSecret = () => crypto.randomBytes(32).toString('base64url');
const sameHash = (a, b) => !!a && !!b && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

const refreshError = (reason, message = 'Refresh token is invalid or expired. Please sign in again.') =>
  new HttpError(401, message, { reason });

export function parseRefreshToken(token) {
  const [id, secret, extra] = String(token || '').split('.');
  if (extra !== undefined || !UUID_RE.test(id || '') || !secret || secret.length < 40) return null;
  return { id, secret };
}

/** Start a session at login. For single-session portals, other sessions of the user are revoked. */
export async function createSession(db, { userId, portal, userAgent, ip }) {
  const cfg = PORTALS[portal];
  let replaced = 0;
  if (cfg.singleSession) {
    replaced = (await revokeUserSessions(db, userId, { portal, reason: 'signed_in_elsewhere' })).length;
  }
  const secret = newSecret();
  const row = await queryOne(
    `INSERT INTO auth_sessions (user_id, portal, refresh_token_hash, user_agent, ip_address, expires_at, absolute_expires_at)
     VALUES ($1, $2, $3, $4, $5::inet,
             now() + make_interval(secs => $6), now() + make_interval(secs => $7))
     RETURNING id, expires_at, absolute_expires_at`,
    [userId, portal, sha256(secret), userAgent, ip, Math.min(cfg.refreshIdleTtl, cfg.sessionMaxTtl), cfg.sessionMaxTtl],
    db
  );
  return { sessionId: row.id, refreshToken: `${row.id}.${secret}`, refreshTokenExpiresAt: row.expiresAt, replacedSessions: replaced };
}

/**
 * Validate + rotate a refresh token. Run inside a transaction (the row is locked).
 * Returns { ok: true, session, refreshToken, refreshTokenExpiresAt } or { ok: false, error }.
 * Failures are returned rather than thrown so that a revocation (reuse / expiry)
 * is committed before the caller responds with the error.
 */
export async function rotateSession(db, token, portal, meta) {
  try {
    return { ok: true, ...(await rotate(db, token, portal, meta)) };
  } catch (err) {
    if (err instanceof HttpError) return { ok: false, error: err };
    throw err;
  }
}

async function rotate(db, token, portal, { userAgent, ip }) {
  const parsed = parseRefreshToken(token);
  if (!parsed) throw refreshError('malformed');

  const s = await queryOne(
    `SELECT *, (expires_at <= now() OR absolute_expires_at <= now()) AS is_expired,
            (rotated_at > now() - make_interval(secs => $3)) AS in_grace
       FROM auth_sessions WHERE id = $1 AND portal = $2 FOR UPDATE`,
    [parsed.id, portal, REUSE_GRACE_SECONDS],
    db
  );
  if (!s) throw refreshError('unknown_session');
  if (s.revokedAt) throw refreshError('session_revoked', 'This session has been signed out. Please sign in again.');

  const presented = sha256(parsed.secret);
  if (!sameHash(presented, s.refreshTokenHash)) {
    if (sameHash(presented, s.previousTokenHash)) {
      if (s.inGrace) throw refreshError('already_rotated', 'This refresh token was just used. Use the newest token.');
      await revokeSession(db, s.id, 'refresh_token_reuse');
      throw refreshError('token_reuse', 'This refresh token was already used, so the session has been signed out for safety.');
    }
    throw refreshError('invalid_secret');
  }
  if (s.isExpired) {
    await revokeSession(db, s.id, 'expired');
    throw refreshError('expired', 'Your session has expired. Please sign in again.');
  }

  const cfg = PORTALS[portal];
  const secret = newSecret();
  const updated = await queryOne(
    `UPDATE auth_sessions
        SET previous_token_hash = refresh_token_hash,
            refresh_token_hash  = $2,
            rotated_at          = now(),
            rotation_count      = rotation_count + 1,
            last_used_at        = now(),
            expires_at          = LEAST(now() + make_interval(secs => $3), absolute_expires_at),
            user_agent          = COALESCE($4, user_agent),
            ip_address          = COALESCE($5::inet, ip_address)
      WHERE id = $1
      RETURNING *`,
    [s.id, sha256(secret), cfg.refreshIdleTtl, userAgent, ip],
    db
  );
  return { session: updated, refreshToken: `${s.id}.${secret}`, refreshTokenExpiresAt: updated.expiresAt };
}

/** Revoke the session a refresh token belongs to, if the token is genuine. Returns the session id or null. */
export async function revokeByRefreshToken(db, token, portal, reason = 'logout') {
  const parsed = parseRefreshToken(token);
  if (!parsed) return null;
  const s = await queryOne(
    'SELECT id, refresh_token_hash, previous_token_hash FROM auth_sessions WHERE id = $1 AND portal = $2',
    [parsed.id, portal], db
  );
  const presented = sha256(parsed.secret);
  if (!s || !(sameHash(presented, s.refreshTokenHash) || sameHash(presented, s.previousTokenHash))) return null;
  await revokeSession(db, s.id, reason);
  return s.id;
}

/** Active (not revoked, not expired) session or null. */
export async function getActiveSession(id, db) {
  if (!UUID_RE.test(id || '')) return null;
  return queryOne(
    `SELECT * FROM auth_sessions
      WHERE id = $1 AND revoked_at IS NULL AND expires_at > now() AND absolute_expires_at > now()`,
    [id], db
  );
}

export async function revokeSession(db, id, reason) {
  const { rowCount } = await query(
    `UPDATE auth_sessions SET revoked_at = now(), revoked_reason = $2 WHERE id = $1 AND revoked_at IS NULL`,
    [id, reason], db
  );
  return rowCount > 0;
}

/** Revoke a user's sessions (optionally for one portal, optionally keeping one). Returns revoked ids. */
export async function revokeUserSessions(db, userId, { portal = null, exceptId = null, reason }) {
  const { rows } = await query(
    `UPDATE auth_sessions SET revoked_at = now(), revoked_reason = $4
      WHERE user_id = $1 AND revoked_at IS NULL
        AND ($2::text IS NULL OR portal = $2)
        AND ($3::uuid IS NULL OR id <> $3)
      RETURNING id`,
    [userId, portal, exceptId, reason], db
  );
  return rows.map((r) => r.id);
}

export async function listActiveSessions(userId, portal) {
  const { rows } = await query(
    `SELECT id, portal, user_agent, host(ip_address) AS ip_address, created_at, last_used_at, expires_at, absolute_expires_at
       FROM auth_sessions
      WHERE user_id = $1 AND portal = $2 AND revoked_at IS NULL AND expires_at > now() AND absolute_expires_at > now()
      ORDER BY last_used_at DESC`,
    [userId, portal]
  );
  return rows;
}

/** Housekeeping: drop old attempts and long-dead sessions. */
export async function cleanupExpired() {
  const a = await query(`DELETE FROM auth_login_attempts WHERE created_at < now() - interval '30 days'`);
  const s = await query(
    `DELETE FROM auth_sessions
      WHERE (revoked_at IS NOT NULL AND revoked_at < now() - interval '30 days')
         OR (revoked_at IS NULL AND absolute_expires_at < now() - interval '30 days')`
  );
  return { attempts: a.rowCount, sessions: s.rowCount };
}
