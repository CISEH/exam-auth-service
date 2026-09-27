import { Router } from 'express';
import crypto from 'node:crypto';
import { env } from '../config/env.js';
import { PORTALS } from '../config/portals.js';
import { keystore } from '../keys/keystore.js';
import { checkConnection } from '../db/pool.js';
import { verifyAccessToken } from '../services/tokens.js';
import { getActiveSession } from '../services/sessions.js';
import { loadUser, denialReason } from '../services/users.js';
import { HttpError, notFound } from '../utils/httpError.js';
import { validate, z } from '../utils/validate.js';

const router = Router();

/** GET /.well-known/jwks.json — public keys for verifying access tokens (all portals) */
router.get('/.well-known/jwks.json', (_req, res) => {
  res.set('Cache-Control', 'public, max-age=300');
  res.json(keystore.jwks);
});

/** GET /api/health */
router.get('/api/health', async (_req, res) => {
  try {
    await checkConnection();
    res.json({ status: 'ok', db: 'up', keys: keystore.summary().map((k) => ({ portal: k.portal, active: k.active })) });
  } catch (err) {
    res.status(503).json({ status: 'degraded', db: 'down', error: err.message });
  }
});

/** GET /api/config — what a portal API needs to verify tokens */
router.get('/api/config', (req, res) => {
  const base = `${req.protocol}://${req.headers.host}`;
  res.json({
    issuer: env.issuer,
    jwksUri: `${base}/.well-known/jwks.json`,
    algorithms: ['RS256'],
    tokenType: 'at+jwt',
    portals: Object.fromEntries(Object.entries(PORTALS).map(([key, p]) => [key, {
      name: p.name, audience: p.audience, roles: p.roles,
      accessTokenTtl: p.accessTtl, refreshIdleTtl: p.refreshIdleTtl, sessionMaxTtl: p.sessionMaxTtl,
      singleSession: p.singleSession,
      endpoints: {
        login: `${base}/api/${key}/login`, refresh: `${base}/api/${key}/refresh`,
        logout: `${base}/api/${key}/logout`, me: `${base}/api/${key}/me`,
      },
    }])),
  });
});

/**
 * POST /api/introspect   header: x-api-key   body: { token, portal? }
 * For portal APIs that need up-to-the-second revocation (e.g. the exam portal's
 * single-session rule). Response follows RFC 7662: { active: false } or { active: true, ...claims }.
 * Roles are re-read from the database, so role changes apply immediately.
 */
router.post('/api/introspect', async (req, res) => {
  if (!env.introspectApiKey) throw notFound('Introspection is disabled');
  const given = Buffer.from(String(req.headers['x-api-key'] || ''));
  const expected = Buffer.from(env.introspectApiKey);
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
    throw new HttpError(401, 'Invalid API key');
  }

  const body = validate(z.object({ token: z.string().min(1), portal: z.enum(Object.keys(PORTALS)).optional() }), req.body);
  res.set('Cache-Control', 'no-store');
  try {
    const { payload, portal } = await verifyAccessToken(body.token, { portal: body.portal });
    const session = await getActiveSession(payload.sid);
    if (!session || session.userId !== payload.sub) return res.json({ active: false, reason: 'session_revoked' });
    const user = await loadUser(payload.sub);
    const denied = denialReason(user, PORTALS[portal]);
    if (denied) return res.json({ active: false, reason: denied });
    return res.json({
      active: true,
      token_type: 'access_token',
      iss: payload.iss, aud: payload.aud, sub: payload.sub, sid: payload.sid, jti: payload.jti,
      iat: payload.iat, exp: payload.exp,
      portal,
      roles: user.roles.filter((r) => PORTALS[portal].roles.includes(r)),
      college_id: user.collegeId ?? null,
      name: user.fullName,
    });
  } catch {
    return res.json({ active: false });
  }
});

export default router;
