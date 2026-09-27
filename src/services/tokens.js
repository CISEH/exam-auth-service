import crypto from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { env } from '../config/env.js';
import { PORTALS, portalByAudience } from '../config/portals.js';
import { keystore } from '../keys/keystore.js';

export const ACCESS_TOKEN_TYPE = 'at+jwt'; // RFC 9068 — stops other JWT kinds being used as access tokens

/** Roles of the user that are meaningful on this portal. */
export const portalRoles = (user, portal) => user.roles.filter((r) => PORTALS[portal].roles.includes(r));

/**
 * Issue a short-lived access token.
 * Claims: iss, aud, sub (user id), sid (session id), jti, iat, exp, portal, roles, college_id, name
 */
export async function issueAccessToken({ user, portal, sessionId }) {
  const cfg = PORTALS[portal];
  const key = keystore.signingKey(portal);
  const now = Math.floor(Date.now() / 1000);
  const exp = now + cfg.accessTtl;

  const token = await new SignJWT({
    sid: sessionId,
    portal,
    roles: portalRoles(user, portal),
    college_id: user.collegeId ?? null,
    name: user.fullName,
  })
    .setProtectedHeader({ alg: 'RS256', kid: key.kid, typ: ACCESS_TOKEN_TYPE })
    .setIssuer(env.issuer)
    .setAudience(cfg.audience)
    .setSubject(user.id)
    .setJti(crypto.randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(key.privateKey);

  return { accessToken: token, expiresIn: cfg.accessTtl, expiresAt: new Date(exp * 1000).toISOString() };
}

// Resolve the verification key from the token header; only keys we hold are accepted.
async function keyFor(header) {
  const key = keystore.get(header.kid);
  if (!key) {
    const err = new Error('Unknown signing key');
    err.code = 'ERR_JWKS_NO_MATCHING_KEY';
    throw err;
  }
  return key.publicKey;
}

/**
 * Verify signature + standard claims. `portal` limits the accepted audience;
 * omit it to accept a token for any portal (introspection).
 * Returns { payload, portal }. Throws on any problem.
 */
export async function verifyAccessToken(token, { portal } = {}) {
  const audiences = portal ? [PORTALS[portal].audience] : Object.values(PORTALS).map((p) => p.audience);
  const { payload, protectedHeader } = await jwtVerify(token, keyFor, {
    issuer: env.issuer,
    audience: audiences,
    algorithms: ['RS256'],
    typ: ACCESS_TOKEN_TYPE,
    clockTolerance: 5,
    requiredClaims: ['sub', 'sid', 'exp', 'iat', 'jti'],
  });

  // Defence in depth: the signing key must belong to the portal the token is for.
  const tokenPortal = portalByAudience(Array.isArray(payload.aud) ? payload.aud[0] : payload.aud);
  if (!tokenPortal || keystore.get(protectedHeader.kid)?.portal !== tokenPortal || payload.portal !== tokenPortal) {
    const err = new Error('Token was not signed by the portal it is issued for');
    err.code = 'ERR_JWT_CLAIM_VALIDATION_FAILED';
    throw err;
  }
  return { payload, portal: tokenPortal };
}

/** Map jose errors to a short reason for API responses. */
export function tokenErrorReason(err) {
  switch (err?.code) {
    case 'ERR_JWT_EXPIRED': return 'token_expired';
    case 'ERR_JWT_CLAIM_VALIDATION_FAILED': return err.claim === 'aud' ? 'wrong_audience' : 'invalid_claims';
    case 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED': return 'bad_signature';
    case 'ERR_JWKS_NO_MATCHING_KEY': return 'unknown_key';
    default: return 'invalid_token';
  }
}
