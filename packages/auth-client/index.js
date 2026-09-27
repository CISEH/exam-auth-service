/**
 * @exam-portal/auth-client
 * Verify access tokens issued by exam-auth-service and authorize requests.
 *
 *   import { createAuthClient } from '@exam-portal/auth-client';
 *   const auth = createAuthClient({ authUrl: 'http://localhost:4001', audience: 'exam-hub-admin' });
 *   app.use('/api', auth.authenticate());
 *   router.post('/exams', auth.requireRoles('college_admin', 'instructor'), handler);
 *
 * Tokens are verified locally against the service's public keys (JWKS, cached and
 * refreshed automatically when keys rotate). Set `introspect: true` to also ask the
 * service on each request (cached briefly) whether the session is still active —
 * use it where an immediate sign-out matters, e.g. the exam portal.
 */
import { createRemoteJWKSet, jwtVerify } from 'jose';

export class AuthError extends Error {
  constructor(status, reason, message) {
    super(message);
    this.status = status;
    this.reason = reason;
  }
}

const REASONS = {
  ERR_JWT_EXPIRED: 'token_expired',
  ERR_JWS_SIGNATURE_VERIFICATION_FAILED: 'bad_signature',
  ERR_JWKS_NO_MATCHING_KEY: 'unknown_key',
  ERR_JWT_CLAIM_VALIDATION_FAILED: 'invalid_claims',
};

function bearer(req) {
  const [scheme, token] = String(req.headers?.authorization || '').split(' ');
  return scheme?.toLowerCase() === 'bearer' && token ? token : null;
}

function deny(res, status, reason, message) {
  if (status === 401) res.setHeader('WWW-Authenticate', `Bearer error="invalid_token", error_description="${reason}"`);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify({ error: { message, reason } }));
}

/**
 * @param {object}  opts
 * @param {string}  opts.audience            'exam-hub-admin' or 'exam-portal' (required)
 * @param {string} [opts.authUrl]            base URL of exam-auth-service, e.g. http://localhost:4001
 * @param {string} [opts.jwksUrl]            defaults to `${authUrl}/.well-known/jwks.json`
 * @param {string} [opts.issuer]             defaults to 'exam-auth-service'
 * @param {boolean}[opts.introspect]         also check the session is still active (needs introspectApiKey)
 * @param {string} [opts.introspectApiKey]   INTROSPECT_API_KEY of the auth service
 * @param {number} [opts.introspectCacheSeconds] default 15
 * @param {number} [opts.clockTolerance]     seconds, default 5
 * @param {string} [opts.superRole]          role that passes every requireRoles check (default 'super_admin', null to disable)
 */
export function createAuthClient(opts = {}) {
  const {
    audience,
    authUrl,
    jwksUrl = authUrl ? `${authUrl.replace(/\/$/, '')}/.well-known/jwks.json` : undefined,
    issuer = 'exam-auth-service',
    introspect = false,
    introspectApiKey,
    introspectCacheSeconds = 15,
    clockTolerance = 5,
    superRole = 'super_admin',
    fetch: fetchImpl = globalThis.fetch,
  } = opts;

  if (!audience) throw new Error('createAuthClient: `audience` is required');
  if (!jwksUrl) throw new Error('createAuthClient: pass `authUrl` or `jwksUrl`');
  if (introspect && (!authUrl || !introspectApiKey)) {
    throw new Error('createAuthClient: `introspect` needs `authUrl` and `introspectApiKey`');
  }

  const jwks = createRemoteJWKSet(new URL(jwksUrl), { cooldownDuration: 30_000, cacheMaxAge: 10 * 60_000 });
  const introspectCache = new Map(); // jti -> { until, result }

  async function introspectToken(token, jti) {
    const hit = introspectCache.get(jti);
    if (hit && hit.until > Date.now()) return hit.result;

    let result;
    try {
      const res = await fetchImpl(`${authUrl.replace(/\/$/, '')}/api/introspect`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-api-key': introspectApiKey },
        body: JSON.stringify({ token }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      result = await res.json();
    } catch (err) {
      // Fail closed: if we can't confirm the session, don't let the request through.
      throw new AuthError(503, 'auth_unavailable', `Could not reach the authentication service (${err.message})`);
    }

    if (introspectCache.size > 5000) {
      const now = Date.now();
      for (const [k, v] of introspectCache) if (v.until <= now) introspectCache.delete(k);
    }
    introspectCache.set(jti, { until: Date.now() + introspectCacheSeconds * 1000, result });
    return result;
  }

  /**
   * Verify a raw access token. Resolves to the auth context:
   * { userId, sessionId, roles, collegeId, name, portal, expiresAt, claims, hasRole(...roles) }
   * Rejects with AuthError.
   */
  async function verify(token) {
    let payload;
    try {
      ({ payload } = await jwtVerify(token, jwks, {
        issuer,
        audience,
        algorithms: ['RS256'],
        typ: 'at+jwt',
        clockTolerance,
        requiredClaims: ['sub', 'sid', 'exp', 'jti'],
      }));
    } catch (err) {
      const reason = err.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' && err.claim === 'aud'
        ? 'wrong_audience'
        : REASONS[err.code] || 'invalid_token';
      throw new AuthError(401, reason, reason === 'token_expired' ? 'Access token expired' : 'Invalid access token');
    }

    let roles = Array.isArray(payload.roles) ? payload.roles : [];
    let collegeId = payload.college_id ?? null;
    if (introspect) {
      const r = await introspectToken(token, payload.jti);
      if (!r.active) throw new AuthError(401, r.reason || 'session_revoked', 'This session has been signed out');
      roles = r.roles; // freshest roles from the database
      collegeId = r.college_id ?? null;
    }

    return {
      userId: payload.sub,
      sessionId: payload.sid,
      roles,
      collegeId,
      name: payload.name ?? null,
      portal: payload.portal ?? null,
      expiresAt: new Date(payload.exp * 1000),
      claims: payload,
      hasRole: (...want) => roles.some((r) => want.includes(r)) || (!!superRole && roles.includes(superRole)),
    };
  }

  /** Middleware: requires a valid token and sets req.auth. `{ optional: true }` lets anonymous requests through. */
  function authenticate({ optional = false } = {}) {
    return (req, res, next) => {
      const token = bearer(req);
      if (!token) {
        if (optional) return next();
        return deny(res, 401, 'missing_token', 'Authentication required');
      }
      verify(token).then(
        (auth) => { req.auth = auth; next(); },
        (err) => (err instanceof AuthError ? deny(res, err.status, err.reason, err.message) : next(err))
      );
    };
  }

  /** Middleware: user must have at least one of the roles (superRole always passes). Use after authenticate(). */
  function requireRoles(...roles) {
    return (req, res, next) => {
      if (!req.auth) return deny(res, 401, 'missing_token', 'Authentication required');
      if (!req.auth.hasRole(...roles)) return deny(res, 403, 'insufficient_role', 'You do not have permission to perform this action');
      next();
    };
  }

  /**
   * Middleware with your own rule, e.g.
   *   auth.authorize((a, req) => a.collegeId === req.params.collegeId)
   */
  function authorize(check, message = 'You do not have permission to perform this action') {
    return async (req, res, next) => {
      if (!req.auth) return deny(res, 401, 'missing_token', 'Authentication required');
      try {
        if (await check(req.auth, req)) return next();
        return deny(res, 403, 'forbidden', message);
      } catch (err) {
        return next(err);
      }
    };
  }

  return { verify, authenticate, requireRoles, authorize };
}

export default createAuthClient;
