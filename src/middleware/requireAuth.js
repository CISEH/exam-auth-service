import { PORTALS } from '../config/portals.js';
import { verifyAccessToken, tokenErrorReason } from '../services/tokens.js';
import { getActiveSession } from '../services/sessions.js';
import { loadUser, denialReason } from '../services/users.js';
import { HttpError, notFound } from '../utils/httpError.js';
import { bearerToken } from '../utils/request.js';

const unauthorized = (reason, message = 'Authentication required') => new HttpError(401, message, { reason });

/** Validates :portal and attaches req.portal / req.portalCfg. */
export function resolvePortal(req, _res, next) {
  const key = req.params.portal;
  if (!Object.hasOwn(PORTALS, key)) throw notFound(`Unknown portal "${key}"`);
  req.portal = key;
  req.portalCfg = PORTALS[key];
  next();
}

/**
 * For the auth service's own endpoints (/me, /sessions, /logout-all ...):
 * token must be for this portal, its session must still be active and the user
 * must still be allowed on the portal.
 */
export async function requireAuth(req, _res, next) {
  const token = bearerToken(req);
  if (!token) throw unauthorized('missing_token');

  let verified;
  try {
    verified = await verifyAccessToken(token, { portal: req.portal });
  } catch (err) {
    throw unauthorized(tokenErrorReason(err), 'Invalid or expired access token');
  }
  const { payload } = verified;

  const session = await getActiveSession(payload.sid);
  if (!session || session.userId !== payload.sub) throw unauthorized('session_revoked', 'This session has been signed out');

  const user = await loadUser(payload.sub);
  const denied = denialReason(user, req.portalCfg);
  if (denied) throw unauthorized(denied, 'Account is no longer allowed to use this portal');

  req.auth = { payload, session, user };
  next();
}
