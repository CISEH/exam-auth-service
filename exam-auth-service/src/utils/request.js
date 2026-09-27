import { isIP } from 'node:net';
import { env } from '../config/env.js';

/** Client IP (honours "trust proxy") and user agent, trimmed for storage. */
export const clientMeta = (req) => ({
  ip: req.ip && isIP(req.ip) ? req.ip : null,
  userAgent: (req.headers['user-agent'] || '').slice(0, 400) || null,
});

export const bearerToken = (req) => {
  const [scheme, token] = (req.headers.authorization || '').split(' ');
  return scheme?.toLowerCase() === 'bearer' && token ? token : null;
};

// ---- optional HttpOnly refresh-token cookie ------------------------------------
const cookieName = (portal) => `${portal}_refresh_token`;
const cookiePath = (portal) => `/api/${portal}`;

export function setRefreshCookie(res, portal, token, expiresAt) {
  if (!env.cookie.enabled) return;
  res.cookie(cookieName(portal), token, {
    httpOnly: true,
    secure: env.cookie.secure,
    sameSite: env.cookie.sameSite,
    path: cookiePath(portal),
    expires: new Date(expiresAt),
  });
}

export function clearRefreshCookie(res, portal) {
  if (!env.cookie.enabled) return;
  res.clearCookie(cookieName(portal), { path: cookiePath(portal), httpOnly: true, secure: env.cookie.secure, sameSite: env.cookie.sameSite });
}

export function readRefreshCookie(req, portal) {
  if (!env.cookie.enabled) return null;
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === cookieName(portal)) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}
