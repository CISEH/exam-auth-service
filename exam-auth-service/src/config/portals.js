import { parseDuration } from './env.js';

const e = process.env;

/**
 * One entry per front-end portal. Each portal gets:
 *  - its own RS256 signing key (keys/<portal>/)
 *  - its own JWT audience, so a token for one portal is rejected by the other
 *  - its own allowed roles and token lifetimes
 *
 * accessTtl        lifetime of the JWT access token
 * refreshIdleTtl   a session expires if it is not refreshed within this time
 * sessionMaxTtl    hard limit for a session, however often it is refreshed
 * singleSession    true = a new login signs the user out everywhere else on this portal
 */
export const PORTALS = {
  admin: {
    name: 'Exam Hub Admin',
    audience: 'exam-hub-admin',
    roles: ['super_admin', 'college_admin', 'instructor'],
    accessTtl: parseDuration(e.ADMIN_ACCESS_TTL, '15m'),
    refreshIdleTtl: parseDuration(e.ADMIN_REFRESH_IDLE_TTL, '12h'),
    sessionMaxTtl: parseDuration(e.ADMIN_SESSION_MAX_TTL, '7d'),
    singleSession: false,
  },
  exam: {
    name: 'Exam Portal',
    audience: 'exam-portal',
    roles: ['student'],
    accessTtl: parseDuration(e.EXAM_ACCESS_TTL, '10m'),
    refreshIdleTtl: parseDuration(e.EXAM_REFRESH_IDLE_TTL, '2h'),
    sessionMaxTtl: parseDuration(e.EXAM_SESSION_MAX_TTL, '8h'),
    singleSession: true,
  },
};

export const PORTAL_KEYS = Object.keys(PORTALS);
export const portalByAudience = (aud) => PORTAL_KEYS.find((k) => PORTALS[k].audience === aud) || null;
