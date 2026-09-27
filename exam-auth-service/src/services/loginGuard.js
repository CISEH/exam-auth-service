/**
 * Brute-force protection backed by auth_login_attempts (works across several
 * service instances because the counts live in Postgres). Only wrong credentials
 * count as failures; a correct password on the wrong portal does not.
 *  - per account: LOGIN_MAX_FAILURES failures inside LOGIN_WINDOW (reset by a successful login)
 *  - per IP:      LOGIN_MAX_FAILURES_PER_IP failures inside LOGIN_WINDOW
 */
import { query, queryOne } from '../db/pool.js';
import { env } from '../config/env.js';
import { HttpError } from '../utils/httpError.js';

export async function assertNotLocked(identifier, ip) {
  const { maxFailures, maxFailuresPerIp, windowSeconds } = env.login;
  const r = await queryOne(
    `WITH win AS (
       SELECT * FROM auth_login_attempts
        WHERE created_at > now() - make_interval(secs => $3)
          AND (identifier = $1 OR ($2::inet IS NOT NULL AND ip_address = $2::inet))
     ),
     last_ok AS (SELECT max(created_at) AS at FROM win WHERE identifier = $1 AND succeeded)
     SELECT
       count(*) FILTER (WHERE identifier = $1 AND is_failure
                          AND created_at > COALESCE((SELECT at FROM last_ok), '-infinity')) AS account_failures,
       count(*) FILTER (WHERE $2::inet IS NOT NULL AND ip_address = $2::inet AND is_failure)  AS ip_failures,
       max(created_at) FILTER (WHERE is_failure) AS last_failure_at
     FROM (SELECT *, (NOT succeeded AND reason IN ('bad_password', 'unknown_user')) AS is_failure FROM win) w`,
    [identifier, ip, windowSeconds]
  );

  if (r.accountFailures >= maxFailures || r.ipFailures >= maxFailuresPerIp) {
    const retryAfter = Math.max(
      1,
      Math.ceil((new Date(r.lastFailureAt).getTime() + windowSeconds * 1000 - Date.now()) / 1000)
    );
    const err = new HttpError(429, `Too many failed sign-in attempts. Try again in ${Math.ceil(retryAfter / 60)} minute(s).`, {
      reason: 'locked',
      retryAfter,
    });
    err.retryAfter = retryAfter;
    throw err;
  }
}

export async function recordAttempt({ identifier, portal, ip, userId = null, succeeded, reason = null }) {
  await query(
    `INSERT INTO auth_login_attempts (identifier, portal, user_id, ip_address, succeeded, reason)
     VALUES ($1, $2, $3, $4::inet, $5, $6)`,
    [identifier, portal, userId, ip, succeeded, reason]
  );
}
