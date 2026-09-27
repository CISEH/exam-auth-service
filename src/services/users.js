import { query, queryOne } from '../db/pool.js';

const ROLE_PRIORITY = ['super_admin', 'college_admin', 'instructor', 'student'];
export const ROLE_LABELS = {
  super_admin: 'Super Admin',
  college_admin: 'College Admin',
  instructor: 'Instructor',
  student: 'Student',
};

/**
 * Normalise what the user typed: emails are compared case-insensitively,
 * phone numbers by digits only ("+1 (415) 555-0172" == "14155550172").
 */
export function normalizeIdentifier(raw) {
  const s = String(raw || '').trim();
  if (s.includes('@')) return { kind: 'email', value: s.toLowerCase() };
  return { kind: 'phone', value: s.replace(/\D/g, '') };
}

/** Returns the single matching user row { id, passwordHash } or null (none / ambiguous). */
export async function findLoginCandidate(identifier) {
  if (identifier.kind === 'email') {
    return queryOne('SELECT id, password_hash FROM users WHERE email = $1', [identifier.value]);
  }
  if (identifier.value.length < 7) return null;
  // Exact digits, or a 10+ digit number without country code ("4155550199").
  const { rows } = await query(
    `SELECT id, password_hash FROM users
      WHERE regexp_replace(coalesce(phone, ''), '\\D', '', 'g') = $1
         OR (length($1) >= 10 AND regexp_replace(coalesce(phone, ''), '\\D', '', 'g') LIKE '%' || $1)
      LIMIT 2`,
    [identifier.value]
  );
  return rows.length === 1 ? rows[0] : null;
}

/** User + college + role keys. */
export async function loadUser(id, db) {
  const u = await queryOne(
    `SELECT u.id, u.college_id, u.email, u.full_name, u.phone, u.status, u.is_platform_admin, u.last_login_at,
            c.name AS college_name, c.code AS college_code, c.status AS college_status,
            COALESCE(array_agg(DISTINCT r.key::text) FILTER (WHERE r.key IS NOT NULL), '{}') AS roles
       FROM users u
       LEFT JOIN colleges   c  ON c.id = u.college_id
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles      r  ON r.id = ur.role_id
      WHERE u.id = $1
      GROUP BY u.id, c.id`,
    [id], db
  );
  if (!u) return null;
  const roles = [...u.roles];
  if (u.isPlatformAdmin && !roles.includes('super_admin')) roles.push('super_admin');
  roles.sort((a, b) => ROLE_PRIORITY.indexOf(a) - ROLE_PRIORITY.indexOf(b));
  return { ...u, roles, isSuperAdmin: roles.includes('super_admin') };
}

/**
 * Why this user may not use the portal, or null when allowed.
 * Checks account status, college status and that the user holds a role the portal accepts.
 */
export function denialReason(user, portalCfg) {
  if (!user) return 'user_not_found';
  if (user.status === 'invited') return 'account_not_activated';
  if (user.status !== 'active') return 'account_disabled';
  if (!user.isSuperAdmin && user.collegeId && user.collegeStatus !== 'active') return 'college_inactive';
  if (!user.roles.some((r) => portalCfg.roles.includes(r))) return 'role_not_allowed';
  return null;
}

const initialsOf = (name = '') => {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return '?';
  return (parts.length === 1 ? parts[0].slice(0, 2) : parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
};

/** Public profile for a portal (only that portal's roles are exposed). */
export function toPublicUser(user, portalCfg) {
  const roles = user.roles.filter((r) => portalCfg.roles.includes(r));
  return {
    id: user.id,
    email: user.email,
    name: user.fullName,
    initials: initialsOf(user.fullName),
    phone: user.phone,
    roles,
    role: roles[0] ?? null,
    roleLabel: ROLE_LABELS[roles[0]] ?? null,
    collegeId: user.collegeId,
    college: user.collegeId ? { id: user.collegeId, name: user.collegeName, code: user.collegeCode } : null,
    lastLoginAt: user.lastLoginAt,
  };
}
