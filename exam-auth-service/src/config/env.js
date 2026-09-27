import 'dotenv/config';
import path from 'node:path';

const bool = (v, def = false) => (v === undefined || v === '' ? def : ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase()));
const int = (v, def) => (v === undefined || v === '' || Number.isNaN(Number(v)) ? def : Number(v));

/** "90" | "30s" | "15m" | "12h" | "7d" -> seconds */
export function parseDuration(v, def) {
  if (v === undefined || v === '') return parseDuration(def);
  if (typeof v === 'number') return v;
  const m = String(v).trim().match(/^(\d+)\s*([smhd]?)$/i);
  if (!m) throw new Error(`Invalid duration "${v}" (use e.g. 30s, 15m, 12h, 7d)`);
  return Number(m[1]) * { '': 1, s: 1, m: 60, h: 3600, d: 86400 }[m[2].toLowerCase()];
}

const e = process.env;

export const env = {
  nodeEnv: e.NODE_ENV || 'development',
  port: int(e.PORT, 4001),
  corsOrigins: (e.CORS_ORIGIN || 'http://localhost:5173').split(',').map((s) => s.trim()).filter(Boolean),

  db: {
    connectionString: e.DATABASE_URL || undefined,
    ssl: bool(e.PGSSL) ? { rejectUnauthorized: false } : undefined,
    max: int(e.PG_POOL_MAX, 10),
  },

  issuer: e.AUTH_ISSUER || 'exam-auth-service',
  keysDir: path.resolve(e.KEYS_DIR || './keys'),

  login: {
    maxFailures: int(e.LOGIN_MAX_FAILURES, 5),
    maxFailuresPerIp: int(e.LOGIN_MAX_FAILURES_PER_IP, 30),
    windowSeconds: parseDuration(e.LOGIN_WINDOW, '15m'),
  },

  cookie: {
    enabled: bool(e.REFRESH_TOKEN_COOKIE),
    secure: bool(e.COOKIE_SECURE),
    sameSite: (e.COOKIE_SAMESITE || 'lax').toLowerCase(),
  },

  introspectApiKey: e.INTROSPECT_API_KEY || '',
};

env.isProd = env.nodeEnv === 'production';

if (env.isProd && env.introspectApiKey === 'change-me-to-a-long-random-string') {
  throw new Error('Set INTROSPECT_API_KEY to a real secret (or leave it empty to disable introspection).');
}
