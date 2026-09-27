import pg from 'pg';
import { env } from '../config/env.js';

const { Pool, types } = pg;

// Return NUMERIC (1700) and BIGINT/COUNT (20) as JS numbers instead of strings.
// Values in this schema (marks, scores, money up to 12 digits) fit safely in a double.
types.setTypeParser(1700, (v) => (v === null ? null : parseFloat(v)));
types.setTypeParser(20, (v) => (v === null ? null : parseInt(v, 10)));

export const pool = new Pool({
  connectionString: env.db.connectionString, // falls back to PGHOST/PGUSER/... when undefined
  ssl: env.db.ssl,
  max: env.db.max,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

pool.on('error', (err) => {
  // Errors on idle clients (e.g. DB restarted) — log and let the pool replace the client.
  console.error('[db] idle client error:', err.message);
});

// snake_case -> camelCase for API responses
const toCamel = (s) => s.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());
export const camelize = (row) => {
  if (!row || typeof row !== 'object' || Array.isArray(row) || row instanceof Date) return row;
  const out = {};
  for (const [k, v] of Object.entries(row)) out[toCamel(k)] = v;
  return out;
};

/**
 * Run a parameterised query. Always pass user input through `params` — never
 * interpolate it into `text`.
 * @returns {Promise<{rows: object[], rowCount: number}>} rows are camelCased
 */
export async function query(text, params = [], client = pool) {
  const res = await client.query(text, params);
  return { rows: res.rows.map(camelize), rowCount: res.rowCount };
}

export async function queryOne(text, params = [], client = pool) {
  const { rows } = await query(text, params, client);
  return rows[0] ?? null;
}

/**
 * Run `fn(client)` inside a transaction. Commits on success, rolls back on error.
 */
export async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    throw err;
  } finally {
    client.release();
  }
}

export async function checkConnection() {
  const { rows } = await pool.query('SELECT now() AS now, current_database() AS db, version() AS version');
  return rows[0];
}
