// Applies db/migrations/*.sql in order, once each (tracked in auth_schema_migrations).
// Usage: npm run db:migrate
import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { pool } from '../src/db/pool.js';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'db', 'migrations');

const client = await pool.connect();
try {
  const { rows: [base] } = await client.query(`SELECT to_regclass('public.users') IS NOT NULL AS ok`);
  if (!base.ok) {
    throw new Error('The exam schema (users/roles tables) is missing. Apply ddl_1.sql / run exam-hub-api "npm run db:migrate" first.');
  }
  await client.query(`CREATE TABLE IF NOT EXISTS auth_schema_migrations (
    name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  const { rows } = await client.query('SELECT name FROM auth_schema_migrations');
  const done = new Set(rows.map((r) => r.name));

  const files = (await readdir(dir)).filter((f) => f.endsWith('.sql')).sort();
  let applied = 0;
  for (const file of files) {
    if (done.has(file)) continue;
    const sql = await readFile(path.join(dir, file), 'utf8');
    await client.query('BEGIN');
    try {
      await client.query(sql);
      await client.query('INSERT INTO auth_schema_migrations (name) VALUES ($1)', [file]);
      await client.query('COMMIT');
      console.log(`[migrate] applied ${file}`);
      applied++;
    } catch (err) {
      await client.query('ROLLBACK');
      throw new Error(`${file}: ${err.message}`);
    }
  }
  if (!applied) console.log('[migrate] up to date');
} catch (err) {
  console.error('[migrate] failed:', err.message);
  process.exitCode = 1;
} finally {
  client.release();
  await pool.end();
}
