import { env } from './config/env.js';
import { createApp } from './app.js';
import { pool, checkConnection } from './db/pool.js';
import { keystore } from './keys/keystore.js';
import { cleanupExpired } from './services/sessions.js';

async function start() {
  try {
    const info = await checkConnection();
    console.log(`[db] connected to "${info.db}"`);
    const { rows: [t] } = await pool.query(`SELECT to_regclass('public.auth_sessions') IS NOT NULL AS ok`);
    if (!t.ok) throw new Error('auth tables are missing — run: npm run db:migrate');
  } catch (err) {
    console.error('[db]', err.message);
    process.exit(1);
  }

  try {
    await keystore.load();
    for (const k of keystore.summary()) console.log(`[keys] ${k.portal}: signing with ${k.active} (${k.published.length} published)`);
  } catch (err) {
    console.error('[keys]', err.message);
    process.exit(1);
  }

  const app = createApp();
  const server = app.listen(env.port, () => console.log(`[auth] listening on http://localhost:${env.port}`));

  // Housekeeping every 6 hours
  const timer = setInterval(() => cleanupExpired().catch((e) => console.error('[cleanup]', e.message)), 6 * 3600_000);
  timer.unref();

  const shutdown = (signal) => {
    console.log(`[auth] ${signal} received, shutting down...`);
    server.close(async () => { await pool.end(); process.exit(0); });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

start();
