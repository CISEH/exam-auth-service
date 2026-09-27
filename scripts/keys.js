// Key management for the RS256 signing keys.
//   npm run keys:generate            create a key for every portal that has none
//   npm run keys:rotate -- admin     add a new signing key for a portal (old one stays published)
//   npm run keys:rotate -- all       rotate every portal
//   npm run keys:list                show keys per portal
// Restart the service after generating/rotating so it picks up the new key.
import { env } from '../src/config/env.js';
import { PORTALS, PORTAL_KEYS } from '../src/config/portals.js';
import { generateKey, listKeyFiles } from '../src/keys/keystore.js';

const [cmd, target] = process.argv.slice(2);

function list() {
  console.log(`Keys directory: ${env.keysDir}`);
  for (const p of PORTAL_KEYS) {
    const files = listKeyFiles(p);
    console.log(`\n${p} (${PORTALS[p].audience})`);
    if (!files.length) console.log('  (none)');
    files.forEach((f, i) => console.log(`  ${i === files.length - 1 ? '* active   ' : '  published'} ${f.kid}`));
  }
}

const portalsFor = (t) => {
  if (!t || t === 'all') return PORTAL_KEYS;
  if (!PORTALS[t]) { console.error(`Unknown portal "${t}". Use one of: ${PORTAL_KEYS.join(', ')}, all`); process.exit(1); }
  return [t];
};

switch (cmd) {
  case 'generate':
    for (const p of portalsFor(target)) {
      if (listKeyFiles(p).length) console.log(`[keys] ${p}: already has a key (use keys:rotate to add a new one)`);
      else console.log(`[keys] ${p}: generated ${generateKey(p)}`);
    }
    break;
  case 'rotate':
    if (!target) { console.error('Usage: npm run keys:rotate -- <portal|all>'); process.exit(1); }
    for (const p of portalsFor(target)) console.log(`[keys] ${p}: new signing key ${generateKey(p)}`);
    console.log('[keys] Restart the service. Delete the old key file once its tokens have expired '
      + `(admin: ${PORTALS.admin.accessTtl}s, exam: ${PORTALS.exam.accessTtl}s after restart).`);
    break;
  case 'list':
    list();
    break;
  default:
    console.log('Usage: node scripts/keys.js <generate|rotate|list> [portal|all]');
    process.exit(1);
}
