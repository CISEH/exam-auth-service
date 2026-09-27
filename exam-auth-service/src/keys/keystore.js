/**
 * RS256 key management.
 *
 * Layout:  <KEYS_DIR>/<portal>/<kid>.key.pem   (PKCS#8 private key, public key is derived)
 * kid:     <portal>-<UTC timestamp>-<random>   e.g. admin-20260911T023000Z-a1b2c3
 *
 * The newest key of each portal signs new tokens. Older keys stay published in the
 * JWKS so tokens they signed keep verifying until they expire — that is how rotation
 * works without logging anyone out. Delete an old key file once its tokens have
 * expired (i.e. after the portal's access-token TTL).
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { exportJWK } from 'jose';
import { env } from '../config/env.js';
import { PORTAL_KEYS } from '../config/portals.js';

const KEY_SUFFIX = '.key.pem';

export function newKid(portal) {
  const ts = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  return `${portal}-${ts}-${crypto.randomBytes(3).toString('hex')}`;
}

/** Create a new 2048-bit RSA key for a portal; returns its kid. */
export function generateKey(portal, dir = env.keysDir) {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = newKid(portal);
  const portalDir = path.join(dir, portal);
  fs.mkdirSync(portalDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(portalDir, kid + KEY_SUFFIX), privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  return kid;
}

export function listKeyFiles(portal, dir = env.keysDir) {
  const portalDir = path.join(dir, portal);
  if (!fs.existsSync(portalDir)) return [];
  return fs.readdirSync(portalDir)
    .filter((f) => f.endsWith(KEY_SUFFIX))
    .sort() // kid embeds a UTC timestamp, so lexical order = age order
    .map((f) => ({ kid: f.slice(0, -KEY_SUFFIX.length), file: path.join(portalDir, f) }));
}

class Keystore {
  constructor() {
    this.byPortal = new Map(); // portal -> [{ kid, privateKey, publicKey, jwk }], newest last
    this.byKid = new Map();
    this.jwks = { keys: [] };
  }

  async load({ autoGenerate = !env.isProd } = {}) {
    this.byPortal.clear();
    this.byKid.clear();
    for (const portal of PORTAL_KEYS) {
      let files = listKeyFiles(portal);
      if (!files.length) {
        if (!autoGenerate) {
          throw new Error(`No signing key for portal "${portal}" in ${env.keysDir}. Run: npm run keys:generate`);
        }
        const kid = generateKey(portal);
        console.warn(`[keys] no key found for "${portal}" — generated ${kid} (development only)`);
        files = listKeyFiles(portal);
      }
      const keys = [];
      for (const { kid, file } of files) {
        const privateKey = crypto.createPrivateKey(fs.readFileSync(file));
        if (privateKey.asymmetricKeyType !== 'rsa') throw new Error(`${file} is not an RSA key`);
        const publicKey = crypto.createPublicKey(privateKey);
        const jwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
        const entry = { kid, portal, privateKey, publicKey, jwk };
        keys.push(entry);
        this.byKid.set(kid, entry);
      }
      this.byPortal.set(portal, keys);
    }
    this.jwks = { keys: [...this.byKid.values()].map((k) => k.jwk) };
    return this;
  }

  /** Key used to sign new tokens for a portal (the newest one). */
  signingKey(portal) {
    const keys = this.byPortal.get(portal);
    if (!keys?.length) throw new Error(`No signing key loaded for portal "${portal}"`);
    return keys[keys.length - 1];
  }

  get(kid) {
    return this.byKid.get(kid) || null;
  }

  summary() {
    return PORTAL_KEYS.map((p) => ({
      portal: p,
      active: this.signingKey(p).kid,
      published: this.byPortal.get(p).map((k) => k.kid),
    }));
  }
}

export const keystore = new Keystore();
