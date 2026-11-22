/**
 * Regression: OpenSSH private-key padding must be 01..N (once, over the full private block).
 * Run: node web/keygen_test.mjs
 */
import { generateKeyPairSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { encodeEd25519OpenSSHPrivate, openSSHPadding } from './openssh.js';

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function readOpenSSHPrivPadding(pem) {
  const lines = pem.trim().split(/\r?\n/);
  const b64 = lines.slice(1, -1).join('');
  const raw = Buffer.from(b64, 'base64');
  let i = 15; // skip "openssh-key-v1\0"
  const rs = () => {
    const n = raw.readUInt32BE(i);
    i += 4;
    const s = raw.subarray(i, i + n);
    i += n;
    return s;
  };
  rs(); // cipher
  rs(); // kdf
  rs(); // kdf options
  i += 4; // nkeys
  rs(); // public
  const priv = rs();
  let j = 8; // skip checkints
  const ps = () => {
    const n = priv.readUInt32BE(j);
    j += 4;
    const s = priv.subarray(j, j + n);
    j += n;
    return s;
  };
  ps(); // type
  ps(); // pub
  ps(); // priv
  ps(); // comment
  return Buffer.from(priv.subarray(j));
}

function expectPad(pad) {
  const exp = Buffer.from(Array.from({ length: pad.length }, (_, k) => k + 1));
  assert(pad.equals(exp), `bad padding: got ${pad.toString('hex')} expected ${exp.toString('hex')}`);
}

function randomEd25519() {
  const { privateKey } = generateKeyPairSync('ed25519');
  const jwk = privateKey.export({ format: 'jwk' });
  const seed = new Uint8Array(Buffer.from(jwk.d, 'base64url'));
  const pub = new Uint8Array(Buffer.from(jwk.x, 'base64url'));
  return { seed, pub };
}

// Unit: openSSHPadding alone
{
  const empty = openSSHPadding(new Uint8Array(0));
  assert(empty.length === 0, 'empty already aligned');
  const five = openSSHPadding(new Uint8Array(5));
  assert(five.length === 8, '5 → 8');
  expectPad(Buffer.from(five.subarray(5)));
}

const longComment = 'Hetzner Cloudserver mit Meilisearch';
const comments = ['', 'a', 'short', longComment, 'x'.repeat(64)];

for (const comment of comments) {
  const { seed, pub } = randomEd25519();
  const privatePEM = encodeEd25519OpenSSHPrivate(pub, seed, comment);
  const pad = readOpenSSHPrivPadding(privatePEM);
  expectPad(pad);

  const dir = mkdtempSync(join(tmpdir(), 'ssh-sync-keygen-'));
  const keyPath = join(dir, 'test_id');
  try {
    writeFileSync(keyPath, privatePEM, { mode: 0o600 });
    const r = spawnSync('ssh-keygen', ['-y', '-f', keyPath], { encoding: 'utf8' });
    assert(r.status === 0, `ssh-keygen -y failed for comment=${JSON.stringify(comment)}: ${r.stderr}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

console.log('keygen_test.mjs: OK');
