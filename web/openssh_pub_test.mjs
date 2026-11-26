/**
 * Regression: Public Key aus OpenSSH-Private-PEM ableiten (ohne .pub-Datei).
 * Run: node web/openssh_pub_test.mjs
 */
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  encodeEd25519OpenSSHPrivate,
  marshalAuthorizedEd25519,
  derivePublicKeyFromPrivate,
  publicLineFromOpenSSHPrivate,
} from './openssh.js';

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function randomEd25519() {
  const { privateKey } = generateKeyPairSync('ed25519');
  const jwk = privateKey.export({ format: 'jwk' });
  const seed = new Uint8Array(Buffer.from(jwk.d, 'base64url'));
  const pub = new Uint8Array(Buffer.from(jwk.x, 'base64url'));
  return { seed, pub };
}

{
  const { seed, pub } = randomEd25519();
  const pem = encodeEd25519OpenSSHPrivate(pub, seed, 'regression-pub');
  const expected = marshalAuthorizedEd25519(pub);
  const got = publicLineFromOpenSSHPrivate(pem);
  assert(got === expected, `publicLine mismatch:\n got ${got}\n want ${expected}`);
  assert(derivePublicKeyFromPrivate(pem) === expected, 'derivePublicKeyFromPrivate mismatch');
}

{
  // ssh-keygen OpenSSH-PEM ohne .pub: Tool muss dieselbe Zeile wie `ssh-keygen -y` liefern.
  const dir = mkdtempSync(join(tmpdir(), 'ssh-sync-pub-'));
  try {
    const keyPath = join(dir, 'id_ed25519');
    const gen = spawnSync('ssh-keygen', ['-t', 'ed25519', '-f', keyPath, '-N', '', '-C', 'nopub-test'], {
      encoding: 'utf8',
    });
    assert(gen.status === 0, `ssh-keygen failed: ${gen.stderr}`);
    rmSync(`${keyPath}.pub`, { force: true });
    const pem = readFileSync(keyPath, 'utf8');
    const derived = derivePublicKeyFromPrivate(pem);
    assert(derived.startsWith('ssh-ed25519 '), `unexpected derived: ${derived}`);
    const y = spawnSync('ssh-keygen', ['-y', '-f', keyPath], { encoding: 'utf8' });
    assert(y.status === 0, `ssh-keygen -y failed: ${y.stderr}`);
    const fromTool = y.stdout.trim().split(/\s+/).slice(0, 2).join(' ');
    const fromDerived = derived.trim().split(/\s+/).slice(0, 2).join(' ');
    assert(fromDerived === fromTool, `ssh-keygen -y mismatch:\n derived ${fromDerived}\n tool ${fromTool}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

{
  assert(derivePublicKeyFromPrivate('not a key') === '', 'non-openssh must be empty');
  assert(publicLineFromOpenSSHPrivate('-----BEGIN RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY-----') === '', 'classic PEM empty');
}

console.log('openssh_pub_test.mjs: OK');
