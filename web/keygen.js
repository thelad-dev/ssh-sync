import { ed25519 } from '@noble/curves/ed25519';
import { encodeEd25519OpenSSHPrivate, marshalAuthorizedEd25519 } from './openssh.js';

/**
 * Erzeugt ein Ed25519-Keypair im OpenSSH-Format (kompatibel mit ssh-keygen / ssh-sync pull).
 * @param {string} [comment]
 * @returns {{ privatePEM: string, publicLine: string }}
 */
export function generateEd25519Keypair(comment = '') {
  const seed = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(seed);
  return {
    privatePEM: encodeEd25519OpenSSHPrivate(pub, seed, comment),
    publicLine: marshalAuthorizedEd25519(pub),
  };
}

export { openSSHPadding } from './openssh.js';

export function normalizeKeyName(name) {
  const trimmed = String(name || '').trim();
  if (!trimmed) return '';
  return trimmed.replace(/[^\w.-]+/g, '_').replace(/^_|_$/g, '');
}
