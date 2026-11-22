/** Shared OpenSSH wire helpers (no CDN deps — usable from Node tests). */

export function u32be(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

export function concat(...parts) {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function sshString(data) {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return concat(u32be(bytes.length), bytes);
}

/** OpenSSH private-key padding: bytes 1..N so the block length is a multiple of blockSize. */
export function openSSHPadding(block, blockSize = 8) {
  const padLen = (blockSize - (block.length % blockSize)) % blockSize;
  const out = new Uint8Array(block.length + padLen);
  out.set(block, 0);
  for (let i = 0; i < padLen; i++) {
    out[block.length + i] = i + 1;
  }
  return out;
}

function wrapOpenSSHPEM(body) {
  const b64 = btoa(String.fromCharCode(...body));
  const lines = b64.match(/.{1,70}/g) || [];
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${lines.join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

/**
 * Serialisiert ein Ed25519-Keypair als unverschlüsseltes OpenSSH-PEM.
 * @param {Uint8Array} pub 32-byte public key
 * @param {Uint8Array} seed 32-byte private seed
 * @param {string} [comment]
 * @param {number} [checkInt] optional fixed checkint (tests)
 */
export function encodeEd25519OpenSSHPrivate(pub, seed, comment = '', checkInt) {
  if (pub.length !== 32 || seed.length !== 32) {
    throw new Error('ed25519 pub/seed must be 32 bytes');
  }
  const priv64 = new Uint8Array(64);
  priv64.set(seed, 0);
  priv64.set(pub, 32);

  if (checkInt === undefined) {
    const check = crypto.getRandomValues(new Uint8Array(4));
    checkInt = new DataView(check.buffer).getUint32(0, false);
  }

  // Padding once over the full private section (checkints + type + key material + comment).
  const edRest = concat(sshString(pub), sshString(priv64), sshString(comment || ''));
  const pk1Raw = concat(u32be(checkInt), u32be(checkInt), sshString('ssh-ed25519'), edRest);
  const privKeyBlock = openSSHPadding(pk1Raw);

  const pubWire = concat(sshString('ssh-ed25519'), sshString(pub));
  const payload = concat(
    sshString('none'),
    sshString('none'),
    sshString(''),
    u32be(1),
    sshString(pubWire),
    sshString(privKeyBlock),
  );

  const magic = new TextEncoder().encode('openssh-key-v1\0');
  return wrapOpenSSHPEM(concat(magic, payload));
}

export function marshalAuthorizedEd25519(pub) {
  const wire = concat(sshString('ssh-ed25519'), sshString(pub));
  const b64 = btoa(String.fromCharCode(...wire));
  return `ssh-ed25519 ${b64}`;
}
