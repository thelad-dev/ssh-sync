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

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function openSSHReader(bytes) {
  let i = 0;
  return {
    u32() {
      if (i + 4 > bytes.length) throw new Error('OpenSSH: truncated');
      const v = ((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0;
      i += 4;
      return v;
    },
    str() {
      const n = this.u32();
      if (i + n > bytes.length) throw new Error('OpenSSH: truncated string');
      const s = bytes.subarray(i, i + n);
      i += n;
      return s;
    },
  };
}

/**
 * Liest die authorized_keys-Zeile aus dem Klartext-Public-Blob eines OpenSSH-Private-PEM.
 * Keine Entschluesselung noetig (auch bei cipher != none liegt der Public Key im Klartext).
 * @param {string} pemText
 * @returns {string} z.B. "ssh-ed25519 AAAA..." oder "" wenn kein OpenSSH-PEM
 */
export function publicLineFromOpenSSHPrivate(pemText) {
  const text = String(pemText || '');
  if (!/BEGIN OPENSSH PRIVATE KEY/.test(text)) return '';
  const b64 = text
    .split(/\r?\n/)
    .filter((l) => l && !l.startsWith('-----'))
    .join('');
  const raw = b64ToBytes(b64);
  const magic = new TextEncoder().encode('openssh-key-v1\0');
  for (let i = 0; i < magic.length; i++) {
    if (raw[i] !== magic[i]) throw new Error('OpenSSH: ungueltige Magic');
  }
  const r = openSSHReader(raw.subarray(magic.length));
  r.str(); // ciphername
  r.str(); // kdfname
  r.str(); // kdf options
  const nkeys = r.u32();
  if (nkeys < 1) return '';
  const pubWire = r.str();
  const type = new TextDecoder().decode(openSSHReader(pubWire).str());
  if (!type) return '';
  return `${type} ${bytesToB64(pubWire)}`;
}

/** Ableitung fuer Import/Pub: OpenSSH-PEM → authorized_keys-Zeile, sonst leer. */
export function derivePublicKeyFromPrivate(pemText) {
  try {
    return publicLineFromOpenSSHPrivate(pemText).trim();
  } catch {
    return '';
  }
}
