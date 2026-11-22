import { argon2id } from './vendor/hash-wasm/index.esm.js';

const NONCE_LEN = 12;
const KEY_LEN = 32;
const CIPHER_VERSION_AAD = 1;
const AUTH_INFO = 'ssh-sync-auth';
const ENC_INFO = 'ssh-sync-enc';
const EXPORT_MAC_INFO = 'ssh-sync-export-mac';

async function argonIkm(password, saltBytes) {
  const key = await argon2id({
    password,
    salt: saltBytes,
    parallelism: 4,
    iterations: 3,
    memorySize: 65536,
    hashLength: KEY_LEN,
    outputType: 'binary',
  });
  return new Uint8Array(key);
}

async function hkdfExpand(ikm, info) {
  const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(),
      info: new TextEncoder().encode(info),
    },
    baseKey,
    KEY_LEN * 8,
  );
  return new Uint8Array(bits);
}

/** @deprecated Legacy: IKM als AES-Key (nur Migration). */
export async function deriveKey(password, saltBytes) {
  return argonIkm(password, saltBytes);
}

export async function deriveKeys(password, saltBytes) {
  const legacyKey = await argonIkm(password, saltBytes);
  const authKey = await hkdfExpand(legacyKey, AUTH_INFO);
  const encKey = await hkdfExpand(legacyKey, ENC_INFO);
  return { authKey, encKey, legacyKey };
}

export async function deriveExportMACKey(password, saltBytes) {
  const legacyKey = await argonIkm(password, saltBytes);
  return hkdfExpand(legacyKey, EXPORT_MAC_INFO);
}

export async function hmacSha256Hex(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, dataBytes);
  return bytesToHex(new Uint8Array(sig));
}

export function identityAAD(id, publicKey) {
  return new TextEncoder().encode(`${id}|${publicKey || ''}`);
}

export async function encrypt(keyBytes, plaintext, aadBytes) {
  if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== 32) {
    throw new Error('Verschluesselung nicht bereit - bitte abmelden und erneut anmelden');
  }
  const iv = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  );
  const encoded = new TextEncoder().encode(plaintext);
  const params = { name: 'AES-GCM', iv };
  if (aadBytes) {
    params.additionalData = aadBytes;
  }
  const ciphertext = await crypto.subtle.encrypt(params, cryptoKey, encoded);
  const ct = new Uint8Array(ciphertext);
  if (aadBytes) {
    const combined = new Uint8Array(1 + NONCE_LEN + ct.byteLength);
    combined[0] = CIPHER_VERSION_AAD;
    combined.set(iv, 1);
    combined.set(ct, 1 + NONCE_LEN);
    return btoa(String.fromCharCode(...combined));
  }
  const combined = new Uint8Array(NONCE_LEN + ct.byteLength);
  combined.set(iv, 0);
  combined.set(ct, NONCE_LEN);
  return btoa(String.fromCharCode(...combined));
}

export async function encryptIdentity(encKey, id, publicKey, plaintext) {
  return encrypt(encKey, plaintext, identityAAD(id, publicKey));
}

export async function decrypt(keyBytes, encoded, aadBytes, expectVersion) {
  const combined = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
  let iv;
  let data;
  if (expectVersion) {
    if (combined.length < 1 + NONCE_LEN) {
      throw new Error('ciphertext zu kurz');
    }
    if (combined[0] !== CIPHER_VERSION_AAD) {
      throw new Error('unbekannte cipher-version');
    }
    iv = combined.slice(1, 1 + NONCE_LEN);
    data = combined.slice(1 + NONCE_LEN);
  } else {
    if (combined.length < NONCE_LEN) {
      throw new Error('ciphertext zu kurz');
    }
    iv = combined.slice(0, NONCE_LEN);
    data = combined.slice(NONCE_LEN);
  }
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );
  const params = { name: 'AES-GCM', iv };
  if (aadBytes) {
    params.additionalData = aadBytes;
  }
  const plain = await crypto.subtle.decrypt(params, cryptoKey, data);
  return new TextDecoder().decode(plain);
}

export async function decryptIdentity(keys, id, publicKey, encoded) {
  const aad = identityAAD(id, publicKey);
  try {
    return await decrypt(keys.encKey, encoded, aad, true);
  } catch {
    return decrypt(keys.legacyKey, encoded, undefined, false);
  }
}

export function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function randomId() {
  const buf = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function newSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}
