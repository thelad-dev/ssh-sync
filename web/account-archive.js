import { deriveExportMACKey, hmacSha256Hex, hexToBytes } from './crypto.js';

const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;
const FORMAT_ID = 'ssh-sync-account-export';

/**
 * Oeffnet ein Kontoarchiv: HMAC nur ueber die geprueften Payload-Bytes,
 * genau ein payload-Schluessel, Rueckgabe nur aus diesen Bytes.
 */
export async function openAccountArchive(password, rawText) {
  if (rawText.length > MAX_ARCHIVE_BYTES) throw new Error('Archiv zu gross');
  let env;
  try {
    env = JSON.parse(rawText);
  } catch {
    throw new Error('ungueltiges Archiv');
  }
  if (env.format !== FORMAT_ID) throw new Error('unbekanntes Archiv-Format');
  if (!env.schema_version || env.schema_version < 1) throw new Error('schema_version ungueltig');
  if (env.schema_version > 1) throw new Error('Archiv-Version zu neu');
  if (env.integrity?.alg !== 'hmac-sha256') throw new Error('unbekannter Integritaetsalgorithmus');

  const payloadCount = countTopLevelKey(rawText, 'payload');
  if (payloadCount !== 1) {
    throw new Error('Archiv enthaelt nicht genau ein payload');
  }

  const payloadMatch = rawText.match(/"payload"\s*:\s*/);
  if (!payloadMatch) throw new Error('Payload fehlt');
  const start = payloadMatch.index + payloadMatch[0].length;
  const payloadRaw = extractJSONValue(rawText, start);

  let payload;
  try {
    payload = JSON.parse(payloadRaw);
  } catch {
    throw new Error('Payload ungueltig');
  }
  if (!payload?.kdf_salt) throw new Error('kdf_salt fehlt');

  if (JSON.stringify(payload) !== JSON.stringify(env.payload)) {
    throw new Error('Payload inkonsistent');
  }

  const salt = hexToBytes(payload.kdf_salt);
  const macKey = await deriveExportMACKey(password, salt);
  const mac = await hmacSha256Hex(macKey, new TextEncoder().encode(payloadRaw));
  if (mac !== env.integrity.mac) {
    throw new Error('Integritaetspruefung fehlgeschlagen (falsches Passwort oder manipuliertes Archiv)');
  }
  return payload;
}

/** Zaehlt Top-Level-Schluessel; JSON-Unescape (\u0070ayload) zaehlt als payload. */
export function countTopLevelKey(text, want) {
  let i = 0;
  while (i < text.length && /\s/.test(text[i])) i++;
  if (text[i] !== '{') throw new Error('ungueltiges Archiv');
  i++;
  let count = 0;
  let expectKey = true;
  while (i < text.length) {
    while (i < text.length && /\s/.test(text[i])) i++;
    if (text[i] === '}') return count;
    if (text[i] === ',') {
      i++;
      expectKey = true;
      continue;
    }
    if (!expectKey) throw new Error('ungueltiges Archiv');
    if (text[i] !== '"') throw new Error('ungueltiges Archiv');
    const { value: key, end } = readJSONString(text, i);
    i = end;
    if (key === want) count++;
    while (i < text.length && /\s/.test(text[i])) i++;
    if (text[i] !== ':') throw new Error('ungueltiges Archiv');
    i++;
    while (i < text.length && /\s/.test(text[i])) i++;
    i = skipJSONValue(text, i);
    expectKey = false;
  }
  throw new Error('ungueltiges Archiv');
}

function readJSONString(text, start) {
  if (text[start] !== '"') throw new Error('Payload ungueltig');
  let i = start + 1;
  let out = '';
  while (i < text.length) {
    const c = text[i];
    if (c === '"') return { value: out, end: i + 1 };
    if (c === '\\') {
      const n = text[i + 1];
      if (n === 'u' && i + 5 < text.length) {
        const hex = text.slice(i + 2, i + 6);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error('Payload ungueltig');
        out += String.fromCharCode(parseInt(hex, 16));
        i += 6;
        continue;
      }
      if (n === '"' || n === '\\' || n === '/' || n === 'b' || n === 'f' || n === 'n' || n === 'r' || n === 't') {
        const map = { b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
        out += map[n] || n;
        i += 2;
        continue;
      }
      throw new Error('Payload ungueltig');
    }
    out += c;
    i++;
  }
  throw new Error('Payload unvollstaendig');
}

function skipJSONValue(text, start) {
  let i = start;
  while (i < text.length && /\s/.test(text[i])) i++;
  if (text[i] === '{' || text[i] === '[') {
    const raw = extractJSONValue(text, i);
    return i + raw.length;
  }
  if (text[i] === '"') {
    return readJSONString(text, i).end;
  }
  const m = text.slice(i).match(/^(null|true|false|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/);
  if (!m) throw new Error('Payload ungueltig');
  return i + m[0].length;
}

export function extractJSONValue(text, start) {
  let i = start;
  while (i < text.length && /\s/.test(text[i])) i++;
  if (text[i] !== '{' && text[i] !== '[') {
    const m = text.slice(i).match(/^("(?:\\.|[^"\\])*"|null|true|false|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/);
    if (!m) throw new Error('Payload ungueltig');
    return m[0];
  }
  const open = text[i];
  const close = open === '{' ? '}' : ']';
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let j = i; j < text.length; j++) {
    const c = text[j];
    if (inStr) {
      if (esc) esc = false;
      else if (c === '\\') esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') {
      inStr = true;
      continue;
    }
    if (c === open) depth++;
    else if (c === close) {
      depth--;
      if (depth === 0) return text.slice(i, j + 1);
    }
  }
  throw new Error('Payload unvollstaendig');
}
