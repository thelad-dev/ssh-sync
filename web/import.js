const MANAGED_BEGIN = '# --- BEGIN ssh-sync (managed) ---';
const MANAGED_END = '# --- END ssh-sync (managed) ---';

/**
 * @param {string} text
 * @param {{ keepManaged?: boolean }} [options] keepManaged: auch verwalteten ssh-sync-Block parsen (für IdentityFile)
 */
export function parseSSHConfig(text, options = {}) {
  if (!options.keepManaged) {
    text = stripManaged(text);
  }
  const hosts = [];
  let current = null;

  const flush = () => {
    if (!current?.alias) return;
    if (!current.host_name) current.host_name = current.alias;
    if (!current.port) current.port = 22;
    hosts.push(current);
    current = null;
  };

  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const sp = line.indexOf(' ');
    if (sp < 0) continue;
    const key = line.slice(0, sp).toLowerCase();
    let val = line.slice(sp + 1).trim().replace(/^"|"$/g, '');
    switch (key) {
      case 'host': {
        flush();
        const alias = val.split(/\s+/)[0];
        if (alias.includes('*') || alias.includes('?')) {
          current = null;
          break;
        }
        current = { alias, host_name: '', user: '', port: 22, identity_file: '', proxy_jump: '', identities_only: false };
        break;
      }
      case 'hostname':
        if (current) current.host_name = val;
        break;
      case 'user':
        if (current) current.user = val;
        break;
      case 'port':
        if (current) current.port = parseInt(val, 10) || 22;
        break;
      case 'identityfile':
        if (current) current.identity_file = val;
        break;
      case 'proxyjump':
        if (current) current.proxy_jump = val;
        break;
      case 'identitiesonly':
        if (current) current.identities_only = parseBoolDirective(val);
        break;
      default:
        break;
    }
  }
  flush();
  return hosts;
}

function parseBoolDirective(val) {
  switch (String(val || '').trim().toLowerCase()) {
    case 'yes':
    case 'true':
    case '1':
    case 'on':
      return true;
    default:
      return false;
  }
}

function stripManaged(text) {
  const begin = text.indexOf(MANAGED_BEGIN);
  if (begin < 0) return text;
  const end = text.indexOf(MANAGED_END, begin);
  if (end < 0) return text.slice(0, begin);
  return text.slice(0, begin) + text.slice(end + MANAGED_END.length);
}

export function normalizeIdentityName(pathOrName) {
  let base = String(pathOrName || '').replace(/.*[/\\]/, '').replace(/\.pub$/, '');
  for (const ext of ['.pem', '.key', '.ppk']) {
    if (base.endsWith(ext)) {
      base = base.slice(0, -ext.length);
      break;
    }
  }
  if (base.endsWith('_id')) base = base.slice(0, -3);
  if (base.endsWith('_pem')) base = base.slice(0, -4);
  return base.trim() || 'imported';
}

export function keyFileBasename(identityName) {
  return sanitizeKeyName(normalizeIdentityName(identityName));
}

function sanitizeKeyName(name) {
  return String(name || 'identity').replace(/[^a-zA-Z0-9_-]/g, '_') || 'identity';
}

export function identityNameFromFile(name) {
  return normalizeIdentityName(name);
}

/** Mögliche Identity-Namen zu einem IdentityFile-Pfad (inkl. ssh-sync Keys). */
export function identityNameCandidatesFromFile(identityFile) {
  if (!identityFile) return [];
  const seen = new Set();
  const out = [];
  const add = (s) => {
    const t = String(s || '').trim();
    if (t && !seen.has(t)) {
      seen.add(t);
      out.push(t);
    }
  };
  const base = identityFile.replace(/.*[/\\]/, '').replace(/^["']|["']$/g, '');
  add(normalizeIdentityName(base));
  add(base.replace(/\.pub$/, ''));
  add(base);
  if (base.endsWith('_id')) add(base.slice(0, -3));
  return out;
}

/**
 * Findet identity_id zu einem IdentityFile-Pfad.
 * @param {string} identityFile
 * @param {Array<{id:string,name:string}>} identityList
 * @param {Record<string,string>} [pathToId] frisch importierte Keys name→id
 */
export function matchIdentityForKeyFile(identityFile, identityList, pathToId = {}) {
  for (const name of identityNameCandidatesFromFile(identityFile)) {
    if (pathToId[name]) return pathToId[name];
    const hit = identityList.find(
      (i) => i.name === name || normalizeIdentityName(i.name) === name,
    );
    if (hit) return hit.id;
  }
  return null;
}

/** Liefert mögliche Basisnamen für die .pub-Datei zu einem Private-Key-Dateinamen. */
export function publicKeyLookupNames(privateFileName) {
  const base = privateFileName.replace(/.*[/\\]/, '');
  const names = new Set([base]);
  if (base.endsWith('.pem')) {
    names.add(base.replace(/\.pem$/, ''));
  }
  return [...names];
}

export function isPublicKeyFile(name, text) {
  const base = name.replace(/.*[/\\]/, '');
  if (base.endsWith('.pub')) return true;
  const t = text.trim();
  return /^(ssh-(rsa|ed25519|ecdsa|dss)|ecdsa-sha2-|sk-ssh-ed25519@openssh\.com)/.test(t);
}

export function isPrivateKeyText(text) {
  return text.includes('PRIVATE KEY');
}

export function matchPublicKey(privateFileName, pubMap) {
  for (const name of publicKeyLookupNames(privateFileName)) {
    const pub = pubMap.get(name);
    if (pub) return pub;
  }
  return '';
}

/** Gleicher Key-Typ + Blob, Kommentar (3. Feld) wird ignoriert. */
export function publicKeysEqual(a, b) {
  const na = normalizePublicKeyLine(a);
  const nb = normalizePublicKeyLine(b);
  return na !== '' && na === nb;
}

export function normalizePublicKeyLine(line) {
  const t = String(line || '').trim();
  if (!t) return '';
  const parts = t.split(/\s+/);
  if (parts.length < 2) return t;
  return `${parts[0]} ${parts[1]}`;
}

export function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ''));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}
