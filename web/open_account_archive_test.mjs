/**
 * Regression portal.openAccountArchive.first-payload-mac-returns-last:
 * Doppeltes payload (inkl. Unicode-Escape) darf nicht das letzte ungepruefte Objekt liefern.
 * Run: node web/open_account_archive_test.mjs
 */
import { deriveExportMACKey, hmacSha256Hex, bytesToHex } from './crypto.js';
import { openAccountArchive } from './account-archive.js';

const password = 'master-password-12';
const salt = new Uint8Array(16).fill(0x42);
const saltHex = bytesToHex(salt);

const goodPayload = {
  kdf_salt: saltHex,
  auth_scheme: 'auth_v1',
  identities: [],
  hosts: [{ alias: 'good', host_name: 'good.example' }],
  devices: [],
  settings: {},
};
const evilPayload = {
  kdf_salt: saltHex,
  auth_scheme: 'auth_v1',
  identities: [],
  hosts: [{ alias: 'evil', host_name: 'evil.example' }],
  devices: [],
  settings: { cf_access_client_id: 'attacker' },
};

const goodJSON = JSON.stringify(goodPayload);
const evilJSON = JSON.stringify(evilPayload);
const macKey = await deriveExportMACKey(password, salt);
const mac = await hmacSha256Hex(macKey, new TextEncoder().encode(goodJSON));

async function expectReject(label, raw) {
  try {
    const got = await openAccountArchive(password, raw);
    throw new Error(`${label}: erwartet Ablehnung, bekam alias=${got?.hosts?.[0]?.alias}`);
  } catch (err) {
    if (String(err.message || err).includes('erwartet Ablehnung')) throw err;
  }
}

const dupLiteral =
  `{"format":"ssh-sync-account-export","schema_version":1,"exported_at":"2026-01-01T00:00:00.000Z",` +
  `"integrity":{"alg":"hmac-sha256","mac":${JSON.stringify(mac)}},"payload":${goodJSON},"payload":${evilJSON}}`;

const dupUnicode =
  `{"format":"ssh-sync-account-export","schema_version":1,"exported_at":"2026-01-01T00:00:00.000Z",` +
  `"integrity":{"alg":"hmac-sha256","mac":${JSON.stringify(mac)}},"payload":${goodJSON},"\\u0070ayload":${evilJSON}}`;

await expectReject('dup-literal', dupLiteral);
await expectReject('dup-unicode', dupUnicode);

const honest =
  `{"format":"ssh-sync-account-export","schema_version":1,"exported_at":"2026-01-01T00:00:00.000Z",` +
  `"integrity":{"alg":"hmac-sha256","mac":${JSON.stringify(mac)}},"payload":${goodJSON}}`;
const ok = await openAccountArchive(password, honest);
if (ok.hosts?.[0]?.alias !== 'good') {
  throw new Error(`ehrliches Archiv: alias=${ok.hosts?.[0]?.alias}`);
}

console.log('open_account_archive_test.mjs: OK');
