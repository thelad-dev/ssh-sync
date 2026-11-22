/**
 * Setup/Login-Bodies duerfen kein Klartext-Passwort enthalten (H4).
 * Run: node web/auth_no_password_test.mjs
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const apiSrc = readFileSync(resolve('web/api.js'), 'utf8');
const appSrc = readFileSync(resolve('web/app.js'), 'utf8');

if (/setup:\s*\(password\)/.test(apiSrc)) {
  throw new Error('api.setup darf kein password-Argument mehr haben');
}
if (!apiSrc.includes('auth_key')) {
  throw new Error('api.js muss auth_key senden');
}
if (/JSON\.stringify\(\{\s*password\s*\}/.test(apiSrc) && !apiSrc.includes('loginLegacy')) {
  throw new Error('api.js sendet noch password ohne Legacy-Pfad');
}
if (!appSrc.includes('deriveKeys') || !appSrc.includes('bytesToHex(cryptoKeys.authKey)')) {
  throw new Error('app.js muss Auth-Key ableiten und senden');
}
if (appSrc.includes('api.setup(password)')) {
  throw new Error('app.js darf setup(password) nicht mehr aufrufen');
}

console.log('auth_no_password_test.mjs: OK');
