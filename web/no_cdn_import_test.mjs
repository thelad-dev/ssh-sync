/**
 * Regression M5: Portal-JS darf keine https://-Imports nutzen.
 * Run: node web/no_cdn_import_test.mjs
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const webDir = resolve('web');
const files = readdirSync(webDir).filter((f) => f.endsWith('.js'));
const bad = [];
for (const f of files) {
  const text = readFileSync(join(webDir, f), 'utf8');
  if (/from\s+['"]https:\/\//.test(text) || /import\s*\(\s*['"]https:\/\//.test(text)) {
    bad.push(f);
  }
}
if (bad.length) {
  throw new Error('CDN/https imports forbidden in: ' + bad.join(', '));
}
console.log('no_cdn_import_test.mjs: OK');
