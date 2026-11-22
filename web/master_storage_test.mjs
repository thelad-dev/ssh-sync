/**
 * Regression M4: Nach setMasterPassword darf sessionStorage kein Passwort halten.
 * Run: node web/master_storage_test.mjs
 */
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const dir = mkdtempSync(join(tmpdir(), 'sps-master-'));
try {
  const apiSrc = readFileSync(new URL('./api.js', import.meta.url), 'utf8');
  writeFileSync(join(dir, 'api.js'), apiSrc);
  writeFileSync(
    join(dir, 'runner.mjs'),
    `
globalThis.window = { location: { origin: 'http://test' } };
globalThis.sessionStorage = (() => {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => { m.set(k, String(v)); },
    removeItem: (k) => { m.delete(k); },
  };
})();

const { setMasterPassword, getMasterPassword, clearToken } = await import('./api.js');

setMasterPassword('Dummy-Master-PW-12345');
if (getMasterPassword() !== 'Dummy-Master-PW-12345') throw new Error('memory missing');
if (sessionStorage.getItem('ssh_sync_master') != null) {
  throw new Error('password leaked into sessionStorage');
}
clearToken();
if (getMasterPassword() != null) throw new Error('memory not cleared');
console.log('ok');
`,
  );
  const run = spawnSync(process.execPath, [join(dir, 'runner.mjs')], { encoding: 'utf8' });
  if (run.status !== 0) {
    throw new Error(run.stderr || run.stdout || 'runner failed');
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}
console.log('master_storage_test.mjs: OK');
