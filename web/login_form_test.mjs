/**
 * Login/Setup: Enter bzw. Form-Submit löst Handler aus (bindAuthForms aus auth-forms.js).
 * Run: node web/login_form_test.mjs
 */
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const depDir = mkdtempSync(join(tmpdir(), 'ssh-sync-auth-test-'));
try {
  spawnSync('npm', ['init', '-y'], { cwd: depDir, stdio: 'ignore' });
  writeFileSync(join(depDir, 'package.json'), JSON.stringify({ type: 'module' }, null, 2));
  const install = spawnSync('npm', ['install', 'jsdom', '@testing-library/user-event', '@testing-library/dom'], {
    cwd: depDir,
    stdio: 'pipe',
  });
  if (install.status !== 0) {
    throw new Error(`npm install failed: ${install.stderr}`);
  }

  const webSrc = resolve('web');
  cpSync(join(webSrc, 'auth-forms.js'), join(depDir, 'auth-forms.js'));

  const runner = `
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';
import userEvent from '@testing-library/user-event';
import { bindAuthForms } from './auth-forms.js';

const html = readFileSync(process.argv[2], 'utf8');
const dom = new JSDOM(html, { url: 'http://test/' });
const { document, window } = dom.window;
globalThis.document = document;
globalThis.window = window;

let loginCalls = 0;
let setupCalls = 0;

bindAuthForms({
  onLogin: async () => { loginCalls++; },
  onSetup: async () => { setupCalls++; },
});

const user = userEvent.setup({ document });

document.getElementById('login-password').value = 'test-master-password';
await user.click(document.getElementById('btn-login'));
await new Promise((r) => setTimeout(r, 0));
if (loginCalls !== 1) throw new Error('login button submit count ' + loginCalls);

loginCalls = 0;
document.getElementById('login-password').value = 'another-password-12';
await user.type(document.getElementById('login-password'), '{Enter}');
await new Promise((r) => setTimeout(r, 0));
if (loginCalls !== 1) throw new Error('login enter count ' + loginCalls);

document.getElementById('setup-password').value = 'test-master-password';
document.getElementById('setup-password-confirm').value = 'test-master-password';
await user.click(document.getElementById('btn-setup'));
await new Promise((r) => setTimeout(r, 0));
if (setupCalls !== 1) throw new Error('setup submit count ' + setupCalls);

console.log('runner ok');
`;

  writeFileSync(join(depDir, 'runner.mjs'), runner);
  const run = spawnSync('node', [join(depDir, 'runner.mjs'), resolve('web/index.html')], {
    cwd: depDir,
    encoding: 'utf8',
  });
  if (run.status !== 0) {
    throw new Error(run.stderr || run.stdout || 'runner failed');
  }
} finally {
  rmSync(depDir, { recursive: true, force: true });
}

console.log('login_form_test.mjs: OK');
