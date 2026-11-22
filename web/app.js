import { bindAuthForms } from './auth-forms.js?v=opensshpad1';
import { api, getToken, setToken, clearToken, setMasterPassword, getMasterPassword } from './api.js?v=opensshpad1';
import {
  deriveKeys,
  encryptIdentity,
  decryptIdentity,
  deriveExportMACKey,
  hmacSha256Hex,
  hexToBytes,
  bytesToHex,
  newSalt,
  randomId,
} from './crypto.js?v=opensshpad1';
import {
  parseSSHConfig,
  identityNameFromFile,
  readFileAsText,
  isPublicKeyFile,
  isPrivateKeyText,
  matchPublicKey,
  matchIdentityForKeyFile,
  publicKeysEqual,
} from './import.js?v=opensshpad1';
import { renderSSHConfigPreview, sortedHosts as sortedHostsList } from './config-preview.js?v=opensshpad1';
import { generateEd25519Keypair, normalizeKeyName } from './keygen.js?v=opensshpad1';
import { initCollapsibleSections, updateCollapsibleDefault } from './collapsible.js?v=opensshpad1';
import { openAccountArchive } from './account-archive.js?v=opensshpad1';

let kdfSalt = null;
/** @type {{ authKey: Uint8Array, encKey: Uint8Array, legacyKey: Uint8Array } | null} */
let cryptoKeys = null;
let identities = [];
let hosts = [];
let devices = [];
let hostSearchQuery = '';
let editingHostId = null;

const DEVICE_SETUP_KEY = 'ssh_sync_device_setups';
let refreshTimer = null;

const views = {
  setup: document.getElementById('view-setup'),
  login: document.getElementById('view-login'),
  app: document.getElementById('view-app'),
};

const panels = {
  hosts: document.getElementById('panel-hosts'),
  devices: document.getElementById('panel-devices'),
};

init();

async function init() {
  bindAuthForms({ onSetup, onLogin });
  document.getElementById('btn-logout').addEventListener('click', onLogout);
  document.querySelectorAll('.tab').forEach((tab) => {
    if (tab.dataset.panel) tab.addEventListener('click', () => showPanel(tab.dataset.panel));
  });
  document.getElementById('btn-add-host').addEventListener('click', onAddHost);
  document.getElementById('btn-sync-all-hosts').addEventListener('click', onSyncAllDevices);
  document.getElementById('btn-add-device').addEventListener('click', onAddDevice);
  document.getElementById('btn-save-cf-bootstrap').addEventListener('click', onSaveCfBootstrap);
  document.getElementById('btn-copy-device-config').addEventListener('click', () => copyTextarea('device-setup-config'));
  document.getElementById('btn-copy-device-cmds').addEventListener('click', () => copyTextarea('device-setup-cmds'));
  document.getElementById('btn-device-setup-close').addEventListener('click', () => {
    document.getElementById('device-setup-dialog').close();
  });
  document.getElementById('btn-import').addEventListener('click', openImportDialog);
  document.getElementById('btn-import-preview').addEventListener('click', previewImport);
  document.getElementById('import-form').addEventListener('submit', onImportSubmit);
  document.getElementById('btn-account-export').addEventListener('click', () => openAccountMigrate('export'));
  document.getElementById('btn-account-import').addEventListener('click', () => openAccountMigrate('import'));
  document.getElementById('account-migrate-form').addEventListener('submit', onAccountMigrateSubmit);
  document.getElementById('host-search').addEventListener('input', (e) => {
    hostSearchQuery = e.target.value.trim().toLowerCase();
    renderHosts();
  });
  document.getElementById('btn-import-all-devices').addEventListener('click', onImportAllDevices);
  document.getElementById('btn-keygen').addEventListener('click', openKeygenDialog);
  document.getElementById('keygen-form').addEventListener('submit', onKeygenSubmit);
  document.getElementById('btn-copy-keygen-public').addEventListener('click', () => copyTextarea('keygen-public'));
  document.getElementById('host-form').addEventListener('submit', onHostFormSubmit);

  const status = await api.setupStatus();
  if (!status.initialized) {
    showView('setup');
    return;
  }
  // Nach Reload kein Master-Passwort im Speicher: erneut anmelden (M4).
  if (getToken() && cryptoKeys) {
    await enterApp();
  } else {
    showView(status.initialized ? 'login' : 'setup');
  }
}

function showView(name) {
  Object.entries(views).forEach(([k, el]) => el.classList.toggle('hidden', k !== name));
}

function showPanel(name) {
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.panel === name));
  Object.entries(panels).forEach(([k, el]) => el.classList.toggle('hidden', k !== name));
}

async function onSetup() {
  const password = document.getElementById('setup-password').value;
  const confirm = document.getElementById('setup-password-confirm').value;
  if (password.length < 12) return flash('setup-error', 'Passwort mindestens 12 Zeichen.');
  if (password !== confirm) return flash('setup-error', 'Passwoerter stimmen nicht ueberein.');
  try {
    kdfSalt = newSalt();
    cryptoKeys = await deriveKeys(password, kdfSalt);
    const res = await api.setup(bytesToHex(cryptoKeys.authKey), bytesToHex(kdfSalt));
    setToken(res.token);
    setMasterPassword(password);
    await enterApp();
  } catch (err) {
    flash('setup-error', err.message);
  }
}

async function onLogin() {
  const password = document.getElementById('login-password').value;
  try {
    const saltRes = await api.kdfSalt();
    kdfSalt = hexToBytes(saltRes.kdf_salt);
    cryptoKeys = await deriveKeys(password, kdfSalt);
    let res;
    try {
      res = await api.login(bytesToHex(cryptoKeys.authKey));
    } catch {
      res = await api.loginLegacy(password);
      setToken(res.token);
      if (res.auth_scheme !== 'auth_v1') {
        await upgradeLegacyIdentities(password);
      }
      setMasterPassword(password);
      await enterApp();
      return;
    }
    setToken(res.token);
    setMasterPassword(password);
    await enterApp();
  } catch (err) {
    flash('login-error', err.message);
  }
}

async function upgradeLegacyIdentities(password) {
  const list = await api.identities();
  const upgraded = [];
  for (const id of list) {
    const plain = await decryptIdentity(cryptoKeys, id.id, id.public_key, id.encrypted_private_key);
    const enc = await encryptIdentity(cryptoKeys.encKey, id.id, id.public_key, plain);
    upgraded.push({ id: id.id, encrypted_private_key: enc });
  }
  await api.upgradeAuth(bytesToHex(cryptoKeys.authKey), upgraded, password);
}

function onLogout() {
  clearToken();
  cryptoKeys = null;
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
  showView('login');
}

async function enterApp() {
  showView('app');
  initCollapsibleSections();
  if (!cryptoKeys && getMasterPassword()) {
    const saltRes = await api.kdfSalt();
    kdfSalt = hexToBytes(saltRes.kdf_salt);
    cryptoKeys = await deriveKeys(getMasterPassword(), kdfSalt);
  }
  if (!cryptoKeys) {
    showView('login');
    return;
  }
  await refreshAll();
  await loadCfBootstrapForm();
  showPanel('hosts');
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(() => refreshAll().catch(() => {}), 30000);
}

async function loadCfBootstrapForm() {
  const status = document.getElementById('cf-bootstrap-status');
  try {
    const b = await api.clientBootstrap();
    document.getElementById('cf-access-id').value = b.access_client_id || '';
    document.getElementById('cf-access-secret').value = b.access_client_secret || '';
    if (b.access_client_id && b.access_client_secret) {
      status.textContent = b.source === 'env' ? 'Gesetzt (Server-.env)' : 'Gespeichert';
    } else {
      status.textContent = 'Optional — für Agent-Zugriff hinter Cloudflare';
    }
  } catch {
    status.textContent = '';
  }
}

async function onSaveCfBootstrap() {
  const id = document.getElementById('cf-access-id').value.trim();
  const secret = document.getElementById('cf-access-secret').value.trim();
  const status = document.getElementById('cf-bootstrap-status');
  if (!id || !secret) {
    status.textContent = 'Client ID und Secret ausfüllen';
    return;
  }
  try {
    await api.saveClientBootstrap(id, secret);
    status.textContent = 'Gespeichert';
    renderInstallHints();
  } catch (err) {
    status.textContent = err.message;
  }
}

async function refreshAll() {
  [identities, hosts, devices] = await Promise.all([api.identities(), api.hosts(), api.devices()]);
  renderIdentities();
  renderHosts();
  renderDevices();
  renderConfigPreview();
  renderInstallHints();
}

function renderInstallHints() {
  const base = window.location.origin;
  document.getElementById('install-linux').textContent =
    `# cosign erforderlich (Sigstore). Skript speichern, lesen, dann ausfuehren - kein curl|sh
curl -fsSL ${base}/install/linux.sh -o install-linux.sh
less install-linux.sh
sh install-linux.sh
# ohne cosign (keine Herkunft): sh install-linux.sh --unsicher-nur-pruefsumme`;
  document.getElementById('install-windows').textContent =
    `# cosign erforderlich. Skript speichern, lesen, dann ausfuehren - kein irm|iex
Invoke-WebRequest -Uri ${base}/install/windows.ps1 -OutFile install-windows.ps1
notepad install-windows.ps1
powershell -File install-windows.ps1
# ohne cosign: powershell -File install-windows.ps1 -UnsicherNurPruefsumme`;
  document.getElementById('install-post').textContent =
    `# Nach Install: Geraet hier anlegen -> Config + Befehle kopieren
# Binary kommt vom GitHub-Release; Installer prueft manifest.json per cosign
# Linux: ~/.config/ssh-sync/config.json -> ssh-sync unlock -> systemctl --user enable --now ssh-sync
# Windows: %USERPROFILE%\\.config\\ssh-sync\\config.json -> ssh-sync.exe unlock -> Dienst starten`;
}

function renderIdentities() {
  const el = document.getElementById('identity-list');
  const count = document.getElementById('key-count');
  if (count) count.textContent = String(identities.length);
  if (!el) return;
  if (!identities.length) {
    el.innerHTML = '<p class="muted">Keine Keys — Import oder „+ Key erzeugen“.</p>';
    return;
  }
  el.innerHTML = identities
    .map(
      (i) => `
    <div class="key-row">
      <strong>${esc(i.name)}</strong>
      <span class="muted">${esc(i.comment || '')}</span>
      <span class="btn-group-inline">
        ${i.public_key ? `<button type="button" data-copy-pub="${esc(i.id)}" class="secondary" title="Public Key">Pub</button>` : ''}
        <button data-del-identity="${esc(i.id)}" class="danger">×</button>
      </span>
    </div>`,
    )
    .join('');
  el.querySelectorAll('[data-copy-pub]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = btn.dataset.copyPub;
      const item = identities.find((x) => x.id === id);
      if (item?.public_key) copyText(item.public_key);
    });
  });
  el.querySelectorAll('[data-del-identity]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!confirm('Key löschen?')) return;
      await api.deleteIdentity(btn.dataset.delIdentity);
      await refreshAll();
    });
  });
  updateCollapsibleDefault(
    document.getElementById('keys-section'),
    el,
    identities.length,
  );
}

function hostPayload(h, overrides = {}) {
  return {
    alias: h.alias,
    host_name: h.host_name,
    user: h.user || '',
    port: h.port || 22,
    identity_id: h.identity_id || null,
    proxy_jump: h.proxy_jump || '',
    identities_only: !!h.identities_only,
    extra: h.extra || '',
    sort_order: h.sort_order ?? 0,
    ...overrides,
  };
}

function nextHostSortOrder() {
  if (!hosts.length) return 0;
  return Math.max(...hosts.map((h) => h.sort_order ?? 0)) + 1;
}

function renderConfigPreview() {
  const el = document.getElementById('config-preview');
  if (!el) return;
  el.textContent = hosts.length ? renderSSHConfigPreview(hosts, identities) : '# (keine Hosts)';
  const lines = (el.textContent || '').split('\n').length;
  updateCollapsibleDefault(document.getElementById('preview-section'), el, lines);
}

function identitySelectOptions(selectedId) {
  const opts = ['<option value="">— kein Key —</option>'];
  for (const i of identities) {
    const sel = i.id === selectedId ? ' selected' : '';
    opts.push(`<option value="${esc(i.id)}"${sel}>${esc(i.name)}</option>`);
  }
  return opts.join('');
}

function hostTarget(h) {
  const port = h.port || 22;
  const user = h.user || '';
  return `${user}${user ? '@' : ''}${h.host_name}:${port}`.toLowerCase();
}

function hostMatchesSearch(h, q) {
  if (!q) return true;
  const blob = `${h.alias} ${h.host_name} ${h.user || ''} ${h.port || 22} ${hostTarget(h)}`.toLowerCase();
  return blob.includes(q);
}

function renderHosts() {
  const el = document.getElementById('host-list');
  const searchStatus = document.getElementById('host-search-status');
  const countEl = document.getElementById('host-list-count');
  if (!hosts.length) {
    el.innerHTML = '<p class="muted">Noch keine Hosts — Import oder + Host.</p>';
    if (searchStatus) searchStatus.textContent = '';
    if (countEl) countEl.textContent = '0';
    updateCollapsibleDefault(document.getElementById('hosts-section'), el, 0);
    renderConfigPreview();
    return;
  }
  const fullList = sortedHostsList(hosts);
  const list = fullList.filter((h) => hostMatchesSearch(h, hostSearchQuery));
  if (searchStatus) {
    searchStatus.textContent = hostSearchQuery
      ? `${list.length} von ${hosts.length} Host(s)`
      : `${hosts.length} Host(s)`;
  }
  if (countEl) {
    countEl.textContent = hostSearchQuery ? `${list.length}/${hosts.length}` : String(hosts.length);
  }
  if (!list.length) {
    el.innerHTML = '<p class="muted">Kein Treffer für die Suche.</p>';
    updateCollapsibleDefault(document.getElementById('hosts-section'), el, 0);
    return;
  }
  el.innerHTML = `
    <table class="host-table">
      <thead>
        <tr><th></th><th>Alias</th><th>Ziel</th><th>Key</th><th></th></tr>
      </thead>
      <tbody>
        ${list
          .map((h) => {
            const idx = fullList.findIndex((x) => x.id === h.id);
            return `
        <tr data-host-id="${esc(h.id)}">
          <td class="host-order">
            <button type="button" class="secondary icon-btn" data-move-host="${esc(h.id)}" data-dir="-1" ${idx === 0 ? 'disabled' : ''}>↑</button>
            <button type="button" class="secondary icon-btn" data-move-host="${esc(h.id)}" data-dir="1" ${idx === fullList.length - 1 ? 'disabled' : ''}>↓</button>
          </td>
          <td><strong>${esc(h.alias)}</strong>${h.identities_only ? ' <span class="muted" title="IdentitiesOnly">IO</span>' : ''}</td>
          <td class="mono muted">${esc(h.user || '')}${h.user ? '@' : ''}${esc(h.host_name)}:${h.port || 22}</td>
          <td><select class="host-identity-select" data-host-id="${esc(h.id)}">${identitySelectOptions(h.identity_id)}</select></td>
          <td class="host-actions">
            <button type="button" class="secondary icon-btn" data-edit-host="${esc(h.id)}" title="Bearbeiten">✎</button>
            <button type="button" data-del-host="${esc(h.id)}" class="danger">×</button>
          </td>
        </tr>`;
          })
          .join('')}
      </tbody>
    </table>`;

  el.querySelectorAll('[data-del-host]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!confirm('Host löschen?')) return;
      await api.deleteHost(btn.dataset.delHost);
      await refreshAll();
    });
  });
  el.querySelectorAll('[data-edit-host]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const h = hosts.find((x) => x.id === btn.dataset.editHost);
      if (h) openHostDialog(h);
    });
  });
  el.querySelectorAll('[data-move-host]').forEach((btn) => {
    btn.addEventListener('click', () => moveHost(btn.dataset.moveHost, parseInt(btn.dataset.dir, 10)));
  });
  el.querySelectorAll('.host-identity-select').forEach((sel) => {
    sel.addEventListener('change', () => onHostIdentityChange(sel.dataset.hostId, sel.value));
  });
  updateCollapsibleDefault(document.getElementById('hosts-section'), el, list.length);
  renderConfigPreview();
}

async function onHostIdentityChange(hostId, identityId) {
  const h = hosts.find((x) => x.id === hostId);
  if (!h) return;
  await api.putHost(h.id, hostPayload(h, { identity_id: identityId || null }));
  await refreshAll();
}

async function moveHost(hostId, delta) {
  const list = sortedHostsList(hosts);
  const idx = list.findIndex((h) => h.id === hostId);
  const ni = idx + delta;
  if (idx < 0 || ni < 0 || ni >= list.length) return;
  [list[idx], list[ni]] = [list[ni], list[idx]];
  for (let i = 0; i < list.length; i++) {
    await api.putHost(list[i].id, hostPayload(list[i], { sort_order: i }));
  }
  await refreshAll();
}

function deviceAgentStatus(d) {
  if (!d.last_seen) {
    return { className: 'never', label: 'nie verbunden' };
  }
  if (d.online) {
    return { className: 'online', label: 'Agent aktiv' };
  }
  return { className: 'stale', label: `inaktiv (${formatAgo(d.last_seen)})` };
}

function formatAgo(iso) {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const sec = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (sec < 60) return `vor ${sec}s`;
  if (sec < 3600) return `vor ${Math.floor(sec / 60)} Min`;
  if (sec < 86400) return `vor ${Math.floor(sec / 3600)} h`;
  return `vor ${Math.floor(sec / 86400)} T`;
}

function renderDevices() {
  const el = document.getElementById('device-list');
  const countEl = document.getElementById('device-count');
  if (countEl) countEl.textContent = String(devices.length);
  if (!devices.length) {
    el.innerHTML = '<p class="muted">Noch keine Geräte.</p>';
    updateCollapsibleDefault(document.getElementById('devices-section'), el, 0);
    return;
  }
  el.innerHTML = devices
    .map(
      (d) => {
        const st = deviceAgentStatus(d);
        return `
    <article class="card">
      <header>
        <strong>${esc(d.name)}</strong>
        <span class="status-pill ${st.className}" title="Letzter Agent-Ping">${esc(st.label)}</span>
        <button data-import-device="${esc(d.id)}" class="secondary">Import</button>
        <button data-sync-device="${esc(d.id)}" class="secondary">Sync</button>
        <button data-purge-device="${esc(d.id)}" class="danger secondary" title="Gerät abgeben - entfernt nur vom Syncer verwaltete SSH-Einträge">Abgeben</button>
        ${getSavedDeviceSetup(d.id) ? `<button data-setup-device="${esc(d.id)}" class="secondary">Config</button>` : ''}
        <button data-del-device="${esc(d.id)}" class="danger">×</button>
      </header>
      <p class="muted mono">${esc(d.id)}${d.last_seen ? ` · Ping ${esc(formatAgo(d.last_seen))}` : ''}</p>
      ${renderLastCommand(d.last_command)}
    </article>`;
      },
    )
    .join('');
  el.querySelectorAll('[data-del-device]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!confirm('Gerät löschen?')) return;
      await api.deleteDevice(btn.dataset.delDevice);
      await refreshAll();
    });
  });
  el.querySelectorAll('[data-import-device]').forEach((btn) => {
    btn.addEventListener('click', () => triggerDeviceImport(btn.dataset.importDevice, btn));
  });
  el.querySelectorAll('[data-sync-device]').forEach((btn) => {
    btn.addEventListener('click', () => triggerDeviceSync(btn.dataset.syncDevice, btn));
  });
  el.querySelectorAll('[data-purge-device]').forEach((btn) => {
    btn.addEventListener('click', () => triggerDevicePurge(btn.dataset.purgeDevice, btn));
  });
  el.querySelectorAll('[data-setup-device]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const saved = getSavedDeviceSetup(btn.dataset.setupDevice);
      if (!saved) return;
      const bootstrap = await api.clientBootstrap().catch(() => ({}));
      showDeviceSetupDialog(saved.name, saved, bootstrap);
    });
  });
  updateCollapsibleDefault(document.getElementById('devices-section'), el, devices.length);
}

function getSavedDeviceSetup(deviceId) {
  try {
    const map = JSON.parse(sessionStorage.getItem(DEVICE_SETUP_KEY) || '{}');
    return map[deviceId] || null;
  } catch {
    return null;
  }
}

function saveDeviceSetup(device) {
  const map = JSON.parse(sessionStorage.getItem(DEVICE_SETUP_KEY) || '{}');
  map[device.id] = { id: device.id, name: device.name, jwt: device.jwt };
  sessionStorage.setItem(DEVICE_SETUP_KEY, JSON.stringify(map));
}

function buildDeviceConfig(device, bootstrap) {
  const base = window.location.origin;
  return JSON.stringify(
    {
      server_url: base,
      device_id: device.id,
      jwt: device.jwt,
      access_client_id: bootstrap?.access_client_id || '<CF Client ID>',
      access_client_secret: bootstrap?.access_client_secret || '<CF Secret>',
    },
    null,
    2,
  );
}

function buildDeviceCommands() {
  return `mkdir -p ~/.config/ssh-sync
# Config oben nach ~/.config/ssh-sync/config.json
ssh-sync unlock
systemctl --user enable --now ssh-sync`;
}

function showDeviceSetupDialog(name, device, bootstrap) {
  document.getElementById('device-setup-title').textContent = `Gerät: ${name}`;
  document.getElementById('device-setup-config').value = buildDeviceConfig(device, bootstrap);
  document.getElementById('device-setup-cmds').value = buildDeviceCommands();
  document.getElementById('device-setup-dialog').showModal();
}

async function copyTextarea(id) {
  const el = document.getElementById(id);
  el.focus();
  el.select();
  try {
    await navigator.clipboard.writeText(el.value);
  } catch {
    document.execCommand('copy');
  }
}

function renderLastCommand(cmd) {
  if (!cmd) return '';
  const kind = { sync: 'Sync', import: 'Import', purge: 'Abgeben' }[cmd.command] || cmd.command || 'Befehl';
  const label = { pending: 'wartend', running: 'läuft', completed: 'ok', failed: 'fehlgeschlagen' }[cmd.status] || cmd.status;
  const conflictHint =
    cmd.message && /Konflikt/i.test(cmd.message) ? ' <span class="conflict">(Konflikte)</span>' : '';
  return `<p class="muted">${esc(kind)}: ${esc(label)}${conflictHint}${cmd.message ? ` — ${esc(cmd.message)}` : ''}</p>`;
}

async function triggerDeviceImport(deviceId, btn) {
  const prev = btn?.textContent;
  if (btn) {
    btn.disabled = true;
    btn.textContent = '…';
  }
  try {
    await api.triggerImport(deviceId);
    await refreshAll();
  } catch (err) {
    alert(err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = prev;
    }
  }
}

async function onImportAllDevices() {
  if (!devices.length) {
    alert('Zuerst Geräte anlegen.');
    return;
  }
  for (const d of devices) {
    try {
      await api.triggerImport(d.id);
    } catch (err) {
      alert(`${d.name}: ${err.message}`);
    }
  }
  await refreshAll();
  alert(`Import an ${devices.length} Gerät(e) ausgelöst — Ergebnis unter jedem Gerät (nach ~30s).`);
}

async function triggerDeviceSync(deviceId, btn) {
  const prev = btn?.textContent;
  if (btn) {
    btn.disabled = true;
    btn.textContent = '…';
  }
  try {
    await api.triggerSync(deviceId);
    await refreshAll();
  } catch (err) {
    alert(err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = prev;
    }
  }
}

async function triggerDevicePurge(deviceId, btn) {
  const dev = devices.find((d) => d.id === deviceId);
  const name = dev?.name || deviceId;
  if (
    !confirm(
      `Gerät „${name}“ abgeben?\n\nLöscht auf dem Client: ~/.ssh, ssh-sync Config/Keyring, Dienst und das ssh-sync Binary.\nDer Agent muss online sein.`,
    )
  ) {
    return;
  }
  const prev = btn?.textContent;
  if (btn) {
    btn.disabled = true;
    btn.textContent = '…';
  }
  try {
    await api.triggerPurge(deviceId);
    await refreshAll();
    alert('Abgeben ausgelöst — der Client meldet sich ab, sobald der Purge abgeschlossen ist.');
  } catch (err) {
    alert(err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = prev;
    }
  }
}

async function onSyncAllDevices() {
  if (!devices.length) {
    alert('Zuerst unter „Geräte“ einen Client anlegen.');
    return;
  }
  let ok = 0;
  for (const d of devices) {
    try {
      await api.triggerSync(d.id);
      ok++;
    } catch (err) {
      alert(`${d.name}: ${err.message}`);
    }
  }
  await refreshAll();
  const status = document.getElementById('sync-all-status');
  if (status && ok) status.textContent = `Sync an ${ok} Gerät(e) ausgelöst.`;
}

async function ensureCryptoKeys() {
  if (cryptoKeys) return cryptoKeys;
  const pw = getMasterPassword() || prompt('Master-Passwort:');
  if (!pw) throw new Error('Master-Passwort erforderlich');
  const saltRes = await api.kdfSalt();
  kdfSalt = hexToBytes(saltRes.kdf_salt);
  cryptoKeys = await deriveKeys(pw, kdfSalt);
  setMasterPassword(pw);
  return cryptoKeys;
}

async function onAddHost() {
  openHostDialog(null);
}

const hostDialog = document.getElementById('host-dialog');

function fillHostIdentitySelect(selectedId) {
  const sel = document.getElementById('host-identity');
  sel.innerHTML = identitySelectOptions(selectedId);
}

function openHostDialog(host) {
  editingHostId = host?.id || null;
  document.getElementById('host-dialog-title').textContent = host ? 'Host bearbeiten' : 'Host hinzufügen';
  document.getElementById('host-alias').value = host?.alias || '';
  document.getElementById('host-hostname').value = host?.host_name || '';
  document.getElementById('host-user').value = host?.user || '';
  document.getElementById('host-port').value = String(host?.port || 22);
  fillHostIdentitySelect(host?.identity_id || '');
  document.getElementById('host-proxy-jump').value = host?.proxy_jump || '';
  document.getElementById('host-identities-only').checked = !!host?.identities_only;
  document.getElementById('host-extra').value = host?.extra || '';
  document.getElementById('host-error').classList.add('hidden');
  hostDialog.showModal();
}

async function onHostFormSubmit(e) {
  const submitter = e.submitter?.value;
  if (submitter === 'cancel') {
    hostDialog.close();
    return;
  }
  e.preventDefault();
  const alias = document.getElementById('host-alias').value.trim();
  const hostName = document.getElementById('host-hostname').value.trim();
  if (!alias || !hostName) {
    flash('host-error', 'Alias und HostName sind erforderlich.');
    return;
  }
  const port = parseInt(document.getElementById('host-port').value, 10) || 22;
  const identityVal = document.getElementById('host-identity').value;
  const data = {
    alias,
    host_name: hostName,
    user: document.getElementById('host-user').value.trim(),
    port,
    identity_id: identityVal || null,
    proxy_jump: document.getElementById('host-proxy-jump').value.trim(),
    identities_only: document.getElementById('host-identities-only').checked,
    extra: document.getElementById('host-extra').value.trim(),
  };
  const duplicate = hosts.find((h) => h.alias === alias && h.id !== editingHostId);
  if (duplicate) {
    flash('host-error', `Alias „${alias}“ existiert bereits.`);
    return;
  }
  try {
    const existing = editingHostId ? hosts.find((h) => h.id === editingHostId) : null;
    const id = editingHostId || randomId();
    await api.putHost(
      id,
      hostPayload(existing || data, {
        ...data,
        sort_order: existing?.sort_order ?? nextHostSortOrder(),
      }),
    );
    hostDialog.close();
    await refreshAll();
  } catch (err) {
    flash('host-error', err.message);
  }
}

async function onAddDevice() {
  const name = prompt('Gerätename (z.B. laptop):');
  if (!name) return;
  try {
    const [res, bootstrap] = await Promise.all([
      api.createDevice(name),
      api.clientBootstrap().catch(() => ({})),
    ]);
    saveDeviceSetup(res);
    showDeviceSetupDialog(name, res, bootstrap);
    await refreshAll();
  } catch (err) {
    alert(err.message);
  }
}

function flash(id, msg) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.classList.remove('hidden');
}

function esc(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

const importDialog = document.getElementById('import-dialog');

function openImportDialog() {
  document.getElementById('import-preview').innerHTML = '';
  document.getElementById('import-error').classList.add('hidden');
  importDialog.showModal();
}

let accountMigrateMode = 'export';

function openAccountMigrate(mode) {
  accountMigrateMode = mode;
  document.getElementById('account-migrate-title').textContent =
    mode === 'export' ? 'Konto exportieren' : 'Konto importieren';
  document.getElementById('account-export-panel').classList.toggle('hidden', mode !== 'export');
  document.getElementById('account-import-panel').classList.toggle('hidden', mode !== 'import');
  document.getElementById('account-migrate-report').classList.add('hidden');
  document.getElementById('account-migrate-report').textContent = '';
  document.getElementById('account-migrate-error').classList.add('hidden');
  document.getElementById('account-migrate-submit').textContent =
    mode === 'export' ? 'Herunterladen' : 'Import starten';
  document.getElementById('account-migrate-dialog').showModal();
}

async function onAccountMigrateSubmit(e) {
  if (e.submitter?.value === 'cancel') return;
  e.preventDefault();
  const errEl = document.getElementById('account-migrate-error');
  errEl.classList.add('hidden');
  const reportEl = document.getElementById('account-migrate-report');
  try {
    const pw = getMasterPassword() || prompt('Master-Passwort bestaetigen:');
    if (!pw) throw new Error('Master-Passwort erforderlich');
    setMasterPassword(pw);
    if (accountMigrateMode === 'export') {
      await downloadAccountArchive(pw);
      reportEl.textContent = 'Archiv heruntergeladen (Rechte lokal 0600 empfohlen).';
      reportEl.classList.remove('hidden');
      return;
    }
    const file = document.getElementById('account-import-file').files?.[0];
    if (!file) throw new Error('Archiv-Datei waehlen');
    if (file.size > 64 * 1024 * 1024) throw new Error('Archiv zu gross');
    const rawText = await file.text();
    const payload = await openAccountArchive(pw, rawText);
    const mode = document.getElementById('account-import-mode').value;
    const dryRun = document.getElementById('account-import-dry-run').checked;
    const rep = await api.accountImport(payload, mode, dryRun);
    reportEl.textContent = JSON.stringify(rep, null, 2);
    reportEl.classList.remove('hidden');
    if (!dryRun) await refreshAll();
  } catch (err) {
    errEl.textContent = err.message || String(err);
    errEl.classList.remove('hidden');
  }
}

async function downloadAccountArchive(password) {
  const payload = await api.accountExport();
  const salt = hexToBytes(payload.kdf_salt);
  const payloadJSON = JSON.stringify(payload);
  const macKey = await deriveExportMACKey(password, salt);
  const mac = await hmacSha256Hex(macKey, new TextEncoder().encode(payloadJSON));
  const exportedAt = new Date().toISOString();
  // Payload-Bytes 1:1 einbetten, damit MAC und Dateiinhalt uebereinstimmen.
  const raw =
    `{"format":"ssh-sync-account-export","schema_version":1,"exported_at":${JSON.stringify(exportedAt)},` +
    `"integrity":{"alg":"hmac-sha256","mac":${JSON.stringify(mac)}},"payload":${payloadJSON}}`;
  const blob = new Blob([raw], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'ssh-sync-account-export.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

function openKeygenDialog() {
  document.getElementById('keygen-name').value = '';
  document.getElementById('keygen-comment').value = '';
  document.getElementById('keygen-result').classList.add('hidden');
  document.getElementById('keygen-error').classList.add('hidden');
  document.getElementById('keygen-dialog').showModal();
}

async function onKeygenSubmit(e) {
  if (e.submitter?.value === 'cancel') return;
  e.preventDefault();
  const errEl = document.getElementById('keygen-error');
  errEl.classList.add('hidden');

  const name = normalizeKeyName(document.getElementById('keygen-name').value);
  if (!name) {
    errEl.textContent = 'Name erforderlich (Buchstaben, Zahlen, -, _)';
    errEl.classList.remove('hidden');
    return;
  }
  if (identities.some((i) => i.name === name)) {
    errEl.textContent = `Key „${name}“ existiert bereits`;
    errEl.classList.remove('hidden');
    return;
  }

  const comment = document.getElementById('keygen-comment').value.trim() || `ssh-sync keygen: ${name}`;
  try {
    const { privatePEM, publicLine } = generateEd25519Keypair(comment);
    const id = randomId();
    const keys = await ensureCryptoKeys();
    const enc = await encryptIdentity(keys.encKey, id, publicLine, privatePEM);
    await api.putIdentity(id, {
      name,
      public_key: publicLine,
      encrypted_private_key: enc,
      comment,
    });
    document.getElementById('keygen-public').value = publicLine;
    document.getElementById('keygen-result').classList.remove('hidden');
    await refreshAll();
  } catch (err) {
    errEl.textContent = err.message || String(err);
    errEl.classList.remove('hidden');
  }
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    prompt('Kopieren:', text);
  }
}

function analyzeImportPlan(importedHosts, keys) {
  const serverByAlias = Object.fromEntries(hosts.map((h) => [h.alias, h]));
  const serverByName = Object.fromEntries(identities.map((i) => [i.name, i]));
  const plan = { newHosts: [], newKeys: [], skipped: [], conflicts: [] };

  for (const k of keys) {
    const existing = serverByName[k.name];
    if (!existing) {
      plan.newKeys.push(k.name);
      continue;
    }
    if (k.publicKey && existing.public_key && !publicKeysEqual(k.publicKey, existing.public_key)) {
      plan.conflicts.push(`Key ${k.name}: anderer Public Key auf dem Server`);
    } else {
      plan.skipped.push(`Key ${k.name} (existiert)`);
    }
  }

  for (const h of importedHosts) {
    const existing = serverByAlias[h.alias];
    if (!existing) {
      plan.newHosts.push(h);
      continue;
    }
    const port = h.port || 22;
    const exPort = existing.port || 22;
    if (existing.host_name !== h.host_name || (existing.user || '') !== (h.user || '') || exPort !== port) {
      plan.conflicts.push(
        `Host ${h.alias}: Server ${existing.user || ''}${existing.user ? '@' : ''}${existing.host_name}:${exPort} ≠ import ${h.user || ''}${h.user ? '@' : ''}${h.host_name}:${port}`,
      );
    } else {
      plan.skipped.push(`Host ${h.alias} (identisch)`);
    }
  }
  return plan;
}

function renderImportPlanPreview(plan, keyCount, hostCount) {
  const lines = [`<p><strong>${keyCount} Key(s), ${hostCount} Host(s)</strong> in der Datei</p>`];
  if (plan.newKeys.length) {
    lines.push(`<p>Neu: ${plan.newKeys.map(esc).join(', ')}</p>`);
  }
  if (plan.newHosts.length) {
    lines.push(
      `<p>Neue Hosts: ${plan.newHosts.map((h) => esc(`${h.alias} → ${h.user || ''}${h.user ? '@' : ''}${h.host_name}`)).join(', ')}</p>`,
    );
  }
  if (plan.conflicts.length) {
    lines.push('<p class="conflict"><strong>Konflikte (werden nicht überschrieben):</strong></p><ul>');
    for (const c of plan.conflicts) lines.push(`<li class="conflict">${esc(c)}</li>`);
    lines.push('</ul>');
  }
  if (plan.skipped.length) {
    lines.push(`<p>Übersprungen: ${plan.skipped.slice(0, 8).map(esc).join('; ')}${plan.skipped.length > 8 ? '…' : ''}</p>`);
  }
  return lines.join('\n');
}

async function collectImportData() {
  let configText = document.getElementById('import-config-text').value.trim();
  const configFile = document.getElementById('import-config-file').files[0];
  if (configFile) configText = await readFileAsText(configFile);
  const parsedHosts = configText ? parseSSHConfig(configText, { keepManaged: true }) : [];

  const keyFiles = [...document.getElementById('import-key-files').files];
  const pubMap = new Map();
  const privateEntries = [];

  for (const file of keyFiles) {
    const text = await readFileAsText(file);
    const base = file.name.replace(/.*[/\\]/, '');
    if (isPrivateKeyText(text)) {
      privateEntries.push({ file, text, base });
      continue;
    }
    if (isPublicKeyFile(base, text)) {
      const stem = base.replace(/\.pub$/, '');
      pubMap.set(stem, text.trim());
      if (stem.endsWith('.pem')) pubMap.set(stem.replace(/\.pem$/, ''), text.trim());
    }
  }

  const keys = [];
  for (const { file, text, base } of privateEntries) {
    keys.push({
      name: identityNameFromFile(base),
      privateKey: text.trim() + '\n',
      fileName: file.name,
      publicKey: matchPublicKey(base, pubMap),
    });
  }

  return { hosts: parsedHosts, keys };
}

async function previewImport(e) {
  e.preventDefault();
  try {
    const { hosts: h, keys } = await collectImportData();
    const plan = analyzeImportPlan(h, keys);
    document.getElementById('import-preview').innerHTML = renderImportPlanPreview(plan, keys.length, h.length);
    document.getElementById('import-error').classList.add('hidden');
  } catch (err) {
    flash('import-error', err.message);
  }
}

async function onImportSubmit(e) {
  const submitter = e.submitter?.value;
  if (submitter === 'cancel') {
    importDialog.close();
    return;
  }
  e.preventDefault();
  try {
    const { hosts: imported, keys } = await collectImportData();
    if (!keys.length && !imported.length) {
      flash('import-error', 'Keine Keys oder Hosts.');
      return;
    }
    const keysLocal = await ensureCryptoKeys();
    const plan = analyzeImportPlan(imported, keys);
    const pathToId = {};
    let importedKeys = 0;

    for (const k of keys) {
      const existing = identities.find((i) => i.name === k.name);
      if (existing) {
        if (!existing.public_key && k.publicKey) {
          await api.putIdentity(existing.id, {
            name: existing.name,
            public_key: k.publicKey,
            encrypted_private_key: existing.encrypted_private_key,
            comment: existing.comment || '',
          });
          importedKeys++;
        }
        continue;
      }
      const id = randomId();
      const encrypted = await encryptIdentity(keysLocal.encKey, id, k.publicKey || '', k.privateKey);
      await api.putIdentity(id, {
        name: k.name,
        public_key: k.publicKey || '',
        encrypted_private_key: encrypted,
        comment: `importiert von ${k.fileName}`,
      });
      pathToId[k.name] = id;
      importedKeys++;
    }

    await refreshAll();
    const identityByName = Object.fromEntries(identities.map((i) => [i.name, i.id]));
    for (const i of identities) pathToId[i.name] = i.id;

    let importedHosts = 0;
    let linkedHosts = 0;
    const serverByAlias = Object.fromEntries((await api.hosts()).map((h) => [h.alias, h]));

    for (const h of imported) {
      const identityID = h.identity_file
        ? matchIdentityForKeyFile(h.identity_file, identities, { ...pathToId, ...identityByName })
        : null;
      const existing = serverByAlias[h.alias];
      if (existing) {
        if (!existing.identity_id && identityID) {
          await api.putHost(existing.id, hostPayload(existing, { identity_id: identityID }));
          linkedHosts++;
        }
        continue;
      }
      await api.putHost(randomId(), hostPayload(h, {
        identity_id: identityID,
        identities_only: !!h.identities_only,
        proxy_jump: h.proxy_jump || '',
        extra: h.extra || '',
        sort_order: nextHostSortOrder(),
      }));
      importedHosts++;
    }

    await refreshAll();
    importDialog.close();
    const linkMsg = linkedHosts ? `, ${linkedHosts} verknüpft` : '';
    const conflictMsg = plan.conflicts.length ? `\n\nKonflikte (${plan.conflicts.length}):\n${plan.conflicts.join('\n')}` : '';
    alert(`Import: ${importedKeys} Key(s), ${importedHosts} Host(s)${linkMsg}.${conflictMsg}`);
  } catch (err) {
    flash('import-error', err.message);
  }
}
