const API_BASE = window.location.origin;

export function getToken() {
  return sessionStorage.getItem('ssh_sync_token');
}

export function setToken(token) {
  sessionStorage.setItem('ssh_sync_token', token);
}

export function clearToken() {
  sessionStorage.removeItem('ssh_sync_token');
  sessionStorage.removeItem('ssh_sync_master');
  masterPasswordMemory = null;
}

// Master-Passwort nur im Arbeitsspeicher (nicht in sessionStorage / localStorage).
let masterPasswordMemory = null;

export function setMasterPassword(pw) {
  masterPasswordMemory = pw || null;
  sessionStorage.removeItem('ssh_sync_master');
}

export function getMasterPassword() {
  return masterPasswordMemory;
}

async function request(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  const token = getToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  const text = await res.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { raw: text };
    }
  }
  if (!res.ok) {
    throw new Error(body?.error || res.statusText);
  }
  return body;
}

export const api = {
  setupStatus: () => request('/api/setup/status'),
  setup: (authKeyHex, kdfSaltHex) =>
    request('/api/setup', {
      method: 'POST',
      body: JSON.stringify({ auth_key: authKeyHex, kdf_salt: kdfSaltHex }),
    }),
  login: (authKeyHex) =>
    request('/api/auth/login', { method: 'POST', body: JSON.stringify({ auth_key: authKeyHex }) }),
  loginLegacy: (password) =>
    request('/api/auth/login', { method: 'POST', body: JSON.stringify({ password }) }),
  upgradeAuth: (authKeyHex, identities, password) =>
    request('/api/auth/upgrade', {
      method: 'POST',
      body: JSON.stringify({ auth_key: authKeyHex, identities, password }),
    }),
  kdfSalt: () => request('/api/auth/kdf-salt'),
  identities: () => request('/api/identities'),
  putIdentity: (id, data) => request(`/api/identities/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteIdentity: (id) => request(`/api/identities/${id}`, { method: 'DELETE' }),
  hosts: () => request('/api/hosts'),
  putHost: (id, data) => request(`/api/hosts/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteHost: (id) => request(`/api/hosts/${id}`, { method: 'DELETE' }),
  devices: () => request('/api/devices'),
  createDevice: (name) => request('/api/devices', { method: 'POST', body: JSON.stringify({ name }) }),
  clientBootstrap: () => request('/api/client-bootstrap'),
  saveClientBootstrap: (access_client_id, access_client_secret) =>
    request('/api/client-bootstrap', {
      method: 'PUT',
      body: JSON.stringify({ access_client_id, access_client_secret }),
    }),
  deleteDevice: (id) => request(`/api/devices/${id}`, { method: 'DELETE' }),
  triggerSync: (deviceId) => request(`/api/devices/${deviceId}/trigger-sync`, { method: 'POST' }),
  triggerImport: (deviceId) => request(`/api/devices/${deviceId}/trigger-import`, { method: 'POST' }),
  triggerPurge: (deviceId) => request(`/api/devices/${deviceId}/trigger-purge`, { method: 'POST' }),
  accountExport: () => request('/api/account/export'),
  accountImport: (payload, mode, dry_run) =>
    request('/api/account/import', {
      method: 'POST',
      body: JSON.stringify({ payload, mode, dry_run }),
    }),
};
