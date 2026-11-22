/** Vorschau des managed SSH-Config-Blocks (wie der Agent schreibt). */

import { keyFileBasename } from './import.js';

export function sortedHosts(hosts) {
  return [...hosts].sort(
    (a, b) => (a.sort_order ?? 0) - (b.sort_order ?? 0) || String(a.alias).localeCompare(String(b.alias)),
  );
}

export function renderSSHConfigPreview(hosts, identities) {
  const idByID = Object.fromEntries(identities.map((i) => [i.id, i]));
  const lines = [
    '# --- BEGIN ssh-sync (managed) ---',
    '# Vorschau — identisch auf allen Clients; Keys können von mehreren Host-Blöcken referenziert werden',
  ];
  for (const h of sortedHosts(hosts)) {
    lines.push('', `Host ${h.alias}`, `  HostName ${h.host_name}`);
    if (h.port && h.port !== 22) lines.push(`  Port ${h.port}`);
    if (h.user) lines.push(`  User ${h.user}`);
    if (h.identity_id && idByID[h.identity_id]) {
      const fn = keyFileBasename(idByID[h.identity_id].name);
      lines.push(`  IdentityFile ~/.ssh/${fn}`);
    }
    if (h.identities_only) lines.push('  IdentitiesOnly yes');
    if (h.proxy_jump) lines.push(`  ProxyJump ${h.proxy_jump}`);
    if (h.extra?.trim()) {
      for (const line of h.extra.trim().split('\n')) {
        const t = line.trim();
        if (t) lines.push(t.startsWith('  ') ? t : `  ${t}`);
      }
    }
  }
  lines.push('', '# --- END ssh-sync (managed) ---');
  return lines.join('\n');
}
