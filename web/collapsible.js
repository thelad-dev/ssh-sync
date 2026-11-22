/** Merkt manuelles Auf-/Zuklappen pro Sektion (über Re-Renders hinweg). */
const userOpen = new Map();

export function bindCollapsibleSection(detailsEl) {
  if (!detailsEl?.id || detailsEl.dataset.collapseBound) return;
  detailsEl.dataset.collapseBound = '1';
  detailsEl.addEventListener('toggle', () => {
    userOpen.set(detailsEl.id, detailsEl.open);
  });
}

/**
 * Kurze Listen offen, lange (über ~Bildschirmhöhe) zu.
 * @param {HTMLDetailsElement} detailsEl
 * @param {HTMLElement} contentEl
 * @param {number} [itemCount]
 */
export function updateCollapsibleDefault(detailsEl, contentEl, itemCount = 0) {
  if (!detailsEl) return;
  if (userOpen.has(detailsEl.id)) {
    detailsEl.open = userOpen.get(detailsEl.id);
    return;
  }
  const apply = () => {
    const threshold = Math.max(300, window.innerHeight * 0.5);
    const tall = itemCount > 10 || (contentEl?.scrollHeight ?? 0) > threshold;
    detailsEl.open = !tall;
  };
  requestAnimationFrame(() => requestAnimationFrame(apply));
}

export function initCollapsibleSections() {
  document.querySelectorAll('details.list-section').forEach(bindCollapsibleSection);
}
