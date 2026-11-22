/** Bindet Login/Setup-Formulare an Submit-Handler (Enter + Button). */
export function bindAuthForms({ onSetup, onLogin }) {
  document.getElementById('setup-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    await onSetup();
  });
  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    await onLogin();
  });
}
