/**
 * NeuroShield Guard — Options Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  const apiUrlInput = document.getElementById('api-url');
  const btnSave = document.getElementById('btn-save');
  const btnTest = document.getElementById('btn-test');
  const statusEl = document.getElementById('status');
  const radios = document.getElementsByName('privacy-mode');

  // Load existing settings
  chrome.storage.local.get(['apiUrl', 'privacyMode'], (res) => {
    apiUrlInput.value = res.apiUrl || 'http://localhost:3000';
    if (res.privacyMode) {
      for (const r of radios) {
        if (r.value === res.privacyMode) r.checked = true;
      }
    }
  });

  btnSave.addEventListener('click', () => {
    let mode = 'STANDARD';
    for (const r of radios) {
      if (r.checked) mode = r.value;
    }

    const apiUrl = apiUrlInput.value.trim() || 'http://localhost:3000';
    chrome.storage.local.set({ apiUrl, privacyMode: mode }, () => {
      statusEl.textContent = 'Settings saved successfully!';
      statusEl.style.color = '#34d399';
      statusEl.style.display = 'block';
      setTimeout(() => { statusEl.style.display = 'none'; }, 3000);
    });
  });

  btnTest.addEventListener('click', async () => {
    const apiUrl = apiUrlInput.value.trim() || 'http://localhost:3000';
    btnTest.textContent = 'Testing...';
    try {
      const res = await fetch(`${apiUrl}/api/neuroshield/model-status`);
      if (res.ok) {
        statusEl.textContent = '✅ Connected to NeuroShield Core successfully!';
        statusEl.style.color = '#34d399';
      } else {
        statusEl.textContent = `⚠️ Connected but received HTTP ${res.status}`;
        statusEl.style.color = '#fbbf24';
      }
    } catch (err) {
      statusEl.textContent = `❌ Connection failed: ${err.message}`;
      statusEl.style.color = '#f87171';
    }
    statusEl.style.display = 'block';
    btnTest.textContent = 'Test Connection';
  });
});
