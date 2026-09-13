/** Same-origin by default. Separate frontend hosting must configure VITE_API_BASE_URL. */
const envBase = ((import.meta as any).env?.VITE_API_BASE_URL || '').replace(/\/$/, '');

export function getApiBaseUrl(): string {
  if (envBase) return envBase;
  return '';
}

export function apiFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const base = getApiBaseUrl();
  let target = input;
  if (typeof input === 'string') {
    if ((input.startsWith('/api/') || input.startsWith('/scan') || input.startsWith('/health')) && base) {
      target = `${base}${input}`;
    }
  }
  return globalThis.fetch(target, init);
}

// Global fetch safeguard in browser context so all components reach backend
if (typeof window !== 'undefined' && window.fetch && !(window as any).__neuroshield_fetch_patched) {
  (window as any).__neuroshield_fetch_patched = true;
  const originalFetch = window.fetch;
  window.fetch = function (input: RequestInfo | URL, init?: RequestInit) {
    const base = getApiBaseUrl();
    if (base && typeof input === 'string' && (input.startsWith('/api/') || input.startsWith('/scan') || input.startsWith('/health'))) {
      input = `${base}${input}`;
    }
    return originalFetch.call(this, input, init);
  };
}
