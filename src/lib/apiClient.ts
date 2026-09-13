/** Same-origin by default; static or dev deployments on port 5173/etc point to port 3000. */
const envBase = ((import.meta as any).env?.VITE_API_BASE_URL || '').replace(/\/$/, '');

export function getApiBaseUrl(): string {
  if (envBase) return envBase;
  if (typeof window !== 'undefined' && window.location) {
    const port = window.location.port;
    // If the frontend is running on a port other than 3000 (e.g. 5173, 5174, 4173):
    if (port && port !== '3000') {
      return `${window.location.protocol}//${window.location.hostname}:3000`;
    }
  }
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

