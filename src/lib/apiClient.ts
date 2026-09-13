/** Same-origin by default; static deployments may point to the Node backend. */
const base = ((import.meta as any).env?.VITE_API_BASE_URL || '').replace(/\/$/, '');
export function apiFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const target = typeof input === 'string' && input.startsWith('/api/') && base ? `${base}${input}` : input;
  return globalThis.fetch(target, init);
}
