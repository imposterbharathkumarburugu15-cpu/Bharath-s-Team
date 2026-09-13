import { isIP, BlockList } from 'node:net';
import { createHash } from 'node:crypto';
import { domainToASCII } from 'node:url';

export const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const blocked = new BlockList();
for (const [address, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
] as [string, number][]) blocked.addSubnet(address, prefix, 'ipv4');
const globalV6 = new BlockList();
globalV6.addSubnet('2000::', 3, 'ipv6');
for (const [address, prefix] of [['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]] as [string, number][])
  blocked.addSubnet(address, prefix, 'ipv6');

export function publicIP(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return !blocked.check(ip, 'ipv4');
  // Excludes mapped IPv4, local/link-local, transition and documentation ranges.
  return family === 6 && globalV6.check(ip, 'ipv6') && !blocked.check(ip, 'ipv6');
}
export function normalizeDomain(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 2048) return null;
  try {
    const input = value.trim();
    const u = new URL(input.includes('://') ? input : `https://${input}`);
    if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password || u.port) return null;
    const host = domainToASCII(u.hostname.toLowerCase().replace(/\.$/, ''));
    if (host.length > 253 || isIP(host) || host.includes(':') || !host.includes('.')) return null;
    if (!host.split('.').every(p => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(p))) return null;
    if (/(^|\.)(localhost|local|internal|invalid|test|example|onion)$/.test(host)) return null;
    return host;
  } catch { return null; }
}
const safeSegments = new Set(['login', 'signin', 'verify', 'account', 'auth', 'oauth', 'password', 'reset', 'payment', 'invoice', 'index.html', 'index.php', 'submit', 'secure', 'api', 'v1']);
export function urlStructure(value: string): { domain: string; origin: string; path: string; queryKeys: string[] } | null {
  try {
    const u = new URL(value);
    const domain = normalizeDomain(u.origin);
    if (!domain) return null;
    return {
      domain, origin: `${u.protocol}//${domain}`,
      path: u.pathname.split('/').map(p => !p ? '' : safeSegments.has(p.toLowerCase()) ? p.toLowerCase() : ':segment').join('/'),
      queryKeys: [...new Set([...u.searchParams.keys()].map(k => digest(k).slice(0, 16)))].sort().slice(0, 16),
    };
  } catch { return null; }
}
export function validIndicator(type: string, value: string): boolean {
  if (type === 'domain') return normalizeDomain(value) === value && !value.includes('/');
  if (type === 'ip') return publicIP(value);
  if (type === 'sha256') return /^[a-f0-9]{64}$/.test(value);
  if (type === 'url') {
    const u = urlStructure(value);
    return Boolean(u && u.origin === value); // Deliberately origin-scoped; no secrets in paths/queries.
  }
  return false;
}
