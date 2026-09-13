import { Resolver } from 'node:dns/promises';
import { normalizeDomain, publicIP } from './indicators';

export interface OSINTReport {
  domain: string;
  observedAt: string;
  status: 'complete' | 'partial' | 'unavailable';
  evidence: { kind: string; value: string; provenance: 'observed' | 'externally_reported'; source: string; observedAt: string }[];
  unavailable: string[];
  disclaimer: string;
}
const cache = new Map<string, { expires: number; report: OSINTReport }>();
const rdapRoots: Record<string, string> = { com: 'https://rdap.verisign.com/com/v1/domain/', net: 'https://rdap.verisign.com/net/v1/domain/', org: 'https://rdap.publicinterestregistry.org/rdap/domain/', in: 'https://rdap.registry.in/rdap/domain/' };
async function json(url: string) {
  const r = await fetch(url, { signal: AbortSignal.timeout(3500), redirect: 'error', headers: { Accept: 'application/json' } });
  if (!r.ok) throw new Error('Provider unavailable');
  const reader = r.body?.getReader();
  if (!reader) throw new Error('Empty provider response');
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > 262144) throw new Error('Provider response too large'); chunks.push(value); }
  } finally { await reader.cancel().catch(() => {}); }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
/** Passive queries to DNS and fixed public registries. Never visits a submitted URL. */
export async function domainOSINT(input: unknown): Promise<OSINTReport> {
  const domain = normalizeDomain(input);
  if (!domain) throw new Error('Enter a valid public domain or an HTTP(S) URL without credentials or a custom port.');
  const hit = cache.get(domain);
  if (hit && hit.expires > Date.now()) return hit.report;
  const report: OSINTReport = { domain, observedAt: new Date().toISOString(), status: 'complete', evidence: [], unavailable: [],
    disclaimer: 'Infrastructure observations are not attacker identity or physical location. Shared hosting and DNS relationships do not prove maliciousness.' };
  const add = (kind: string, value: string, source: string, provenance: 'observed' | 'externally_reported' = 'observed') => report.evidence.push({ kind, value: value.slice(0, 500), source, provenance, observedAt: report.observedAt });
  const resolver = new Resolver({ timeout: 1800, tries: 1 });
  const timer = setTimeout(() => resolver.cancel(), 2500);
  try {
    const result = await Promise.allSettled([resolver.resolve4(domain), resolver.resolve6(domain), resolver.resolveMx(domain), resolver.resolveNs(domain), resolver.resolveTxt(domain), resolver.resolveTxt(`_dmarc.${domain}`)]);
    const labels = ['A', 'AAAA', 'MX', 'NS', 'SPF', 'DMARC'];
    result.forEach((r, i) => {
      if (r.status !== 'fulfilled') { report.unavailable.push(`${labels[i]}: no record or DNS unavailable`); return; }
      if (i < 2) for (const ip of r.value as string[]) { if (publicIP(ip)) add(labels[i], ip, 'System DNS resolver'); else report.unavailable.push('Non-public DNS address excluded'); }
      if (i === 2) for (const mx of r.value as { exchange: string; priority: number }[]) add('MX', `${mx.priority} ${mx.exchange}`, 'System DNS resolver');
      if (i === 3) for (const ns of r.value as string[]) add('NS', ns, 'System DNS resolver');
      if (i >= 4) for (const txt of r.value as string[][]) { const value = txt.join(''); if (value.startsWith(i === 4 ? 'v=spf1' : 'v=DMARC1')) add(labels[i], value, 'System DNS resolver'); }
    });
  } finally { clearTimeout(timer); resolver.cancel(); }
  const tld = domain.split('.').at(-1)!;
  const root = rdapRoots[tld];
  const providers: Promise<void>[] = [];
  if (root) providers.push((async () => {
    try {
      const data = await json(root + encodeURIComponent(domain));
      for (const ev of (data.events || []).slice(0, 10)) if (['registration', 'expiration', 'last changed'].includes(ev.eventAction) && !Number.isNaN(Date.parse(ev.eventDate))) add(`RDAP ${ev.eventAction}`, new Date(ev.eventDate).toISOString(), root, 'externally_reported');
      for (const status of (data.status || []).slice(0, 8)) if (typeof status === 'string') add('RDAP status', status, root, 'externally_reported');
      // Deliberately exclude registrant/contact entities, addresses and personal names.
    } catch { report.unavailable.push('RDAP unavailable for this domain (a subdomain may have no record)'); }
  })());
  else report.unavailable.push('RDAP provider not configured for this suffix');
  const ip = report.evidence.find(e => e.kind === 'A')?.value;
  if (ip) providers.push((async () => {
    try {
      const data = await json(`https://ipwho.is/${encodeURIComponent(ip)}`);
      if (data.success === false || data.ip !== ip) throw new Error();
      if (Number.isInteger(data.connection?.asn)) add('ASN', `AS${data.connection.asn}`, 'ipwho.is', 'externally_reported');
      if (typeof data.connection?.isp === 'string') add('Hosting / ISP', data.connection.isp, 'ipwho.is', 'externally_reported');
      if (typeof data.country === 'string') add('Infrastructure country (approximate)', data.country, 'ipwho.is', 'externally_reported');
    } catch { report.unavailable.push('ASN / hosting provider unavailable'); }
  })());
  await Promise.allSettled(providers);
  report.unavailable.push('Certificate and live redirect inspection not collected by this passive lookup');
  report.status = report.evidence.length ? (report.unavailable.length ? 'partial' : 'complete') : 'unavailable';
  if (cache.size >= 256) cache.delete(cache.keys().next().value!);
  cache.set(domain, { expires: Date.now() + 300000, report });
  return report;
}
