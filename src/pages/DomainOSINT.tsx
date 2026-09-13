import { apiFetch as fetch } from '../lib/apiClient';
import React, { useState } from 'react';
import { Globe, Search, Loader2 } from 'lucide-react';
import type { OSINTReport } from '../services/intelligence/osint';

export function DomainOSINT() {
  const [domain, setDomain] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [report, setReport] = useState<OSINTReport | null>(null);
  const lookup = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true); setError(''); setReport(null);
    try {
      const r = await fetch('/api/osint/domain', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain }), signal: AbortSignal.timeout(15000) });
      const data = await r.json(); if (!r.ok) throw new Error(data.error || 'Lookup unavailable'); setReport(data);
    } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  };
  return <main className="ns-workspace"><div className="ns-eyebrow">INFRASTRUCTURE INTELLIGENCE</div><h1>Domain OSINT<span className="ns-accent">.</span></h1><p className="ns-lead">Inspect public DNS, registry records and hosting relationships. Every finding includes its source.</p>
    <form onSubmit={lookup} className="ns-search-form"><Globe size={22} /><label className="sr-only" htmlFor="osint-domain">Domain or URL</label><input id="osint-domain" value={domain} onChange={e => setDomain(e.target.value)} placeholder="Enter a domain or URL" required maxLength={2048} /><button className="ns-primary" disabled={busy}>{busy ? <Loader2 size={18} className="animate-spin" /> : <Search size={18} />}{busy ? 'Looking up…' : 'Investigate'}</button></form>
    {error && <p className="ns-error" role="alert">{error}</p>}
    {!report && !busy && <div className="ns-empty"><Globe size={38} /><h2>Start with an observed domain</h2><p>Copy the sender domain or a suspicious link from your email investigation.</p><p className="ns-caption">This passive lookup does not open the submitted website.</p></div>}
    {report && <><div className="ns-section-heading"><h2>{report.domain}</h2><span className="ns-badge">{report.status}</span></div><p className="ns-caption">Observed {new Date(report.observedAt).toLocaleString()}</p><div className="ns-table-wrap"><table className="ns-table"><thead><tr><th>Indicator</th><th>Finding</th><th>Evidence type</th><th>Source</th></tr></thead><tbody>{report.evidence.map((e, i) => <tr key={i}><td>{e.kind}</td><td className="ns-mono">{e.value}</td><td><span className="ns-badge">{e.provenance.replace('_', ' ')}</span></td><td>{e.source}</td></tr>)}</tbody></table></div><details className="ns-panel"><summary>Unavailable observations ({report.unavailable.length})</summary><ul>{report.unavailable.map((s, i) => <li key={i}>{s}</li>)}</ul></details><p className="ns-caption">{report.disclaimer}</p></>}
  </main>;
}
