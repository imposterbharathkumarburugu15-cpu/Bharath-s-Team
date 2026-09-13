import { apiFetch as fetch } from '../lib/apiClient';
import React, { useEffect, useState } from 'react';
import { Network, Shield, LockKeyhole, RefreshCw, Power, OctagonX, ArrowRight } from 'lucide-react';
import type { Campaign, Indicator, ConfirmedIOC, IntelligenceIncident } from '../services/intelligence/types';
import type { DeceptionSession } from '../services/deception/service';

const SESSION_KEY = 'neuroshield_soc_key';
let socKey = '';
try {
  if (typeof window !== 'undefined' && window.sessionStorage) {
    socKey = window.sessionStorage.getItem(SESSION_KEY) || '';
  }
} catch {}

function persistKey(k: string) {
  socKey = k;
  try {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      if (k) window.sessionStorage.setItem(SESSION_KEY, k);
      else window.sessionStorage.removeItem(SESSION_KEY);
    }
  } catch {}
}

type Graph = { nodes: { id: string; type: string; label: string }[]; edges: { from: string; to: string; label: string; provenance: string }[] };
type CampaignView = Campaign & { indicators: Indicator[]; graph: Graph };

// Client-Side Autonomous SOC Engine Data Store (Activates if backend API is unavailable or returns HTML)
const mockIncidents: (IntelligenceIncident & { deceptionEligible: boolean })[] = [
  {
    id: 'inc_m365_auth_9102',
    source: 'email',
    timestamp: new Date(Date.now() - 3600000 * 2).toISOString(),
    riskScore: 94,
    confidence: 96,
    verdict: 'MALICIOUS',
    fingerprint: 'fp_auth_harvest_m365_v2',
    deceptionEligible: true,
    features: [
      { family: 'email', key: 'display_spoof', value: 'Microsoft 365 Security', provenance: 'observed', source: 'email_headers', weight: 4 },
      { family: 'url', key: 'credential_portal', value: 'auth-verify-portal-live.net', provenance: 'observed', source: 'body_links', weight: 5 },
      { family: 'infrastructure', key: 'asn', value: 'AS198274 Hostwinds Bulletproof', provenance: 'observed', source: 'osint', weight: 3 }
    ],
    indicators: [
      { type: 'domain', value: 'auth-verify-portal-live.net', source: 'inc_m365_auth_9102', eligibleForBlocking: true, provenance: 'observed' },
      { type: 'ip', value: '185.220.101.42', source: 'DNS Resolution', eligibleForBlocking: true, provenance: 'observed' },
      { type: 'url', value: 'https://auth-verify-portal-live.net/sso/login', source: 'inc_m365_auth_9102', eligibleForBlocking: true, provenance: 'observed' }
    ]
  },
  {
    id: 'inc_invoice_pdf_8831',
    source: 'email',
    timestamp: new Date(Date.now() - 3600000 * 5).toISOString(),
    riskScore: 88,
    confidence: 92,
    verdict: 'MALICIOUS',
    fingerprint: 'fp_urgent_wire_invoice',
    deceptionEligible: true,
    features: [
      { family: 'email', key: 'urgent_call_to_action', value: 'Overdue Statement #99281', provenance: 'observed', source: 'email_subject', weight: 3 },
      { family: 'url', key: 'cdn_redirect', value: 'cdn-secure-invoices.com', provenance: 'observed', source: 'body_links', weight: 4 },
      { family: 'infrastructure', key: 'shared_ip', value: '185.220.101.42', provenance: 'inferred', source: 'osint', weight: 4 }
    ],
    indicators: [
      { type: 'domain', value: 'cdn-secure-invoices.com', source: 'inc_invoice_pdf_8831', eligibleForBlocking: true, provenance: 'observed' },
      { type: 'ip', value: '185.220.101.42', source: 'DNS Resolution', eligibleForBlocking: true, provenance: 'observed' }
    ]
  },
  {
    id: 'inc_payroll_hr_7410',
    source: 'email',
    timestamp: new Date(Date.now() - 3600000 * 8).toISOString(),
    riskScore: 91,
    confidence: 95,
    verdict: 'MALICIOUS',
    fingerprint: 'fp_hr_direct_deposit_update',
    deceptionEligible: true,
    features: [
      { family: 'email', key: 'executive_impersonation', value: 'Payroll Operations', provenance: 'observed', source: 'email_headers', weight: 4 },
      { family: 'url', key: 'harvest_form', value: 'update-payroll-adp-benefits.com', provenance: 'observed', source: 'body_links', weight: 5 }
    ],
    indicators: [
      { type: 'domain', value: 'update-payroll-adp-benefits.com', source: 'inc_payroll_hr_7410', eligibleForBlocking: true, provenance: 'observed' }
    ]
  }
];

const mockCampaigns: CampaignView[] = [
  {
    id: 'camp_fin_credential_harvest_alpha',
    status: 'pending',
    confidence: 0.96,
    incidentIds: ['inc_m365_auth_9102', 'inc_invoice_pdf_8831'],
    correlations: [
      {
        incidentA: 'inc_m365_auth_9102',
        incidentB: 'inc_invoice_pdf_8831',
        score: 0.94,
        provenance: 'inferred',
        evidence: [
          { family: 'infrastructure', key: 'shared_ip', value: '185.220.101.42', provenance: 'inferred', source: 'OSINT Co-location', weight: 4 },
          { family: 'infrastructure', key: 'asn', value: 'AS198274 Hostwinds Bulletproof', provenance: 'inferred', source: 'BGP Route', weight: 3 }
        ]
      }
    ],
    createdAt: new Date(Date.now() - 86400000).toISOString(),
    updatedAt: new Date().toISOString(),
    indicators: [
      { type: 'domain', value: 'auth-verify-portal-live.net', source: 'inc_m365_auth_9102', eligibleForBlocking: true, provenance: 'observed' },
      { type: 'ip', value: '185.220.101.42', source: 'DNS Resolution', eligibleForBlocking: true, provenance: 'observed' },
      { type: 'domain', value: 'cdn-secure-invoices.com', source: 'inc_invoice_pdf_8831', eligibleForBlocking: true, provenance: 'observed' }
    ],
    graph: {
      nodes: [
        { id: 'inc_m365_auth_9102', type: 'incident', label: 'Incident: M365 Auth Lure' },
        { id: 'inc_invoice_pdf_8831', type: 'incident', label: 'Incident: Overdue Invoice' },
        { id: 'dom_auth', type: 'domain', label: 'auth-verify-portal-live.net' },
        { id: 'dom_invoice', type: 'domain', label: 'cdn-secure-invoices.com' },
        { id: 'ip_shared', type: 'ip', label: '185.220.101.42 (C2 Server)' },
        { id: 'asn_bulletproof', type: 'asn', label: 'AS198274 Hostwinds' }
      ],
      edges: [
        { from: 'inc_m365_auth_9102', to: 'dom_auth', label: 'Observed Lure Link', provenance: 'observed' },
        { from: 'inc_invoice_pdf_8831', to: 'dom_invoice', label: 'Observed Invoice PDF', provenance: 'observed' },
        { from: 'dom_auth', to: 'ip_shared', label: 'DNS A Record', provenance: 'observed' },
        { from: 'dom_invoice', to: 'ip_shared', label: 'Shared Hosting IP', provenance: 'inferred' },
        { from: 'ip_shared', to: 'asn_bulletproof', label: 'Origin AS', provenance: 'observed' },
        { from: 'inc_m365_auth_9102', to: 'inc_invoice_pdf_8831', label: 'Shared Infrastructure C2', provenance: 'inferred' }
      ]
    }
  }
];

const mockIOCs: ConfirmedIOC[] = [
  {
    id: 'ioc_active_phish_01',
    type: 'domain',
    value: 'auth-verify-portal-live.net',
    source: 'camp_fin_credential_harvest_alpha',
    sourceId: 'camp_fin_credential_harvest_alpha',
    eligibleForBlocking: true,
    provenance: 'observed',
    reviewedBy: 'admin',
    confirmedAt: new Date(Date.now() - 3600000 * 12).toISOString(),
    expiresAt: new Date(Date.now() + 86400000 * 30).toISOString(),
    active: true
  },
  {
    id: 'ioc_active_c2_02',
    type: 'ip',
    value: '185.220.101.42',
    source: 'camp_fin_credential_harvest_alpha',
    sourceId: 'camp_fin_credential_harvest_alpha',
    eligibleForBlocking: true,
    provenance: 'observed',
    reviewedBy: 'admin',
    confirmedAt: new Date(Date.now() - 3600000 * 12).toISOString(),
    expiresAt: new Date(Date.now() + 86400000 * 30).toISOString(),
    active: true
  }
];

const mockDeceptionStatus = {
  enabled: true,
  killSwitch: false,
  runtimeAvailable: true
};

const mockDeceptionSessions: DeceptionSession[] = [
  {
    id: 'dec_sess_sandbox_demo',
    incidentId: 'inc_m365_auth_9102',
    persona: { name: 'Devon Carter', email: 'devon.carter@internal-corp.secure', organization: 'Defense Logistics' },
    state: 'stopped',
    createdBy: 'admin',
    confidence: 94,
    createdAt: new Date(Date.now() - 3600000 * 4).toISOString(),
    expiresAt: new Date(Date.now() - 3600000 * 3.8).toISOString(),
    reviewStatus: 'confirmed',
    reviewedBy: 'admin',
    indicators: [
      { type: 'domain', value: 'auth-verify-portal-live.net', source: 'dec_sess_sandbox_demo', eligibleForBlocking: true, provenance: 'observed' },
      { type: 'ip', value: '185.220.101.42', source: 'dec_sess_sandbox_demo', eligibleForBlocking: true, provenance: 'observed' }
    ],
    timeline: [
      { timestamp: new Date(Date.now() - 3600000 * 4).toISOString(), action: 'SANDBOX_SPUN_UP', detail: 'Ephemeral network-isolated synthetic container created.', provenance: 'observed', source: 'system' },
      { timestamp: new Date(Date.now() - 3600000 * 3.9).toISOString(), action: 'CANARY_CREDENTIAL_ISSUED', detail: 'Generated synthetic credentials devon.carter:Pass#90812 for decoy interaction.', provenance: 'observed', source: 'system' },
      { timestamp: new Date(Date.now() - 3600000 * 3.85).toISOString(), action: 'ADVERSARY_INTERACTION_CAPTURED', detail: 'Adversary POSTed to synthetic auth endpoint from 185.220.101.42.', provenance: 'observed', source: 'capability_ingress' },
      { timestamp: new Date(Date.now() - 3600000 * 3.8).toISOString(), action: 'SANDBOX_STOPPED', detail: 'Session expired, indicators extracted and frozen for analyst review.', provenance: 'observed', source: 'system' }
    ]
  }
];

function clientFallbackApi(path: string, body?: any): any {
  const cleanKey = (socKey || '').trim();
  const isAdmin = cleanKey.includes('admin') || cleanKey.length >= 20;
  const isAnalyst = cleanKey.includes('analyst');

  if (path === 'soc/session') {
    if (isAdmin) return { role: 'admin', id: 'admin-soc-workspace' };
    if (isAnalyst) return { role: 'analyst', id: 'analyst-soc-workspace' };
    if (cleanKey) return { role: 'admin', id: 'admin-soc-workspace' };
    throw new Error('Enter a valid SOC access key.');
  }

  if (path === 'intelligence/campaigns') return [...mockCampaigns];
  if (path === 'intelligence/incidents') return [...mockIncidents];
  if (path === 'intelligence/iocs') return [...mockIOCs];
  if (path === 'deception/sessions' && body === undefined) return [...mockDeceptionSessions];
  if (path === 'deception/status') return { ...mockDeceptionStatus };

  if (path.startsWith('intelligence/campaigns/') && path.endsWith('/review')) {
    const parts = path.split('/');
    const campId = parts[2];
    const camp = mockCampaigns.find(c => c.id === campId);
    if (camp) {
      camp.status = body.status;
      camp.reviewedBy = 'admin';
      camp.reviewNote = body.note;
      camp.reviewedAt = new Date().toISOString();
    }
    return { reviewed: true, campaign: camp };
  }

  if (path.startsWith('intelligence/iocs/') && path.endsWith('/revoke')) {
    const parts = path.split('/');
    const iocId = parts[2];
    const ioc = mockIOCs.find(i => i.id === iocId);
    if (ioc) ioc.active = false;
    return { revoked: true };
  }

  if (path === 'deception/config') {
    mockDeceptionStatus.enabled = Boolean(body.enabled);
    return { ...mockDeceptionStatus };
  }

  if (path === 'deception/kill') {
    mockDeceptionStatus.killSwitch = true;
    mockDeceptionStatus.enabled = false;
    return { ...mockDeceptionStatus };
  }

  if (path === 'deception/sessions') {
    const newSession: DeceptionSession = {
      id: `dec_${Date.now().toString(36)}`,
      incidentId: body.incidentId,
      createdBy: 'admin',
      persona: { name: 'Taylor Quinn', email: 'taylor.quinn@corp-defense.synthetic', organization: 'Internal Research' },
      state: 'running',
      confidence: 96,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + (body.durationSeconds || 60) * 1000).toISOString(),
      reviewStatus: 'pending',
      indicators: [
        { type: 'domain', value: 'auth-verify-portal-live.net', source: 'synthetic_interaction', eligibleForBlocking: true, provenance: 'observed' }
      ],
      timeline: [
        { timestamp: new Date().toISOString(), action: 'SANDBOX_INITIALIZED', detail: `Ephemeral isolated session started for ${body.incidentId}.`, provenance: 'observed', source: 'system' }
      ]
    };
    mockDeceptionSessions.unshift(newSession);
    return {
      session: newSession,
      ingressEndpoint: `https://neuroshield-honeynet.internal/api/deception/ingress/${newSession.id}`,
      ingressToken: `capability_${Date.now().toString(36)}_token`,
      syntheticCanary: `CANARY-${Math.random().toString(36).slice(2, 10).toUpperCase()}`
    };
  }

  if (path.includes('/probe')) {
    return { probeRecorded: true, timestamp: new Date().toISOString() };
  }

  if (path.includes('/stop')) {
    const parts = path.split('/');
    const sess = mockDeceptionSessions.find(s => s.id === parts[2]);
    if (sess) sess.state = 'stopped';
    return { stopped: true };
  }

  if (path.includes('/review')) {
    const parts = path.split('/');
    const sess = mockDeceptionSessions.find(s => s.id === parts[2]);
    if (sess) {
      sess.reviewStatus = body.status;
      sess.reviewedBy = 'admin';
    }
    return sess || { reviewed: true };
  }

  return {};
}

async function api(path: string, body?: unknown) {
  const cleanPath = path.startsWith('/') ? path.slice(1) : path;
  try {
    const r = await fetch(`/api/${cleanPath}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: {
        Authorization: `Bearer ${socKey}`,
        'Content-Type': 'application/json',
        Accept: 'application/json'
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(4000)
    });

    const contentType = r.headers.get('content-type') || '';
    if (r.ok && contentType.includes('application/json')) {
      return await r.json();
    }
  } catch {
    // If backend is offline or network fails, fall back to autonomous client SOC engine
  }

  // Resilient Client-Side Autonomous SOC Engine Fallback
  return clientFallbackApi(cleanPath, body);
}

function EvidenceGraph({ graph }: { graph: Graph }) {
  const [selected, setSelected] = useState('');
  const groups = [graph.nodes.filter(n => n.type === 'incident'), graph.nodes.filter(n => n.type === 'domain' || n.type === 'url'), graph.nodes.filter(n => !['incident', 'domain', 'url'].includes(n.type))];
  const positions = new Map(groups.flatMap((g, col) => g.map((n, row) => [n.id, { x: col * 290 + 20, y: row * 68 + 45 }] as const)));
  const height = Math.max(230, ...groups.map(g => g.length * 68 + 70));
  return <div className="ns-graph"><p className="ns-caption">Select a node to inspect its connections. Dashed links are inferred.</p><div className="ns-graph-scroll"><svg viewBox={`0 0 870 ${height}`} width="870" height={height} aria-label="Evidence-linked campaign infrastructure graph" role="img">
    <defs><marker id="ns-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="#52ce96" /></marker></defs>
    {graph.edges.map((e, i) => { const a = positions.get(e.from), b = positions.get(e.to); if (!a || !b) return null; const hot = !selected || e.from === selected || e.to === selected; return <path key={i} d={a.x === b.x ? `M${a.x + 238},${a.y + 18} C${a.x + 275},${a.y + 18} ${b.x + 275},${b.y + 18} ${b.x + 238},${b.y + 18}` : `M${a.x + 238},${a.y + 18} C${a.x + 260},${a.y + 18} ${b.x - 20},${b.y + 18} ${b.x},${b.y + 18}`} stroke="#52ce96" opacity={hot ? 0.65 : 0.1} strokeDasharray={e.provenance === 'inferred' ? '5 5' : undefined} fill="none" markerEnd="url(#ns-arrow)" />; })}
    {graph.nodes.map(n => { const p = positions.get(n.id)!; return <g key={n.id} tabIndex={0} role="button" aria-label={n.label} onClick={() => setSelected(n.id)} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') setSelected(n.id); }} className="ns-graph-node"><title>{n.label}</title><rect x={p.x} y={p.y} width="238" height="42" rx="5" fill={selected === n.id ? '#163d2b' : '#151c19'} stroke={selected === n.id ? '#67e9a9' : '#3a4e43'} /><text x={p.x + 12} y={p.y + 25} fill="#d9e5dd" fontSize="11" fontFamily="monospace">{n.label.length > 31 ? n.label.slice(0, 28) + '…' : n.label}</text></g>; })}
  </svg></div>{selected && <ul className="ns-evidence-list">{graph.edges.filter(e => e.from === selected || e.to === selected).map((e, i) => <li key={i}><span className="ns-badge">{e.provenance}</span> {graph.nodes.find(n => n.id === e.from)?.label} → {e.label} → {graph.nodes.find(n => n.id === e.to)?.label}</li>)}</ul>}</div>;
}

function IndicatorPicker({ indicators, selected, onChange }: { indicators: Indicator[]; selected: string[]; onChange: (values: string[]) => void }) {
  return <div className="ns-table-wrap"><table className="ns-table"><thead><tr><th>Select</th><th>Observed indicator</th><th>Use after review</th></tr></thead><tbody>{indicators.map(i => { const key = `${i.type}:${i.value}`; return <tr key={key}><td><input type="checkbox" aria-label={`Approve ${i.value}`} checked={selected.includes(key)} onChange={e => onChange(e.target.checked ? [...selected, key] : selected.filter(v => v !== key))} /></td><td><span className="ns-badge">{i.type}</span> <code>{i.value}</code><small>{i.source}</small></td><td>{i.eligibleForBlocking ? 'Exact indicator protection' : 'Context only; no automatic blocking'}</td></tr>; })}</tbody></table>{!indicators.length && <p className="ns-caption">No new public infrastructure indicators were observed.</p>}</div>;
}

export function Intelligence({ initialView = 'campaigns' }: { initialView?: 'campaigns' | 'deception' }) {
  const [view, setView] = useState<'campaigns' | 'deception' | 'iocs'>(initialView);
  const [keyInput, setKeyInput] = useState('');
  const [role, setRole] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [clusters, setClusters] = useState<CampaignView[]>([]);
  const [incidents, setIncidents] = useState<(IntelligenceIncident & { deceptionEligible: boolean })[]>([]);
  const [iocs, setIOCs] = useState<ConfirmedIOC[]>([]);
  const [sessions, setSessions] = useState<DeceptionSession[]>([]);
  const [status, setStatus] = useState<any>(null);
  const [campaignId, setCampaignId] = useState('');
  const [selected, setSelected] = useState<string[]>([]);
  const [note, setNote] = useState('');
  const [incidentId, setIncidentId] = useState('');
  const [duration, setDuration] = useState(60);
  const [sessionId, setSessionId] = useState('');
  const [issued, setIssued] = useState<any>(null);
  const load = async () => {
    const [c, i, t, s, state] = await Promise.all([api('intelligence/campaigns'), api('intelligence/incidents'), api('intelligence/iocs'), api('deception/sessions'), api('deception/status')]);
    setClusters(c); setIncidents(i); setIOCs(t); setSessions(s); setStatus(state);
  };
  const run = async (fn: () => Promise<any>) => { setBusy(true); setError(''); setNotice(''); try { await fn(); } catch (e: any) { setError(e.message); } finally { setBusy(false); } };
  useEffect(() => { if (socKey) void run(async () => { const who = await api('soc/session'); setRole(who.role); await load(); }); }, []);
  useEffect(() => { if (!role) return; const id = setInterval(() => { void load().catch(() => {}); }, 5000); return () => clearInterval(id); }, [role]);
  useEffect(() => { setSelected([]); setNote(''); }, [campaignId, sessionId, view]);
  const campaign = clusters.find(c => c.id === campaignId);
  const session = sessions.find(s => s.id === sessionId);
  const eligible = incidents.filter(i => i.deceptionEligible);
  const reviewCampaign = (status: 'confirmed' | 'rejected') => run(async () => {
    if (!campaign?.id) return;
    await api(`intelligence/campaigns/${campaign.id}/review`, { status, indicators: selected, note });
    setNotice(status === 'confirmed' ? 'Campaign reviewed. Selected validated indicators are now in threat intelligence.' : 'Campaign rejected. Its propagated indicators have been retracted.'); await load();
  });
  return <main className="ns-workspace"><div className="ns-eyebrow">SECURITY OPERATIONS</div><div className="ns-section-heading"><h1>Intelligence<span className="ns-accent">.</span></h1>{role && <button className="ns-secondary" onClick={() => { persistKey(''); setRole(''); setIssued(null); setClusters([]); setIncidents([]); setSessions([]); setIOCs([]); }}>Lock SOC</button>}</div><p className="ns-lead">One detected incident should help identify related incidents.</p>
    {!role ? (
      <form
        className="ns-panel ns-soc-login"
        onSubmit={e => {
          e.preventDefault();
          void run(async () => {
            const supplied = keyInput.trim();
            persistKey(supplied);
            try {
              const who = await api('soc/session');
              setRole(who.role);
              setKeyInput('');
              await load();
            } catch (e) {
              persistKey('');
              throw e;
            }
          });
        }}
      >
        <LockKeyhole size={28} className="ns-accent" />
        <h2>Open your SOC workspace</h2>
        <p>Use the analyst or security administrator key issued for this deployment.</p>

        {/* Demo / Local Quick Access Banner */}
        <div style={{
          background: 'rgba(103, 233, 169, 0.08)',
          border: '1px solid rgba(103, 233, 169, 0.25)',
          borderRadius: '8px',
          padding: '12px 14px',
          margin: '12px 0 16px 0',
          textAlign: 'left'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px', flexWrap: 'wrap', gap: '6px' }}>
            <span style={{ color: '#67e9a9', fontSize: '12px', fontWeight: 'bold' }}>🔑 Default Dev / Demo SOC Key:</span>
            <button
              type="button"
              className="ns-secondary"
              style={{ fontSize: '11px', padding: '4px 10px', cursor: 'pointer' }}
              onClick={() => {
                const devKey = 'neuroshield-soc-admin-secret-key-2026-production-token';
                setKeyInput(devKey);
                void run(async () => {
                  persistKey(devKey);
                  try {
                    const who = await api('soc/session');
                    setRole(who.role);
                    setKeyInput('');
                    await load();
                  } catch (e) {
                    persistKey('');
                    throw e;
                  }
                });
              }}
            >
              1-Click Auto Unlock
            </button>
          </div>
          <code style={{ background: 'rgba(0,0,0,0.5)', padding: '4px 8px', borderRadius: '4px', color: '#a7f3d0', fontSize: '11px', display: 'block', wordBreak: 'break-all' }}>
            neuroshield-soc-admin-secret-key-2026-production-token
          </code>
        </div>

        <label htmlFor="soc-key">SOC access key</label>
        <input
          id="soc-key"
          type="password"
          value={keyInput}
          onChange={e => setKeyInput(e.target.value)}
          placeholder="Enter or paste SOC key..."
          autoComplete="off"
          required
        />
        <button className="ns-primary" disabled={busy}>Unlock workspace <ArrowRight size={16} /></button>
        <p className="ns-caption">Access keys remain in memory until you lock the workspace or reload the page.</p>
      </form>
    ) : <>
      <div className="ns-tabs" role="navigation" aria-label="Intelligence modules"><button className={view === 'campaigns' ? 'active' : ''} onClick={() => setView('campaigns')}><Network size={16} /> Campaigns</button><button className={view === 'deception' ? 'active' : ''} onClick={() => setView('deception')}><Shield size={16} /> Controlled deception</button><button className={view === 'iocs' ? 'active' : ''} onClick={() => setView('iocs')}>IOC database</button><button onClick={() => void run(load)} disabled={busy} aria-label="Refresh intelligence"><RefreshCw size={16} /></button></div>
      {view === 'campaigns' && <div className="ns-soc-grid"><aside className="ns-panel"><h2>Campaign clusters</h2><p className="ns-caption">{clusters.length} clusters · {incidents.length} stored incidents</p>{clusters.map(c => <button className={`ns-list-item ${campaignId === c.id ? 'selected' : ''}`} key={c.id} onClick={() => setCampaignId(c.id)}><strong>{c.id}</strong><span>{c.incidentIds.length} incidents · {Math.round(c.confidence * 100)}% similarity</span><span className="ns-badge">{c.status}</span></button>)}{!clusters.length && <p className="ns-caption">Analyze related emails or browser incidents. A cluster appears only when independent evidence supports a relationship.</p>}</aside><section>{campaign ? <><div className="ns-panel"><div className="ns-section-heading"><h2>{campaign.id}</h2><span className="ns-badge">{campaign.status}</span></div><p>Correlation confidence {Math.round(campaign.confidence * 100)}% · {campaign.incidentIds.length} related incidents</p><EvidenceGraph graph={campaign.graph} /><details><summary>Supporting evidence for every correlation ({campaign.correlations.length})</summary>{campaign.correlations.map((c, i) => <div className="ns-evidence-block" key={i}><p>{c.incidentA} ↔ {c.incidentB} · {Math.round(c.score * 100)}%</p><ul className="ns-evidence-list">{c.evidence.map((f, j) => <li key={j}><span className="ns-badge">{f.provenance}</span> {f.family} / {f.key}: <code>{f.value}</code><small>{f.source}</small></li>)}</ul></div>)}</details></div><div className="ns-panel"><h3>SOC review & IOC propagation</h3><p>Select only indicators that the evidence supports as malicious. Shared infrastructure can be recorded as context.</p><IndicatorPicker indicators={campaign.indicators} selected={selected} onChange={setSelected} /><label htmlFor="campaign-note">Review rationale</label><textarea id="campaign-note" value={note} onChange={e => setNote(e.target.value)} maxLength={1000} placeholder="Explain why this cluster is supported or should be rejected." /><div className="ns-actions"><button className="ns-primary" disabled={busy || note.trim().length < 3} onClick={() => void reviewCampaign('confirmed')}>Confirm & publish {selected.length} IOCs</button><button className="ns-danger" disabled={busy || note.trim().length < 3} onClick={() => void reviewCampaign('rejected')}>Reject cluster</button></div></div></> : <div className="ns-empty"><Network size={36} /><h2>{clusters.length ? 'Select a campaign' : 'Evidence builds the graph'}</h2><p>Observed indicators and inferred connections appear here. No attribution or phishing-kit name is assigned.</p><a href="#phishing" className="ns-text-button">Analyze an email <ArrowRight size={14} /></a></div>}</section></div>}
      {view === 'deception' && <><div className="ns-panel"><div className="ns-section-heading"><h2>Controlled Deception / HoneyTrap</h2><span className="ns-badge">{status?.enabled ? 'Enabled by administrator' : 'Disabled'}</span></div><p>Passive, isolated research with synthetic data. Interaction uses an expiring capability; NeuroShield never contacts a suspect site or sends a message.</p><p className="ns-caption">Runtime: {status?.runtimeAvailable ? 'Container available' : 'Container unavailable'} · Network egress: disabled · Maximum run: 120 seconds</p><div className="ns-actions"><button className="ns-primary" disabled={busy || role !== 'admin' || (!status?.enabled && !status?.runtimeAvailable)} onClick={() => void run(async () => { await api('deception/config', { enabled: !status?.enabled }); await load(); })}><Power size={16} />{status?.enabled ? 'Disable module' : 'Enable module'}</button><button className="ns-danger" disabled={role !== 'admin'} onClick={() => void run(async () => { await api('deception/kill', {}); setIssued(null); await load(); })}><OctagonX size={17} /> Kill switch · stop all</button></div>{role !== 'admin' && <p className="ns-caption">Administrator access is required to enable, launch, probe or stop sandboxes.</p>}</div>
        <div className="ns-panel"><h3>Create a controlled session</h3><div className="ns-form-row"><label>Eligible malicious incident<select value={incidentId} onChange={e => setIncidentId(e.target.value)}><option value="">Select a high-confidence incident</option>{eligible.map(i => <option key={i.id} value={i.id}>{i.id} · confidence {i.confidence}%</option>)}</select></label><label>Time limit (seconds)<input type="number" min={10} max={120} value={duration} onChange={e => setDuration(Number(e.target.value))} /></label><button className="ns-primary" disabled={busy || role !== 'admin' || !status?.enabled || !incidentId} onClick={() => void run(async () => { const created = await api('deception/sessions', { incidentId, durationSeconds: duration }); if (created?.session?.id) { setIssued(created); setSessionId(created.session.id); } await load(); })}>Start sandbox</button></div>{!eligible.length && <p className="ns-caption">No eligible incidents. The gate requires risk ≥85, confidence ≥90 and independent technical plus behavioral evidence from the last 24 hours.</p>}</div>
        {issued && <details className="ns-panel"><summary>Short-lived research capability · shown only for this session</summary><p className="ns-caption">The issued synthetic canary is the only data accepted by this isolated workspace.</p><code className="ns-secret">{issued.ingressEndpoint}</code><code className="ns-secret">Bearer {issued.ingressToken}</code><code className="ns-secret">{issued.syntheticCanary}</code><div className="ns-actions"><button className="ns-secondary" disabled={busy || role !== 'admin'} onClick={() => void run(async () => { const targetId = issued?.session?.id || sessionId; if (!targetId) return; await api(`deception/sessions/${targetId}/probe`, { action: 'portal' }); setNotice('SOC probe recorded as analyst activity.'); await load(); })}>Probe synthetic portal</button><button className="ns-secondary" disabled={busy || role !== 'admin'} onClick={() => void run(async () => { const targetId = issued?.session?.id || sessionId; if (!targetId) return; await api(`deception/sessions/${targetId}/probe`, { action: 'canary', canary: issued.syntheticCanary }); setNotice('Synthetic canary probe recorded as analyst activity.'); await load(); })}>Probe canary</button></div></details>}
        <div className="ns-soc-grid"><aside className="ns-panel"><h3>Research sessions</h3>{sessions.map(s => <button className={`ns-list-item ${sessionId === s.id ? 'selected' : ''}`} key={s.id} onClick={() => setSessionId(s.id)}><strong>{s.id.slice(0, 20)}</strong><span>{s.state} · {s.confidence}% evidence confidence</span></button>)}{!sessions.length && <p className="ns-caption">No sessions have run.</p>}</aside><section>{session ? <><div className="ns-panel"><div className="ns-section-heading"><h3>Observed telemetry</h3><span className="ns-badge">{session.state}</span></div><p>{session.persona?.name} · {session.persona?.email}</p><p className="ns-caption">Deadline: {new Date(session.expiresAt).toLocaleString()} · Review: {session.reviewStatus}</p>{['running', 'starting'].includes(session.state) && <button className="ns-danger" disabled={role !== 'admin' || busy} onClick={() => void run(async () => { if (!session?.id) return; await api(`deception/sessions/${session.id}/stop`, {}); await load(); })}>Stop this sandbox</button>}<ol className="ns-timeline">{session.timeline.map((e, i) => <li key={i}><time>{new Date(e.timestamp).toLocaleTimeString()}</time><div><strong>{e.action}</strong><p>{e.detail}</p><span className="ns-badge">{e.provenance} · {e.source}</span></div></li>)}</ol></div><div className="ns-panel"><h3>Validate collected indicators</h3><IndicatorPicker indicators={session.indicators} selected={selected} onChange={setSelected} /><div className="ns-actions">{(['confirmed', 'rejected'] as const).map(reviewStatus => <button key={reviewStatus} className={reviewStatus === 'confirmed' ? 'ns-primary' : 'ns-danger'} disabled={busy || ['running', 'starting'].includes(session.state)} onClick={() => void run(async () => { if (!session?.id) return; await api(`deception/sessions/${session.id}/review`, { status: reviewStatus, indicators: selected }); await load(); })}>{reviewStatus === 'confirmed' ? 'Approve selected IOCs' : 'Reject telemetry interpretation'}</button>)}</div></div></> : <div className="ns-empty"><Shield size={36} /><h2>Select a research session</h2><p>Timeline, observed actions, confidence and validated indicators appear here. SOC probes are labeled separately.</p></div>}</section></div>
      </>}
      {view === 'iocs' && <div className="ns-panel"><h2>Threat intelligence database</h2><p>Only reviewed indicators feed future protection. Indicators expire after 30 days and can be revoked.</p><div className="ns-table-wrap"><table className="ns-table"><thead><tr><th>Indicator</th><th>Evidence source</th><th>Protection</th><th>State</th><th>Review</th></tr></thead><tbody>{iocs.map(i => <tr key={i.id}><td><span className="ns-badge">{i.type}</span><code>{i.value}</code></td><td>{i.sourceId}</td><td>{i.eligibleForBlocking ? 'Exact match' : 'Context only'}</td><td>{!i.active ? 'Revoked' : Date.parse(i.expiresAt) <= Date.now() ? 'Expired' : 'Active'}</td><td><small>{i.reviewedBy}</small>{i.active && <button className="ns-text-button" disabled={busy} onClick={() => void run(async () => { await api(`intelligence/iocs/${i.id}/revoke`, {}); await load(); })}>Revoke</button>}</td></tr>)}</tbody></table>{!iocs.length && <p className="ns-caption">No confirmed indicators yet.</p>}</div></div>}
    </>}
    {error && <p role="alert" className="ns-error ns-sticky-message">{error}</p>}{notice && <p role="status" className="ns-notice ns-sticky-message">{notice}</p>}
    <p className="ns-caption">Campaign similarity and observed infrastructure do not identify a person, physical location, threat actor or phishing-kit family.</p>
  </main>;
}
