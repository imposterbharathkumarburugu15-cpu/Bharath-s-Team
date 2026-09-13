import React, { useState } from 'react';
import { ShieldCheck, Network, FileSearch, ArrowRight, RefreshCw } from 'lucide-react';

export function IncidentWorkflow({ analysis, loading, onRetry }: { analysis: any; loading: boolean; onRetry?: () => void }) {
  const [step, setStep] = useState(0);
  if (loading) return (
    <div className="ns-panel" role="status" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
      <RefreshCw className="animate-spin" size={16} />
      <span>Analyzing email → checking forensic evidence → matching campaign intelligence → resolving protection…</span>
    </div>
  );
  if (!analysis) return (
    <div className="ns-panel ns-error" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap' }}>
      <span>No backend decision is available. Treat this email as unverified and retry analysis.</span>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          style={{
            background: 'rgba(255,255,255,0.1)',
            border: '1px solid rgba(255,255,255,0.2)',
            color: '#fff',
            padding: '4px 12px',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '12px',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px'
          }}
        >
          <RefreshCw size={12} />
          Retry Analysis
        </button>
      )}
    </div>
  );
  const decision = analysis.authoritativeProtectionDecision;
  const evidence = analysis.evidence_provenance || [];
  return <section className="ns-workspace ns-incident-flow">
    <nav className="ns-tabs" aria-label="Email review workflow">{['1 · Forensic Email DNA', '2 · Infrastructure & Campaign', '3 · Protection decision'].map((title, i) => <button className={i === step ? 'active' : ''} onClick={() => setStep(i)} key={title}>{title}</button>)}</nav>
    <div className="ns-panel">
      {step === 0 && <><FileSearch className="ns-accent" /><h3>What makes this email suspicious?</h3><p>Risk {analysis.risk_score}/100 · Evidence confidence {analysis.confidence}%</p><ul className="ns-evidence-list">{evidence.slice(0, 5).map((e: any, i: number) => <li key={i}><span className="ns-badge">{e.status === 'OBSERVED' ? 'observed' : e.status === 'UNAVAILABLE' ? 'unavailable' : 'inferred'}</span> {e.evidence || e.signal}<small>{e.source}</small></li>)}</ul>{!evidence.length && <p>No detailed evidence was returned. Open protocol forensics below for available headers.</p>}<p className="ns-caption">Reported authentication headers are evidence claims; they are not a fresh cryptographic verification.</p></>}
      {step === 1 && <><Network className="ns-accent" /><h3>Is this connected to other incidents?</h3><p>{analysis.intelligence?.campaignId ? `Possible campaign: ${analysis.intelligence.campaignId}` : 'No supported campaign relationship has been found yet.'}</p><p className="ns-caption">Fingerprint: <code>{analysis.intelligence?.fingerprint?.slice(0, 24) || 'Unavailable'}</code></p><p>{analysis.intelligence?.matches?.length ? 'An analyst-confirmed IOC matched this incident.' : 'Relationships remain inferred until a SOC analyst reviews their supporting evidence.'}</p><a className="ns-text-button" href="#intelligence">Review campaign graph <ArrowRight size={14} /></a><a className="ns-text-button" href="#osint">Investigate a domain <ArrowRight size={14} /></a></>}
      {step === 2 && <><ShieldCheck className="ns-accent" /><h3>{decision?.protectionDecision === 'ALLOW' ? 'No automatic restriction recommended' : decision?.protectionDecision?.startsWith('BLOCK') ? 'Avoid this interaction' : 'Review this email before acting'}</h3><p>Backend decision: <strong>{decision?.protectionDecision || 'UNKNOWN'}</strong> · Enforcement: {decision?.enforcementStatus || 'UNKNOWN'}</p><p>{analysis.protection?.recommended_action}</p><p className="ns-caption">Dangerous links stay inactive in this email workspace. Gmail itself remains read-only; mailbox quarantine is unavailable. Browser protection requires the extension.</p><a href="#guard" className="ns-text-button">Set up browser protection <ArrowRight size={14} /></a></>}
      {step < 2 && <button className="ns-primary" onClick={() => setStep(step + 1)}>Next: {step === 0 ? 'connections' : 'protection'} <ArrowRight size={16} /></button>}
    </div>
  </section>;
}
