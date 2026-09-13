import React, { useEffect, useState } from 'react';
import { ArrowRight, Mail, ShieldCheck, FileSearch, Network, Check, Loader2 } from 'lucide-react';
import { googleSignIn, getAccessToken, initAuth } from '../services/googleAuth';

export function Start({ navigate }: { navigate: (tab: string) => void }) {
  const [connected, setConnected] = useState(Boolean(getAccessToken()));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => initAuth(() => setConnected(true), () => setConnected(false)), []);
  const connect = async () => {
    if (connected) { navigate('phishing'); return; }
    setBusy(true); setError('');
    try { const result = await googleSignIn(); if (result) { setConnected(true); navigate('phishing'); } }
    catch (e: any) { setError(e.message || 'Could not connect. Please try again.'); }
    finally { setBusy(false); }
  };
  return <main className="ns-workspace ns-start">
    <div className="ns-eyebrow"><span className="ns-status-dot" /> EMAIL DEFENSE / NEUROSHIELD</div>
    <div className="ns-start-grid">
      <section>
        <p className="ns-kicker">YOUR NEXT STEP</p>
        <h1>Start with your inbox.<br /><span>Know what to trust.</span></h1>
        <p className="ns-lead">Connect Gmail, choose an email, and see the evidence behind every protection decision.</p>
        <button className="ns-primary ns-start-cta" onClick={connect} disabled={busy}>
          {busy ? <Loader2 className="animate-spin" size={20} /> : <Mail size={20} />}
          {busy ? 'Connecting…' : connected ? 'Open inbox' : 'Connect Gmail'}<ArrowRight size={20} />
        </button>
        <p className="ns-caption">Gmail access is read-only. NeuroShield shows evidence and protects links inside its workspace.</p>
        {error && <p role="alert" className="ns-error">{error}</p>}
        <button className="ns-text-button" onClick={() => { sessionStorage.setItem('ns-open-eml', 'true'); navigate('phishing'); }}>Have an .eml file? Analyze it here <ArrowRight size={14} /></button>
      </section>
      <aside className="ns-journey" aria-label="How to get started">
        <div className="ns-eyebrow">ONE EMAIL. A CLEAR ANSWER.</div>
        {[
          { title: 'Connect your inbox', detail: 'Choose your Google account.', done: connected },
          { title: 'Open an email', detail: 'Inspect a suspicious message.', done: false },
          { title: 'Review the evidence', detail: 'See the risk and the action to take.', done: false },
        ].map((step, i) => <div className="ns-step" key={step.title}><span className={step.done ? 'ns-step-number done' : 'ns-step-number'}>{step.done ? <Check size={18} /> : `0${i + 1}`}</span><div><h2>{step.title}</h2><p>{step.detail}</p></div></div>)}
        <div className="ns-journey-footer"><ShieldCheck size={18} /> Evidence first. Clear decisions.</div>
      </aside>
    </div>
    <div className="ns-start-bottom">
      <div><FileSearch size={20} /><strong>Forensic Email DNA</strong><span>Understand the message and its technical evidence.</span></div>
      <div><Network size={20} /><strong>Campaign intelligence</strong><span>Connect related incidents through observable evidence.</span></div>
      <div><ShieldCheck size={20} /><strong>Autonomous protection</strong><span>Turn the backend assessment into an actionable decision.</span></div>
    </div>
    <div className="ns-analyst-entry"><span>Working in security operations?</span><button className="ns-text-button" onClick={() => navigate('intelligence')}>Open SOC intelligence <ArrowRight size={14} /></button></div>
  </main>;
}
