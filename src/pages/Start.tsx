import React, { useEffect, useState } from 'react';
import { ArrowRight, Mail, ShieldCheck, FileSearch, Network, Check, Loader2 } from 'lucide-react';
import { googleSignIn, getAccessToken, initAuth } from '../services/googleAuth';
import { useLanguage } from '@/contexts/LanguageContext';

export function Start({ navigate }: { navigate: (tab: string) => void }) {
  const { t } = useLanguage();
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
        <p className="ns-kicker">{t('start_kicker') || 'YOUR NEXT STEP'}</p>
        <h1>{t('start_title_1') || 'Start with your inbox.'}<br /><span>{t('start_title_2') || 'Know what to trust.'}</span></h1>
        <p className="ns-lead">{t('start_lead') || 'Connect Gmail, choose an email, and see the evidence behind every protection decision.'}</p>
        <button className="ns-primary ns-start-cta" onClick={connect} disabled={busy}>
          {busy ? <Loader2 className="animate-spin" size={20} /> : <Mail size={20} />}
          {busy ? (t('connecting_status') || 'Connecting…') : connected ? (t('open_inbox_cta') || 'Open inbox') : (t('connect_gmail_cta') || 'Connect Gmail')}<ArrowRight size={20} />
        </button>
        <p className="ns-caption">{t('gmail_read_only_caption') || 'Gmail access is read-only. NeuroShield shows evidence and protects links inside its workspace.'}</p>
        <button className="ns-secondary" onClick={() => navigate('lab')}><FileSearch size={18} /> Explore Evidence Lab <ArrowRight size={16} /></button>
        {error && <p role="alert" className="ns-error">{error}</p>}
        <button className="ns-text-button" onClick={() => { sessionStorage.setItem('ns-open-eml', 'true'); navigate('phishing'); }}>{t('have_eml_file') || 'Have an .eml file? Analyze it here'} <ArrowRight size={14} /></button>
      </section>
      <aside className="ns-journey" aria-label="How to get started">
        <div className="ns-eyebrow">{t('journey_eyebrow') || 'ONE EMAIL. A CLEAR ANSWER.'}</div>
        {[
          { title: t('step_1_title') || 'Connect your inbox', detail: t('step_1_detail') || 'Choose your Google account.', done: connected },
          { title: t('step_2_title') || 'Open an email', detail: t('step_2_detail') || 'Inspect a suspicious message.', done: false },
          { title: t('step_3_title') || 'Review the evidence', detail: t('step_3_detail') || 'See the risk and the action to take.', done: false },
        ].map((step, i) => <div className="ns-step" key={step.title}><span className={step.done ? 'ns-step-number done' : 'ns-step-number'}>{step.done ? <Check size={18} /> : `0${i + 1}`}</span><div><h2>{step.title}</h2><p>{step.detail}</p></div></div>)}
        <div className="ns-journey-footer"><ShieldCheck size={18} /> {t('evidence_first_footer') || 'Evidence first. Clear decisions.'}</div>
      </aside>
    </div>
    <div className="ns-start-bottom">
      <div><FileSearch size={20} /><strong>{t('feature_email_dna') || 'Forensic Email DNA'}</strong><span>{t('feature_email_dna_desc') || 'Understand the message and its technical evidence.'}</span></div>
      <div><Network size={20} /><strong>{t('feature_campaign_intel') || 'Campaign intelligence'}</strong><span>{t('feature_campaign_intel_desc') || 'Connect related incidents through observable evidence.'}</span></div>
      <div><ShieldCheck size={20} /><strong>{t('feature_autonomous_prot') || 'Autonomous protection'}</strong><span>{t('feature_autonomous_prot_desc') || 'Turn the backend assessment into an actionable decision.'}</span></div>
    </div>
    <div className="ns-analyst-entry"><span>{t('working_secops') || 'Working in security operations?'}</span><button className="ns-text-button" onClick={() => navigate('intelligence')}>{t('open_soc_intel') || 'Open SOC intelligence'} <ArrowRight size={14} /></button></div>
  </main>;
}
