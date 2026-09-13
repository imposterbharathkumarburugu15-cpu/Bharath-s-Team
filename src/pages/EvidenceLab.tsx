import React, { useRef, useState } from 'react';
import { ArrowRight, Check, Download, FileSearch, FlaskConical, Loader2, Play, ShieldCheck, Upload } from 'lucide-react';
import { apiFetch } from '../lib/apiClient';
import { labFixtures } from '../services/lab/fixtures';
import type { LabInput, LabReport, EvaluationReport } from '../services/lab/types';
import './EvidenceLab.css';

async function post<T>(path: string, body: unknown): Promise<T> {
  let key = ''; try { key = sessionStorage.getItem('neuroshield_soc_key') || ''; } catch { /* Public demo mode. */ }
  const response = await apiFetch(`/api/lab/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(key ? { Authorization: `Bearer ${key}` } : {}) }, body: JSON.stringify(body), signal: AbortSignal.timeout(20000) });
  if (!response.headers.get('content-type')?.includes('application/json')) throw new Error('Analysis backend unavailable. Start the Node server or configure its API URL.');
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `Request failed (${response.status}).`);
  return result;
}
const riskTone = (score: number) => score >= 65 ? 'danger' : score >= 40 ? 'caution' : 'calm';
const nice = (value: string) => value.replace(/_/g, ' ').toLowerCase();

export function EvidenceLab() {
  const [caseId, setCaseId] = useState(labFixtures[0].id);
  const [input, setInput] = useState<LabInput>({ ...labFixtures[0].input });
  const [report, setReport] = useState<LabReport | null>(null);
  const [evaluation, setEvaluation] = useState<EvaluationReport | null>(null);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [verification, setVerification] = useState('');
  const upload = useRef<HTMLInputElement>(null);
  const selected = labFixtures.find(c => c.id === caseId);
  const change = (key: keyof LabInput, value: string) => { setInput(previous => ({ ...previous, [key]: value })); setCaseId('custom'); setReport(null); setVerification(''); };
  const work = async (name: string, fn: () => Promise<void>) => {
    setBusy(name); setError('');
    try { await fn(); } catch (e) { setError(e instanceof Error ? e.message : 'Request failed.'); } finally { setBusy(''); }
  };
  const download = () => {
    if (!report) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(report.receipt, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url; link.download = 'neuroshield-decision-receipt.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return <main className="el-workspace">
    <header className="el-header"><div><div className="el-eyebrow"><FlaskConical size={15} /> NEUROSHIELD / EVIDENCE LAB</div><h1>A verdict you can interrogate.</h1><p>Inspect the evidence. Remove a signal. Watch the decision change.</p></div><span className="el-mode"><span /> LOCAL RULES · NO EXTERNAL LOOKUPS</span></header>
    <div className="el-layout">
      <section className="el-input el-panel" aria-label="Analysis input">
        <div className="el-section-title"><h2>01 / Choose a case</h2><span className="el-tag">SYNTHETIC EXAMPLES</span></div>
        <label htmlFor="el-case">Scenario</label>
        <select id="el-case" value={caseId} disabled={!!busy} onChange={e => { const sample = labFixtures.find(c => c.id === e.target.value); if (sample) { setCaseId(sample.id); setInput({ ...sample.input }); setReport(null); setVerification(''); } }}>
          {labFixtures.map(sample => <option value={sample.id} key={sample.id}>{sample.title}</option>)}<option value="custom" disabled>Custom input</option>
        </select>
        <p className="el-hint">{selected?.rationale || 'Your input is analyzed on this backend without contacting destinations or storing an incident.'}</p>
        <fieldset disabled={!!busy} className="el-fields">
          <div className="el-input-row"><div><label htmlFor="el-source">Channel</label><select id="el-source" value={input.source} onChange={e => change('source', e.target.value)}><option value="email">Email</option><option value="web">Web page</option><option value="sms">SMS</option></select></div><div><label htmlFor="el-from">Sender (optional)</label><input id="el-from" value={input.from || ''} maxLength={500} onChange={e => change('from', e.target.value)} placeholder="Team <team@office.example>" /></div></div>
          <label htmlFor="el-subject">Subject</label><input id="el-subject" value={input.subject || ''} maxLength={500} onChange={e => change('subject', e.target.value)} placeholder="Message subject" />
          <label htmlFor="el-content">Message</label><textarea id="el-content" value={input.content} maxLength={32000} rows={5} onChange={e => change('content', e.target.value)} placeholder="Paste the message to inspect…" />
          <details open={!!input.html}><summary>HTML &amp; page context</summary><label htmlFor="el-html">HTML source (parsed, never rendered)</label><textarea id="el-html" className="el-code" value={input.html || ''} maxLength={64000} rows={4} onChange={e => change('html', e.target.value)} spellCheck={false} /><label htmlFor="el-page">Original page URL (for form comparisons)</label><input id="el-page" value={input.pageUrl || ''} maxLength={2048} onChange={e => change('pageUrl', e.target.value)} placeholder="https://workspace.example/" /></details>
        </fieldset>
        <button className="el-primary" disabled={!!busy} onClick={() => void work('analyze', async () => { setReport(null); setVerification(''); setReport(await post<LabReport>('analyze', input)); })}>{busy === 'analyze' ? <Loader2 className="el-spin" size={18} /> : <Play size={18} />} Analyze &amp; challenge verdict <ArrowRight size={18} /></button>
        <p className="el-hint">Four real engine runs. No browsing, LLM calls or enforcement actions.</p>
      </section>
      <section className="el-results" aria-label="Evidence results" aria-live="polite" aria-busy={busy === 'analyze'}>
        {error && <div className="el-error" role="alert">{error}</div>}
        {!report ? <div className="el-empty el-panel"><FileSearch size={40} /><h2>Follow the evidence.</h2><p>Start with a disguised document link, a form destination override, or a normal urgent email. Every result comes from the running detector.</p><div className="el-empty-steps"><span>Inspect</span><ArrowRight size={16} /><span>Challenge</span><ArrowRight size={16} /><span>Verify</span></div></div> : <>
          <div className={`el-verdict el-panel ${riskTone(report.baseline.riskScore)}`}><div><div className="el-eyebrow">02 / CURRENT DECISION</div><h2>{nice(report.baseline.decision)}</h2><p>{report.baseline.verdict} · Recommendation only; no action executed</p></div><div className="el-score"><strong>{report.baseline.riskScore}</strong><span>/ 100 risk score</span></div></div>
          <div className="el-panel"><div className="el-section-title"><h2>Where does the action really go?</h2><span className="el-tag">{report.baseline.destinations.linksInspected} LINKS · {report.baseline.destinations.formsInspected} FORMS</span></div>
            {report.baseline.destinations.findings.map((finding, i) => <article className="el-finding" key={i}><span className="el-tag">{nice(finding.signal)}</span>{(finding.displayedHost || finding.destinationHost) && <div className="el-hosts"><code>{finding.displayedHost || 'password form'}</code><ArrowRight size={18} /><code>{finding.destinationHost || 'active content'}</code></div>}<p>{finding.explanation}</p></article>)}
            {!report.baseline.destinations.findings.length && <p className="el-hint">{report.baseline.destinations.status === 'unavailable' ? 'HTML was not supplied. Link labels and form destinations are unverified.' : 'No destination mismatch was found in the inspected HTML. This does not establish safety.'}</p>}
            {report.baseline.destinations.truncated && <p className="el-error">Inspection limit reached. Some HTML was not examined.</p>}
          </div>
          <div className="el-panel"><div className="el-section-title"><h2>03 / Remove evidence. Rerun.</h2><span className="el-tag">{report.durationMs} MS</span></div><p className="el-hint">Each row is a new analysis. The difference shows sensitivity to missing evidence, not a safe way to rewrite a message.</p>
            <div className="el-variants">{report.variants.map(variant => <article key={variant.id}><div><h3>{variant.label}</h3><p>{variant.removed}</p></div><div className="el-variant-result"><strong>{variant.result.riskScore}</strong><span className={variant.riskDelta ? 'el-delta' : ''}>{variant.riskDelta > 0 ? '+' : ''}{variant.riskDelta} points</span><small>{nice(variant.result.decision)}</small></div></article>)}</div>
          </div>
          <details className="el-panel"><summary>Detector evidence &amp; missing context</summary><p className="el-hint">Coverage: {Math.round(report.baseline.coverage * 100)}% in the existing core coverage model. Heuristic scores are not calibrated probabilities.</p><div className="el-detectors">{report.baseline.detectors.map((detector, i) => <div key={i}><span>{nice(detector.name)}</span><meter min={0} max={100} value={detector.score} aria-label={`${detector.name} score`} /><strong>{detector.status === 'unavailable' ? 'N/A' : detector.score}</strong></div>)}</div>{report.baseline.missing.map(item => <p className="el-hint" key={item}>{item}</p>)}<div className="el-signal-list">{report.baseline.signals.filter(s => s.severity === 'high' || s.severity === 'critical' || s.status === 'OBSERVED').map((signal, i) => <div key={i}><span className="el-tag">{signal.status}</span> {nice(signal.signal)} <small>{signal.source}</small></div>)}</div></details>
          <div className="el-panel"><div className="el-section-title"><h2>04 / Keep a decision receipt</h2><ShieldCheck size={18} /></div><p className="el-hint">A minimal JSON record of the policy, signals, verdict and reruns. Message text and raw destinations are excluded.</p><div className="el-buttons"><button disabled={!!busy} onClick={download}><Download size={16} /> Export receipt</button><button disabled={!!busy} onClick={() => void work('verify', async () => { const response = await post<{ valid: boolean }>('verify', report.receipt); setVerification(response.valid ? 'Checksum matches. Preserve the original digest separately to detect later changes.' : 'Checksum mismatch. The receipt has changed.'); })}><Check size={16} /> Verify checksum</button></div><code className="el-digest">SHA-256 {report.receipt.integrity.digest}</code><p className="el-hint">A checksum detects changes against a trusted original digest. It is not a digital signature.</p></div>
        </>}
      </section>
    </div>
    <section className="el-panel el-evaluation"><div className="el-section-title"><div><h2>Prove it on the controls, too.</h2><p className="el-hint">Run {labFixtures.length} synthetic regression cases, including benign messages and missing input. Failures remain visible.</p></div><button disabled={!!busy} onClick={() => void work('evaluate', async () => { setEvaluation(null); setEvaluation(await post<EvaluationReport>('evaluate', {})); })}>{busy === 'evaluate' ? <Loader2 size={16} className="el-spin" /> : <FlaskConical size={16} />} Run evaluation</button></div>
      {evaluation && <><div className="el-metrics"><div><strong>{evaluation.passed}/{evaluation.total}</strong><span>expectations met</span></div><div><strong>{evaluation.reviewRecall === null ? 'N/A' : `${Math.round(evaluation.reviewRecall * 100)}%`}</strong><span>review recall · synthetic</span></div><div><strong>{evaluation.falsePositiveRate === null ? 'N/A' : `${Math.round(evaluation.falsePositiveRate * 100)}%`}</strong><span>false positives · synthetic</span></div></div><div className="el-table-wrap"><table><thead><tr><th>Case</th><th>Expected</th><th>Actual</th><th>Risk</th><th>Result</th></tr></thead><tbody>{evaluation.rows.map(row => <tr key={row.id}><td>{row.title}</td><td>{row.expected}</td><td>{row.actual}</td><td>{row.riskScore}</td><td className={row.passed ? 'el-pass' : 'el-fail'}>{row.passed ? 'Pass' : 'Needs work'}</td></tr>)}</tbody></table></div><p className="el-hint">{evaluation.limitations}</p></>}
    </section>
    <footer className="el-footer"><div><button disabled={!!busy} onClick={() => upload.current?.click()}><Upload size={16} /> Verify a saved receipt</button><input hidden ref={upload} type="file" accept="application/json,.json" onChange={e => { const file = e.target.files?.[0]; e.target.value = ''; if (file) void work('upload', async () => { setVerification(''); if (file.size > 128000) throw new Error('Receipt must be smaller than 128 KB.'); const result = await post<{ valid: boolean }>('verify', JSON.parse(await file.text())); setVerification(result.valid ? 'Uploaded receipt checksum matches. Authenticity requires a separately trusted original digest.' : 'Checksum mismatch. This receipt has changed or is invalid.'); }); }} /><p role="status">{verification}</p></div><details><summary>What this lab can establish</summary>{(report?.limitations || ['Local heuristic analysis of supplied text and HTML. Synthetic tests do not establish real-world accuracy.', 'No external lookups, destination visits, incident storage or enforcement actions.']).map(line => <p key={line}>{line}</p>)}</details></footer>
  </main>;
}
