import { createHash, timingSafeEqual } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { NeuroShieldCore } from '../core/neuroshieldCore';
import { EmailAdapter } from '../core/adapters/EmailAdapter';
import type { UnifiedThreatInput, UnifiedThreatAnalysis } from '../core/types';
import type { LabInput, LabSummary, LabReport, DecisionReceipt, ReceiptEnvelope, EvaluationReport } from './types';
import { labFixtures } from './fixtures';

export const LAB_POLICY_VERSION = 'evidence-lab-1.0.0';

export function validateLabInput(body: unknown): LabInput {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Provide an input object.');
  const data = body as Record<string, unknown>;
  if (!['email', 'web', 'sms'].includes(String(data.source))) throw new Error('Choose email, web or sms.');
  const limits = { content: 32000, subject: 500, from: 500, html: 64000, pageUrl: 2048 };
  const clean: Record<string, string> = { source: String(data.source) };
  for (const [key, limit] of Object.entries(limits)) {
    if (data[key] !== undefined && typeof data[key] !== 'string') throw new Error(`${key} must be text.`);
    const value = (data[key] as string) || '';
    if (value.length > limit) throw new Error(`${key} exceeds ${limit} characters.`);
    clean[key] = value;
  }
  if (clean.pageUrl) {
    let url: URL; try { url = new URL(clean.pageUrl); } catch { throw new Error('Page URL must be an absolute HTTP(S) URL.'); }
    if (!/^https?:$/.test(url.protocol) || url.username || url.password) throw new Error('Page URL must use HTTP(S) without embedded credentials.');
  }
  return clean as unknown as LabInput;
}

function prepare(input: LabInput): UnifiedThreatInput {
  const base: UnifiedThreatInput = input.source === 'email' ? EmailAdapter.normalize({
    source: 'email', from: input.from, subject: input.subject, body: { text: input.content, html: input.html },
  }) : { source: input.source, content: input.content, subject: input.subject };
  // User-supplied JSON cannot claim verified identity, browser enforcement or a reviewed IOC.
  base.metadata = { ...base.metadata, html: input.html, pageUrl: input.pageUrl, client: 'headless', actualEnforcementApplied: false };
  return base;
}
const analyze = (input: UnifiedThreatInput) => NeuroShieldCore.analyze(input, input.source, { deepForensics: false });
function summarize(a: UnifiedThreatAnalysis): LabSummary {
  return {
    verdict: a.verdict, riskScore: a.risk_score, decision: a.protectionDecision || 'WARN', enforcementStatus: 'NOT_EXECUTED',
    coverage: a.analysis_coverage.coverageRatio,
    detectors: a.evidence.map(e => ({ name: e.detector, score: e.score, status: e.status })),
    missing: (a.analysis_coverage.detectorsUnavailable || []).map(e => `${e.detector}: ${e.reason}`),
    signals: (a.evidence_provenance || []).map(e => ({ signal: e.signal, source: e.source, status: e.status || 'INFERRED', severity: e.severity })),
    destinations: a.destination_analysis || { status: 'unavailable', linksInspected: 0, formsInspected: 0, riskFloor: 0, findings: [], truncated: false, limitations: ['HTML unavailable.'] },
    auth: { spf: a.technical_evidence.spfStatus, dkim: a.technical_evidence.dkimStatus, dmarc: a.technical_evidence.dmarcStatus },
  };
}

// Canonical serialization is versioned by the receipt schema. Arrays retain their order.
export function canonicalJSON(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalJSON((value as any)[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
const digest = (receipt: unknown) => createHash('sha256').update(canonicalJSON(receipt)).digest('hex');
export function verifyReceipt(envelope: unknown): boolean {
  if (!envelope || typeof envelope !== 'object') return false;
  const { receipt, integrity } = envelope as ReceiptEnvelope;
  if (!receipt || receipt.schema !== 'neuroshield.decision-receipt.v1' || integrity?.algorithm !== 'SHA-256' || !/^[0-9a-f]{64}$/.test(integrity?.digest || '')) return false;
  return timingSafeEqual(Buffer.from(digest(receipt), 'hex'), Buffer.from(integrity.digest, 'hex'));
}

export async function runEvidenceLab(input: LabInput): Promise<LabReport> {
  const started = performance.now(), prepared = prepare(input);
  const baseline = summarize(await analyze(prepared));
  const noNarrative = { ...prepared, content: '', subject: '', rawPayload: undefined, metadata: { ...prepared.metadata, subject: '' } };
  const noIdentity = { ...prepared, sender: null, identity: undefined, history: null, headers: {}, metadata: { ...prepared.metadata, headers: {}, authentication: undefined, replyTo: undefined, spfStatus: 'UNAVAILABLE', dkimStatus: 'UNAVAILABLE', dmarcStatus: 'UNAVAILABLE' } };
  const noDestinations = { ...prepared, content: prepared.content.replace(/https?:\/\/[^\s<>"']+/gi, '[link removed]'), rawPayload: undefined, urls: [], metadata: { ...prepared.metadata, html: undefined, pageUrl: undefined } };
  const variants: LabReport['variants'] = [];
  for (const [id, label, removed, candidate] of [
    ['narrative', 'Without message wording', 'Message body and subject; HTML and sender evidence retained.', noNarrative],
    ['identity', 'Without sender context', 'Sender, authentication claims and relationship metadata.', noIdentity],
    ['destinations', 'Without link / form evidence', 'URL tokens and HTML; other wording and sender retained.', noDestinations],
  ] as const) {
    const result = summarize(await analyze(candidate));
    variants.push({ id, label, removed, result, riskDelta: result.riskScore - baseline.riskScore });
  }
  const receipt: DecisionReceipt = {
    schema: 'neuroshield.decision-receipt.v1', policyVersion: LAB_POLICY_VERSION, createdAt: new Date().toISOString(),
    mode: 'LOCAL_RULES', verdict: baseline.verdict, riskScore: baseline.riskScore, decision: baseline.decision,
    enforcement: 'NOT_EXECUTED', coverage: baseline.coverage, signals: baseline.signals,
    ablations: variants.map(v => ({ id: v.id, riskScore: v.result.riskScore, decision: v.result.decision })),
    privacy: 'No message text, sender, destinations, credentials or raw evidence included',
  };
  return {
    baseline, variants, receipt: { receipt, integrity: { algorithm: 'SHA-256', digest: digest(receipt), scope: 'Canonical receipt JSON only. Checksum is not a digital signature or proof of detector accuracy.' } },
    durationMs: Math.round(performance.now() - started),
    limitations: [
      'Local rule engine; no LLM, DNS lookup, URL visit, sandbox or IOC database is used in this lab.',
      'Ablation measures sensitivity to removed evidence, not causation. Missing evidence is not proof of safety.',
      'Scores and detector confidence are heuristic, not calibrated probabilities.',
      'No incidents are persisted and no protection action is executed. HTML is parsed without rendering.',
      'Supplied authentication headers are claims; independent SPF/DKIM/DMARC verification is unavailable.',
    ],
  };
}

export async function runLabEvaluation(): Promise<EvaluationReport> {
  const rows: EvaluationReport['rows'] = [];
  for (const sample of labFixtures) {
    const result = summarize(await analyze(prepare(sample.input)));
    const actual = result.verdict === 'UNKNOWN' ? 'UNKNOWN' : result.decision === 'ALLOW' ? 'ALLOW' : 'REVIEW';
    rows.push({ id: sample.id, title: sample.title, expected: sample.expected, actual, riskScore: result.riskScore, passed: actual === sample.expected });
  }
  const positives = rows.filter(r => r.expected === 'REVIEW'), negatives = rows.filter(r => r.expected === 'ALLOW');
  return { suite: `${LAB_POLICY_VERSION}/synthetic-v1`, synthetic: true, total: rows.length, passed: rows.filter(r => r.passed).length,
    reviewRecall: positives.length ? positives.filter(r => r.actual === 'REVIEW').length / positives.length : null,
    falsePositiveRate: negatives.length ? negatives.filter(r => r.actual === 'REVIEW').length / negatives.length : null, rows,
    limitations: 'Small authored regression suite. These measurements do not establish real-world accuracy or superiority over other products. REVIEW includes warnings and block recommendations, not executed protection.' };
}
