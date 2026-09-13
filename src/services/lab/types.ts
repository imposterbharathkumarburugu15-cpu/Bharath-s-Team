import type { DestinationAnalysis } from '../core/detectors/DestinationDetector';
export interface LabInput { source: 'email' | 'web' | 'sms'; content: string; subject?: string; from?: string; html?: string; pageUrl?: string }
export interface LabSummary {
  verdict: string; riskScore: number; decision: string; enforcementStatus: string;
  coverage: number; detectors: { name: string; score: number; status: string }[];
  missing: string[]; signals: { signal: string; source: string; status: string; severity: string }[];
  destinations: DestinationAnalysis; auth: { spf: string; dkim: string; dmarc: string };
}
export interface LabVariant { id: string; label: string; removed: string; result: LabSummary; riskDelta: number }
export interface DecisionReceipt {
  schema: 'neuroshield.decision-receipt.v1'; policyVersion: string; createdAt: string;
  mode: 'LOCAL_RULES'; verdict: string; riskScore: number; decision: string;
  enforcement: 'NOT_EXECUTED'; coverage: number;
  signals: { signal: string; source: string; status: string; severity: string }[];
  ablations: { id: string; riskScore: number; decision: string }[];
  privacy: 'No message text, sender, destinations, credentials or raw evidence included';
}
export interface ReceiptEnvelope { receipt: DecisionReceipt; integrity: { algorithm: 'SHA-256'; digest: string; scope: string } }
export interface LabReport { baseline: LabSummary; variants: LabVariant[]; receipt: ReceiptEnvelope; durationMs: number; limitations: string[] }
export interface LabFixture { id: string; title: string; rationale: string; expected: 'REVIEW' | 'ALLOW' | 'UNKNOWN'; input: LabInput }
export interface EvaluationReport {
  suite: string; synthetic: true; total: number; passed: number; reviewRecall: number | null; falsePositiveRate: number | null;
  rows: { id: string; title: string; expected: string; actual: string; riskScore: number; passed: boolean }[];
  limitations: string;
}
