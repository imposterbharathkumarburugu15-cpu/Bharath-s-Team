import { NeuroShieldCore } from '../core/neuroshieldCore';
import { EnforcementEngine } from '../core/enforcementEngine';
import { IntelligenceStore } from './store';
import { CampaignService } from './campaigns';
import { extractDNA } from './features';
import { EmailAdapter } from '../core/adapters/EmailAdapter';
import type { OSINTReport } from './osint';
import type { IntelligenceIncident } from './types';

export const intelligenceStore = new IntelligenceStore();
export const campaigns = new CampaignService(intelligenceStore);

export async function analyzeWithIntelligence(input: any, source?: any) {
  // Browser capability claims do not establish that an action was actually blocked.
  if (input && typeof input === 'object') {
    input = { ...input, metadata: { ...input.metadata, actualEnforcementApplied: false, knownCampaignClusters: [] } };
  }
  const analysis = await NeuroShieldCore.analyze(input, source);
  let featureInput = input;
  if (input.source === 'email') {
    try { featureInput = { ...input, ...EmailAdapter.toUnifiedInput(EmailAdapter.toNormalizedEmail(input)), ...input }; } catch { /* Core reports missing coverage. */ }
  }
  let dna = extractDNA(featureInput, analysis);
  for (const indicator of dna.indicators.filter(i => i.type === 'domain')) {
    const report = intelligenceStore.get<OSINTReport & { id: string }>('osint', indicator.value);
    if (report && Date.now() - Date.parse(report.observedAt) < 86400000) appendInfrastructure(dna, report);
  }
  const matches = campaigns.match(dna.indicators);
  if (matches.length) {
    analysis.risk_score = Math.max(analysis.risk_score, 85);
    analysis.risk_level = 'CRITICAL';
    analysis.verdict = 'MALICIOUS';
    analysis.confidence = Math.max(analysis.confidence, 95);
    analysis.evidence_provenance = [...(analysis.evidence_provenance || []), ...matches.map(i => ({ signal: 'CONFIRMED_IOC_MATCH', source: 'Threat Intelligence' as const, severity: 'critical' as const, evidence: `Exact ${i.type} match: ${i.value}; reviewed source ${i.sourceId}`, confidence: 95, status: 'OBSERVED' as const }))];
    const decision = EnforcementEngine.evaluatePolicy({ verdict: 'MALICIOUS', riskScore: analysis.risk_score, confidence: analysis.confidence, requestedAction: analysis.action_risk.detectedAction, threatTypes: [...analysis.attack_types, 'CONFIRMED_IOC_MATCH'], evidence: analysis.evidence_provenance, client: input.metadata?.client || 'web_app', clientCapabilities: input.metadata?.clientCapabilities || {} });
    Object.assign(analysis, { protectionDecision: decision.protectionDecision, enforcementStatus: decision.enforcementStatus, enforcementLevel: decision.enforcementLevel, authoritativeProtectionDecision: decision });
    Object.assign(analysis.protection, { decision: 'BLOCK', protectionDecision: decision.protectionDecision, authoritativeDecision: decision, enforcementStatus: decision.enforcementStatus, recommended_action: 'Do not interact with this confirmed indicator. Review the linked SOC evidence.' });
    dna.features.push({ family: 'infrastructure', key: 'confirmed_ioc', value: matches[0].value, weight: 6, provenance: 'externally_reported', source: 'SOC-reviewed IOC database' });
    dna.riskScore = analysis.risk_score; dna.confidence = analysis.confidence; dna.verdict = analysis.verdict;
  }
  dna = campaigns.ingest(dna);
  analysis.intelligence = { incidentId: dna.id, fingerprint: dna.fingerprint, campaignId: dna.campaignId || null, matches: matches.map(m => ({ type: m.type, value: m.value, sourceId: m.sourceId })), label: 'Observed evidence and inferred correlations; no actor attribution' };
  return analysis;
}

export function appendInfrastructure(incident: IntelligenceIncident, report: OSINTReport) {
  for (const e of report.evidence.filter(e => ['A', 'AAAA', 'ASN'].includes(e.kind))) {
    const key = e.kind === 'ASN' ? 'asn' : 'dns_ip';
    if (!incident.features.some(f => f.key === key && f.value === e.value && f.source === report.domain)) incident.features.push({ family: 'infrastructure', key, value: e.value, weight: 1, provenance: e.provenance, source: report.domain });
    if (key === 'dns_ip' && !incident.indicators.some(i => i.type === 'ip' && i.value === e.value)) incident.indicators.push({ type: 'ip', value: e.value, eligibleForBlocking: false, provenance: 'observed', source: `DNS ${report.domain}` });
  }
}
