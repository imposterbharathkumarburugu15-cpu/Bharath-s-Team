/**
 * NeuroShield Behaviour Engine Foundation
 * Evaluates linguistic psychological coercion, artificial urgency, and isolation tactics.
 */

import { UnifiedThreatInput, BehaviourAnalysis, DetectorEvidence } from '../types';

export class BehaviourDetector {
  static evaluate(input: UnifiedThreatInput): {
    analysis: BehaviourAnalysis;
    evidence: DetectorEvidence;
  } {
    const text = (input.content + ' ' + (input.metadata?.subject || '')).toLowerCase();
    const evidenceList: string[] = [];

    // 1. Artificial Urgency / Amygdala Hijack
    const urgencyKeywords = [
      'immediately', 'within 24 hours', 'within 15 minutes', 'within 1 hour',
      'action required now', 'urgent notice', 'critical alert', 'account suspended',
      'suspension pending', 'final reminder', 'expire tonight', 'terminating service',
      'time-sensitive', 'immediate attention', 'do not delay'
    ];
    const matchedUrgency = urgencyKeywords.filter((k) => text.includes(k));
    let urgencyScore = 0;
    if (matchedUrgency.length > 0) {
      urgencyScore = Math.min(100, 45 + matchedUrgency.length * 18);
      evidenceList.push(`Artificial urgency markers detected: [${matchedUrgency.slice(0, 3).join(', ')}].`);
    }

    // 2. Coercion & Intimidation
    const coercionKeywords = [
      'legal action', 'law enforcement', 'disciplinary action', 'account terminated',
      'access revoked', 'penalty fee', 'breach of contract', 'reported to authorities',
      'lawsuit', 'warrant'
    ];
    const matchedCoercion = coercionKeywords.filter((k) => text.includes(k));
    let coercionScore = 0;
    if (matchedCoercion.length > 0) {
      coercionScore = Math.min(100, 50 + matchedCoercion.length * 20);
      evidenceList.push(`Intimidation and coercive consequences asserted: [${matchedCoercion.join(', ')}].`);
    }

    // 3. Isolation & Secrecy Tactics
    const secrecyKeywords = [
      "don't tell anyone", 'do not tell anyone', 'keep this confidential', 'strictly confidential',
      "don't involve the team", 'do not involve the team', "don't tell the rest of the team",
      'do not tell the rest of the team', 'off the record', 'strictly private',
      'between you and me', 'between us', 'keep this between us', 'keep between us',
      'do not contact it', 'bypassing standard channels', 'handle this quietly', 'keep this quiet'
    ];
    const secrecyRegex = /(?:do\s*not|don'?t)\s*(?:tell|involve|contact|share\s*with)\s*(?:anyone|the\s*(?:rest\s*of\s*the\s*)?team|others|colleagues|it)|strictly\s*(?:confidential|private)|keep\s*this\s*(?:confidential|quiet|between\s*us)/i;
    
    const matchedSecrecy = secrecyKeywords.filter((k) => text.includes(k));
    if (secrecyRegex.test(text) && matchedSecrecy.length === 0) {
      const match = text.match(secrecyRegex);
      if (match) matchedSecrecy.push(match[0]);
    }
    const isolationRequested = matchedSecrecy.length > 0 || secrecyRegex.test(text);
    if (isolationRequested) {
      evidenceList.push(`Social engineering isolation tactic: requests user to conceal transaction/activity: [${matchedSecrecy.join(', ')}].`);
    }

    // 4. Sudden Financial / Credential / Sensitive Data Request Markers
    const hasFinancialDemand = /(wire transfer|ach routing|bank transfer|gift card|crypto|bitcoin|urgent payment|invoice overdue|pay now|western union)/i.test(text);
    const hasCredentialDemand = /(update your password|reset password|verify account credentials|re-authenticate|login to verify|session expired)/i.test(text);
    const hasSensitiveDataDemand = /(send client list|employee ssn|w-2|tax form|confidential report|private keys)/i.test(text);

    if (hasFinancialDemand) {
      evidenceList.push('BEHAVIOURAL DEMAND: High-risk financial remittance or payment redirection requested.');
    }
    if (hasCredentialDemand) {
      evidenceList.push('BEHAVIOURAL DEMAND: Direct solicitation of account credentials or authentication secrets.');
    }
    if (hasSensitiveDataDemand) {
      evidenceList.push('BEHAVIOURAL DEMAND: Out-of-band transmission of sensitive corporate/PII assets demanded.');
    }

    // 5. History-aware behavioral delta comparison
    if (input.history) {
      if (input.history.previousInteractionsCount > 0 && (hasFinancialDemand || hasCredentialDemand)) {
        evidenceList.push(`BEHAVIOURAL SHIFT COMPARISON: Current high-risk request deviates significantly from the sender's ${input.history.previousInteractionsCount} prior historical communications.`);
      }
    } else {
      evidenceList.push('Behavioural context note: Historical baseline is unavailable; analyzing observable current behaviour exclusively.');
    }

    // Compute compound behavioural risk
    let baselineDemandBonus = 0;
    if (hasFinancialDemand) baselineDemandBonus += 25;
    if (hasCredentialDemand) baselineDemandBonus += 25;
    if (hasSensitiveDataDemand) baselineDemandBonus += 20;

    let riskScore = Math.round(urgencyScore * 0.40 + coercionScore * 0.30 + (isolationRequested ? 20 : 0) + baselineDemandBonus * 0.50);
    riskScore = Math.min(100, Math.max(0, riskScore));

    if (evidenceList.length === 0 || (evidenceList.length === 1 && evidenceList[0].includes('Historical baseline is unavailable'))) {
      evidenceList.unshift('No anomalous behavioural coercion, urgency, or isolation tactics detected.');
      riskScore = 0;
    }

    return {
      analysis: {
        status: 'available',
        urgencyScore,
        coercionScore,
        isolationRequested,
        secrecyKeywords: matchedSecrecy,
        riskScore,
        evidence: evidenceList,
      },
      evidence: {
        detector: 'behaviour_engine',
        score: riskScore,
        status: 'available',
        evidence: evidenceList,
      },
    };
  }
}
