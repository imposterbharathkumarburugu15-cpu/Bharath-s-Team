/**
 * NeuroShield Evidence Correlator
 * Fuses disparate multi-detector signals into a coherent multi-signal threat evaluation.
 * Avoids treating security signals in isolation.
 * Formulates explicit explanations of "Why the risk increased".
 */

import {
  CorrelatedEvidenceMap,
  IdentityAnalysis,
  RelationshipAnalysis,
  BehaviourAnalysis,
  IntentAnalysis,
  ActionRiskAnalysis,
  TechnicalEvidenceAnalysis,
  PromptInjectionAnalysis,
  SensitiveDataAnalysis,
} from './types';

export interface EvidenceCorrelationResult {
  evidenceMap: CorrelatedEvidenceMap;
  correlatedThreats: string[];
  whyRiskIncreased: string[];
  compoundRiskScore: number;
  confidenceScore: number;
}

export class EvidenceCorrelator {
  static correlate(params: {
    identity: IdentityAnalysis;
    relationship: RelationshipAnalysis;
    behaviour: BehaviourAnalysis;
    intent: IntentAnalysis;
    actionRisk: ActionRiskAnalysis;
    technical: TechnicalEvidenceAnalysis;
    promptInjection: PromptInjectionAnalysis;
    sensitiveData: SensitiveDataAnalysis;
  }): EvidenceCorrelationResult {
    const {
      identity,
      relationship,
      behaviour,
      intent,
      actionRisk,
      technical,
      promptInjection,
      sensitiveData,
    } = params;

    // 1. Central Evidence Object
    const evidenceMap: CorrelatedEvidenceMap = {
      identity: [...identity.evidence],
      relationship: [...relationship.evidence],
      behaviour: [...behaviour.evidence],
      intent: [...intent.evidence],
      action: [...actionRisk.evidence],
      technical: [...technical.evidence],
      prompt_injection: [...promptInjection.evidence],
      sensitive_data: [...sensitiveData.evidence],
    };

    const whyRiskIncreased: string[] = [];
    const correlatedThreats: string[] = [];

    // Baseline individual scores
    const intentRisk = intent.primaryIntent === 'BENIGN_COMMUNICATION' ? 0 : intent.intentConfidence;
    const scores = [
      identity.riskScore,
      relationship.riskScore,
      behaviour.riskScore,
      intentRisk,
      actionRisk.actionRisk === 'CRITICAL' ? 95 : actionRisk.actionRisk === 'HIGH' ? 85 : actionRisk.actionRisk === 'MEDIUM' ? 50 : 0,
      technical.riskScore,
      promptInjection.adversarialRiskScore,
      sensitiveData.riskScore,
    ];

    let maxIndividual = Math.max(...scores);
    let compoundScore = maxIndividual;

    // COMPOUND CORRELATION RULES

    // RULE 1: BEC / CEO Wire Fraud Pattern
    // Unknown sender / first contact + Reply-To mismatch + urgent wire transfer
    const isFirstContactOrUnknown = relationship.relationshipState === 'FIRST_CONTACT' || relationship.relationshipState === 'UNKNOWN' || identity.newSender;
    const hasReplyToMismatch = Boolean(identity.fromReplyToMismatch);
    const hasUrgentPayment = actionRisk.detectedAction === 'TRANSFER_MONEY' || sensitiveData.demandsPayment;

    if (hasUrgentPayment && (hasReplyToMismatch || isFirstContactOrUnknown)) {
      correlatedThreats.push('Business Email Compromise (BEC) / Wire Redirection Fraud');
      compoundScore = Math.max(compoundScore, 96);
      whyRiskIncreased.push(
        'Compound correlation: Immediate financial disbursement demanded alongside unfamiliar origin or diverted Reply-To destination.'
      );
    } else if (hasReplyToMismatch && isFirstContactOrUnknown) {
      correlatedThreats.push('Reply-To Redirection & Sender Inconsistency');
      compoundScore = Math.max(compoundScore, 85);
      whyRiskIncreased.push(
        'Compound correlation: First-time or unfamiliar sender exhibits an unaligned Reply-To address diverting responses to external infrastructure.'
      );
    } else if (hasReplyToMismatch) {
      whyRiskIncreased.push(
        'Routing discrepancy: Reply-To address routes communications away from the originating domain.'
      );
    } else if (isFirstContactOrUnknown && behaviour.urgencyScore > 40) {
      whyRiskIncreased.push(
        'Compound correlation: First-time sender introduces artificial urgency and aggressive deadline pressure.'
      );
    }

    // RULE 2: Ephemeral Reverse Tunnel / Typosquatting + Credential Demand
    const hasCloakedInfrastructure = technical.reverseTunnelDetected || technical.typosquattingDetected || technical.suspiciousTldDetected;
    const hasCredentialHarvester =
      actionRisk.detectedAction === 'ENTER_PASSWORD' ||
      actionRisk.detectedAction === 'LOGIN' ||
      sensitiveData.demandsCredentials ||
      sensitiveData.demandsOtp;

    if (hasCloakedInfrastructure && hasCredentialHarvester) {
      correlatedThreats.push('Evasive Infrastructure Credential Harvesting Campaign');
      compoundScore = Math.max(compoundScore, 98);
      whyRiskIncreased.push(
        'Compound correlation: Authentication credentials solicited on evasive infrastructure (reverse proxy tunnel / typosquatted domain).'
      );
    }

    // RULE 3: Prompt Injection / AI Filter Subversion
    if (promptInjection.detected) {
      correlatedThreats.push('Adversarial Prompt Injection & Policy Subversion');
      compoundScore = 98;
      whyRiskIncreased.push(
        'Compound correlation: Input embeds explicit instruction-override tokens designed to compromise downstream AI agents and bypass detection guardrails.'
      );
    }

    // RULE 4: Account Compromise of Known Contact (Behavioural Shift)
    if (relationship.relationshipState === 'KNOWN_TRUSTED' && relationship.behaviourShiftDetected) {
      correlatedThreats.push('Compromised Trusted Partner Account (Account Takeover)');
      compoundScore = Math.max(compoundScore, 88);
      whyRiskIncreased.push(
        'Compound correlation: Known trusted correspondent exhibits sudden anomalous high-risk financial/credential demands inconsistent with baseline history.'
      );
    }

    // RULE 5: Display Spoofing + Brand Lookalike URL
    if (identity.isSpoofed && (technical.typosquattingDetected || technical.bareIpUrlDetected)) {
      correlatedThreats.push('Weaponized Brand Impersonation Phishing');
      compoundScore = Math.max(compoundScore, 94);
      whyRiskIncreased.push(
        'Compound correlation: Display name asserts trusted brand authority while routing links to unauthorized lookalike or IP infrastructure.'
      );
    }

    // RULE 6: Multi-Signal Synergy (3 or more high signals)
    const highSignals = [
      identity.riskScore > 60,
      behaviour.riskScore > 50,
      technical.riskScore > 60,
      actionRisk.actionRisk === 'CRITICAL' || actionRisk.actionRisk === 'HIGH',
      sensitiveData.riskScore > 60,
    ].filter(Boolean).length;

    if (highSignals >= 3) {
      compoundScore = Math.min(100, compoundScore + 10);
      whyRiskIncreased.push(
        `Compound correlation: Multiple independent telemetry vectors (${highSignals} elevated signals across identity, behaviour, technical, and action) mutually corroborate threat veracity.`
      );
    }

    // RULE 7: CORE HYPOTHESIS: SENSITIVE-DATA + ACTION + CONTEXT CORRELATION
    // An unknown or anomalous sender soliciting sensitive data (OTP, credentials, API key, employee files) coupled with action
    const hasSensitiveDataDemand = sensitiveData.demandsOtp || sensitiveData.demandsCredentials || sensitiveData.demandsApiKeys || sensitiveData.demandsPayment || sensitiveData.demandsConfidentialOrgData;
    const hasCriticalAction = actionRisk.actionRisk === 'CRITICAL' || actionRisk.actionRisk === 'HIGH';

    if (hasSensitiveDataDemand && isFirstContactOrUnknown) {
      correlatedThreats.push('Contextual Sensitive-Data Exfiltration / Credential Solicitation');
      compoundScore = Math.max(compoundScore, 95);
      whyRiskIncreased.push(
        'Core research correlation: Unfamiliar origin or first-contact entity solicits high-value sensitive data (passwords, OTPs, or confidential assets) without established trust baseline.'
      );
    }

    if (hasSensitiveDataDemand && hasCriticalAction) {
      correlatedThreats.push('Dangerous Action Coupled with Sensitive-Data Exploitation');
      compoundScore = Math.max(compoundScore, 96);
      whyRiskIncreased.push(
        'Action-sensitive fusion: Target communication couples sensitive data extraction directly to an irreversible user action (' + actionRisk.detectedAction + ').'
      );
    }

    // RULE 8: AUTHENTICATED SENDER BUT HOSTILE ACTION (Technical PASS != SAFE)
    const hasAuthPass = technical.evidence.some(e => e.includes('SPF: PASS') || e.includes('DKIM: PASS'));
    if (hasAuthPass && (hasCriticalAction || hasSensitiveDataDemand)) {
      correlatedThreats.push('Compromised Authenticated Channel / Weaponized Infrastructure');
      compoundScore = Math.max(compoundScore, 88);
      whyRiskIncreased.push(
        'Zero-trust validation: Technical authentication (SPF/DKIM) passes, but requested user action or sensitive data solicitation is hostile.'
      );
    }

    // RULE 9: BENIGN URGENT BUSINESS EMAIL GUARANTEE
    // Urgency alone without sensitive data, without credentials, and without payment action MUST NOT become malicious
    const isBenignContext = !hasSensitiveDataDemand && actionRisk.detectedAction === 'UNKNOWN' && !hasCloakedInfrastructure && !identity.isSpoofed;
    if (behaviour.urgencyScore > 40 && isBenignContext) {
      compoundScore = Math.min(compoundScore, 35);
      whyRiskIncreased.push(
        'Benign urgency calibration: High urgency detected in business context, but zero credential, financial, or exfiltration indicators observed. Maintained as LOW/SAFE.'
      );
    }

    // Default explanation when risk is low / benign
    if (whyRiskIncreased.length === 0 && compoundScore <= 30) {
      whyRiskIncreased.push('Signals aligned: Sender identity, communication behaviour, and requested actions reflect benign, non-hostile interactions.');
    }

    // Calculate confidence based on evidence richness (RISK vs CONFIDENCE separation)
    let availableEvidenceCount = 0;
    Object.values(evidenceMap).forEach((evList) => {
      availableEvidenceCount += evList.length;
    });

    // Baseline confidence calculation:
    // If telemetry is rich, confidence is 80-95. If history or technical metadata is missing, confidence adjusts accordingly.
    let confidence = 70;
    if (technical.urlsEvaluated > 0) confidence += 10;
    if (relationship.status === 'available') confidence += 10;
    if (identity.status === 'available') confidence += 5;
    if (technical.spfStatus && technical.spfStatus !== 'UNAVAILABLE') confidence += 5;
    confidence = Math.min(95, Math.max(40, confidence));

    return {
      evidenceMap,
      correlatedThreats,
      whyRiskIncreased,
      compoundRiskScore: Math.min(100, Math.max(0, compoundScore)),
      confidenceScore: confidence,
    };
  }
}
