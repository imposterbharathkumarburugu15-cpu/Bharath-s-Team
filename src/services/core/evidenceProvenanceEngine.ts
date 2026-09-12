/**
 * NeuroShield Evidence Provenance & Conflict Engine
 * Phase 7.5 — Advanced Security Intelligence
 *
 * Requirements 11 & 12:
 * 1. Provenance Tracking: Every evidence item records:
 *    - detector
 *    - signal
 *    - value
 *    - confidence
 *    - source of observation
 *    - status: OBSERVED | INFERRED | UNAVAILABLE
 *
 * 2. Explicit Conflict Handling:
 *    - Detects contradictory signals (e.g. DKIM=PASS vs Brand Spoof / OTP demand)
 *    - Produces structured conflict resolution:
 *      { conflict: true, contradictory_signals: [...], resolution: '...', final_weight: ... }
 *    - Never silently overwrites or discards contradictory evidence.
 */

import {
  UnifiedThreatInput,
  IdentityAnalysis,
  RelationshipAnalysis,
  BehaviourAnalysis,
  IntentAnalysis,
  TechnicalEvidenceAnalysis,
  ActionRiskAnalysis,
  PromptInjectionAnalysis,
  SensitiveDataAnalysis,
  EvasionAnalysis,
  EvidenceItemWithProvenance,
  ConflictResolution,
} from './types';

export class EvidenceProvenanceEngine {
  /**
   * Builds exhaustive evidence items with strict provenance metadata
   */
  static buildProvenance(params: {
    input: UnifiedThreatInput;
    identity: IdentityAnalysis;
    relationship: RelationshipAnalysis;
    behaviour: BehaviourAnalysis;
    intent: IntentAnalysis;
    technical: TechnicalEvidenceAnalysis;
    actionRisk: ActionRiskAnalysis;
    promptInjection: PromptInjectionAnalysis;
    sensitiveData: SensitiveDataAnalysis;
    evasion?: EvasionAnalysis;
  }): EvidenceItemWithProvenance[] {
    const {
      identity,
      behaviour,
      technical,
      actionRisk,
      promptInjection,
      sensitiveData,
      evasion,
    } = params;

    const items: EvidenceItemWithProvenance[] = [];

    // 1. Identity Provenance
    if (identity.claimedIdentity) {
      items.push({
        detector: 'identity_engine',
        source: 'Identity Engine',
        signal: 'CLAIMED_IDENTITY',
        value: identity.claimedIdentity,
        confidence: 95,
        severity: 'info',
        observed: true,
        status: 'OBSERVED',
        evidence: `Claimed sender display name: '${identity.claimedIdentity}'.`,
      });
    }

    if (identity.actualIdentity) {
      items.push({
        detector: 'identity_engine',
        source: 'Identity Engine',
        signal: 'ACTUAL_IDENTITY',
        value: identity.actualIdentity,
        confidence: 99,
        severity: 'info',
        observed: true,
        status: 'OBSERVED',
        evidence: `Actual routing identifier: '${identity.actualIdentity}'.`,
      });
    }

    if (identity.isSpoofed) {
      items.push({
        detector: 'identity_engine',
        source: 'Identity Engine',
        signal: 'IDENTITY_SPOOFED',
        value: 'true',
        confidence: 92,
        severity: 'critical',
        observed: true,
        status: 'OBSERVED',
        evidence: identity.evidence[0] || 'Sender display name contradicts routing domain.',
      });
    }

    if (identity.fromReplyToMismatch) {
      items.push({
        detector: 'identity_engine',
        source: 'Identity Engine',
        signal: 'FROM_REPLY_TO_MISMATCH',
        value: 'true',
        confidence: 95,
        severity: 'high',
        observed: true,
        status: 'OBSERVED',
        evidence: 'Reply-To header diverts replies away from From domain.',
      });
    }

    if (identity.continuity?.historical_identity_analysis === 'AVAILABLE') {
      items.push({
        detector: 'identity_continuity_engine',
        source: 'Identity Engine',
        signal: 'HISTORICAL_CONTINUITY_ANALYSIS',
        value: String(identity.continuity.identity_match ?? false),
        confidence: identity.continuity.identity_confidence,
        severity: identity.continuity.identity_mismatch ? 'high' : 'info',
        observed: true,
        status: 'OBSERVED',
        evidence: identity.continuity.evidence[0] || 'Historical interaction baseline evaluated.',
      });
    }

    // 2. Technical Provenance
    if (technical.reverseTunnelDetected) {
      items.push({
        detector: 'technical_detector',
        source: 'URL analysis',
        signal: 'REVERSE_TUNNEL_DETECTED',
        value: 'true',
        confidence: 99,
        severity: 'critical',
        observed: true,
        status: 'OBSERVED',
        evidence: 'Destination URL routes through ephemeral reverse proxy tunnel (ngrok, trycloudflare, etc.).',
      });
    }

    if (technical.spfStatus || technical.dkimStatus || technical.dmarcStatus) {
      items.push({
        detector: 'technical_detector',
        source: 'Email Forensics',
        signal: 'CRYPTO_AUTH_HEADERS',
        value: `SPF:${technical.spfStatus || 'NONE'}|DKIM:${technical.dkimStatus || 'NONE'}|DMARC:${technical.dmarcStatus || 'NONE'}`,
        confidence: 98,
        severity: technical.spfStatus === 'FAIL' || technical.dkimStatus === 'FAIL' ? 'high' : 'info',
        observed: true,
        status: 'OBSERVED',
        evidence: 'RFC email cryptographic authentication headers extracted directly from message.',
      });
    }

    // 3. Evasion Provenance
    if (evasion?.detected) {
      items.push({
        detector: 'evasion_detection',
        source: 'Threat Intelligence',
        signal: 'EVASION_TECHNIQUES_OBSERVED',
        value: evasion.techniques.join(','),
        confidence: 94,
        severity: 'critical',
        observed: true,
        status: 'OBSERVED',
        evidence: evasion.evidence[0] || 'Adversarial evasion technique detected.',
      });
    }

    // 4. Action Risk Provenance
    if (actionRisk.detectedAction && actionRisk.detectedAction !== 'UNKNOWN') {
      items.push({
        detector: 'action_risk_engine',
        source: 'Action Engine',
        signal: 'ACTION_REQUESTED',
        value: actionRisk.detectedAction,
        confidence: 90,
        severity: actionRisk.actionRisk === 'CRITICAL' ? 'critical' : actionRisk.actionRisk === 'HIGH' ? 'high' : 'medium',
        observed: true,
        status: 'OBSERVED',
        evidence: `User action requested by message: ${actionRisk.detectedAction} (${actionRisk.actionRisk} hazard).`,
      });
    }

    // 5. Prompt Injection Provenance
    if (promptInjection.detected) {
      items.push({
        detector: 'prompt_injection_detector',
        source: 'Prompt Injection',
        signal: 'PROMPT_INJECTION_TOKENS',
        value: promptInjection.overrideTokens.slice(0, 3).join(', '),
        confidence: 98,
        severity: 'critical',
        observed: true,
        status: 'OBSERVED',
        evidence: 'Payload contains explicit system instruction overrides or jailbreak directives.',
      });
    }

    // 6. Sensitive Data Exfiltration Provenance
    if (sensitiveData.detected) {
      items.push({
        detector: 'sensitive_data_detector',
        source: 'Sensitive Data',
        signal: 'SENSITIVE_DATA_SOLICITATION',
        value: sensitiveData.categories.join(','),
        confidence: 92,
        severity: 'high',
        observed: true,
        status: 'OBSERVED',
        evidence: sensitiveData.evidence[0] || 'Message solicits credentials, OTPs, or PII.',
      });
    }

    // 7. Behavioural Provenance
    if (behaviour.urgencyScore > 0) {
      items.push({
        detector: 'behaviour_engine',
        source: 'Behaviour Engine',
        signal: 'URGENCY_SCORE',
        value: String(behaviour.urgencyScore),
        confidence: 85,
        severity: behaviour.urgencyScore > 50 ? 'high' : 'medium',
        observed: true,
        status: 'INFERRED',
        evidence: `Manufactured urgency score: ${behaviour.urgencyScore}/100.`,
      });
    }

    return items;
  }

  /**
   * Identifies contradictions and produces principled resolutions
   */
  static evaluateConflicts(params: {
    input: UnifiedThreatInput;
    identity: IdentityAnalysis;
    relationship: RelationshipAnalysis;
    behaviour: BehaviourAnalysis;
    intent: IntentAnalysis;
    technical: TechnicalEvidenceAnalysis;
    actionRisk: ActionRiskAnalysis;
    promptInjection: PromptInjectionAnalysis;
    sensitiveData: SensitiveDataAnalysis;
    evasion?: EvasionAnalysis;
  }): {
    conflicts: ConflictResolution[];
    scoreAdjustment: number;
  } {
    const {
      identity,
      relationship,
      behaviour,
      intent,
      technical,
      actionRisk,
      promptInjection,
      sensitiveData,
      evasion,
    } = params;

    const conflicts: ConflictResolution[] = [];
    let scoreAdjustment = 0;

    // CONFLICT 1: Technical Authentication Passes (SPF/DKIM/DMARC = PASS) vs Display Name Spoofing or OTP / Financial Demand
    const isCryptoPassing = technical.spfStatus === 'PASS' || technical.dkimStatus === 'PASS';
    const isSocialEngineeringOrSpoof =
      identity.isSpoofed ||
      identity.fromReplyToMismatch ||
      actionRisk.detectedAction === 'SHARE_OTP' ||
      actionRisk.detectedAction === 'TRANSFER_MONEY' ||
      (evasion?.homoglyphsDetected ?? false);

    if (isCryptoPassing && isSocialEngineeringOrSpoof) {
      conflicts.push({
        conflictType: 'AUTH_PASS_VS_SOCIAL_ENGINEERING',
        detectorA: {
          name: 'TechnicalDetector',
          finding: 'Email passed cryptographic domain authentication (SPF/DKIM = PASS).',
          signal: 'CRYPTO_AUTH_PASS',
        },
        detectorB: {
          name: 'Identity / ActionRisk Detector',
          finding: identity.isSpoofed
            ? `Display name '${identity.claimedIdentity}' impersonates brand while asking for ${actionRisk.detectedAction}.`
            : `Requests critical action [${actionRisk.detectedAction}] despite technical pass.`,
          signal: 'HOSTILE_ACTION_OR_SPOOF',
        },
        resolution:
          'DKIM/SPF proves sending domain authorization, NOT absence of social engineering, brand impersonation, or compromised sender accounts. Action risk and identity spoofing supersede technical domain passes.',
        reconciledScoreAdjustment: 25,
        explanation: 'Authentication success does not override high-risk financial demand, OTP solicitation, or brand mimicry.',
      });
      scoreAdjustment += 25;
    }

    // CONFLICT 2: Known Trusted Contact with sudden uncharacteristic urgent demand (Account Takeover / BEC hypothesis)
    if (relationship.relationshipState === 'KNOWN_TRUSTED') {
      const hasSevereDemand =
        (actionRisk.detectedAction === 'TRANSFER_MONEY' ||
          actionRisk.detectedAction === 'SHARE_OTP' ||
          sensitiveData.demandsCredentials) &&
        (behaviour.urgencyScore > 40 || identity.fromReplyToMismatch);

      if (hasSevereDemand) {
        conflicts.push({
          conflictType: 'KNOWN_TRUSTED_CONTACT_BEHAVIOURAL_ANOMALY',
          detectorA: {
            name: 'RelationshipDetector',
            finding: 'Sender matches established historical trusted communication partner.',
            signal: 'KNOWN_TRUSTED_CONTACT',
          },
          detectorB: {
            name: 'Behaviour / ActionRisk Detector',
            finding: `Unprecedented request to execute [${actionRisk.detectedAction}] under manufactured urgency.`,
            signal: 'ATO_SUSPICION',
          },
          resolution:
            'Flagged as potential Account Takeover (ATO). Historical trust is suspended when an established mailbox suddenly issues anomalous high-risk payment or credential demands.',
          reconciledScoreAdjustment: 30,
          explanation: 'Historical trust does not permit out-of-band high-risk transactions without independent multi-channel verification.',
        });
        scoreAdjustment += 30;
      }
    }

    // CONFLICT 3: New Sender / First Contact with completely benign message
    if (
      (relationship.firstContact || identity.newSender || identity.continuity?.identity_novelty) &&
      actionRisk.actionRisk === 'NONE' &&
      intent.primaryIntent === 'BENIGN_COMMUNICATION' &&
      technical.riskScore === 0 &&
      !promptInjection.detected &&
      !(evasion?.detected ?? false)
    ) {
      conflicts.push({
        conflictType: 'NEW_SENDER_BENIGN_CONTENT',
        detectorA: {
          name: 'Identity / Relationship Detector',
          finding: 'Novelty sender: initial contact without prior history.',
          signal: 'UNVERIFIED_NEW_ORIGIN',
        },
        detectorB: {
          name: 'Intent / ActionRisk Detector',
          finding: 'Operational benign content: zero links, zero coercive demands, zero urgency.',
          signal: 'BENIGN_CONTENT',
        },
        resolution:
          'Novelty origin does NOT constitute an attack without corroborating deceptive lures or hostile actions. Evaluated as SAFE with standard sender verification posture.',
        reconciledScoreAdjustment: -10,
        explanation: 'Novelty alone without deceptive indicators remains SAFE.',
      });
      scoreAdjustment -= 10;
    }

    // CONFLICT 4: Suspicious URL Structure without Malicious Intent or Credential Demand
    if (technical.urlsEvaluated > 0 && technical.riskScore > 40) {
      const isBenignCommunication = intent.primaryIntent === 'BENIGN_COMMUNICATION';
      const noHarmfulAction = actionRisk.actionRisk === 'NONE' || actionRisk.actionRisk === 'LOW';
      const noSensitiveSolicitation =
        !sensitiveData.demandsCredentials && !sensitiveData.demandsPayment && !sensitiveData.demandsOtp;

      if (isBenignCommunication && noHarmfulAction && noSensitiveSolicitation && !technical.reverseTunnelDetected) {
        conflicts.push({
          conflictType: 'SUSPICIOUS_URL_WITHOUT_MALICIOUS_INTENT',
          detectorA: {
            name: 'TechnicalDetector',
            finding: 'URL infrastructure flagged on structural anomaly (TLD or subdomain).',
            signal: 'URL_ANOMALY',
          },
          detectorB: {
            name: 'Intent / ActionRisk Detector',
            finding: 'Content lacks credential forms, coercive threats, or financial demands.',
            signal: 'BENIGN_CONTEXT',
          },
          resolution:
            'Unfamiliar URL infrastructure alone without coercive deception warrants inspection, but does not justify an outright MALICIOUS classification.',
          reconciledScoreAdjustment: -15,
          explanation: 'Down-weighted standalone URL score due to absence of corroborating phishing indicators.',
        });
        scoreAdjustment -= 15;
      }
    }

    // CONFLICT 5: Surface Conversational Tone vs Prompt Injection Directives
    if (promptInjection.detected && intent.primaryIntent === 'BENIGN_COMMUNICATION') {
      conflicts.push({
        conflictType: 'PROMPT_INJECTION_VS_BENIGN_NLP',
        detectorA: {
          name: 'IntentDetector (NLP)',
          finding: 'Text conversational tone appears polite or benign on the surface.',
          signal: 'BENIGN_SURFACE_TONE',
        },
        detectorB: {
          name: 'PromptInjectionDetector',
          finding: 'Adversarial system instruction override or jailbreak markers detected in payload.',
          signal: 'ADVERSARIAL_INJECTION',
        },
        resolution:
          'Adversarial prompt injection tokens take absolute precedence over surface linguistic tone.',
        reconciledScoreAdjustment: 50,
        explanation: 'Surface tone discarded in favor of critical AI injection override directives.',
      });
      scoreAdjustment += 50;
    }

    return { conflicts, scoreAdjustment };
  }
}
