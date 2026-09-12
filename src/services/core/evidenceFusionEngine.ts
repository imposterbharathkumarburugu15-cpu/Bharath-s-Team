/**
 * NeuroShield Central Evidence Fusion Engine
 * Phase 4 — Unified Intelligence Fusion & Multi-Signal Protection Decision Layer
 *
 * Concepts:
 * - Collects available signals across all detectors
 * - Attaches explicit evidence provenance (Source, Signal, Severity, Evidence)
 * - Identifies conflicting detector signals and applies calibrated resolutions
 * - Classifies attacks into structured taxonomy (multi-category representation)
 * - Computes triad risk: content_risk, action_risk, combined_risk
 * - Performs general Identity + Action and Relationship + Behaviour correlations
 * - Establishes Cross-Channel correlation foundation
 * - Separates Risk (severity) from Confidence (evidence completeness)
 * - Compiles full analysis coverage tracking
 */

import {
  UnifiedThreatInput,
  IdentityAnalysis,
  RelationshipAnalysis,
  BehaviourAnalysis,
  IntentAnalysis,
  ActionRiskAnalysis,
  TechnicalEvidenceAnalysis,
  PromptInjectionAnalysis,
  SensitiveDataAnalysis,
  EvidenceItemWithProvenance,
  EvidenceSource,
  ConflictResolution,
  AttackCategory,
  ContentRiskAssessment,
  ActionRiskAssessment,
  CombinedRiskAssessment,
  CrossChannelAnalysis,
  CrossChannelEvent,
  AnalysisCoverage,
  ActionRiskLevel,
  ThreatSource,
  EvasionAnalysis,
} from './types';

export interface FusionResult {
  evidenceWithProvenance: EvidenceItemWithProvenance[];
  conflicts: ConflictResolution[];
  attackTypes: AttackCategory[];
  contentRisk: ContentRiskAssessment;
  actionRiskAssessment: ActionRiskAssessment;
  combinedRisk: CombinedRiskAssessment;
  crossChannel: CrossChannelAnalysis;
  coverage: AnalysisCoverage;
  fusedRiskScore: number;
  confidenceScore: number;
  correlatedThreats: string[];
  whyRiskIncreased: string[];
}

export class EvidenceFusionEngine {
  /**
   * Main fusion entrypoint: fuses all detector outputs into one correlated threat assessment.
   */
  static fuse(params: {
    input: UnifiedThreatInput;
    identity: IdentityAnalysis;
    relationship: RelationshipAnalysis;
    behaviour: BehaviourAnalysis;
    intent: IntentAnalysis;
    actionRisk: ActionRiskAnalysis;
    technical: TechnicalEvidenceAnalysis;
    promptInjection: PromptInjectionAnalysis;
    sensitiveData: SensitiveDataAnalysis;
    emailDossier?: any;
    evasion?: EvasionAnalysis;
  }): FusionResult {
    const {
      input,
      identity,
      relationship,
      behaviour,
      intent,
      actionRisk,
      technical,
      promptInjection,
      sensitiveData,
      emailDossier,
      evasion,
    } = params;

    // 1. COLLECT EVIDENCE WITH PROVENANCE
    const evidenceWithProvenance: EvidenceItemWithProvenance[] = [];
    const timestamp = input.metadata?.timestamp || new Date().toISOString();

    // Identity Engine Provenance
    if (identity.status === 'available') {
      identity.evidence.forEach((ev) => {
        evidenceWithProvenance.push({
          signal: identity.isSpoofed ? 'identity_spoofed' : identity.fromReplyToMismatch ? 'reply_to_mismatch' : 'identity_evaluated',
          source: 'Identity Engine',
          severity: identity.riskScore >= 70 ? 'high' : identity.riskScore >= 40 ? 'medium' : 'low',
          evidence: ev,
          confidence: 85,
          timestamp,
        });
      });
    }

    // Relationship Engine Provenance
    if (relationship.status === 'available') {
      relationship.evidence.forEach((ev) => {
        evidenceWithProvenance.push({
          signal: relationship.behaviourShiftDetected ? 'behaviour_shift' : relationship.firstContact ? 'first_contact' : 'relationship_context',
          source: 'Relationship Engine',
          severity: relationship.riskScore >= 70 ? 'high' : relationship.riskScore >= 40 ? 'medium' : 'low',
          evidence: ev,
          confidence: 80,
          timestamp,
        });
      });
    }

    // Behaviour Engine Provenance
    behaviour.evidence.forEach((ev) => {
      evidenceWithProvenance.push({
        signal: behaviour.isolationRequested ? 'isolation_requested' : behaviour.urgencyScore > 50 ? 'coercive_urgency' : 'behaviour_profile',
        source: 'Behaviour Engine',
        severity: behaviour.riskScore >= 70 ? 'high' : behaviour.riskScore >= 40 ? 'medium' : 'low',
        evidence: ev,
        confidence: 85,
        timestamp,
      });
    });

    // Intent Engine Provenance (NLP / Intent Model)
    intent.evidence.forEach((ev) => {
      evidenceWithProvenance.push({
        signal: `intent_${intent.primaryIntent.toLowerCase()}`,
        source: 'NLP',
        severity: intent.primaryIntent === 'BENIGN_COMMUNICATION' ? 'info' : intent.intentConfidence >= 70 ? 'high' : 'medium',
        evidence: ev,
        confidence: intent.intentConfidence,
        timestamp,
      });
    });

    // Action Engine Provenance
    actionRisk.evidence.forEach((ev) => {
      evidenceWithProvenance.push({
        signal: `action_${actionRisk.detectedAction.toLowerCase()}`,
        source: 'Action Engine',
        severity: actionRisk.actionRisk === 'CRITICAL' ? 'critical' : actionRisk.actionRisk === 'HIGH' ? 'high' : actionRisk.actionRisk === 'MEDIUM' ? 'medium' : 'low',
        evidence: ev,
        confidence: 90,
        timestamp,
      });
    });

    // Technical Evidence & URL Analysis Provenance
    technical.evidence.forEach((ev) => {
      const isUrl = technical.urlsEvaluated > 0;
      evidenceWithProvenance.push({
        signal: technical.reverseTunnelDetected ? 'reverse_tunnel' : technical.typosquattingDetected ? 'typosquatting' : 'technical_infrastructure',
        source: isUrl ? 'URL analysis' : 'Email Forensics',
        severity: technical.riskScore >= 70 ? 'high' : technical.riskScore >= 40 ? 'medium' : 'low',
        evidence: ev,
        confidence: 90,
        timestamp,
      });
    });

    // Email Forensics Dossier Provenance (if available)
    if (emailDossier) {
      if (emailDossier.headers?.spf) {
        evidenceWithProvenance.push({
          signal: `spf_${String(emailDossier.headers.spf).toLowerCase()}`,
          source: 'Email Forensics',
          severity: emailDossier.headers.spf === 'FAIL' ? 'high' : 'info',
          evidence: `RFC 5322 Email Forensic SPF Header verification: ${emailDossier.headers.spf}`,
          confidence: 95,
          timestamp,
        });
      }
      if (emailDossier.threatIntel?.matchFound) {
        evidenceWithProvenance.push({
          signal: 'threat_intel_match',
          source: 'Threat Intelligence',
          severity: 'critical',
          evidence: `Threat Intelligence match: ${emailDossier.threatIntel.details || 'Known hostile threat actor indicator'}`,
          confidence: 95,
          timestamp,
        });
      }
    }

    // Prompt Injection Provenance
    promptInjection.evidence.forEach((ev) => {
      evidenceWithProvenance.push({
        signal: promptInjection.detected ? 'prompt_injection_detected' : 'prompt_injection_scanned',
        source: 'Prompt Injection',
        severity: promptInjection.detected ? 'critical' : 'low',
        evidence: ev,
        confidence: 95,
        timestamp,
      });
    });

    // Sensitive Data Provenance
    sensitiveData.evidence.forEach((ev) => {
      evidenceWithProvenance.push({
        signal: sensitiveData.demandsCredentials ? 'credential_harvesting' : sensitiveData.demandsPayment ? 'payment_solicitation' : 'sensitive_data_monitored',
        source: 'Sensitive Data',
        severity: sensitiveData.riskScore >= 70 ? 'critical' : sensitiveData.riskScore >= 40 ? 'medium' : 'low',
        evidence: ev,
        confidence: 90,
        timestamp,
      });
    });

    // Evasion Analysis Provenance (Phase 7.5)
    if (evasion?.detected) {
      evasion.evidence.forEach((ev) => {
        evidenceWithProvenance.push({
          signal: 'adversarial_evasion_detected',
          source: 'Threat Intelligence',
          severity: 'critical',
          evidence: ev,
          confidence: 95,
          timestamp,
        });
      });
    }

    // De-duplicate provenance entries with identical signal and source
    const seenSignals = new Set<string>();
    const deduplicatedEvidence = evidenceWithProvenance.filter((item) => {
      const key = `${item.source}:${item.signal}:${item.evidence}`;
      if (seenSignals.has(key)) return false;
      seenSignals.add(key);
      return true;
    });

    // 2. CONFLICT HANDLING
    const conflicts: ConflictResolution[] = [];
    let conflictScoreAdjustment = 0;

    // Conflict Scenario 1: SPF/DKIM = PASS but Identity Anomaly or Financial Demand = HIGH
    if (technical.spfStatus === 'PASS' || technical.dkimStatus === 'PASS') {
      const hasIdentityOrWireRisk =
        identity.isSpoofed ||
        Boolean(identity.fromReplyToMismatch) ||
        actionRisk.detectedAction === 'TRANSFER_MONEY' ||
        sensitiveData.demandsPayment;

      if (hasIdentityOrWireRisk) {
        conflicts.push({
          conflictType: 'AUTH_PASS_VS_HOSTILE_INTENT',
          detectorA: {
            name: 'TechnicalDetector (SPF/DKIM)',
            finding: `Authentication passed: SPF=${technical.spfStatus}, DKIM=${technical.dkimStatus}`,
            signal: 'AUTHENTICATION_PASS',
          },
          detectorB: {
            name: 'Identity / ActionRisk Detector',
            finding: 'Anomalous display name, diverted reply-to, or urgent financial disbursement demand present.',
            signal: 'SPOOFING_OR_WIRE_DEMAND',
          },
          resolution: 'SPF/DKIM pass verifies originating mailserver authorization only; it does NOT authenticate message body intent, display name alignment, or prevent compromised sender accounts. High-risk behavioral and action signals prevail.',
          reconciledScoreAdjustment: 0, // Do NOT lower the risk
          explanation: 'Authentication success does not override high-risk financial demand or identity anomaly.',
        });
      }
    }

    // Conflict Scenario 2: Suspicious URL structure without malicious intent or credential demand
    if (technical.urlsEvaluated > 0 && technical.riskScore > 40) {
      const isBenignCommunication = intent.primaryIntent === 'BENIGN_COMMUNICATION';
      const noHarmfulAction =
        actionRisk.actionRisk === 'NONE' || actionRisk.actionRisk === 'LOW';
      const noSensitiveSolicitation =
        !sensitiveData.demandsCredentials && !sensitiveData.demandsPayment && !sensitiveData.demandsOtp;

      if (isBenignCommunication && noHarmfulAction && noSensitiveSolicitation && !technical.reverseTunnelDetected) {
        conflicts.push({
          conflictType: 'SUSPICIOUS_URL_WITHOUT_MALICIOUS_INTENT',
          detectorA: {
            name: 'TechnicalDetector',
            finding: 'URL infrastructure flagged on heuristic pattern (e.g. unfamiliar TLD or subdomain count).',
            signal: 'URL_ANOMALY',
          },
          detectorB: {
            name: 'Intent / ActionRisk Detector',
            finding: 'Content lacks credential forms, coercive threats, or financial demands.',
            signal: 'BENIGN_CONTEXT',
          },
          resolution: 'Unfamiliar URL infrastructure alone in standard operational discourse without coercive deception warrants warning/inspection, but does not justify outright malicious classification.',
          reconciledScoreAdjustment: -15,
          explanation: 'Down-weighted standalone URL score due to absence of corroborating phishing indicators.',
        });
        conflictScoreAdjustment -= 15;
      }
    }

    // Conflict Scenario 3: Known Trusted Contact with sudden anomalous urgent financial/credential demand (ATO)
    if (relationship.relationshipState === 'KNOWN_TRUSTED') {
      const hasUrgentHighRiskDemand =
        (actionRisk.detectedAction === 'TRANSFER_MONEY' || sensitiveData.demandsCredentials) &&
        behaviour.urgencyScore > 50;

      if (hasUrgentHighRiskDemand) {
        conflicts.push({
          conflictType: 'KNOWN_TRUSTED_CONTACT_BEHAVIOURAL_ANOMALY',
          detectorA: {
            name: 'RelationshipDetector',
            finding: 'Sender matches known trusted contact history with established baseline.',
            signal: 'KNOWN_TRUSTED_CONTACT',
          },
          detectorB: {
            name: 'Behaviour / ActionRisk Detector',
            finding: 'Urgent uncharacteristic financial transfer or credential submission requested.',
            signal: 'SUDDEN_HIGH_RISK_ACTION',
          },
          resolution: 'Flagged as potential Account Takeover (ATO) or hijacked sender mailbox. Historical relationship trust is suspended in presence of out-of-band high-risk transaction requests.',
          reconciledScoreAdjustment: 20,
          explanation: 'Trust score overridden by anomalous high-risk financial demand from compromised mailbox.',
        });
        conflictScoreAdjustment += 20;
      }
    }

    // Conflict Scenario 4: New Sender / First Contact with completely benign message
    if (
      (relationship.firstContact || identity.newSender || relationship.relationshipState === 'FIRST_CONTACT') &&
      actionRisk.actionRisk === 'NONE' &&
      intent.primaryIntent === 'BENIGN_COMMUNICATION' &&
      technical.riskScore === 0 &&
      !promptInjection.detected
    ) {
      conflicts.push({
        conflictType: 'NEW_SENDER_BENIGN_CONTENT',
        detectorA: {
          name: 'Identity / Relationship Detector',
          finding: 'Novelty sender / first-time contact without prior relationship history.',
          signal: 'UNVERIFIED_NEW_ORIGIN',
        },
        detectorB: {
          name: 'ActionRisk / Intent Detector',
          finding: 'Benign operational discourse with zero hostile requests, zero links, zero urgency.',
          signal: 'BENIGN_CONTENT',
        },
        resolution: 'Novelty origin does NOT constitute a threat without corroborating deceptive lures or hostile actions. Evaluated as SAFE with standard sender verification posture.',
        reconciledScoreAdjustment: -10,
        explanation: 'Novelty contact alone without deceptive signals remains SAFE.',
      });
      conflictScoreAdjustment -= 10;
    }

    // Conflict Scenario 5: Benign Intent vs Prompt Injection Tokens
    if (promptInjection.detected && intent.primaryIntent === 'BENIGN_COMMUNICATION') {
      conflicts.push({
        conflictType: 'PROMPT_INJECTION_VS_BENIGN_NLP',
        detectorA: {
          name: 'IntentDetector (NLP)',
          finding: 'Text conversational tone appears benign or inquiry-like.',
          signal: 'BENIGN_SURFACE_TONE',
        },
        detectorB: {
          name: 'PromptInjectionDetector',
          finding: 'Explicit system instruction override / jailbreak delimiters identified in payload.',
          signal: 'ADVERSARIAL_INJECTION',
        },
        resolution: 'Adversarial prompt injection tokens take absolute precedence over surface linguistic tone.',
        reconciledScoreAdjustment: 50,
        explanation: 'Surface tone discarded in favor of critical AI injection override tokens.',
      });
      conflictScoreAdjustment += 50;
    }

    // 3. TRIAD RISK MODEL (Content Risk, Action Risk, Combined Risk)
    // Content Risk: urgency, coercion, deception, prompt injection, sensitive data requests
    const contentIndicators: string[] = [];
    let contentRiskScore = 0;

    if (behaviour.urgencyScore > 40) {
      contentRiskScore += Math.round(behaviour.urgencyScore * 0.4);
      contentIndicators.push('Coercive urgency and deadline pressure');
    }
    if (behaviour.isolationRequested) {
      contentRiskScore += 30;
      contentIndicators.push('Demands isolation / secrecy');
    }
    if (intent.primaryIntent !== 'BENIGN_COMMUNICATION' && intent.primaryIntent !== 'UNKNOWN') {
      contentRiskScore += Math.round(intent.intentConfidence * 0.3);
      contentIndicators.push(`Deceptive intent: ${intent.primaryIntent}`);
    }
    if (promptInjection.detected) {
      contentRiskScore = 98;
      contentIndicators.push('System instruction override tokens');
    }
    if (sensitiveData.demandsCredentials || sensitiveData.demandsOtp) {
      contentRiskScore = Math.max(contentRiskScore, 85);
      contentIndicators.push('Credential / authentication secret solicitation');
    }
    if (sensitiveData.demandsPayment) {
      contentRiskScore = Math.max(contentRiskScore, 80);
      contentIndicators.push('Financial disbursement demand');
    }

    contentRiskScore = Math.min(100, Math.max(0, contentRiskScore));
    const contentRiskLevel: ActionRiskLevel =
      contentRiskScore >= 80 ? 'CRITICAL' : contentRiskScore >= 60 ? 'HIGH' : contentRiskScore >= 35 ? 'MEDIUM' : contentRiskScore > 10 ? 'LOW' : 'NONE';

    const contentRisk: ContentRiskAssessment = {
      level: contentRiskLevel,
      score: contentRiskScore,
      indicators: contentIndicators.length > 0 ? contentIndicators : ['Normal conversational syntax; no adversarial or deceptive pressure identified'],
    };

    // Action Risk: severity of the requested user action
    let actionNumericScore = 0;
    switch (actionRisk.detectedAction) {
      case 'TRANSFER_MONEY':
        actionNumericScore = 95;
        break;
      case 'SHARE_OTP':
        actionNumericScore = 95;
        break;
      case 'ENTER_PASSWORD':
      case 'LOGIN':
        actionNumericScore = 85;
        break;
      case 'SHARE_SENSITIVE_DATA':
        actionNumericScore = 80;
        break;
      case 'EXECUTE_INSTRUCTION':
        actionNumericScore = promptInjection.detected ? 98 : 70;
        break;
      case 'DOWNLOAD':
      case 'DOWNLOAD_FILE':
        actionNumericScore = 75;
        break;
      case 'CLICK':
      case 'CLICK_LINK':
      case 'VISIT_WEBSITE':
        actionNumericScore = technical.reverseTunnelDetected ? 95 : technical.riskScore > 50 ? 70 : 40;
        break;
      case 'SCAN_QR':
        actionNumericScore = 50;
        break;
      case 'CALL_NUMBER':
        actionNumericScore = 35;
        break;
      default:
        actionNumericScore = 0;
        break;
    }

    const actionRiskAssessment: ActionRiskAssessment = {
      detected_action: actionRisk.detectedAction,
      level: actionRisk.actionRisk,
      score: actionNumericScore,
      target_destination: actionRisk.targetDestination || null,
    };

    // Combined Risk: Principled fusion of content risk and action risk
    let combinedScore = 0;
    if (actionNumericScore === 0) {
      combinedScore = Math.round(contentRiskScore * 0.75);
    } else if (actionRisk.actionRisk === 'CRITICAL') {
      // Critical dangerous actions (wire transfer, OTP theft) must maintain critical risk floor
      combinedScore = Math.max(actionNumericScore, Math.round(contentRiskScore * 0.3 + actionNumericScore * 0.7));
    } else if (actionRisk.actionRisk === 'HIGH') {
      // High actions (credential input, sensitive doc exfiltration) maintain high risk floor
      combinedScore = Math.max(Math.round(actionNumericScore * 0.85), Math.round(contentRiskScore * 0.35 + actionNumericScore * 0.65));
    } else {
      // Both content and action exist: high action severity multiplies content risk
      combinedScore = Math.round(contentRiskScore * 0.45 + actionNumericScore * 0.55);
    }

    // Special escalations: Prompt injection or reverse tunnel credential harvesting
    if (promptInjection.detected) combinedScore = 98;
    if (technical.reverseTunnelDetected && (actionRisk.detectedAction === 'LOGIN' || actionRisk.detectedAction === 'ENTER_PASSWORD')) combinedScore = 98;

    combinedScore = Math.min(100, Math.max(0, combinedScore));
    const combinedLevel: ActionRiskLevel =
      combinedScore >= 80 ? 'CRITICAL' : combinedScore >= 60 ? 'HIGH' : combinedScore >= 35 ? 'MEDIUM' : combinedScore > 10 ? 'LOW' : 'NONE';

    const combinedRisk: CombinedRiskAssessment = {
      level: combinedLevel,
      score: combinedScore,
    };

    // 4. ATTACK TAXONOMY CLASSIFICATION
    const attackTypes = this.classifyAttackTaxonomy({
      identity,
      relationship,
      behaviour,
      intent,
      actionRisk,
      technical,
      promptInjection,
      sensitiveData,
    });

    // 5. CROSS-CHANNEL CORRELATION FOUNDATION
    const crossChannel = this.evaluateCrossChannel(input, technical);

    // 6. MULTI-SIGNAL CORRELATION & WHY RISK INCREASED
    const whyRiskIncreased: string[] = [];
    const correlatedThreats: string[] = [];

    // General Identity + Action Correlation
    const isUnverifiedSender = identity.isSpoofed || identity.newSender || relationship.firstContact || identity.fromReplyToMismatch;
    if (isUnverifiedSender && (actionRisk.detectedAction === 'TRANSFER_MONEY' || sensitiveData.demandsPayment)) {
      correlatedThreats.push('Business Email Compromise (BEC) / Executive Impersonation Wire Fraud');
      whyRiskIncreased.push('Identity + Action Correlation: Unfamiliar or unverified sender origin paired with immediate financial disbursement request.');
    }

    if (isUnverifiedSender && (actionRisk.detectedAction === 'LOGIN' || actionRisk.detectedAction === 'ENTER_PASSWORD' || sensitiveData.demandsCredentials)) {
      correlatedThreats.push('Deceptive Credential Harvesting Campaign');
      whyRiskIncreased.push('Identity + Action Correlation: Unverified origin soliciting sensitive account login credentials.');
    }

    if (sensitiveData.demandsOtp) {
      correlatedThreats.push('Two-Factor Authentication (OTP) Interception Attack');
      whyRiskIncreased.push('Action Hazard: Explicit solicitation of one-time authentication tokens (OTPs) to bypass multi-factor authentication.');
    }

    if (technical.reverseTunnelDetected) {
      correlatedThreats.push('Evasive Reverse Proxy / Tunnel Phishing Infrastructure');
      whyRiskIncreased.push('Technical Correlation: External destination utilizes ephemeral reverse proxy tunnels (ngrok/localtunnel/trycloudflare) designed to evade reputation filters.');
    }

    if (promptInjection.detected) {
      correlatedThreats.push('Adversarial Prompt Injection / AI Execution Hijacking');
      whyRiskIncreased.push('Payload Correlation: Prompt injection override tokens targeting automated language models and cognitive assistants.');
    }

    // Relationship + Behaviour Correlation (when history is available)
    if (relationship.status === 'available') {
      if (relationship.relationshipState === 'KNOWN_TRUSTED' && relationship.behaviourShiftDetected) {
        correlatedThreats.push('Compromised Trusted Partner Account (Account Takeover / ATO)');
        whyRiskIncreased.push('Relationship + Behaviour Correlation: Established trusted contact demonstrates sharp behavioural shift with unprecedented high-risk demands.');
      } else if (relationship.firstContact && behaviour.urgencyScore > 50) {
        whyRiskIncreased.push('Relationship + Behaviour Correlation: Novelty contact introduces coercive urgency and deadline pressure on first interaction.');
      }
    } else {
      whyRiskIncreased.push('Telemetry notice: Historical relationship baseline unavailable; evaluating observable current-event signals exclusively.');
    }

    if (whyRiskIncreased.length === 0 && combinedScore <= 20) {
      whyRiskIncreased.push('Signals aligned: Sender identity, communication behaviour, and requested actions reflect benign, non-hostile interactions.');
    }

    // 7. COMPUTE FINAL FUSED RISK SCORE
    // Baseline is fused maximum of correlated signals, adjusted by conflict resolution
    const individualScores = [
      identity.riskScore,
      relationship.riskScore,
      behaviour.riskScore,
      intent.primaryIntent === 'BENIGN_COMMUNICATION' ? 0 : intent.intentConfidence,
      combinedScore,
      technical.riskScore,
      promptInjection.adversarialRiskScore,
      sensitiveData.riskScore,
    ];

    let baseFusedRisk = Math.max(...individualScores);

    // Apply compound synergy if 3 or more high signals exist
    const highSignalCount = [
      identity.riskScore >= 60,
      behaviour.riskScore >= 50,
      technical.riskScore >= 60,
      combinedScore >= 60,
      sensitiveData.riskScore >= 60,
    ].filter(Boolean).length;

    if (highSignalCount >= 3) {
      baseFusedRisk = Math.min(100, baseFusedRisk + 10);
      whyRiskIncreased.push(`Multi-Signal Synergy: ${highSignalCount} elevated signals across identity, behaviour, action, and technical telemetry mutually corroborate threat.`);
    }

    // Apply conflict adjustments
    let finalFusedRisk = Math.min(100, Math.max(0, baseFusedRisk + conflictScoreAdjustment));

    // Hard rules for severe threats & Phase 7.5 Refined Multi-Signal Escalation
    if (promptInjection.detected) {
      finalFusedRisk = Math.max(finalFusedRisk, 98);
    }

    // Technical Evasion + Credential Harvesting
    if (
      (evasion?.detected || technical.reverseTunnelDetected) &&
      (sensitiveData.demandsCredentials || actionRisk.detectedAction === 'LOGIN' || actionRisk.detectedAction === 'ENTER_PASSWORD')
    ) {
      finalFusedRisk = Math.max(finalFusedRisk, 98);
      whyRiskIncreased.push('Technical Evasion + Credential Solicitation: Obfuscation techniques deployed alongside credential harvesting.');
    }

    // Dangerous Action Precedence: OTP Solicitation (Never let polite text hide dangerous action)
    if (actionRisk.detectedAction === 'SHARE_OTP' || sensitiveData.demandsOtp) {
      finalFusedRisk = Math.max(finalFusedRisk, 95);
      whyRiskIncreased.push('Dangerous Action Precedence: Explicit OTP token solicitation elevates risk to critical, overriding polite conversational text.');
    }

    // Dangerous Action Precedence: Money Transfer + Unverified / Untrusted Identity
    const isUntrustedOrigin =
      identity.isSpoofed ||
      Boolean(identity.fromReplyToMismatch) ||
      identity.newSender ||
      relationship.firstContact ||
      relationship.relationshipState !== 'KNOWN_TRUSTED';

    if (
      (actionRisk.detectedAction === 'TRANSFER_MONEY' || sensitiveData.demandsPayment) &&
      isUntrustedOrigin
    ) {
      finalFusedRisk = Math.max(finalFusedRisk, 96);
      whyRiskIncreased.push('Dangerous Action Precedence: High-impact financial disbursement request paired with unfamiliar, unverified, or non-trusted contact origin.');
    }

    // Dangerous Action Precedence: Credential or Password harvesting by non-established source
    if (
      (actionRisk.detectedAction === 'ENTER_PASSWORD' || actionRisk.detectedAction === 'LOGIN' || sensitiveData.demandsCredentials) &&
      isUntrustedOrigin
    ) {
      finalFusedRisk = Math.max(finalFusedRisk, 95);
      whyRiskIncreased.push('Dangerous Action Precedence: Primary credential harvesting attempted by unfamiliar or non-trusted entity.');
    }

    // Sequence / Multi-Message Attack Escalation
    if (input.metadata?.isMultiMessageSequence) {
      const priorEvents = input.metadata?.events || [];
      const hasPriorSuspicious = priorEvents.some((ev: any) => ev.stage === 'SENSITIVE_REQUEST' || ev.stage === 'URGENCY' || ev.stage === 'IDENTITY_CLAIM');
      if (hasPriorSuspicious && (actionRisk.actionRisk === 'CRITICAL' || actionRisk.actionRisk === 'HIGH')) {
        finalFusedRisk = Math.max(finalFusedRisk, 96);
        whyRiskIncreased.push('Sequence Escalation: Multi-message temporal attack transition culminating in dangerous action request.');
      }
    }

    // Urgency + Credential Harvesting
    if (
      behaviour.urgencyScore > 40 &&
      (actionRisk.detectedAction === 'ENTER_PASSWORD' || sensitiveData.demandsCredentials)
    ) {
      finalFusedRisk = Math.max(finalFusedRisk, 92);
      whyRiskIncreased.push('Urgency + Credential Solicitation: Coercive deadline pressure designed to bypass user verification.');
    }

    // 8. EVIDENCE COVERAGE & CONFIDENCE SEPARATION
    const availableComponents: string[] = [];
    const unavailableComponents: Array<{ component: string; reason: string }> = [];
    const failedComponents: Array<{ component: string; error: string }> = [];

    // Check each component
    availableComponents.push('Action Engine');
    availableComponents.push('Behaviour Engine');
    availableComponents.push('Intent Engine (NLP)');
    availableComponents.push('Prompt Injection Detector');
    availableComponents.push('Sensitive Data Detector');
    availableComponents.push('Technical Detector');

    if (identity.status === 'available') {
      availableComponents.push('Identity Engine');
    } else {
      unavailableComponents.push({
        component: 'Identity Engine',
        reason: identity.statusReason || 'No sender identity metadata supplied in payload',
      });
    }

    if (relationship.status === 'available') {
      availableComponents.push('Relationship Engine');
    } else {
      unavailableComponents.push({
        component: 'Relationship Engine',
        reason: relationship.statusReason || 'No historical interaction telemetry supplied',
      });
    }

    if (input.source === 'email' && !emailDossier && input.rawPayload && /From:/i.test(input.rawPayload)) {
      failedComponents.push({
        component: 'Email Forensics Deep Dossier',
        error: 'RFC 5322 deep parser was unable to fully unpack raw headers.',
      });
    }

    const totalPossible = 8;
    const coverageRatio = availableComponents.length / totalPossible;
    const confidenceRating: 'LOW' | 'MEDIUM' | 'HIGH' =
      coverageRatio >= 0.85 ? 'HIGH' : coverageRatio >= 0.65 ? 'MEDIUM' : 'LOW';

    // Strict separation: Confidence measures evidence completeness and corroboration, NOT risk!
    // Example: High Risk + Missing History = High Risk with Moderate Confidence
    let confidenceScore = Math.round(coverageRatio * 60);
    if (technical.urlsEvaluated > 0) confidenceScore += 10;
    if (deduplicatedEvidence.length >= 5) confidenceScore += 10;
    if (emailDossier) confidenceScore += 10;
    if (technical.spfStatus && technical.spfStatus !== 'UNAVAILABLE') confidenceScore += 5;
    confidenceScore = Math.min(95, Math.max(35, confidenceScore));

    const coverage: AnalysisCoverage = {
      available: availableComponents,
      unavailable: unavailableComponents,
      failed: failedComponents,
      coverageRatio,
      confidenceRating,
      detectorsRun: availableComponents,
      detectorsUnavailable: unavailableComponents.map((u) => ({ detector: u.component, reason: u.reason })),
    };

    return {
      evidenceWithProvenance: deduplicatedEvidence,
      conflicts,
      attackTypes,
      contentRisk,
      actionRiskAssessment,
      combinedRisk,
      crossChannel,
      coverage,
      fusedRiskScore: finalFusedRisk,
      confidenceScore,
      correlatedThreats: Array.from(new Set(correlatedThreats)),
      whyRiskIncreased,
    };
  }

  /**
   * Classifies correlated signals into the structured Attack Taxonomy.
   * Multiple categories may apply simultaneously.
   */
  private static classifyAttackTaxonomy(detectors: {
    identity: IdentityAnalysis;
    relationship: RelationshipAnalysis;
    behaviour: BehaviourAnalysis;
    intent: IntentAnalysis;
    actionRisk: ActionRiskAnalysis;
    technical: TechnicalEvidenceAnalysis;
    promptInjection: PromptInjectionAnalysis;
    sensitiveData: SensitiveDataAnalysis;
  }): AttackCategory[] {
    const categories: AttackCategory[] = [];
    const { identity, relationship, behaviour, intent, actionRisk, technical, promptInjection, sensitiveData } = detectors;

    // PROMPT_INJECTION
    if (promptInjection.detected || intent.primaryIntent === 'PROMPT_INJECTION_EXPLOIT' || intent.primaryIntent === 'PROMPT_MANIPULATION') {
      categories.push('PROMPT_INJECTION');
    }

    // BUSINESS_EMAIL_COMPROMISE (BEC)
    if (
      (actionRisk.detectedAction === 'TRANSFER_MONEY' || sensitiveData.demandsPayment) &&
      (identity.fromReplyToMismatch || identity.isSpoofed || identity.newSender || relationship.relationshipState === 'KNOWN_TRUSTED' && relationship.behaviourShiftDetected)
    ) {
      categories.push('BUSINESS_EMAIL_COMPROMISE');
      categories.push('FINANCIAL_FRAUD');
    }

    // IMPERSONATION
    if (identity.isSpoofed || identity.isAnomalousDisplay || identity.fromReplyToMismatch || intent.primaryIntent === 'IMPERSONATION') {
      categories.push('IMPERSONATION');
    }

    // CREDENTIAL_THEFT
    if (
      actionRisk.detectedAction === 'LOGIN' ||
      actionRisk.detectedAction === 'ENTER_PASSWORD' ||
      sensitiveData.demandsCredentials ||
      sensitiveData.demandsOtp ||
      intent.primaryIntent === 'CREDENTIAL_THEFT' ||
      intent.primaryIntent === 'CREDENTIAL_HARVESTING'
    ) {
      categories.push('CREDENTIAL_THEFT');
    }

    // FINANCIAL_FRAUD
    if ((actionRisk.detectedAction === 'TRANSFER_MONEY' || sensitiveData.demandsPayment || intent.primaryIntent === 'FINANCIAL_FRAUD') && !categories.includes('FINANCIAL_FRAUD')) {
      categories.push('FINANCIAL_FRAUD');
    }

    // SOCIAL_ENGINEERING
    if (behaviour.urgencyScore > 40 || behaviour.coercionScore > 40 || behaviour.isolationRequested || intent.primaryIntent === 'SOCIAL_ENGINEERING') {
      categories.push('SOCIAL_ENGINEERING');
    }

    // MALICIOUS_LINK
    if (technical.reverseTunnelDetected || technical.typosquattingDetected || technical.nrdDetected || technical.bareIpUrlDetected || intent.primaryIntent === 'MALICIOUS_LINK_REDIRECTION') {
      categories.push('MALICIOUS_LINK');
    }

    // MALWARE_DELIVERY
    if (actionRisk.detectedAction === 'DOWNLOAD' || actionRisk.detectedAction === 'DOWNLOAD_FILE' || intent.primaryIntent === 'MALWARE_DELIVERY') {
      categories.push('MALWARE_DELIVERY');
    }

    // DATA_EXFILTRATION / SENSITIVE_DATA_ATTACK
    if (sensitiveData.demandsPii || sensitiveData.demandsApiKeys || sensitiveData.demandsConfidentialOrgData || actionRisk.detectedAction === 'SHARE_SENSITIVE_DATA' || intent.primaryIntent === 'DATA_EXFILTRATION') {
      categories.push('DATA_EXFILTRATION');
      categories.push('SENSITIVE_DATA_ATTACK');
    }

    // SPEAR_PHISHING vs PHISHING
    if (categories.includes('IMPERSONATION') && (categories.includes('CREDENTIAL_THEFT') || categories.includes('FINANCIAL_FRAUD'))) {
      categories.push('SPEAR_PHISHING');
    } else if (categories.includes('CREDENTIAL_THEFT') || categories.includes('MALICIOUS_LINK')) {
      categories.push('PHISHING');
    }

    // Default if no specific category applies
    if (categories.length === 0) {
      categories.push('UNKNOWN');
    }

    return Array.from(new Set(categories));
  }

  /**
   * Cross-Channel Correlation Foundation.
   * Evaluates if telemetry spans multiple communication channels (e.g. Email + SMS + Web + QR).
   * Never manufactures cross-channel history when only one source is provided.
   */
  private static evaluateCrossChannel(
    input: UnifiedThreatInput,
    technical: TechnicalEvidenceAnalysis
  ): CrossChannelAnalysis {
    const rawEvents: any[] = Array.isArray(input.metadata?.crossChannelEvents)
      ? input.metadata.crossChannelEvents
      : Array.isArray(input.metadata?.correlatedEvents)
      ? input.metadata.correlatedEvents
      : [];

    if (rawEvents.length <= 1) {
      return {
        isMultiChannel: false,
        channelsObserved: [input.source],
        events: [
          {
            channel: input.source,
            timestamp: input.metadata?.timestamp || new Date().toISOString(),
            entity: input.sender?.identifier || 'Origin',
            actionObserved: input.user_action || 'COMMUNICATION_RECEIVED',
            evidence: `Single-channel observation confined to ${input.source.toUpperCase()}.`,
          },
        ],
        correlationNotes: [
          `Telemetry verified on single communication vector (${input.source.toUpperCase()}). No cross-channel pivoting observed in payload.`,
        ],
      };
    }

    // Multi-channel progression supplied by caller
    const channelsObserved = Array.from(
      new Set([input.source, ...rawEvents.map((e) => (e.channel as ThreatSource) || 'web')])
    );
    const events: CrossChannelEvent[] = rawEvents.map((re, idx) => ({
      channel: (re.channel as ThreatSource) || input.source,
      timestamp: re.timestamp,
      entity: re.entity || re.sender,
      actionObserved: re.action || re.actionObserved,
      evidence: re.evidence || `Cross-channel event step ${idx + 1}`,
    }));

    return {
      isMultiChannel: channelsObserved.length > 1,
      channelsObserved,
      events,
      correlationNotes: [
        `Cross-channel threat correlation: Observed correlated activity traversing ${channelsObserved.join(' → ')}.`,
      ],
    };
  }
}
