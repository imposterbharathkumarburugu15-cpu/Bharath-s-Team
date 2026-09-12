/**
 * NeuroShield Risk Engine & Protective Action Generator
 * Extracts structured feature vectors, computes consolidated risk decision,
 * and formulates concise, actionable protective guidance.
 */

import {
  RiskFeatureVector,
  RiskLevel,
  ProtectionDecision,
  IncidentProtectionDecision,
  RecommendedAction,
  IdentityAnalysis,
  RelationshipAnalysis,
  BehaviourAnalysis,
  IntentAnalysis,
  ActionRiskAnalysis,
  TechnicalEvidenceAnalysis,
  PromptInjectionAnalysis,
  SensitiveDataAnalysis,
  AttackSequenceAnalysis,
  AnalysisCoverage,
  GuardState,
  SafeAlternative,
  GuardWarningCard,
} from './types';
import { EvidenceCorrelationResult } from './evidenceCorrelator';

export class RiskEngine {
  /**
   * Risk Thresholds Specification (Documented):
   * SAFE:     0  - 19
   * LOW:      20 - 39
   * MEDIUM:   40 - 64
   * HIGH:     65 - 84
   * CRITICAL: 85 - 100
   */
  static readonly THRESHOLDS = {
    SAFE_MAX: 19,
    LOW_MAX: 39,
    MEDIUM_MAX: 64,
    HIGH_MAX: 84,
    CRITICAL_MAX: 100,
  } as const;

  /**
   * Extracts the 13-dimension structured feature vector (v2.0 Specification).
   * Standard contract ready for supervised ML / XGBoost pipeline integration.
   */
  static extractFeatureVector(params: {
    identity: IdentityAnalysis;
    relationship: RelationshipAnalysis;
    behaviour: BehaviourAnalysis;
    intent: IntentAnalysis;
    actionRisk: ActionRiskAnalysis;
    contentRiskScore?: number;
    technical: TechnicalEvidenceAnalysis;
    promptInjection: PromptInjectionAnalysis;
    sensitiveData: SensitiveDataAnalysis;
    attackSequence?: AttackSequenceAnalysis;
    evidenceCount: number;
    coverage: AnalysisCoverage;
  }): RiskFeatureVector {
    const {
      identity,
      relationship,
      behaviour,
      intent,
      actionRisk,
      contentRiskScore = 0,
      technical,
      promptInjection,
      sensitiveData,
      attackSequence,
      evidenceCount,
      coverage,
    } = params;

    const actionRiskNum =
      actionRisk.actionRisk === 'CRITICAL'
        ? 95
        : actionRisk.actionRisk === 'HIGH'
        ? 80
        : actionRisk.actionRisk === 'MEDIUM'
        ? 50
        : actionRisk.actionRisk === 'LOW'
        ? 20
        : 0;

    return {
      identity_risk: identity.riskScore,
      relationship_risk: relationship.riskScore,
      behaviour_risk: behaviour.riskScore,
      intent_risk: intent.intentConfidence,
      action_risk: actionRiskNum,
      content_risk: contentRiskScore,
      technical_risk: technical.riskScore,
      url_risk: technical.urlsEvaluated > 0 ? technical.riskScore : 0,
      prompt_injection_risk: promptInjection.adversarialRiskScore,
      sensitive_data_risk: sensitiveData.riskScore,
      sequence_risk: attackSequence?.compoundSequenceRisk || 0,
      evidence_count: evidenceCount,
      analysis_coverage: Math.round(coverage.coverageRatio * 100),
      feature_vector_version: '2.0',
    };
  }

  /**
   * Translates a numeric score (0-100) into the normalized 5-level risk tier.
   */
  static normalizeRiskLevel(score: number): RiskLevel {
    if (score <= this.THRESHOLDS.SAFE_MAX) return 'SAFE';
    if (score <= this.THRESHOLDS.LOW_MAX) return 'LOW';
    if (score <= this.THRESHOLDS.MEDIUM_MAX) return 'MEDIUM';
    if (score <= this.THRESHOLDS.HIGH_MAX) return 'HIGH';
    return 'CRITICAL';
  }

  /**
   * Calculates the final calibrated situation risk score, risk level, and verdict.
   */
  static computeDecision(
    correlationOrScore: EvidenceCorrelationResult | number,
    attackSequence?: AttackSequenceAnalysis
  ): {
    riskScore: number;
    riskLevel: RiskLevel;
    verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  } {
    let combinedScore =
      typeof correlationOrScore === 'number'
        ? correlationOrScore
        : correlationOrScore.compoundRiskScore;

    if (attackSequence?.isSequenceProgression && attackSequence.compoundSequenceRisk > combinedScore) {
      combinedScore = Math.round(combinedScore * 0.7 + attackSequence.compoundSequenceRisk * 0.3);
    }

    const finalRisk = Math.min(100, Math.max(0, combinedScore));
    const riskLevel = this.normalizeRiskLevel(finalRisk);

    let verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN' = 'SAFE';
    if (riskLevel === 'CRITICAL' || riskLevel === 'HIGH') {
      verdict = 'MALICIOUS';
    } else if (riskLevel === 'MEDIUM') {
      verdict = 'SUSPICIOUS';
    } else {
      verdict = 'SAFE';
    }

    return {
      riskScore: finalRisk,
      riskLevel,
      verdict,
    };
  }

  /**
   * Converts evaluated risk, confidence, action, and technical telemetry into
   * a protective decision (ALLOW | WARN | STRONG_WARN | BLOCK) and actionable guidance.
   */
  static generateProtectiveAction(params: {
    verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
    riskLevel: RiskLevel;
    confidence: number;
    actionRisk: ActionRiskAnalysis;
    sensitiveData: SensitiveDataAnalysis;
    technical: TechnicalEvidenceAnalysis;
    promptInjection: PromptInjectionAnalysis;
  }): IncidentProtectionDecision & RecommendedAction {
    const {
      verdict,
      riskLevel,
      confidence,
      actionRisk,
      sensitiveData,
      technical,
      promptInjection,
    } = params;

    // Determine 4-Tier Protection Decision: ALLOW | WARN | STRONG_WARN | BLOCK
    let decision: ProtectionDecision = 'ALLOW';

    if (riskLevel === 'SAFE') {
      decision = 'ALLOW';
    } else if (riskLevel === 'LOW') {
      decision = actionRisk.actionRisk === 'MEDIUM' ? 'WARN' : 'ALLOW';
    } else if (riskLevel === 'MEDIUM') {
      // Suspicious anomalies, or potential false positive with moderate risk
      decision = 'WARN';
    } else if (riskLevel === 'HIGH') {
      // High risk: BLOCK dangerous action
      if (
        actionRisk.actionRisk === 'CRITICAL' ||
        actionRisk.actionRisk === 'HIGH' ||
        sensitiveData.detected ||
        technical.reverseTunnelDetected ||
        technical.typosquattingDetected ||
        confidence >= 50
      ) {
        decision = 'BLOCK';
      } else {
        decision = 'STRONG_WARN';
      }
    } else if (riskLevel === 'CRITICAL') {
      // Critical risk: HARD BLOCK
      decision = 'BLOCK';
    }

    // Actionable Interventions & Steps
    const steps: string[] = [];
    const interventions: string[] = [];
    const circuitBreakers: string[] = [];
    let primaryInstruction = 'Proceed with standard communication workflow.';

    // Safe interaction baseline
    if (decision === 'ALLOW') {
      const safeWarningCard: GuardWarningCard = {
        state: 'SAFE',
        title: 'Communication Verified Safe',
        summary: 'Safe interaction: no malicious deception, credential prompts, or financial demands detected.',
        risk_detected: 'No malicious indicators or anomalies observed.',
        required_action: 'PROCEED NORMALLY',
        safe_alternative: {
          title: 'Direct Official Communication',
          action_label: 'Proceed',
          guidance: 'Communication conforms to legitimate baseline.',
          requires_independent_verification: false,
        },
        primary_button_label: 'Dismiss',
        secondary_button_label: 'Proceed',
      };

      return {
        decision: 'ALLOW',
        protectionDecision: 'ALLOW',
        enforcementLevel: 'ALLOW_PASSIVE_MONITORING',
        enforcementStatus: 'NOT_REQUIRED',
        action: 'ALLOW',
        recommended_action: 'Proceed with standard communication workflow.',
        summary: 'Safe interaction: no malicious deception, credential prompts, or financial demands detected.',
        steps: [
          'Message displays consistent origin identifiers and benign intent.',
          'Standard communications safety posture is sufficient.',
        ],
        interventions: ['Proceed with standard communication workflow.'],
        circuit_breakers: [],
        circuitBreakers: [],
        safe_alternative: safeWarningCard.safe_alternative,
        warning_card: safeWarningCard,
      };
    }

    // 1. PAYMENT REQUEST
    if (actionRisk.detectedAction === 'TRANSFER_MONEY' || sensitiveData.demandsPayment) {
      primaryInstruction = 'Do not transfer money. Verify the request using a trusted contact method.';
      steps.push('Do not transfer money.');
      steps.push('Verify the request using a trusted contact method (such as an established phone number).');
      steps.push('Do not use contact numbers or bank details supplied in this message.');
      interventions.push('HOLD TRANSACTION: Mandate dual-operator verification before releasing funds.');
      circuitBreakers.push('Automatic Payment Hold Triggered');
    }

    // 2. CREDENTIAL REQUEST
    else if (
      actionRisk.detectedAction === 'ENTER_PASSWORD' ||
      actionRisk.detectedAction === 'LOGIN' ||
      sensitiveData.demandsCredentials
    ) {
      primaryInstruction = 'Do not enter credentials. Open the official service manually.';
      steps.push('Do not enter credentials.');
      steps.push('Open the official service manually via your browser address bar.');
      steps.push('Reset your password immediately if credentials were typed into an unverified page.');
      interventions.push('CREDENTIAL LOCK: Prevent submission of authentication passwords.');
      circuitBreakers.push('Form Input Interception Active');
    }

    // 3. OTP REQUEST
    else if (actionRisk.detectedAction === 'SHARE_OTP' || sensitiveData.demandsOtp) {
      primaryInstruction = 'Never share this OTP.';
      steps.push('Never share this OTP.');
      steps.push('Contact the service provider directly through their verified support portal.');
      interventions.push('OTP ISOLATION: Multi-factor authentication secrets must never be transmitted.');
      circuitBreakers.push('Authentication Secret Isolation Enforced');
    }

    // 4. SUSPICIOUS LINK / CLOAKED INFRASTRUCTURE
    else if (
      actionRisk.detectedAction === 'CLICK' ||
      actionRisk.detectedAction === 'CLICK_LINK' ||
      actionRisk.detectedAction === 'VISIT_WEBSITE' ||
      technical.reverseTunnelDetected ||
      technical.typosquattingDetected
    ) {
      primaryInstruction = 'Do not open this link.';
      steps.push('Do not open this link.');
      steps.push('Navigate to the intended destination through official bookmarks or direct domain entry.');
      interventions.push('BLOCK NAVIGATION: Prevent browser routing to unverified destination.');
      circuitBreakers.push('Destination URL Quarantined');
    }

    // 5. PROMPT INJECTION EXPLOIT
    else if (promptInjection.detected) {
      primaryInstruction = 'Do not follow these instructions or provide secrets to the AI system.';
      steps.push('Do not follow these instructions or provide secrets to the AI system.');
      steps.push('Quarantine instruction override text from downstream reasoning processes.');
      interventions.push('AGENT ISOLATION: Discard hostile untrusted input payload.');
      circuitBreakers.push('Downstream Execution Pipeline Suspended');
    }

    // 6. SENSITIVE DATA SOLICITATION
    else if (sensitiveData.demandsPii || sensitiveData.demandsApiKeys || sensitiveData.demandsConfidentialOrgData) {
      primaryInstruction = 'Do not send the requested confidential information.';
      steps.push('Do not send the requested confidential information.');
      steps.push('Verify requester authorization through internal enterprise protocols.');
      interventions.push('DATA LOSS PREVENTION: Redact sensitive assets before transmission.');
      circuitBreakers.push('Data Transmission Blocked');
    }

    // Fallback if no specific condition matched
    else {
      primaryInstruction = 'Exercise heightened caution before acting on this message.';
      steps.push('Exercise heightened caution.');
      steps.push('Verify the identity of the sender through an independent, trusted channel.');
      interventions.push('Apply heightened communication precautions.');
    }

    // 7. Generate structured Safe Alternative & Guard Warning Card
    let safeAlternative: SafeAlternative;
    let guardState: GuardState = 'SAFE';

    if (decision === 'BLOCK') {
      guardState = 'BLOCKED';
    } else if (riskLevel === 'CRITICAL' || riskLevel === 'HIGH' || decision === 'STRONG_WARN') {
      guardState = 'HIGH_RISK';
    } else if (riskLevel === 'MEDIUM' || decision === 'WARN') {
      guardState = 'SUSPICIOUS';
    } else {
      guardState = 'SAFE';
    }

    if (actionRisk.detectedAction === 'TRANSFER_MONEY' || sensitiveData.demandsPayment) {
      safeAlternative = {
        title: 'Verify Recipient Out-of-Band',
        action_label: 'Call Trusted Number',
        guidance: 'Contact the organization or person via an established, verified phone number before authorizing any wire transfer or payment.',
        requires_independent_verification: true,
      };
    } else if (
      actionRisk.detectedAction === 'ENTER_PASSWORD' ||
      actionRisk.detectedAction === 'LOGIN' ||
      sensitiveData.demandsCredentials
    ) {
      safeAlternative = {
        title: 'Open Official Service Manually',
        action_label: 'Open Official Portal',
        guidance: 'Do not enter credentials here. Navigate to the verified service directly using your saved bookmark or official browser address bar.',
        requires_independent_verification: true,
      };
    } else if (actionRisk.detectedAction === 'SHARE_OTP' || sensitiveData.demandsOtp) {
      safeAlternative = {
        title: 'Contact Provider Directly',
        action_label: 'Open Official Support',
        guidance: 'Multi-factor authentication codes should never be shared. Contact the provider through their known official portal.',
        requires_independent_verification: true,
      };
    } else if (
      actionRisk.detectedAction === 'CLICK' ||
      actionRisk.detectedAction === 'CLICK_LINK' ||
      actionRisk.detectedAction === 'VISIT_WEBSITE' ||
      technical.reverseTunnelDetected ||
      technical.typosquattingDetected
    ) {
      safeAlternative = {
        title: 'Navigate Directly to Official Website',
        action_label: 'Use Known Bookmark',
        guidance: 'Do not open this link. Access the service by typing its official domain directly or through your existing bookmarks.',
        requires_independent_verification: true,
      };
    } else if (promptInjection.detected) {
      safeAlternative = {
        title: 'Quarantine Hostile Prompt',
        action_label: 'Discard Unsafe Input',
        guidance: 'Do not execute or forward this instruction payload. Downstream agent guardrails have been activated.',
        requires_independent_verification: false,
      };
    } else if (sensitiveData.demandsPii || sensitiveData.demandsApiKeys || sensitiveData.demandsConfidentialOrgData) {
      safeAlternative = {
        title: 'Validate Internal Clearance',
        action_label: 'Check Enterprise Policy',
        guidance: 'Verify the authorization of the requester through internal security protocols before disclosing any confidential data.',
        requires_independent_verification: true,
      };
    } else {
      safeAlternative = {
        title: 'Verify Through Trusted Channel',
        action_label: 'Independent Verification',
        guidance: 'Verify sender legitimacy through an independent, pre-established communication channel before proceeding.',
        requires_independent_verification: true,
      };
    }

    const summary =
      decision === 'BLOCK'
        ? `Immediate protective block enforced: ${primaryInstruction}`
        : decision === 'STRONG_WARN'
        ? `High-risk alert: ${primaryInstruction}`
        : `Suspicious activity observed: ${primaryInstruction}`;

    const warningCard: GuardWarningCard = {
      state: guardState,
      title:
        guardState === 'BLOCKED'
          ? 'Threat Blocked by NeuroShield'
          : guardState === 'HIGH_RISK'
          ? 'High-Risk Interaction Detected'
          : 'Suspicious Activity Warning',
      summary,
      risk_detected:
        technical.reverseTunnelDetected
          ? 'Hostile reverse proxy tunnel or cloaked infrastructure detected'
          : technical.typosquattingDetected
          ? 'Lookalike or deceptive domain detected'
          : promptInjection.detected
          ? 'Adversarial instruction injection attempt'
          : actionRisk.detectedAction === 'TRANSFER_MONEY'
          ? 'Unverified payment redirection or invoice demand'
          : actionRisk.detectedAction === 'LOGIN' || actionRisk.detectedAction === 'ENTER_PASSWORD'
          ? 'Credential harvesting / fake authentication portal'
          : actionRisk.detectedAction === 'SHARE_OTP'
          ? 'Two-factor secret harvesting attempt'
          : 'Anomalous communication indicators observed',
      required_action: primaryInstruction.toUpperCase(),
      safe_alternative: safeAlternative,
      primary_button_label: 'Go Back',
      secondary_button_label: safeAlternative.action_label,
    };

    const isNavigationLure =
      actionRisk.detectedAction === 'CLICK' ||
      actionRisk.detectedAction === 'CLICK_LINK' ||
      actionRisk.detectedAction === 'VISIT_WEBSITE' ||
      technical.reverseTunnelDetected ||
      technical.typosquattingDetected;

    let canonicalDecision: 'ALLOW' | 'WARN' | 'BLOCK_ACTION' | 'BLOCK_VIEW' = 'WARN';
    let enforcementLevel = 'USER_WARNING_DIALOG';
    let enforcementStatus: import('./types').EnforcementStatus = 'PENDING';

    if (decision === 'BLOCK') {
      if (isNavigationLure) {
        canonicalDecision = 'BLOCK_VIEW';
        enforcementLevel = riskLevel === 'CRITICAL' ? 'HARD_BROWSER_VIEW_BLOCK' : 'BROWSER_VIEW_BLOCK';
      } else {
        canonicalDecision = 'BLOCK_ACTION';
        enforcementLevel = riskLevel === 'CRITICAL' ? 'HARD_CLIENT_ACTION_BLOCK' : 'CLIENT_ACTION_RESTRICTION';
      }
      enforcementStatus = 'PENDING';
    } else if (decision === 'WARN' || decision === 'STRONG_WARN') {
      canonicalDecision = 'WARN';
      enforcementLevel = 'USER_WARNING_DIALOG';
      enforcementStatus = 'WARNED';
    } else {
      canonicalDecision = 'ALLOW';
      enforcementLevel = 'ALLOW_PASSIVE_MONITORING';
      enforcementStatus = 'NOT_REQUIRED';
    }

    return {
      decision,
      protectionDecision: canonicalDecision,
      enforcementLevel,
      enforcementStatus,
      action: decision === 'BLOCK' ? 'BLOCK' : decision === 'STRONG_WARN' ? 'WARN' : 'WARN',
      recommended_action: primaryInstruction,
      summary,
      steps,
      interventions,
      circuit_breakers: circuitBreakers,
      circuitBreakers,
      safe_alternative: safeAlternative,
      warning_card: warningCard,
    };
  }

  /**
   * Reports the model compatibility status.
   * Clarifies retraining requirements without fabricating artificial datasets.
   */
  static getModelCompatibilityReport(): {
    featureVectorVersion: string;
    featureCount: number;
    featuresExpected: string[];
    retrainingRequiredForExternalModel: boolean;
    activeScoringEngine: string;
    complianceNote: string;
  } {
    return {
      featureVectorVersion: '2.0',
      featureCount: 13,
      featuresExpected: [
        'identity_risk',
        'relationship_risk',
        'behaviour_risk',
        'intent_risk',
        'action_risk',
        'content_risk',
        'technical_risk',
        'url_risk',
        'prompt_injection_risk',
        'sensitive_data_risk',
        'sequence_risk',
        'evidence_count',
        'analysis_coverage',
      ],
      retrainingRequiredForExternalModel: true,
      activeScoringEngine: 'Calibrated Deterministic Multi-Signal Fusion Engine',
      complianceNote:
        'Zero-Fabrication Mandate: Pre-trained XGBoost models trained on legacy 5-feature inputs require retraining on the expanded 13-feature v2.0 schema. Calibrated multi-signal fusion operates deterministically in the interim.',
    };
  }
}

