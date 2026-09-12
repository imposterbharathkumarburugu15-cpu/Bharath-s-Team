/**
 * NeuroShield Dynamic Trust Model
 * Phase 7.5 — Advanced Security Intelligence
 *
 * Implements trust as an evidence-based, dynamic, non-permanent context:
 * IDENTITY + RELATIONSHIP + BEHAVIOUR + INTENT + TECHNICAL EVIDENCE + ACTION = CURRENT TRUST CONTEXT
 *
 * CRITICAL FORENSIC PRINCIPLES:
 * 1. Trust is never an indelible or permanent property of a sender.
 * 2. Every trust modification requires concrete, documented evidence.
 * 3. A historically trusted contact degrades immediately upon anomalous coercive action or diversion.
 * 4. Unverified/new senders start at a neutral, conditional baseline—never blindly trusted.
 */

import {
  UnifiedThreatInput,
  IdentityAnalysis,
  RelationshipAnalysis,
  BehaviourAnalysis,
  IntentAnalysis,
  TechnicalEvidenceAnalysis,
  ActionRiskAnalysis,
  EvasionAnalysis,
  PromptInjectionAnalysis,
  SensitiveDataAnalysis,
  DynamicTrustModel,
  DynamicTrustLevel,
} from './types';

export class DynamicTrustEngine {
  static evaluate(params: {
    input: UnifiedThreatInput;
    identity: IdentityAnalysis;
    relationship: RelationshipAnalysis;
    behaviour: BehaviourAnalysis;
    intent: IntentAnalysis;
    technical: TechnicalEvidenceAnalysis;
    actionRisk: ActionRiskAnalysis;
    evasion?: EvasionAnalysis;
    promptInjection?: PromptInjectionAnalysis;
    sensitiveData?: SensitiveDataAnalysis;
  }): DynamicTrustModel {
    const {
      input,
      identity,
      relationship,
      behaviour,
      intent,
      technical,
      actionRisk,
      evasion,
      promptInjection,
      sensitiveData,
    } = params;

    const trustDecayFactors: string[] = [];
    const evidenceList: string[] = [];

    // 1. ESTABLISH BASELINE TRUST (from historical telemetry if genuinely available)
    let baseline_trust = 40; // Neutral unverified baseline
    const history = input.history;

    if (history?.knownSenderTrustScore !== undefined) {
      baseline_trust = Math.min(100, Math.max(0, history.knownSenderTrustScore));
      evidenceList.push(`Historical trust score recorded: ${baseline_trust}/100 based on verified telemetry.`);
    } else if (history && history.previousInteractionsCount > 0) {
      baseline_trust = Math.min(85, 50 + history.previousInteractionsCount * 3);
      evidenceList.push(`Baseline trust of ${baseline_trust}/100 established from ${history.previousInteractionsCount} prior interaction(s).`);
    } else {
      evidenceList.push('No historical trust telemetry available; initializing at neutral conditional baseline (40/100).');
    }

    let current_trust = baseline_trust;

    // 2. EVIDENCE-BASED TRUST DECAY / ELEVATION

    // A. Identity Verification Signals
    if (identity.isSpoofed) {
      current_trust -= 45;
      trustDecayFactors.push('Identity spoofing or brand mimicry detected');
      evidenceList.push('Trust penalized: Claimed identity contradicts sending domain infrastructure.');
    }
    if (identity.fromReplyToMismatch) {
      current_trust -= 35;
      trustDecayFactors.push('Reply-To diversion route differs from sender domain');
      evidenceList.push('Trust penalized: Asymmetric response routing directs replies away from sender.');
    }
    if (identity.signals.includes('HISTORICAL_IDENTITY_CHANGE')) {
      current_trust -= 30;
      trustDecayFactors.push('Sender display name abruptly shifted from established historical baseline');
      evidenceList.push('Trust penalized: Sudden change in identity assertion for known communication channel.');
    }

    // B. Behavioural & Psychological Pressure Signals
    if (behaviour.urgencyScore > 40) {
      const penalty = Math.round(behaviour.urgencyScore * 0.35);
      current_trust -= penalty;
      trustDecayFactors.push(`Coercive urgency pressure applied (score: ${behaviour.urgencyScore})`);
      evidenceList.push(`Trust penalized (-${penalty}): Artificial deadline pressure introduced to compel hasty action.`);
    }
    if (behaviour.isolationRequested) {
      current_trust -= 30;
      trustDecayFactors.push('Sender explicitly demands secrecy or bypassing standard peer verification');
      evidenceList.push('Trust penalized (-30): Isolation tactics detected, attempting to evade organizational oversight.');
    }

    // C. Action Hazard Signals (What is the sender attempting to force?)
    switch (actionRisk.detectedAction) {
      case 'TRANSFER_MONEY':
        current_trust -= 45;
        trustDecayFactors.push('Demands financial transfer, payment remittance, or invoice re-routing');
        evidenceList.push('Trust penalized (-45): High-impact financial disbursement requested.');
        break;
      case 'SHARE_OTP':
        current_trust -= 50;
        trustDecayFactors.push('Demands disclosure of multi-factor one-time verification passcode (OTP)');
        evidenceList.push('Trust penalized (-50): Direct solicitation of authentication bypass token.');
        break;
      case 'ENTER_PASSWORD':
      case 'LOGIN':
        current_trust -= 35;
        trustDecayFactors.push('Directs user to enter account credentials or authentication secrets');
        evidenceList.push('Trust penalized (-35): Credential harvesting endpoint interaction demanded.');
        break;
      case 'SHARE_SENSITIVE_DATA':
        current_trust -= 30;
        trustDecayFactors.push('Requests exfiltration of confidential personnel, tax, or corporate records');
        evidenceList.push('Trust penalized (-30): Sensitive data disclosure requested.');
        break;
      case 'EXECUTE_INSTRUCTION':
        current_trust -= 40;
        trustDecayFactors.push('Requests terminal script execution or AI instruction override');
        evidenceList.push('Trust penalized (-40): Adversarial execution directive observed.');
        break;
      case 'DOWNLOAD':
      case 'DOWNLOAD_FILE':
        current_trust -= 25;
        trustDecayFactors.push('Delivers unsolicited file attachment or binary download');
        evidenceList.push('Trust penalized (-25): File payload transmission requested.');
        break;
      default:
        break;
    }

    // D. Technical & Infrastructure Indicators
    if (technical.reverseTunnelDetected) {
      current_trust -= 40;
      trustDecayFactors.push('Links route through ephemeral reverse proxy tunnel (anti-reputation masking)');
      evidenceList.push('Trust penalized (-40): Infrastructure hides behind dynamic proxy tunnel.');
    }
    if (technical.typosquattingDetected) {
      current_trust -= 40;
      trustDecayFactors.push('Domain uses typosquatting / lookalike brand name');
      evidenceList.push('Trust penalized (-40): Deceptive domain registration detected.');
    }

    // E. Evasion & Prompt Injection Anomalies
    if (evasion?.homoglyphsDetected || evasion?.mixedScriptDetected) {
      current_trust -= 45;
      trustDecayFactors.push('Adversarial homoglyph character substitutions identified');
      evidenceList.push('Trust penalized (-45): Deceptive script mixing bypasses human visual inspection.');
    }
    if (evasion?.urlObfuscationDetected) {
      current_trust -= 25;
      trustDecayFactors.push('URL obfuscation techniques (hex/octal encoding, double percent, userinfo)');
      evidenceList.push('Trust penalized (-25): Intentional hyperlink obfuscation detected.');
    }
    if (promptInjection?.detected) {
      current_trust -= 60;
      trustDecayFactors.push('Adversarial prompt injection override directives embedded in message');
      evidenceList.push('Trust penalized (-60): Direct exploit payload targeting reasoning system.');
    }

    // F. Relationship Baseline Shift (Account Takeover / BEC hypothesis)
    if (relationship.relationshipState === 'KNOWN_TRUSTED' && relationship.behaviourShiftDetected) {
      current_trust -= 35;
      trustDecayFactors.push('Trusted contact exhibits sudden anomalous behavior divergent from historical norms');
      evidenceList.push('Trust penalized (-35): Potential Account Takeover (ATO)—established entity issuing unprecedented demands.');
    }

    // Bound current trust between 0 and 100
    current_trust = Math.min(100, Math.max(0, current_trust));
    const trust_delta = current_trust - baseline_trust;

    // Determine categorical trust level
    let trust_level: DynamicTrustLevel = 'CONDITIONAL';
    if (current_trust >= 75) {
      trust_level = 'TRUSTED';
    } else if (current_trust >= 50) {
      trust_level = 'CONDITIONAL';
    } else if (current_trust >= 25) {
      trust_level = 'DEGRADED';
    } else {
      trust_level = 'ZERO_TRUST';
    }

    let reason = 'Trust evaluated continuously against observed identity, relationship, behaviour, and action indicators.';
    if (trust_delta < -30) {
      reason = `Severe trust erosion (${trust_delta} pts): High-risk requested actions and anomalies actively override baseline sender credibility.`;
    } else if (trust_delta < 0) {
      reason = `Moderate trust decay (${trust_delta} pts) due to observable pressure, unverified routing, or sensitive requests.`;
    } else if (baseline_trust >= 70 && trustDecayFactors.length === 0) {
      reason = 'Sender identity, historical relationship, and current benign requests remain consistent with established baseline.';
    }

    evidenceList.push(`Final Dynamic Trust: ${current_trust}/100 (${trust_level}, Delta: ${trust_delta >= 0 ? '+' : ''}${trust_delta}).`);

    return {
      baseline_trust,
      current_trust,
      trust_delta,
      trust_level,
      reason,
      trust_decay_factors: trustDecayFactors,
      evidence: evidenceList,
    };
  }
}
