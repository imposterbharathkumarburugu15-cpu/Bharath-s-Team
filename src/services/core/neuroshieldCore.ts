/**
 * NeuroShield Core Detection & Interaction Protection Engine
 * Phase 2 Central Intelligence Pipeline
 */

import {
  UnifiedThreatInput,
  UnifiedThreatAnalysis,
  UnifiedIncidentObject,
  ThreatSource,
  DetectorEvidence,
  RecommendedAction,
  AnalysisCoverage,
  NormalizedEmail,
  UnifiedEmailAnalysisResult,
} from './types';
import { EmailAdapter } from './adapters/EmailAdapter';
import { SMSAdapter } from './adapters/SMSAdapter';
import { WebAdapter } from './adapters/WebAdapter';
import { QRAdapter } from './adapters/QRAdapter';

import { ActionRiskDetector } from './detectors/ActionRiskDetector';
import { IdentityDetector } from './detectors/IdentityDetector';
import { RelationshipDetector } from './detectors/RelationshipDetector';
import { BehaviourDetector } from './detectors/BehaviourDetector';
import { IntentDetector } from './detectors/IntentDetector';
import { PromptInjectionDetector } from './detectors/PromptInjectionDetector';
import { SensitiveDataDetector } from './detectors/SensitiveDataDetector';
import { TechnicalDetector } from './detectors/TechnicalDetector';
import { AdversarialEvasionDetector } from './detectors/AdversarialEvasionDetector';
import { executeEmailForensics } from './forensicsEngineProxy';

import { AttackSequenceEngine } from './attackSequenceEngine';
import { EvidenceCorrelator } from './evidenceCorrelator';
import { EvidenceFusionEngine } from './evidenceFusionEngine';
import { ForensicEvidenceGraphBuilder } from './forensicEvidenceGraph';
import { RiskEngine } from './riskEngine';
import { DynamicTrustEngine } from './dynamicTrustModel';
import { CampaignFingerprintEngine } from './campaignFingerprintEngine';
import { EvidenceProvenanceEngine } from './evidenceProvenanceEngine';
import { EnforcementEngine } from './enforcementEngine';
import { PrivacyFilter } from './privacyFilter';
import { UnifiedInteractionEvent } from './types';

export class NeuroShieldCore {
  /**
   * Main sequence entrypoint: analyze an interaction sequence over time or across channels.
   * Models attack transitions (e.g. Conversation A gradual escalation).
   */
  static async analyzeSequence(
    sequence: UnifiedInteractionEvent[]
  ): Promise<UnifiedThreatAnalysis> {
    if (!sequence || sequence.length === 0) {
      throw new Error('Cannot analyze empty interaction sequence');
    }

    if (sequence.length === 1) {
      return NeuroShieldCore.analyze(sequence[0]);
    }

    const latestEvent = sequence[sequence.length - 1];
    const priorEvents = sequence.slice(0, sequence.length - 1);

    const sequenceMetadataEvents = priorEvents.map((ev, idx) => {
      const normalizedEv = NeuroShieldCore.normalize(ev);
      const actionRes = ActionRiskDetector.evaluate(normalizedEv);
      const behRes = BehaviourDetector.evaluate(normalizedEv);
      const sensRes = SensitiveDataDetector.evaluate(normalizedEv);
      const identRes = IdentityDetector.evaluate(normalizedEv);

      let stage = 'STAGE_TRANSITION';
      if (idx === 0) stage = 'NEW_CONTACT';
      else if (identRes.analysis.claimedIdentity || identRes.analysis.isSpoofed) stage = 'IDENTITY_CLAIM';
      else if (behRes.analysis.isolationRequested || behRes.analysis.coercionScore > 0) stage = 'TRUST_BUILDING';
      else if (behRes.analysis.urgencyScore > 20) stage = 'URGENCY';
      else if (sensRes.analysis.detected) stage = 'SENSITIVE_REQUEST';
      else if (actionRes.analysis.detectedAction !== 'UNKNOWN') stage = 'PAYMENT_CREDENTIAL_ACTION';

      return {
        timestamp: ev.timestamp || new Date().toISOString(),
        source: ev.source,
        channel: ev.source,
        entity: ev.sender?.displayName || ev.sender?.identifier || 'Entity',
        stage,
        action: actionRes.analysis.detectedAction,
        evidence: `Prior interaction on ${ev.source}: ${ev.content.substring(0, 100)}`,
        riskContribution: sensRes.analysis.detected || actionRes.analysis.actionRisk === 'CRITICAL' ? 35 : 15,
        riskChange: 15
      };
    });

    const enrichedLatestEvent: UnifiedInteractionEvent = {
      ...latestEvent,
      metadata: {
        ...(latestEvent.metadata || {}),
        events: sequenceMetadataEvents,
        sequenceDepth: sequence.length,
        isMultiMessageSequence: true
      },
      history: latestEvent.history || {
        previousInteractionsCount: priorEvents.length,
        firstContactDate: sequence[0].timestamp || new Date().toISOString(),
        isKnownContact: false
      }
    };

    return NeuroShieldCore.analyze(enrichedLatestEvent);
  }

  /**
   * Authoritative Email Analysis Entrypoint (Phase 2 Canonical Email Pipeline)
   * 
   * EMAIL -> NORMALIZE -> IDENTITY -> CONTEXT -> BEHAVIOUR -> INTENT -> SENSITIVE DATA ->
   * ACTION RISK -> TECHNICAL EVIDENCE -> ADVERSARIAL ANALYSIS -> PROMPT INJECTION ->
   * EVIDENCE FUSION -> ATTACK TRANSITION -> RISK ENGINE -> PROTECTION POLICY
   */
  static async analyzeEmail(
    email: NormalizedEmail | any
  ): Promise<UnifiedEmailAnalysisResult> {
    const normalizedEmail = EmailAdapter.toNormalizedEmail(email);
    const unifiedInput = EmailAdapter.toUnifiedInput(normalizedEmail);

    const analysis = await NeuroShieldCore.analyze(unifiedInput);

    const client = email?.metadata?.client || normalizedEmail?.metadata?.client || 'gmail_api';
    const clientCapabilities = email?.metadata?.clientCapabilities || normalizedEmail?.metadata?.clientCapabilities || {};
    const actualEnforced = Boolean(email?.metadata?.actualEnforcementApplied || normalizedEmail?.metadata?.actualEnforcementApplied);

    const authDecision = EnforcementEngine.evaluatePolicy({
      incidentId: analysis.incident_id,
      verdict: analysis.verdict,
      riskScore: analysis.risk_score,
      confidence: analysis.confidence,
      coverage: analysis.analysis_coverage,
      requestedAction: analysis.action_risk?.detectedAction || 'UNKNOWN',
      threatTypes: analysis.attack_types,
      sensitiveData: analysis.sensitive_data,
      technical: analysis.technical_evidence,
      evidence: analysis.evidence_provenance || analysis.evidence || [],
      client,
      clientCapabilities,
      actualEnforcementApplied: actualEnforced,
    });

    return {
      incidentId: analysis.incident_id,
      verdict: analysis.verdict,
      riskScore: analysis.risk_score,
      confidence: analysis.confidence,
      analysisCoverage: analysis.analysis_coverage,
      threatTypes: analysis.attack_types,
      identity: analysis.identity,
      context: analysis.relationship,
      behaviour: analysis.behaviour,
      intent: analysis.intent,
      sensitiveData: analysis.sensitive_data,
      actionRisk: analysis.action_risk,
      technicalEvidence: analysis.technical_evidence,
      adversarialEvidence: analysis.evasion || {
        status: 'available',
        detected: false,
        evasionRiskScore: 0,
        techniques: [],
        homoglyphsDetected: false,
        punycodeDetected: false,
        urlObfuscationDetected: false,
        redirectChainDetected: false,
        htmlObfuscationDetected: false,
        hiddenLinksDetected: false,
        mixedScriptDetected: false,
        evidence: [],
      },
      attackSequence: analysis.attack_sequence,
      protectionDecision: (authDecision.protectionDecision.startsWith('BLOCK') ? 'BLOCK' : authDecision.protectionDecision) as any,
      enforcementLevel: authDecision.enforcementLevel,
      enforcementStatus: authDecision.enforcementStatus,
      authoritativeProtectionDecision: authDecision,
      blockedAction: authDecision.protectionDecision.startsWith('BLOCK') ? authDecision.requestedAction : null,
      client,
      evidence: analysis.evidence_provenance || analysis.evidence || [],
      normalizedEmail,
      summary: analysis.recommended_action?.summary,
      whyRiskIncreased: analysis.whyRiskIncreased,
      recommendedAction: analysis.recommended_action,
      timestamp: analysis.timestamp,
    };
  }

  /**
   * Main entrypoint: analyze any incoming communication across all channels.
   */
  static async analyze(
    rawInput: UnifiedThreatInput | any,
    explicitSource?: ThreatSource
  ): Promise<UnifiedThreatAnalysis> {
    const startTime = Date.now();

    try {
      // 1. NORMALIZE
      const normalizedInput = NeuroShieldCore.normalize(rawInput, explicitSource);

      // 2. RUN AVAILABLE DETECTORS IN ISOLATED RUNNERS
      const detectorsRun: string[] = [];
      const detectorsUnavailable: Array<{ detector: string; reason: string }> = [];
      const evidenceCollection: DetectorEvidence[] = [];

      // Detector 1: Action Risk
      const actionResult = ActionRiskDetector.evaluate(normalizedInput);
      detectorsRun.push('action_risk');
      evidenceCollection.push(actionResult.evidence);

      // Detector 2: Identity Engine
      const identityResult = IdentityDetector.evaluate(normalizedInput);
      if (identityResult.analysis.status === 'available') {
        detectorsRun.push('identity_engine');
        evidenceCollection.push(identityResult.evidence);
      } else {
        detectorsUnavailable.push({
          detector: 'identity_engine',
          reason: identityResult.analysis.statusReason || 'Sender metadata missing',
        });
      }

      // Detector 3: Relationship & Context Engine
      const relationshipResult = RelationshipDetector.evaluate(normalizedInput);
      if (relationshipResult.analysis.status === 'available') {
        detectorsRun.push('relationship_engine');
        evidenceCollection.push(relationshipResult.evidence);
      } else {
        detectorsUnavailable.push({
          detector: 'relationship_engine',
          reason: relationshipResult.analysis.statusReason || 'No historical interaction data provided',
        });
      }

      // Detector 4: Behaviour & Coercion Engine
      const behaviourResult = BehaviourDetector.evaluate(normalizedInput);
      detectorsRun.push('behaviour_engine');
      evidenceCollection.push(behaviourResult.evidence);

      // Detector 5: Intent Engine
      const intentResult = IntentDetector.evaluate(normalizedInput);
      detectorsRun.push('intent_engine');
      evidenceCollection.push(intentResult.evidence);

      // Detector 6: Adversarial Prompt Injection Detector
      const promptInjectionResult = PromptInjectionDetector.evaluate(normalizedInput);
      detectorsRun.push('prompt_injection');
      evidenceCollection.push(promptInjectionResult.evidence);

      // Detector 7: Sensitive Data Detector
      const sensitiveDataResult = SensitiveDataDetector.evaluate(normalizedInput);
      detectorsRun.push('sensitive_data');
      evidenceCollection.push(sensitiveDataResult.evidence);

      // Detector 8: Technical Evidence Detector
      const technicalResult = TechnicalDetector.evaluate(normalizedInput);
      detectorsRun.push('technical_evidence');
      evidenceCollection.push(technicalResult.evidence);

      // Detector 9: Adversarial & Evasion Detector (Phase 7.5)
      const evasionResult = AdversarialEvasionDetector.evaluate(normalizedInput);
      detectorsRun.push('adversarial_evasion');
      evidenceCollection.push(evasionResult.evidence);

      // 3. OPTIONAL DEEP FORENSIC LAB ENRICHMENT (For Email RFC 5322 inputs)
      let emailDossier: any = undefined;
      if (normalizedInput.source === 'email' && normalizedInput.rawPayload && /^(From|Received|Return-Path):/im.test(normalizedInput.rawPayload)) {
        try {
          emailDossier = await executeEmailForensics(normalizedInput.rawPayload, normalizedInput.content);
        } catch (err) {
          console.warn('Deep RFC 5322 email forensics skipped:', err);
        }
      }

      // 4. CENTRAL EVIDENCE FUSION (Phase 4 & Phase 7.5 Decision Layer)
      const fusionResult = EvidenceFusionEngine.fuse({
        input: normalizedInput,
        identity: identityResult.analysis,
        relationship: relationshipResult.analysis,
        behaviour: behaviourResult.analysis,
        intent: intentResult.analysis,
        actionRisk: actionResult.analysis,
        technical: technicalResult.analysis,
        promptInjection: promptInjectionResult.analysis,
        sensitiveData: sensitiveDataResult.analysis,
        emailDossier,
        evasion: evasionResult.analysis,
      });

      // Also run EvidenceCorrelator for backward compatibility
      const correlationResult = EvidenceCorrelator.correlate({
        identity: identityResult.analysis,
        relationship: relationshipResult.analysis,
        behaviour: behaviourResult.analysis,
        intent: intentResult.analysis,
        actionRisk: actionResult.analysis,
        technical: technicalResult.analysis,
        promptInjection: promptInjectionResult.analysis,
        sensitiveData: sensitiveDataResult.analysis,
      });

      // 5. ATTACK-SEQUENCE ENGINE (Multi-Stage & Single-Event Representation)
      const attackSequence = AttackSequenceEngine.evaluate(normalizedInput, {
        identity: identityResult.analysis,
        relationship: relationshipResult.analysis,
        behaviour: behaviourResult.analysis,
        actionRisk: actionResult.analysis,
        technical: technicalResult.analysis,
      });

      // 6. DYNAMIC TRUST MODEL (Phase 7.5 Zero-Trust Architecture)
      const dynamicTrust = DynamicTrustEngine.evaluate({
        input: normalizedInput,
        identity: identityResult.analysis,
        relationship: relationshipResult.analysis,
        behaviour: behaviourResult.analysis,
        intent: intentResult.analysis,
        technical: technicalResult.analysis,
        actionRisk: actionResult.analysis,
        promptInjection: promptInjectionResult.analysis,
        sensitiveData: sensitiveDataResult.analysis,
        evasion: evasionResult.analysis,
      });

      // 7. ATTACK CAMPAIGN FINGERPRINT & CROSS-CHANNEL CORRELATION (Phase 7.5)
      const primaryAttackCategory = fusionResult.attackTypes[0] || 'CREDENTIAL_THEFT';
      const campaignFingerprint = CampaignFingerprintEngine.generateFingerprint({
        input: normalizedInput,
        identity: identityResult.analysis,
        technical: technicalResult.analysis,
        actionRisk: actionResult.analysis,
        attackCategory: primaryAttackCategory,
      });

      const crossChannelAnalysis = CampaignFingerprintEngine.evaluateCrossChannelCorrelation(
        normalizedInput,
        campaignFingerprint
      );

      // 8. FORENSIC EVIDENCE GRAPH BUILDER (Phase 7.5 Full Entity Correlation)
      const evidenceGraph = ForensicEvidenceGraphBuilder.build(
        normalizedInput,
        {
          identity: identityResult.analysis,
          actionRisk: actionResult.analysis,
          technical: technicalResult.analysis,
          promptInjection: promptInjectionResult.analysis,
          evasion: evasionResult.analysis,
        },
        attackSequence
      );

      // 9. THREAT DECISION & RISK ENGINE (5-Tier Normalized Decision)
      const decision = RiskEngine.computeDecision(fusionResult.fusedRiskScore, attackSequence);
      let finalRiskScore = decision.riskScore;
      let riskLevel = decision.riskLevel;
      let verdict = decision.verdict;

      // Fail-Safe for Empty Telemetry: If input has no content, no URLs, and no attachments, do not falsely classify as SAFE
      const isEmptyContent = !normalizedInput.content || normalizedInput.content.trim() === '';
      const hasNoAssets = (!normalizedInput.urls || normalizedInput.urls.length === 0) && (!normalizedInput.attachments || normalizedInput.attachments.length === 0);
      if (isEmptyContent && hasNoAssets) {
        verdict = 'UNKNOWN';
        riskLevel = 'MEDIUM';
        finalRiskScore = 40;
      }

      // Synthesize all threat signatures
      const threats = Array.from(new Set([
        ...fusionResult.correlatedThreats,
        ...correlationResult.correlatedThreats,
      ]));
      if (promptInjectionResult.analysis.detected && !threats.some((t) => t.includes('Prompt Injection'))) {
        threats.push('Adversarial AI Prompt Injection');
      }
      if (technicalResult.analysis.reverseTunnelDetected && !threats.some((t) => t.includes('Tunnel'))) {
        threats.push('Ephemeral Reverse Tunnel Evasion');
      }
      if (technicalResult.analysis.typosquattingDetected && !threats.some((t) => t.includes('Typosquatting'))) {
        threats.push('Domain Typosquatting / Brand Spoofing');
      }
      if (identityResult.analysis.isSpoofed && !threats.some((t) => t.includes('Impersonation'))) {
        threats.push('Sender Identity Impersonation');
      }
      if (actionResult.analysis.detectedAction === 'TRANSFER_MONEY' && !threats.some((t) => t.includes('Wire') || t.includes('Financial'))) {
        threats.push('Financial Extortion / Wire Redirection');
      }
      if (evasionResult.analysis.detected && !threats.some((t) => t.includes('Evasion') || t.includes('Obfuscation'))) {
        threats.push('Adversarial Lookalike Evasion / Deceptive Character Encoding');
      }

      // 10. STRUCTURED FEATURE VECTOR (v2.0 13-Feature XGBoost / Model Specification)
      const featureVector = RiskEngine.extractFeatureVector({
        identity: identityResult.analysis,
        relationship: relationshipResult.analysis,
        behaviour: behaviourResult.analysis,
        intent: intentResult.analysis,
        actionRisk: actionResult.analysis,
        contentRiskScore: fusionResult.contentRisk.score,
        technical: technicalResult.analysis,
        promptInjection: promptInjectionResult.analysis,
        sensitiveData: sensitiveDataResult.analysis,
        attackSequence,
        evidenceCount: fusionResult.evidenceWithProvenance.length,
        coverage: fusionResult.coverage,
      });

      // 11. ACTION-ORIENTED PROTECTIVE RECOMMENDATIONS (ALLOW | WARN | STRONG_WARN | BLOCK)
      const protectiveDecision = RiskEngine.generateProtectiveAction({
        verdict,
        riskLevel,
        confidence: fusionResult.confidenceScore,
        actionRisk: actionResult.analysis,
        sensitiveData: sensitiveDataResult.analysis,
        technical: technicalResult.analysis,
        promptInjection: promptInjectionResult.analysis,
      });

      // 12. COMPREHENSIVE PROVENANCE
      const provenanceItems = EvidenceProvenanceEngine.buildProvenance({
        input: normalizedInput,
        identity: identityResult.analysis,
        relationship: relationshipResult.analysis,
        behaviour: behaviourResult.analysis,
        intent: intentResult.analysis,
        technical: technicalResult.analysis,
        actionRisk: actionResult.analysis,
        promptInjection: promptInjectionResult.analysis,
        sensitiveData: sensitiveDataResult.analysis,
        evasion: evasionResult.analysis,
      });

      const mergedProvenance = [...fusionResult.evidenceWithProvenance];
      for (const item of provenanceItems) {
        if (!mergedProvenance.some((p) => p.signal === item.signal && p.detector === item.detector)) {
          mergedProvenance.push(item);
        }
      }

      const evaluationTimeMs = Date.now() - startTime;
      const incidentId = `inc_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 7)}`;

      const client = normalizedInput.metadata?.client || (normalizedInput.source === 'email' ? 'gmail_api' : 'headless');
      const clientCapabilities = normalizedInput.metadata?.clientCapabilities || {};
      const actualEnforcementApplied = Boolean(normalizedInput.metadata?.actualEnforcementApplied);

      const authDecision = EnforcementEngine.evaluatePolicy({
        incidentId,
        verdict,
        riskScore: finalRiskScore,
        confidence: fusionResult.confidenceScore,
        coverage: fusionResult.coverage,
        requestedAction: actionResult.analysis.detectedAction,
        threatTypes: fusionResult.attackTypes,
        sensitiveData: sensitiveDataResult.analysis,
        technical: technicalResult.analysis,
        evidence: mergedProvenance,
        client,
        clientCapabilities,
        actualEnforcementApplied,
      });

      // 13. UNIFIED INCIDENT OBJECT (Phase 7.5 Canonical Contract)
      const incident: UnifiedIncidentObject = {
        incident_id: incidentId,
        source: normalizedInput.source,
        verdict,
        risk_level: riskLevel,
        risk_score: finalRiskScore,
        confidence: fusionResult.confidenceScore,

        attack_types: fusionResult.attackTypes,

        content_risk: fusionResult.contentRisk,
        action_risk: {
          ...actionResult.analysis,
          ...fusionResult.actionRiskAssessment,
        },
        combined_risk: fusionResult.combinedRisk,

        identity: identityResult.analysis,
        relationship: relationshipResult.analysis,
        behaviour: behaviourResult.analysis,
        intent: intentResult.analysis,
        action: actionResult.analysis,

        technical_evidence: technicalResult.analysis,
        prompt_injection: promptInjectionResult.analysis,
        sensitive_data: sensitiveDataResult.analysis,

        attack_sequence: attackSequence,
        evidence: evidenceCollection,
        evidence_provenance: mergedProvenance,
        conflicts: fusionResult.conflicts,

        cross_channel: crossChannelAnalysis,
        analysis_coverage: {
          ...fusionResult.coverage,
          detectorsRun,
          detectorsUnavailable,
        },

        // Phase 7.5 Advanced Security Intelligence Fields
        identity_continuity: identityResult.analysis.continuity,
        dynamic_trust: dynamicTrust,
        evasion: evasionResult.analysis,
        campaign_fingerprint: campaignFingerprint,

        protection: {
          decision: protectiveDecision.decision,
          protectionDecision: authDecision.protectionDecision,
          enforcementLevel: authDecision.enforcementLevel,
          enforcementStatus: authDecision.enforcementStatus,
          authoritativeDecision: authDecision,
          recommended_action: protectiveDecision.recommended_action,
          steps: protectiveDecision.steps,
          interventions: protectiveDecision.interventions,
          circuit_breakers: protectiveDecision.circuit_breakers,
          safe_alternative: protectiveDecision.safe_alternative,
          warning_card: protectiveDecision.warning_card,
        },

        // Phase 4 Authoritative Protection Decision & Real Enforcement Status
        protectionDecision: authDecision.protectionDecision,
        enforcementLevel: authDecision.enforcementLevel,
        enforcementStatus: authDecision.enforcementStatus,
        enforcedAt: actualEnforcementApplied ? new Date().toISOString() : undefined,
        blockedAction: authDecision.protectionDecision.startsWith('BLOCK') ? authDecision.requestedAction : null,
        client,
        authoritativeProtectionDecision: authDecision,

        forensics: emailDossier,
        feature_vector: featureVector,

        // Backward compatibility fields
        threats,
        whyRiskIncreased: Array.from(new Set([...fusionResult.whyRiskIncreased, ...correlationResult.whyRiskIncreased])),
        correlated_evidence: correlationResult.evidenceMap,
        evidence_graph: evidenceGraph,
        recommended_action: protectiveDecision,

        timestamp: new Date().toISOString(),
        evaluationTimeMs,
      };

      return incident;
    } catch (coreError: any) {
      console.error('[NeuroShieldCore] Detection pipeline caught unexpected error. Failing safe to UNKNOWN:', coreError);

      const evaluationTimeMs = Date.now() - startTime;
      const incidentId = `inc_err_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`;
      const inferredSource = explicitSource || 'email';

      const coverage: AnalysisCoverage = {
        available: [],
        unavailable: [{ component: 'core_detection_pipeline', reason: 'Pipeline failure during analysis' }],
        failed: [{ component: 'neuroshield_core', error: coreError?.message || 'Unexpected execution error' }],
        coverageRatio: 0.1,
        confidenceRating: 'LOW',
        detectorsRun: [],
        detectorsUnavailable: [{ detector: 'neuroshield_core', reason: coreError?.message || 'Pipeline error' }],
      };

      const protectiveDecision = RiskEngine.generateProtectiveAction({
        verdict: 'UNKNOWN',
        riskLevel: 'MEDIUM',
        confidence: 15,
        actionRisk: {
          detectedAction: 'UNKNOWN',
          actionRisk: 'MEDIUM',
          preventiveIntervention: 'Central analysis encountered a processing error. Exercise caution.',
          evidence: ['Analysis incomplete'],
        },
        sensitiveData: {
          status: 'unavailable',
          detected: false,
          categories: [],
          risk: 0,
          demandsCredentials: false,
          demandsOtp: false,
          demandsPayment: false,
          demandsPii: false,
          matchedCategories: [],
          maskedItems: [],
          riskScore: 0,
          evidence: [],
        },
        technical: {
          status: 'unavailable',
          urlsEvaluated: 0,
          reverseTunnelDetected: false,
          riskScore: 0,
          evidence: [],
        },
        promptInjection: {
          status: 'unavailable',
          detected: false,
          overrideTokens: [],
          adversarialRiskScore: 0,
          evidence: [],
        },
      });

      const failSafeAuthDecision: import('./types').AuthoritativeProtectionDecision = {
        verdict: 'UNKNOWN',
        riskScore: 50,
        confidence: 15,
        requestedAction: 'UNKNOWN',
        threatTypes: ['UNKNOWN'],
        protectionDecision: 'WARN',
        enforcementLevel: 'FAIL_SAFE_OFFLINE_CAUTION',
        enforcementStatus: 'UNKNOWN',
        evidence: ['Pipeline failure during analysis', coreError?.message || 'Execution error'],
      };

      return {
        incident_id: incidentId,
        source: inferredSource,
        verdict: 'UNKNOWN',
        risk_level: 'MEDIUM',
        risk_score: 50,
        confidence: 15,
        attack_types: ['UNKNOWN'],
        content_risk: { level: 'MEDIUM', score: 50, indicators: ['ANALYSIS_INCOMPLETE'] },
        action_risk: {
          detectedAction: 'UNKNOWN',
          detected_action: 'UNKNOWN',
          actionRisk: 'MEDIUM',
          level: 'MEDIUM',
          score: 50,
          target_destination: null,
          evidence: ['Analysis failed gracefully to UNKNOWN'],
          preventiveIntervention: 'Exercise caution before proceeding.',
        },
        combined_risk: { level: 'MEDIUM', score: 50 },
        identity: { status: 'unavailable', risk: 0, riskScore: 0, signals: [], evidence: [] },
        relationship: { status: 'unavailable', relationshipState: 'UNKNOWN', firstContact: null, interactionCount: null, behaviourShiftDetected: null, riskScore: 0, evidence: [] },
        behaviour: { status: 'unavailable', urgencyScore: 0, coercionScore: 0, isolationRequested: false, secrecyKeywords: [], riskScore: 0, evidence: [] },
        intent: { status: 'unavailable', primaryIntent: 'UNKNOWN', intentConfidence: 0, evidence: [] },
        action: { detectedAction: 'UNKNOWN', actionRisk: 'MEDIUM', evidence: [], preventiveIntervention: 'Exercise caution.' },
        technical_evidence: { status: 'unavailable', urlsEvaluated: 0, reverseTunnelDetected: false, riskScore: 0, evidence: [] },
        prompt_injection: { status: 'unavailable', detected: false, overrideTokens: [], adversarialRiskScore: 0, evidence: [] },
        sensitive_data: { status: 'unavailable', detected: false, categories: [], risk: 0, demandsCredentials: false, demandsOtp: false, demandsPayment: false, demandsPii: false, matchedCategories: [], maskedItems: [], riskScore: 0, evidence: [] },
        attack_sequence: { isSequenceProgression: false, sequenceType: 'SINGLE_EVENT', sequence_depth: 1, context_status: 'LIMITED', summary: 'Single interaction event', stagesDetected: ['BENIGN_INTERACTION'], events: [], escalationRate: 'NONE', compoundSequenceRisk: 50, evidence: [] },
        evidence: [],
        conflicts: [],
        analysis_coverage: coverage,
        identity_continuity: {
          identity_match: null,
          identity_mismatch: false,
          identity_change: false,
          identity_novelty: false,
          identity_confidence: 0,
          historical_identity_analysis: 'UNAVAILABLE',
          evidence: ['Historical continuity telemetry unavailable during fail-safe execution.'],
          signals: [],
        },
        dynamic_trust: {
          baseline_trust: 50,
          current_trust: 50,
          trust_delta: 0,
          trust_level: 'CONDITIONAL',
          reason: 'Dynamic trust model evaluated in fail-safe UNKNOWN mode.',
          trust_decay_factors: [],
          evidence: ['Fail-safe mode: neutral zero-trust posture maintained.'],
        },
        evasion: {
          status: 'unavailable',
          detected: false,
          evasionRiskScore: 0,
          techniques: [],
          homoglyphsDetected: false,
          punycodeDetected: false,
          urlObfuscationDetected: false,
          redirectChainDetected: false,
          htmlObfuscationDetected: false,
          hiddenLinksDetected: false,
          mixedScriptDetected: false,
          evidence: ['Adversarial evasion detector unavailable during error recovery.'],
        },
        protection: {
          decision: 'WARN',
          protectionDecision: 'WARN',
          enforcementLevel: 'FAIL_SAFE_OFFLINE_CAUTION',
          enforcementStatus: 'UNKNOWN',
          authoritativeDecision: failSafeAuthDecision,
          recommended_action: 'Verification incomplete due to pipeline exception. Exercise standard security precautions.',
          steps: ['Exercise caution before entering credentials or sharing OTPs.', 'Try re-scanning the input.'],
          interventions: ['Display caution notice'],
          circuit_breakers: [],
          safe_alternative: protectiveDecision.safe_alternative,
          warning_card: protectiveDecision.warning_card,
        },
        protectionDecision: 'WARN',
        enforcementLevel: 'FAIL_SAFE_OFFLINE_CAUTION',
        enforcementStatus: 'UNKNOWN',
        client: explicitSource === 'email' ? 'gmail_api' : 'headless',
        failureReason: coreError?.message || 'Pipeline error',
        authoritativeProtectionDecision: failSafeAuthDecision,
        feature_vector: {
          identity_risk: 0,
          relationship_risk: 0,
          behaviour_risk: 0,
          intent_risk: 0,
          action_risk: 50,
          content_risk: 50,
          technical_risk: 0,
          url_risk: 0,
          prompt_injection_risk: 0,
          sensitive_data_risk: 0,
          sequence_risk: 50,
          evidence_count: 0,
          analysis_coverage: 0.1,
          feature_vector_version: '2.0-fallback',
        },
        threats: ['Analysis Incomplete / Telemetry Offline'],
        recommended_action: protectiveDecision,
        timestamp: new Date().toISOString(),
        evaluationTimeMs,
      };
    }
  }

  /**
   * Normalize any input into the UnifiedThreatInput common contract
   */
  private static normalize(
    input: UnifiedThreatInput | any,
    explicitSource?: ThreatSource
  ): UnifiedThreatInput {
    // If already structured with source and content
    if (input && typeof input === 'object' && input.source && typeof input.content === 'string') {
      const extractedUrls = (Array.isArray(input.urls) && input.urls.length > 0)
        ? input.urls
        : Array.from(new Set(Array.from(input.content.matchAll(/https?:\/\/[^\s"'<>]+/gi)).map((m: any) => m[0])));

      let sender = input.sender || null;
      let recipient = input.recipient || null;
      let metadata = input.metadata || {};

      if (input.source === 'email' && !sender && /^(From|To|Subject):/im.test(input.content)) {
        const emailParsed = EmailAdapter.normalize(input.content);
        sender = sender || emailParsed.sender;
        recipient = recipient || emailParsed.recipient;
        metadata = { ...emailParsed.metadata, ...metadata };
      }

      return PrivacyFilter.apply({
        source: input.source,
        content: input.content,
        rawPayload: input.rawPayload,
        sender,
        recipient,
        urls: extractedUrls,
        attachments: input.attachments || [],
        metadata,
        history: input.history || null,
        user_action: input.user_action || null,
      });
    }

    // Determine target source
    const targetSource = explicitSource || NeuroShieldCore.inferSource(input);
    let normalized: UnifiedThreatInput;

    switch (targetSource) {
      case 'sms':
        normalized = SMSAdapter.normalize(input);
        break;
      case 'web':
        normalized = WebAdapter.normalize(input);
        break;
      case 'qr':
        normalized = QRAdapter.normalize(input);
        break;
      case 'email':
      default:
        normalized = EmailAdapter.normalize(input);
        break;
    }

    return PrivacyFilter.apply(normalized);
  }

  /**
   * Infer source channel if not explicitly specified
   */
  private static inferSource(input: any): ThreatSource {
    if (typeof input === 'string') {
      const clean = input.trim();
      if (/^(WIFI:|BEGIN:VCARD|(bitcoin|ethereum):)/i.test(clean)) return 'qr';
      if (/^https?:\/\//i.test(clean) && !clean.includes('\n')) return 'web';
      if (/^(From|Received|Return-Path|Subject):/im.test(clean)) return 'email';
      if (/^\[[A-Z0-9_-]{3,12}\]/i.test(clean)) return 'sms';
      return 'email'; // Default common text
    }

    if (typeof input === 'object' && input !== null) {
      if (input.rawQrData) return 'qr';
      if (input.url && !input.from) return 'web';
      if (input.senderPhone || input.recipientPhone) return 'sms';
      if (input.from || input.rawHeaders) return 'email';
    }

    return 'email';
  }

  /**
   * Generate situation-specific, concise, actionable prevention guidance
   */
  private static generateActionGuidance(
    verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN',
    riskScore: number,
    actionRisk: any,
    threats: string[]
  ): RecommendedAction {
    if (verdict === 'MALICIOUS' || riskScore >= 70) {
      const steps = [
        'Do NOT click any links, open attachments, or scan QR codes in this communication.',
        actionRisk.preventiveIntervention,
        'Verify the sender identity out-of-band using an official, independently verified contact directory.',
      ];

      if (actionRisk.detectedAction === 'TRANSFER_MONEY') {
        steps.push('Do NOT transfer money, approve invoices, or purchase gift cards.');
      } else if (actionRisk.detectedAction === 'SHARE_OTP') {
        steps.push('Never disclose your OTP, authentication code, or password to anyone.');
      }

      return {
        action: 'BLOCK',
        summary: `HIGH RISK: Identified ${threats[0] || 'adversarial social engineering attack'}. Prevent user compromise.`,
        steps,
        interventions: [
          'Suppress hyperlink navigation',
          'Disable credential autofill',
          'Block attachment preview/execution',
        ],
        circuitBreakers: [
          'ACTION_INTERCEPTED',
          'OUT_OF_BAND_CONFIRMATION_REQUIRED',
        ],
      };
    }

    if (verdict === 'SUSPICIOUS' || riskScore >= 35) {
      return {
        action: 'WARN',
        summary: 'SUSPICIOUS: Potential identity or context anomaly detected. Exercise heightened caution.',
        steps: [
          'Inspect the sender domain and URL destination carefully before interacting.',
          actionRisk.preventiveIntervention,
          'Do not share passwords, financial details, or OTPs.',
        ],
        interventions: ['Display warning banner', 'Prompt user confirmation before navigation'],
        circuitBreakers: ['STEP_UP_USER_WARNING'],
      };
    }

    if (verdict === 'UNKNOWN') {
      return {
        action: 'GUIDE',
        summary: 'INSUFFICIENT TELEMETRY: Limited metadata available. Verify source before proceeding.',
        steps: [
          'Verify sender authenticity independently.',
          'Exercise standard digital safety precautions.',
        ],
        interventions: [],
        circuitBreakers: [],
      };
    }

    return {
      action: 'ALLOW',
      summary: 'SAFE: No malicious indicators, deception tactics, or high-risk actions observed.',
      steps: ['Communication conforms to expected legitimate operational baseline.'],
      interventions: [],
      circuitBreakers: [],
    };
  }
}

export const analyzeEmail = NeuroShieldCore.analyzeEmail;
