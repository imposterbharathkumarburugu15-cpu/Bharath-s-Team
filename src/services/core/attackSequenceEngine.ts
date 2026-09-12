/**
 * NeuroShield Attack Sequence Engine
 * Phase 7.5 — Advanced Security Intelligence
 *
 * Detects attack progression trajectories and multi-event/multi-channel sequences:
 * e.g., IDENTITY_NOVELTY → TRUST_BUILDING → URGENCY → SENSITIVE_REQUEST → PAYMENT_CREDENTIAL_ACTION
 * Multi-channel: EMAIL → SMS → WEB → QR
 *
 * STRICT FORENSIC DIRECTIVES:
 * 1. If only one event exists in observable telemetry:
 *    sequence_status = 'SINGLE_EVENT'
 *    Never fabricate or extrapolate past events.
 * 2. Every event contains: timestamp, channel, entity, action, evidence, risk_contribution.
 */

import {
  UnifiedThreatInput,
  AttackSequenceAnalysis,
  AttackSequenceEvent,
  AttackStage,
  IdentityAnalysis,
  RelationshipAnalysis,
  BehaviourAnalysis,
  ActionRiskAnalysis,
  TechnicalEvidenceAnalysis,
} from './types';

export class AttackSequenceEngine {
  static evaluate(
    input: UnifiedThreatInput,
    detectors: {
      identity: IdentityAnalysis;
      relationship: RelationshipAnalysis;
      behaviour: BehaviourAnalysis;
      actionRisk: ActionRiskAnalysis;
      technical: TechnicalEvidenceAnalysis;
    }
  ): AttackSequenceAnalysis {
    const history = input.history;
    const metadataEvents: any[] = Array.isArray(input.metadata?.events) ? input.metadata.events : [];
    const hasExplicitHistory = Boolean(history !== null && history !== undefined);
    const hasCompositeStages = (
      (Boolean(detectors.identity.claimedIdentity) || detectors.identity.isSpoofed) &&
      (detectors.behaviour.urgencyScore > 0 || detectors.behaviour.isolationRequested) &&
      detectors.actionRisk.detectedAction !== 'UNKNOWN'
    );

    // SINGLE-EVENT ANALYSIS: When only one event exists, no historical context is present, and no composite stage attack pattern is observed
    if (!hasExplicitHistory && metadataEvents.length <= 1 && !hasCompositeStages) {
      const currentStage = this.identifyCurrentStage(detectors);
      const actionLabel = detectors.actionRisk.detectedAction;
      const riskVal = detectors.actionRisk.actionRisk === 'CRITICAL' ? 85 : detectors.actionRisk.actionRisk === 'HIGH' ? 65 : 20;

      const singleEvent: AttackSequenceEvent = {
        step: 1,
        stage: currentStage,
        timestamp: input.metadata?.timestamp || new Date().toISOString(),
        source: input.source,
        channel: input.source,
        entity: input.sender?.displayName || input.sender?.identifier || 'Sender',
        description: `Current message observation: ${actionLabel}`,
        actionObserved: actionLabel,
        evidence: `Single-event observation on ${input.source.toUpperCase()} channel: ${actionLabel}.`,
        riskChange: riskVal,
        riskContribution: riskVal,
      };

      return {
        isSequenceProgression: false,
        sequenceType: 'SINGLE_EVENT',
        sequence_status: 'SINGLE_EVENT',
        sequence_depth: 1,
        context_status: 'LIMITED',
        summary: 'Single-event analysis: evaluated current observation in isolation without historical sequence extrapolation.',
        stagesDetected: [currentStage],
        events: [singleEvent],
        escalationRate: 'NONE',
        compoundSequenceRisk: riskVal,
        evidence: [
          'Single-event analysis: evaluated current observation in isolation without historical sequence extrapolation.',
          `Observable stage: ${currentStage} (Action: ${actionLabel}, Channel: ${input.source}).`,
        ],
      };
    }

    // MULTI-STAGE PROGRESSION: Correlate actual historical/metadata events
    const stagesDetected: AttackStage[] = [];
    const events: AttackSequenceEvent[] = [];
    const evidence: string[] = [];
    let cumulativeRisk = 10;
    let stepCount = 1;

    // Check if metadata provides explicit prior sequence events
    if (metadataEvents.length > 1) {
      for (const ev of metadataEvents) {
        const stage = ev.stage || 'STAGE_TRANSITION';
        stagesDetected.push(stage);
        events.push({
          step: stepCount++,
          stage,
          timestamp: ev.timestamp || new Date().toISOString(),
          source: ev.source || input.source,
          channel: ev.channel || ev.source || input.source,
          entity: ev.entity || input.sender?.identifier || 'Entity',
          description: ev.description || `Observed activity: ${ev.action || 'Unknown'}`,
          actionObserved: ev.action || 'INTERACTION',
          evidence: ev.evidence || `Observed on ${ev.channel || 'channel'}`,
          riskContribution: ev.riskContribution || 15,
          riskChange: ev.riskChange || 15,
        });
        cumulativeRisk += ev.riskContribution || 15;
      }
    } else {
      // Reconstruct sequence from verified history baseline + current interaction
      if (history?.previousInteractionsCount === 0 || detectors.relationship.firstContact) {
        stagesDetected.push('NEW_CONTACT');
        events.push({
          step: stepCount++,
          stage: 'NEW_CONTACT',
          timestamp: history?.firstContactDate || input.metadata?.timestamp || new Date().toISOString(),
          source: input.source,
          channel: input.source,
          entity: input.sender?.identifier || 'New Sender',
          description: 'Initial unsolicited contact established from unfamiliar entity.',
          actionObserved: 'INCOMING_MESSAGE',
          evidence: 'Zero prior recorded communication history.',
          riskContribution: 15,
          riskChange: 15,
        });
        cumulativeRisk += 15;
      } else if ((history?.previousInteractionsCount ?? 0) > 0) {
        stagesDetected.push('TRUST_BUILDING');
        events.push({
          step: stepCount++,
          stage: 'TRUST_BUILDING',
          timestamp: history?.firstContactDate || new Date().toISOString(),
          source: input.source,
          channel: input.source,
          entity: input.sender?.identifier || 'Established Sender',
          description: `Prior communication baseline established (${history?.previousInteractionsCount} interactions).`,
          actionObserved: 'PREVIOUS_INTERACTION',
          evidence: `Historical interaction count: ${history?.previousInteractionsCount}.`,
          riskContribution: 0,
          riskChange: 0,
        });
      }

      // Step: Identity Assertion / Spoofing
      if (detectors.identity.claimedIdentity) {
        const stage: AttackStage = 'IDENTITY_CLAIM';
        stagesDetected.push(stage);
        events.push({
          step: stepCount++,
          stage,
          timestamp: input.metadata?.timestamp || new Date().toISOString(),
          source: input.source,
          channel: input.source,
          entity: detectors.identity.claimedIdentity,
          description: detectors.identity.isSpoofed
            ? `Asserted identity '${detectors.identity.claimedIdentity}' contradicts sending origin.`
            : `Claims identity persona '${detectors.identity.claimedIdentity}'.`,
          actionObserved: 'ASSERT_IDENTITY',
          evidence: detectors.identity.evidence[0] || 'Identity assertion observed.',
          riskContribution: detectors.identity.isSpoofed ? 30 : 5,
          riskChange: detectors.identity.isSpoofed ? 30 : 5,
        });
        cumulativeRisk += detectors.identity.isSpoofed ? 30 : 5;
      }

      // Step: Coercive Urgency Pressure
      if (detectors.behaviour.urgencyScore > 30) {
        stagesDetected.push('URGENCY');
        events.push({
          step: stepCount++,
          stage: 'URGENCY',
          timestamp: input.metadata?.timestamp || new Date().toISOString(),
          source: input.source,
          channel: input.source,
          entity: input.sender?.displayName || 'Sender',
          description: `Adversary introduces artificial deadline pressure (urgency score: ${detectors.behaviour.urgencyScore}).`,
          actionObserved: 'MANUFACTURE_DEADLINE',
          evidence: `Urgency score ${detectors.behaviour.urgencyScore}/100 detected in message content.`,
          riskContribution: 20,
          riskChange: 20,
        });
        cumulativeRisk += 20;
      }

      // Step: Sensitive Request / Action Coercion
      if (detectors.actionRisk.detectedAction !== 'UNKNOWN') {
        const actionStage = this.identifyCurrentStage(detectors);
        stagesDetected.push(actionStage);
        const actionRiskVal = detectors.actionRisk.actionRisk === 'CRITICAL' ? 40 : 25;
        events.push({
          step: stepCount++,
          stage: actionStage,
          timestamp: input.metadata?.timestamp || new Date().toISOString(),
          source: input.source,
          channel: input.source,
          entity: input.sender?.displayName || 'Sender',
          description: `Demands high-risk user action: ${detectors.actionRisk.detectedAction}`,
          actionObserved: detectors.actionRisk.detectedAction,
          evidence: detectors.actionRisk.evidence[0] || 'Action risk detected.',
          riskContribution: actionRiskVal,
          riskChange: actionRiskVal,
        });
        cumulativeRisk += actionRiskVal;
      }
    }

    const escalationRate = events.length >= 4 ? 'RAPID_ESCALATION' : events.length >= 2 ? 'GRADUAL' : 'NONE';
    const compoundSequenceRisk = Math.min(100, cumulativeRisk);

    evidence.push(`Multi-stage attack progression identified across ${events.length} sequential event nodes.`);
    evidence.push(`Sequence trajectory: ${stagesDetected.join(' → ')}.`);
    evidence.push(`Escalation dynamics: ${escalationRate} with compound sequence risk of ${compoundSequenceRisk}/100.`);

    return {
      isSequenceProgression: true,
      sequenceType: 'MULTI_STAGE_PROGRESSION',
      sequence_status: 'PROGRESSION_OBSERVED',
      sequence_depth: events.length,
      context_status: 'PROGRESSION_OBSERVED',
      summary: `Multi-stage attack sequence detected (${stagesDetected.join(' → ')}). Escalation: ${escalationRate}.`,
      stagesDetected,
      events,
      escalationRate,
      compoundSequenceRisk,
      evidence,
    };
  }

  private static identifyCurrentStage(detectors: {
    actionRisk: ActionRiskAnalysis;
    behaviour: BehaviourAnalysis;
    identity: IdentityAnalysis;
    technical: TechnicalEvidenceAnalysis;
  }): AttackStage {
    if (detectors.actionRisk.detectedAction === 'TRANSFER_MONEY') return 'FINANCIAL_ACTION';
    if (
      detectors.actionRisk.detectedAction === 'SHARE_OTP' ||
      detectors.actionRisk.detectedAction === 'ENTER_PASSWORD' ||
      detectors.actionRisk.detectedAction === 'LOGIN'
    ) return 'CREDENTIAL_PROMPT';
    if (detectors.actionRisk.detectedAction === 'SHARE_SENSITIVE_DATA') return 'SENSITIVE_REQUEST';
    if (detectors.actionRisk.detectedAction === 'DOWNLOAD' || detectors.actionRisk.detectedAction === 'DOWNLOAD_FILE') return 'MALWARE_DELIVERY';
    if (detectors.technical.reverseTunnelDetected || detectors.technical.typosquattingDetected) return 'UNFAMILIAR_DESTINATION';
    if (detectors.behaviour.urgencyScore > 50) return 'URGENCY';
    if (detectors.identity.claimedIdentity) return 'IDENTITY_CLAIM';
    return 'BENIGN_INTERACTION';
  }
}
