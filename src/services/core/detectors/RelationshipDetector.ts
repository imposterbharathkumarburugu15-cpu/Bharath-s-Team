/**
 * NeuroShield Relationship & Context Foundation
 * Evaluates historical communication patterns, relationship trust, and behavioural shifts.
 * CRITICAL: If no history exists, explicitly marks status as 'UNKNOWN' - never fabricates trust.
 */

import { UnifiedThreatInput, RelationshipAnalysis, DetectorEvidence } from '../types';

export class RelationshipDetector {
  static evaluate(input: UnifiedThreatInput): {
    analysis: RelationshipAnalysis;
    evidence: DetectorEvidence;
  } {
    const history = input.history;
    const evidenceList: string[] = [];

    // If history is not provided or null: STRICTLY MARK UNKNOWN
    if (!history) {
      return {
        analysis: {
          status: 'unavailable',
          statusReason: 'No historical interaction data provided',
          reason: 'No historical interaction data provided',
          relationshipState: 'UNKNOWN',
          firstContact: null,
          interactionCount: null,
          historicalFrequency: null,
          previousInteractionExists: false,
          behaviourShiftDetected: null,
          unusualRequestForRelationship: false,
          riskScore: 0,
          evidence: ['Historical interaction context is not available for this sender/channel.'],
        },
        evidence: {
          detector: 'relationship_engine',
          score: 0,
          status: 'unavailable',
          statusReason: 'No historical interaction data provided',
          evidence: ['Historical context not provided; relationship state is UNKNOWN.'],
        },
      };
    }

    let relationshipState: 'KNOWN_TRUSTED' | 'KNOWN_PREVIOUS' | 'FIRST_CONTACT' | 'UNKNOWN' = 'UNKNOWN';
    let firstContact: boolean | null = null;
    let behaviourShiftDetected: boolean | null = false;
    let unusualRequestForRelationship = false;
    let riskScore = 0;

    const count = history.previousInteractionsCount ?? 0;
    const previousInteractionExists = count > 0;
    const historicalFrequency = count === 0
      ? 'First Interaction (Novel Sender)'
      : count > 25
      ? 'Frequent Correspondent'
      : 'Occasional / Limited Previous Contact';

    if (count === 0) {
      relationshipState = 'FIRST_CONTACT';
      firstContact = true;
      riskScore = 45; // First time contact introduces moderate caution
      evidenceList.push('First observed interaction from this sender. No historical baseline established.');
    } else {
      firstContact = false;
      const flags = history.previousFlagsCount ?? 0;
      const trustScore = history.knownSenderTrustScore ?? (flags === 0 && count >= 5 ? 90 : 50);

      if (flags > 0) {
        relationshipState = 'KNOWN_PREVIOUS';
        riskScore = Math.min(100, 50 + flags * 15);
        evidenceList.push(`Sender has ${flags} previous security warning(s) on record across ${count} prior interactions.`);
      } else if (trustScore >= 80 || (flags === 0 && count >= 5)) {
        relationshipState = 'KNOWN_TRUSTED';
        riskScore = 5;
        evidenceList.push(`Established communication baseline with ${count} previous legitimate interactions.`);
      } else {
        relationshipState = 'KNOWN_PREVIOUS';
        riskScore = 20;
        evidenceList.push(`Previous contact observed (${count} interactions), baseline trust score: ${trustScore}/100.`);
      }

      // Check for sudden behavioral shift (e.g. established contact suddenly demanding urgency/money)
      const content = input.content.toLowerCase();
      const hasUrgentDemands = /(wire transfer|gift card|crypto|urgent payment|update credentials|send password)/i.test(content);
      if (hasUrgentDemands && relationshipState === 'KNOWN_TRUSTED') {
        behaviourShiftDetected = true;
        unusualRequestForRelationship = true;
        riskScore = Math.max(riskScore, 75);
        evidenceList.push('ANOMALOUS BEHAVIOUR SHIFT: Known contact is exhibiting unprecedented high-risk financial/credential demands.');
      }
    }

    // Check if novelty sender makes an unusual sensitive request
    const lowerContent = input.content.toLowerCase();
    if (firstContact && /(wire transfer|ach|urgent payment|password|otp|w-2)/i.test(lowerContent)) {
      unusualRequestForRelationship = true;
      riskScore = Math.max(riskScore, 80);
      evidenceList.push('RELATIONSHIP NOVELTY RISK: First-time sender immediately solicits financial disbursement or credential disclosure.');
    }

    return {
      analysis: {
        status: 'available',
        relationshipState,
        firstContact,
        interactionCount: count,
        historicalFrequency,
        previousInteractionExists,
        behaviourShiftDetected,
        unusualRequestForRelationship,
        riskScore,
        evidence: evidenceList,
      },
      evidence: {
        detector: 'relationship_engine',
        score: riskScore,
        status: 'available',
        evidence: evidenceList,
      },
    };
  }
}
