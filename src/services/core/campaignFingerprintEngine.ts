/**
 * NeuroShield Attack Campaign Fingerprint & Correlation Engine
 * Phase 7.5 — Advanced Security Intelligence
 *
 * Requirements 6 & 10:
 * Generates deterministic campaign fingerprints and correlates multi-channel activity:
 * - Deterministic fingerprint hash (never random UUIDs)
 * - Normalized infrastructure indicators, sender patterns, action type, attack category, and evidence signatures
 * - Enables cluster detection, variant tracking, and campaign re-use identification
 * - Cross-channel correlation without fabricating phantom data
 */

import {
  UnifiedThreatInput,
  CampaignFingerprint,
  ActionType,
  AttackCategory,
  ThreatSource,
  IdentityAnalysis,
  TechnicalEvidenceAnalysis,
  ActionRiskAnalysis,
  CrossChannelAnalysis,
} from './types';

export class CampaignFingerprintEngine {
  /**
   * Deterministic 64-bit FNV-1a-like hash returning hexadecimal string
   */
  private static deterministicHash(str: string): string {
    let h1 = 0x811c9dc5;
    let h2 = 0x59a7f3e1;

    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 0x01000193);
      h2 = Math.imul(h2 ^ (ch >> 1), 0x01000193);
    }

    const p1 = (h1 >>> 0).toString(16).padStart(8, '0');
    const p2 = (h2 >>> 0).toString(16).padStart(8, '0');
    return `${p1}${p2}`;
  }

  static generateFingerprint(params: {
    input: UnifiedThreatInput;
    identity: IdentityAnalysis;
    technical: TechnicalEvidenceAnalysis;
    actionRisk: ActionRiskAnalysis;
    attackCategory: AttackCategory;
  }): CampaignFingerprint {
    const { input, identity, technical, actionRisk, attackCategory } = params;

    // 1. Normalized domain
    let normalized_domain: string | null = null;
    if (input.sender?.domain) {
      normalized_domain = input.sender.domain.toLowerCase().replace(/^www\./, '');
    } else if (input.urls && input.urls.length > 0) {
      try {
        const u = input.urls[0];
        const parsed = new URL(u.startsWith('http') ? u : `https://${u}`);
        normalized_domain = parsed.hostname.toLowerCase().replace(/^www\./, '');
      } catch {
        normalized_domain = null;
      }
    }

    // 2. Infrastructure indicators
    const infrastructure_indicators: string[] = [];
    if (technical.reverseTunnelDetected) infrastructure_indicators.push('REVERSE_TUNNEL_MASKING');
    if (technical.ipIntelligence?.asn) infrastructure_indicators.push(`ASN:${technical.ipIntelligence.asn}`);
    if (technical.ipIntelligence?.country) infrastructure_indicators.push(`GEO:${technical.ipIntelligence.country}`);
    if (technical.typosquattingDetected) infrastructure_indicators.push('TYPOSQUAT_REGISTRATION');

    // 3. Sender indicators
    const sender_indicators: string[] = [];
    if (identity.claimedIdentity) sender_indicators.push(`BRAND:${identity.claimedIdentity.toLowerCase()}`);
    if (input.sender?.phone) sender_indicators.push(`PHONE_PREFIX:${input.sender.phone.slice(0, 4)}`);
    if (identity.fromReplyToMismatch) sender_indicators.push('ROUTING_DIVERSION');

    // 4. Action Type
    const action_type: ActionType = actionRisk.detectedAction || 'UNKNOWN';

    // 5. Evidence Signature (sorted deduplicated key tokens)
    const rawTokens = [
      ...identity.signals,
      ...(technical.reverseTunnelDetected ? ['REVERSE_TUNNEL'] : []),
      action_type,
      attackCategory,
    ];
    const uniqueTokens = Array.from(new Set(rawTokens)).sort();
    const evidence_signature = uniqueTokens.join('|');

    // Combine into canonical deterministic pre-image
    const preImage = [
      normalized_domain || 'NO_DOMAIN',
      infrastructure_indicators.sort().join(','),
      sender_indicators.sort().join(','),
      action_type,
      attackCategory,
      evidence_signature,
    ].join('::');

    const fingerprint_hash = `camp_${this.deterministicHash(preImage)}`;

    const attribution_note = `Deterministic campaign fingerprint derived from ${
      normalized_domain ? `domain [${normalized_domain}]` : 'infrastructure'
    }, action profile [${action_type}], and ${uniqueTokens.length} structural evidence signals.`;

    return {
      fingerprint_hash,
      normalized_domain,
      infrastructure_indicators,
      sender_indicators,
      action_type,
      attack_category: attackCategory,
      evidence_signature,
      attribution_note,
    };
  }

  static evaluateCrossChannelCorrelation(
    input: UnifiedThreatInput,
    fingerprint: CampaignFingerprint
  ): CrossChannelAnalysis {
    const multiChannelEvents = Array.isArray(input.metadata?.events) ? input.metadata.events : [];
    const knownCampaigns: any[] = Array.isArray(input.metadata?.knownCampaignClusters)
      ? input.metadata.knownCampaignClusters
      : [];

    const channelsObserved: ThreatSource[] = [input.source];
    const correlationNotes: string[] = [];
    const correlation_evidence: string[] = [];
    const crossChannelEvents = [];

    // Evaluate multi-channel sequence events if present in observed telemetry
    for (const ev of multiChannelEvents) {
      const channel = ev.source || ev.channel;
      if (channel && !channelsObserved.includes(channel)) {
        channelsObserved.push(channel);
      }
      crossChannelEvents.push({
        channel: channel || input.source,
        timestamp: ev.timestamp,
        entity: ev.entity,
        actionObserved: ev.actionObserved || ev.action,
        evidence: ev.evidence || 'Recorded event',
      });
    }

    if (channelsObserved.length > 1) {
      correlationNotes.push(`Multi-channel activity observed across: [${channelsObserved.map((c) => String(c).toUpperCase()).join(', ')}].`);
      correlation_evidence.push('Direct correlation: same campaign or entity communicating across distinct channels.');
    }

    // Evaluate shared campaign clusters if recorded in organization telemetry
    let matchedClusterId: string | null = null;
    let isMultiChannel = channelsObserved.length > 1;

    for (const cluster of knownCampaigns) {
      if (
        cluster.fingerprint_hash === fingerprint.fingerprint_hash ||
        (cluster.normalized_domain && cluster.normalized_domain === fingerprint.normalized_domain)
      ) {
        matchedClusterId = cluster.clusterId || cluster.campaignId;
        isMultiChannel = true;
        correlationNotes.push(
          `Campaign correlation confirmed: Matches active cluster '${matchedClusterId}' sharing infrastructure with prior observed channels.`
        );
        correlation_evidence.push(`Cluster attribution signature: ${fingerprint.evidence_signature}`);
        break;
      }
    }

    if (!isMultiChannel) {
      correlationNotes.push('No secondary channel pivots or historical campaign cluster overlap identified for this interaction.');
    }

    return {
      isMultiChannel,
      channelsObserved,
      events: crossChannelEvents,
      correlationNotes,
      correlation_status: isMultiChannel ? 'CORRELATED' : 'NO_CROSS_CHANNEL_DATA',
      correlation_evidence,
      correlation_confidence: isMultiChannel ? 85 : 30,
    };
  }
}
