/**
 * NeuroShield Forensic Evidence Graph Builder
 * Phase 7.5 — Advanced Security Intelligence
 *
 * Constructs a relational evidence graph mapping observed entities, communications,
 * infrastructure nodes, and security indicators.
 *
 * Supported Entity Types (Requirement 3):
 * - Person
 * - Account
 * - Email
 * - Phone
 * - Domain
 * - IP
 * - URL
 * - PaymentDestination
 * - Organization
 * - Incident
 * - Action
 * - ThreatIndicator
 *
 * STRICT FORENSIC DIRECTIVE:
 * The graph structure is an evidence representation, NOT an automated prediction.
 * Never create relationships or nodes that are not supported by observed data.
 */

import {
  UnifiedThreatInput,
  ForensicEvidenceGraphData,
  EvidenceGraphNode,
  EvidenceGraphEdge,
  IdentityAnalysis,
  ActionRiskAnalysis,
  TechnicalEvidenceAnalysis,
  PromptInjectionAnalysis,
  AttackSequenceAnalysis,
  EvasionAnalysis,
} from './types';

export class ForensicEvidenceGraphBuilder {
  static build(
    input: UnifiedThreatInput,
    detectors: {
      identity: IdentityAnalysis;
      actionRisk: ActionRiskAnalysis;
      technical: TechnicalEvidenceAnalysis;
      promptInjection: PromptInjectionAnalysis;
      evasion?: EvasionAnalysis;
    },
    attackSequence?: AttackSequenceAnalysis
  ): ForensicEvidenceGraphData {
    const nodes: EvidenceGraphNode[] = [];
    const edges: EvidenceGraphEdge[] = [];
    const addedNodeIds = new Set<string>();

    const addNode = (node: EvidenceGraphNode) => {
      if (!addedNodeIds.has(node.id)) {
        addedNodeIds.add(node.id);
        nodes.push(node);
      }
    };

    const addEdge = (edge: EvidenceGraphEdge) => {
      edges.push(edge);
    };

    const incidentId = input.metadata?.incidentId || `incident:${Date.now()}`;

    // 1. Root Incident Node
    addNode({
      id: incidentId,
      type: 'Incident',
      label: `Incident (${input.source.toUpperCase()})`,
      attributes: {
        source: input.source,
        timestamp: input.metadata?.timestamp || new Date().toISOString(),
      },
    });

    // 2. Person Node (Claimed display name or persona)
    const personName = input.sender?.displayName || detectors.identity.claimedIdentity;
    let personNodeId: string | null = null;
    if (personName) {
      personNodeId = `person:${personName.toLowerCase().replace(/\s+/g, '_')}`;
      addNode({
        id: personNodeId,
        type: 'Person',
        label: personName,
        attributes: {
          isSpoofed: detectors.identity.isSpoofed,
          claimed: true,
        },
      });

      addEdge({
        id: `edge:${personNodeId}->${incidentId}`,
        source: personNodeId,
        target: incidentId,
        type: 'SENT',
        label: 'Initiated Communication',
      });
    }

    // 3. Email / Sender Identifier Node
    const senderId = input.sender?.identifier || detectors.identity.actualIdentity;
    let senderNodeId: string | null = null;
    if (senderId) {
      const isEmail = senderId.includes('@');
      senderNodeId = isEmail ? `email:${senderId.toLowerCase()}` : `sender:${senderId.toLowerCase()}`;
      addNode({
        id: senderNodeId,
        type: isEmail ? 'Email' : 'Person',
        label: senderId,
        attributes: {
          phone: input.sender?.phone,
        },
      });

      if (personNodeId) {
        addEdge({
          id: `edge:${personNodeId}->${senderNodeId}`,
          source: personNodeId,
          target: senderNodeId,
          type: 'CLAIMS_IDENTITY',
          label: 'Claims Identity',
        });
      }

      addEdge({
        id: `edge:${senderNodeId}->${incidentId}`,
        source: senderNodeId,
        target: incidentId,
        type: 'SENT',
        label: 'Message Origin',
      });
    }

    // 4. Phone Node
    const senderPhone = input.sender?.phone;
    if (senderPhone) {
      const phoneNodeId = `phone:${senderPhone}`;
      addNode({
        id: phoneNodeId,
        type: 'Phone',
        label: senderPhone,
        attributes: {
          verified: senderPhone.startsWith('+'),
        },
      });

      if (senderNodeId) {
        addEdge({
          id: `edge:${senderNodeId}->${phoneNodeId}`,
          source: senderNodeId,
          target: phoneNodeId,
          type: 'USES_PHONE',
          label: 'Uses Phone Line',
        });
      }
    }

    // 5. Domain Node
    const domain = input.sender?.domain || (senderId && senderId.includes('@') ? senderId.split('@')[1] : null);
    let domainNodeId: string | null = null;
    if (domain) {
      domainNodeId = `domain:${domain.toLowerCase()}`;
      addNode({
        id: domainNodeId,
        type: 'Domain',
        label: domain,
        attributes: {
          typosquat: detectors.identity.signals.includes('DOMAIN_TYPOSQUATTING'),
          homoglyph: detectors.evasion?.homoglyphsDetected || false,
        },
      });

      if (senderNodeId) {
        addEdge({
          id: `edge:${senderNodeId}->${domainNodeId}`,
          source: senderNodeId,
          target: domainNodeId,
          type: 'ASSOCIATED_WITH',
          label: 'Routes From Domain',
        });
      }
    }

    // 6. IP Node
    const ip = input.sender?.ip || detectors.technical.ipIntelligence?.ip;
    if (ip) {
      const ipNodeId = `ip:${ip}`;
      addNode({
        id: ipNodeId,
        type: 'IP',
        label: ip,
        attributes: {
          country: detectors.technical.ipIntelligence?.country,
          asn: detectors.technical.ipIntelligence?.asn,
        },
      });

      if (domainNodeId) {
        addEdge({
          id: `edge:${domainNodeId}->${ipNodeId}`,
          source: domainNodeId,
          target: ipNodeId,
          type: 'RESOLVES_TO',
          label: 'Resolves To IP',
        });
      } else if (senderNodeId) {
        addEdge({
          id: `edge:${senderNodeId}->${ipNodeId}`,
          source: senderNodeId,
          target: ipNodeId,
          type: 'HOSTED_ON',
          label: 'Origin Host IP',
        });
      }
    }

    // 7. Reply-To Destination Node
    const replyTo = input.metadata?.replyTo || input.metadata?.headers?.['reply-to'];
    if (replyTo && typeof replyTo === 'string' && replyTo !== senderId) {
      const replyNodeId = `replyTo:${replyTo.toLowerCase()}`;
      addNode({
        id: replyNodeId,
        type: 'Email',
        label: `Reply-To: ${replyTo}`,
      });

      if (senderNodeId) {
        addEdge({
          id: `edge:${senderNodeId}->${replyNodeId}`,
          source: senderNodeId,
          target: replyNodeId,
          type: 'REPLIED_TO',
          label: 'Diverts Responses To',
        });
      }
    }

    // 8. Organization Node (Targeted Brand or Organization)
    const text = (input.content + ' ' + (input.metadata?.subject || '')).toLowerCase();
    const targetedBrand = detectors.identity.signals.find((s) => s.includes('BRAND_IMPERSONATION'))
      ? detectors.identity.claimedIdentity
      : null;

    if (targetedBrand) {
      const orgNodeId = `org:${targetedBrand.toLowerCase().replace(/\s+/g, '_')}`;
      addNode({
        id: orgNodeId,
        type: 'Organization',
        label: targetedBrand,
        attributes: { impersonated: true },
      });

      addEdge({
        id: `edge:${incidentId}->${orgNodeId}`,
        source: incidentId,
        target: orgNodeId,
        type: 'TARGETS',
        label: 'Impersonates Entity',
      });
    }

    // 9. Payment Destination / Account Node (Observed in text)
    const paymentMatch = text.match(/(?:iban|account|routing|wallet|swift|upi|zelle)\s*[:#]?\s*([a-zA-Z0-9-]{6,34})/i);
    if (paymentMatch && paymentMatch[1]) {
      const destId = `payment:${paymentMatch[1]}`;
      addNode({
        id: destId,
        type: 'PaymentDestination',
        label: `Payment: ${paymentMatch[1].slice(0, 4)}****${paymentMatch[1].slice(-4)}`,
        attributes: { rawMasked: true },
      });

      addEdge({
        id: `edge:${incidentId}->${destId}`,
        source: incidentId,
        target: destId,
        type: 'PAYMENT_TO',
        label: 'Demands Remittance To',
      });
    }

    // 10. Action Node
    if (detectors.actionRisk.detectedAction && detectors.actionRisk.detectedAction !== 'UNKNOWN') {
      const actionLabel = detectors.actionRisk.detectedAction;
      const actionNodeId = `action:${actionLabel}`;
      addNode({
        id: actionNodeId,
        type: 'Action',
        label: actionLabel,
        attributes: {
          riskLevel: detectors.actionRisk.actionRisk,
        },
      });

      if (senderNodeId) {
        addEdge({
          id: `edge:${senderNodeId}->${actionNodeId}`,
          source: senderNodeId,
          target: actionNodeId,
          type: 'REQUESTS',
          label: 'Requests Action',
        });
      }
    }

    // 11. URL Nodes
    (input.urls || []).forEach((u) => {
      const urlId = `url:${u}`;
      addNode({
        id: urlId,
        type: 'URL',
        label: u.length > 40 ? `${u.slice(0, 37)}...` : u,
        attributes: { rawUrl: u },
      });

      if (senderNodeId) {
        addEdge({
          id: `edge:${senderNodeId}->${urlId}`,
          source: senderNodeId,
          target: urlId,
          type: 'REQUESTS',
          label: 'Links To',
        });
      }

      try {
        const parsed = new URL(u.startsWith('http') ? u : `https://${u}`);
        const urlDomain = parsed.hostname;
        const targetDomainId = `domain:${urlDomain.toLowerCase()}`;
        addNode({
          id: targetDomainId,
          type: 'Domain',
          label: urlDomain,
        });

        addEdge({
          id: `edge:${urlId}->${targetDomainId}`,
          source: urlId,
          target: targetDomainId,
          type: 'HOSTED_ON',
          label: 'Hosted On Domain',
        });
      } catch {
        // Fallback
      }
    });

    // 12. Threat Indicators
    if (detectors.technical.reverseTunnelDetected) {
      const tunnelNodeId = 'threat:reverse_tunnel';
      addNode({
        id: tunnelNodeId,
        type: 'ThreatIndicator',
        label: 'Reverse Tunnel Masking',
      });
      (input.urls || []).forEach((u) => {
        addEdge({
          id: `edge:${tunnelNodeId}->${u}`,
          source: tunnelNodeId,
          target: `url:${u}`,
          type: 'ASSOCIATED_WITH',
          label: 'Masks Infrastructure',
        });
      });
    }

    if (detectors.promptInjection.detected) {
      const injectionNodeId = 'threat:prompt_injection';
      addNode({
        id: injectionNodeId,
        type: 'ThreatIndicator',
        label: 'Prompt Injection Exploit',
      });
      if (senderNodeId) {
        addEdge({
          id: `edge:${injectionNodeId}->${senderNodeId}`,
          source: injectionNodeId,
          target: senderNodeId,
          type: 'ASSOCIATED_WITH',
          label: 'Embedded In Payload',
        });
      }
    }

    if (detectors.evasion?.homoglyphsDetected) {
      const homoglyphNodeId = 'threat:homoglyph_deception';
      addNode({
        id: homoglyphNodeId,
        type: 'ThreatIndicator',
        label: 'Homoglyph Character Mimicry',
      });
      if (domainNodeId) {
        addEdge({
          id: `edge:${homoglyphNodeId}->${domainNodeId}`,
          source: homoglyphNodeId,
          target: domainNodeId,
          type: 'ASSOCIATED_WITH',
          label: 'Applied To Domain',
        });
      }
    }

    const focalEntities = nodes
      .filter((n) => n.type === 'Domain' || n.type === 'Email' || n.type === 'Action' || n.type === 'PaymentDestination' || n.type === 'Organization')
      .map((n) => n.label);

    return {
      nodes,
      edges,
      summary: {
        nodeCount: nodes.length,
        edgeCount: edges.length,
        focalEntities,
      },
    };
  }
}
