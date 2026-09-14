/**
 * NeuroShield SIH26106 Infrastructure Intelligence Types
 * Defines court-defensible data models for historical observed infrastructure,
 * correlation graphs, relay reconstruction, and forensic case reporting.
 *
 * Core Concept:
 * IP Geolocation reflects the approximate location of the observed network infrastructure,
 * NOT the physical location of the human adversary.
 * IP rotation changes the observation — it does not erase the evidence.
 */

export type InfrastructureSource = 
  | 'email-header'
  | 'received-chain'
  | 'url-resolution'
  | 'dns'
  | 'related-incident'
  | 'threat-intelligence';

export type ConfidenceLevel = 'HIGH' | 'MEDIUM' | 'LOW';

export interface InfrastructureObservation {
  id: string;
  incidentId: string;
  ip: string;
  timestamp: string;
  country: string;
  countryCode?: string;
  countryFlag?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  asn?: string;
  provider?: string;
  organization?: string;
  domain?: string;
  hostname?: string;
  source: InfrastructureSource;
  confidence: number; // 0 to 100 percentage
  confidenceLevel: ConfidenceLevel;
  trustBoundary: 'internal' | 'external' | 'transit' | 'origin';
  reputation: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' | 'ANOMALOUS';
  isCurrentActive?: boolean;
  statusNote?: string;
  relayHopIndex?: number;
  evidenceSnippet?: string;
}

export interface CorrelatedIncidentSummary {
  incidentId: string;
  timestamp: string;
  subject: string;
  senderDomain: string;
  observedIp: string;
  asn: string;
  sharedIndicators: string[];
  relationshipType: 'SHARED_ASN' | 'SHARED_PAYLOAD_DOMAIN' | 'IDENTICAL_RELAY_HOP' | 'REVERSE_TUNNEL_CLUSTER';
  confidenceScore: number;
}

export interface InfrastructureCorrelation {
  primaryIncidentId: string;
  activeIp: string;
  totalHistoricalObservations: number;
  activeDomain: string;
  activeAsn: string;
  activeProvider: string;
  correlatedIncidents: CorrelatedIncidentSummary[];
  campaignId?: string;
  campaignName?: string;
  campaignConfidenceScore: number; // 0 - 100
  campaignConfidenceLevel: ConfidenceLevel;
  continuityEvidence: string[];
  sharedIndicatorSummary: {
    asnMatch: boolean;
    domainClusterMatch: boolean;
    urlHashMatch: boolean;
    reverseTunnelMatch: boolean;
  };
}

export interface ForensicCaseReport {
  caseId: string;
  generatedAt: string;
  classification: {
    threatType: string;
    riskScore: number;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    protectionAction: 'BLOCK' | 'QUARANTINE' | 'WARN' | 'ALLOW';
  };
  emailMetadata: {
    subject: string;
    sender: string;
    fromDomain: string;
    returnPathDomain: string;
    replyToAddress: string;
    dateHeader: string;
    messageId: string;
  };
  authentication: {
    spfStatus: string;
    dkimStatus: string;
    dmarcStatus: string;
    dmarcAlignment: string;
  };
  relayReconstruction: {
    totalHops: number;
    transitTimeSeconds: number;
    observedRelays: Array<{
      hopNumber: number;
      ip: string;
      hostname: string;
      asn: string;
      geo: string;
      isAnomalous: boolean;
    }>;
  };
  observedInfrastructure: InfrastructureObservation[];
  correlation: InfrastructureCorrelation;
  evidenceProvenance: Array<{
    item: string;
    source: InfrastructureSource;
    confidence: number;
    timestamp: string;
  }>;
  chainOfCustody: {
    sha256EvidenceHash: string;
    immutableReceiptId: string;
    analystAttributionNote: string;
  };
}

export interface JudgeDemoStep {
  stepNumber: number;
  title: string;
  description: string;
  observedIp: string;
  geo: string;
  asn: string;
  provider: string;
  activeSignal: string;
  campaignConfidence: number;
  statusMessage: string;
}
