export type Provenance = 'observed' | 'inferred' | 'externally_reported';
export interface DNAFeature {
  family: 'email' | 'url' | 'web' | 'behavior' | 'infrastructure';
  key: string;
  value: string;
  provenance: Provenance;
  source: string;
  weight: number;
}
export interface Indicator {
  type: 'domain' | 'ip' | 'url' | 'sha256';
  value: string;
  source: string;
  provenance: Provenance;
  eligibleForBlocking: boolean;
}
export interface IntelligenceIncident {
  id: string;
  source: string;
  timestamp: string;
  riskScore: number;
  confidence: number;
  verdict: string;
  fingerprint: string;
  observationKey?: string;
  features: DNAFeature[];
  indicators: Indicator[];
  campaignId?: string;
}
export interface Correlation {
  incidentA: string;
  incidentB: string;
  score: number;
  provenance: 'inferred';
  evidence: DNAFeature[];
}
export interface Campaign {
  id: string;
  status: 'pending' | 'confirmed' | 'rejected';
  incidentIds: string[];
  correlations: Correlation[];
  confidence: number;
  createdAt: string;
  updatedAt: string;
  reviewedBy?: string;
  reviewNote?: string;
  reviewedAt?: string;
}
export interface ConfirmedIOC extends Indicator {
  id: string;
  sourceId: string;
  reviewedBy: string;
  confirmedAt: string;
  expiresAt: string;
  active: boolean;
}
