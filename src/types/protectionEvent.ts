/**
 * NeuroShield Phase 5 Authoritative Protection Event & Firestore Contracts
 * Conforms to Phase 5 Part C & Part G Specifications.
 */

export interface ProtectionEvent {
  id: string;
  timestamp: string;
  source: string;
  title: string;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  riskScore: number;
  requestedAction: string;
  threatType: string;
  protectionDecision: 'ALLOW' | 'WARN' | 'BLOCK_ACTION' | 'BLOCK_VIEW' | 'BLOCK';
  enforcementStatus: 'ENFORCED' | 'WARNED' | 'BLOCKED' | 'NOT_SUPPORTED' | 'FAILED' | 'UNKNOWN' | 'NOT_REQUIRED';
  target?: string;
  client?: string;
  sensitiveDataCategories?: string[];
  userId?: string;
}

export interface FirestoreIncident {
  incidentId: string;
  source: string;
  timestamp: string;
  verdict: string;
  riskScore: number;
  confidence: number;
  threatTypes: string[];
  requestedAction: string;
  sensitiveDataCategories: string[];
  protectionDecision: string;
  enforcementStatus: string;
  client: string;
  evidenceSummary: string[];
  createdAt: string;
  userId?: string;
}

export interface DashboardMetrics {
  totalAnalyzed: number;
  threatsBlocked: number;
  warningsIssued: number;
  sensitiveDataEvents: number;
  highRiskEvents: number;
  credentialAttacks: number;
  financialAttacks: number;
  lastUpdated: string;
}

export interface SystemComponentStatus {
  gmail: 'CONNECTED' | 'DISCONNECTED' | 'DEGRADED';
  browser: 'PROTECTED' | 'NOT_DETECTED' | 'DEGRADED';
  coreApi: 'HEALTHY' | 'OFFLINE' | 'DEGRADED';
  database: 'CONNECTED' | 'OFFLINE' | 'DEGRADED';
}
