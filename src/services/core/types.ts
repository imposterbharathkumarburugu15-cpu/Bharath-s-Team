/**
 * NeuroShield Core Common Schema & Contracts
 * Phase 2 — Channel-Agnostic Threat Detection & Interaction Protection Engine
 */

export type ThreatSource = 'email' | 'sms' | 'web' | 'qr' | 'chat';

export interface SenderInfo {
  identifier?: string;       // Email address, phone number, handle, domain
  displayName?: string;      // Display name shown to the user
  domain?: string;           // Derived or explicit domain
  phone?: string;            // E.164 phone number if applicable
  ip?: string;               // Origin IP if known
  authenticated?: boolean;   // Whether sender passed SPF/DKIM or telecom verification
}

export interface RecipientInfo {
  identifier?: string;       // Target email address, phone number, username
  displayName?: string;
  domain?: string;
  phone?: string;
}

export interface AttachmentInfo {
  filename: string;
  mimeType: string;
  sizeBytes?: number;
  hash?: string;             // SHA-256
  isExecutable?: boolean;
}

export interface InteractionHistory {
  previousInteractionsCount: number;
  firstContactDate?: string;
  lastInteractionDate?: string;
  previousFlagsCount?: number;
  knownSenderTrustScore?: number; // 0 to 100
  isKnownContact?: boolean;
  knownIdentity?: string;
}

export type ActionType =
  | 'CLICK'
  | 'CLICK_LINK'
  | 'LOGIN'
  | 'ENTER_PASSWORD'
  | 'SHARE_OTP'
  | 'TRANSFER_MONEY'
  | 'SHARE_SENSITIVE_DATA'
  | 'DOWNLOAD'
  | 'DOWNLOAD_FILE'
  | 'EXECUTE_INSTRUCTION'
  | 'SCAN_QR'
  | 'CALL_NUMBER'
  | 'VISIT_WEBSITE'
  | 'UNKNOWN';

export type ActionRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'NONE';

export type RiskLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ProtectionDecision = 'ALLOW' | 'WARN' | 'STRONG_WARN' | 'BLOCK' | 'BLOCK_ACTION' | 'BLOCK_VIEW';

export type EvidenceSource =
  | 'NLP'
  | 'Transformer'
  | 'URL analysis'
  | 'Email Forensics'
  | 'Identity Engine'
  | 'Relationship Engine'
  | 'Behaviour Engine'
  | 'Action Engine'
  | 'Prompt Injection'
  | 'Sensitive Data'
  | 'Threat Intelligence';

export interface EvidenceItemWithProvenance {
  signal: string;
  source: EvidenceSource;
  severity: 'low' | 'medium' | 'high' | 'critical' | 'info';
  evidence: string;
  confidence?: number;
  timestamp?: string;
  value?: string;
  observed?: boolean;
  detector?: string;
  status?: 'OBSERVED' | 'INFERRED' | 'UNAVAILABLE';
}

export interface ConflictResolution {
  conflictType: string;
  detectorA: { name: string; finding: string; signal: string };
  detectorB: { name: string; finding: string; signal: string };
  resolution: string;
  reconciledScoreAdjustment: number;
  explanation: string;
}

export type AttackCategory =
  | 'PHISHING'
  | 'SPEAR_PHISHING'
  | 'IMPERSONATION'
  | 'BUSINESS_EMAIL_COMPROMISE'
  | 'SOCIAL_ENGINEERING'
  | 'FINANCIAL_FRAUD'
  | 'CREDENTIAL_THEFT'
  | 'DATA_EXFILTRATION'
  | 'MALICIOUS_LINK'
  | 'MALWARE_DELIVERY'
  | 'PROMPT_INJECTION'
  | 'SENSITIVE_DATA_ATTACK'
  | 'MULTI_STAGE_ATTACK'
  | 'UNKNOWN';

export interface ContentRiskAssessment {
  level: ActionRiskLevel;
  score: number;
  indicators: string[];
}

export interface ActionRiskAssessment {
  detected_action: ActionType;
  level: ActionRiskLevel;
  score: number;
  target_destination: string | null;
}

export interface CombinedRiskAssessment {
  level: ActionRiskLevel;
  score: number;
}

export interface CrossChannelEvent {
  channel: ThreatSource;
  timestamp?: string;
  entity?: string;
  actionObserved?: string;
  evidence: string;
}

export interface CrossChannelAnalysis {
  isMultiChannel: boolean;
  channelsObserved: ThreatSource[];
  events: CrossChannelEvent[];
  correlationNotes: string[];
  correlation_status?: 'CORRELATED' | 'UNCORRELATED' | 'NO_CROSS_CHANNEL_DATA';
  correlation_evidence?: string[];
  correlation_confidence?: number;
}

export type DynamicTrustLevel = 'TRUSTED' | 'CONDITIONAL' | 'DEGRADED' | 'ZERO_TRUST';

export interface DynamicTrustModel {
  baseline_trust: number;
  current_trust: number;
  trust_delta: number;
  trust_level: DynamicTrustLevel;
  reason: string;
  trust_decay_factors: string[];
  evidence: string[];
}

export interface IdentityContinuityEvidence {
  identity_match: boolean | null;
  identity_mismatch: boolean;
  identity_change: boolean;
  identity_novelty: boolean;
  identity_confidence: number;
  historical_identity_analysis: 'AVAILABLE' | 'UNAVAILABLE';
  evidence: string[];
  signals: string[];
}

/**
 * 1. COMMON INTERACTION EVENT SCHEMA (Phase 2 Normalized Event Model)
 * Represents any incoming communication normalized across Email, SMS, Web, QR, and Chat.
 */
export interface UnifiedInteractionEvent {
  id?: string;
  source: ThreatSource;
  timestamp?: string;
  sender?: SenderInfo | null;
  recipients?: RecipientInfo[];
  recipient?: RecipientInfo | null;
  subject?: string;
  body?: string;
  content: string;                         // Normalized extracted plain text
  rawPayload?: string;                    // Raw RFC 5322 string, raw SMS, QR string, etc.
  headers?: Record<string, any>;          // Extracted headers map
  urls?: string[];
  attachments?: AttachmentInfo[];
  identity?: {
    claimedIdentity?: string | null;
    verifiedDomain?: string | null;
    authStatus?: 'PASS' | 'FAIL' | 'NONE' | 'UNKNOWN';
  };
  historical_context?: InteractionHistory | null;
  history?: InteractionHistory | null;    // Historical context (null if unavailable - DO NOT FABRICATE)
  requested_action?: ActionType;          // Target action the communication attempts to make user perform
  user_action?: ActionType | null;        // Proposed user action if known
  sensitive_data?: {
    categoriesRequested?: string[];
    demandsCredentials?: boolean;
    demandsOtp?: boolean;
    demandsPayment?: boolean;
    demandsPii?: boolean;
    maskedFields?: Array<{ originalType: string; maskedValue: string }>;
  };
  metadata?: Record<string, any>;         // Channel-specific headers, telemetry, or user-agent
  privacy_level?: 'MASKED' | 'RAW' | 'REDACTED';
}

export type UnifiedThreatInput = UnifiedInteractionEvent;

/**
 * Normalized Email Schema (Phase 2 Canonical Email Contract)
 * Standardized representation of an email interaction across all email ingestion sources.
 */
export interface NormalizedEmailSender {
  address: string;
  displayName?: string;
  domain?: string;
  replyTo?: string;
}

export interface NormalizedEmailRecipient {
  address: string;
  displayName?: string;
}

export interface NormalizedEmailBody {
  text: string;
  html?: string;
  snippet?: string;
}

export interface NormalizedEmailAttachment {
  filename: string;
  mimeType: string;
  sizeBytes?: number;
  hash?: string;
  isExecutable?: boolean;
}

export interface NormalizedEmailAuth {
  spf: 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL' | 'NONE' | 'UNAVAILABLE';
  dkim: 'PASS' | 'FAIL' | 'NONE' | 'UNAVAILABLE';
  dmarc: 'PASS' | 'FAIL' | 'NONE' | 'UNAVAILABLE';
  rawAuthResults?: string;
}

export interface NormalizedEmailContext {
  isFirstContact?: boolean | null;
  relationshipStatus: 'KNOWN_TRUSTED' | 'KNOWN_PREVIOUS' | 'FIRST_CONTACT' | 'UNKNOWN';
  previousInteractionsCount?: number | null;
}

export interface NormalizedEmail {
  id: string;
  threadId?: string;
  timestamp: string;
  source: 'email';
  sender: NormalizedEmailSender;
  recipients: NormalizedEmailRecipient[];
  subject: string;
  body: NormalizedEmailBody;
  headers: Record<string, string | string[]>;
  urls: string[];
  attachments: NormalizedEmailAttachment[];
  authentication: NormalizedEmailAuth;
  context: NormalizedEmailContext;
  requestedActions: ActionType[];
  metadata?: Record<string, any>;
}

export type ThreatVerdict = 'SAFE' | 'LOW' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL' | 'MALICIOUS' | 'UNKNOWN';

export type EnforcementStatus =
  | 'NOT_REQUIRED'
  | 'PENDING'
  | 'ENFORCED'
  | 'PARTIALLY_ENFORCED'
  | 'NOT_SUPPORTED'
  | 'FAILED'
  | 'UNKNOWN'
  | 'DETECTED'
  | 'WARNED'
  | 'BLOCKED'
  | 'RESTRICTED'
  | 'NOT_ENFORCED'
  | 'ALLOWED';

/**
 * Authoritative Core Protection Contract (Phase 4 Contract Specification)
 */
export interface AuthoritativeProtectionDecision {
  verdict: ThreatVerdict;
  riskScore: number;
  confidence: number;
  requestedAction: ActionType;
  threatTypes: string[];
  protectionDecision: ProtectionDecision;
  enforcementLevel: string;
  enforcementStatus: EnforcementStatus;
  evidence: any[];
}

export type SensitiveDataCategory =
  | 'PASSWORD'
  | 'OTP'
  | 'API_KEY'
  | 'ACCESS_TOKEN'
  | 'PAYMENT_DATA'
  | 'BANKING_DATA'
  | 'CONFIDENTIAL_DATA'
  | 'PERSONAL_IDENTIFIER';

export interface EnforcementAuditRecord {
  id?: string;
  timestamp: string;
  incidentId: string;
  requestedAction: ActionType;
  risk: RiskLevel | number;
  decision: ProtectionDecision;
  enforcementStatus: EnforcementStatus;
  client: string; // e.g. 'chrome_extension', 'gmail_api', 'web_app', 'headless'
  failureReason?: string;
  url?: string;
  target?: string;
}

export interface UnifiedEmailAnalysisResult {
  incidentId: string;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  riskScore: number;
  confidence: number;
  analysisCoverage: AnalysisCoverage;
  threatTypes: AttackCategory[];
  identity: IdentityAnalysis;
  context: RelationshipAnalysis;
  behaviour: BehaviourAnalysis;
  intent: IntentAnalysis;
  sensitiveData: SensitiveDataAnalysis;
  actionRisk: ActionRiskAnalysis;
  technicalEvidence: TechnicalEvidenceAnalysis;
  adversarialEvidence: EvasionAnalysis;
  attackSequence: AttackSequenceAnalysis;
  protectionDecision: ProtectionDecision;
  enforcementLevel?: string;
  enforcementStatus: EnforcementStatus;
  authoritativeProtectionDecision?: AuthoritativeProtectionDecision;
  blockedAction?: ActionType | null;
  client?: string;
  failureReason?: string;
  evidence: any[];
  normalizedEmail?: NormalizedEmail;
  summary?: string;
  whyRiskIncreased?: string[];
  recommendedAction?: RecommendedAction;
  timestamp: string;
}

/**
 * Atomic detector evidence item
 */
export interface DetectorEvidence {
  detector: string;
  score: number;                          // 0 to 100
  status: 'available' | 'unavailable' | 'not_applicable';
  statusReason?: string;
  evidence: string[];
}

export interface IdentityAnalysis {
  status: 'available' | 'unavailable';
  statusReason?: string;
  claimedIdentity?: string | null;
  actualIdentity?: string | null;
  domainMatch?: boolean | null;
  isSpoofed?: boolean;
  isAnomalousDisplay?: boolean;
  fromReplyToMismatch?: boolean;
  newSender?: boolean;
  identity_match?: boolean | null;
  identity_mismatch?: boolean;
  identity_change?: boolean;
  identity_novelty?: boolean;
  identity_confidence?: number;
  historical_identity_analysis?: 'AVAILABLE' | 'UNAVAILABLE';
  continuity?: IdentityContinuityEvidence;
  risk: number;                           // 0 to 100 (Phase 3 schema requirement)
  riskScore: number;                      // 0 to 100 (backward compatibility)
  signals: string[];                      // Structured signal tags
  evidence: string[];
}

export interface RelationshipAnalysis {
  status: 'available' | 'unavailable';
  statusReason?: string;
  reason?: string;                        // Alias for Phase 3 schema requirement
  relationshipState: 'KNOWN_TRUSTED' | 'KNOWN_PREVIOUS' | 'FIRST_CONTACT' | 'UNKNOWN';
  firstContact: boolean | null;
  interactionCount: number | null;
  historicalFrequency?: string | null;
  previousInteractionExists?: boolean;
  behaviourShiftDetected: boolean | null;
  unusualRequestForRelationship?: boolean;
  riskScore: number;                      // 0 to 100
  evidence: string[];
}

export interface BehaviourAnalysis {
  status: 'available' | 'unavailable';
  statusReason?: string;
  urgencyScore: number;                   // 0 to 100
  coercionScore: number;                  // 0 to 100
  isolationRequested: boolean;            // "Keep this confidential", "don't ask the team"
  secrecyKeywords: string[];
  riskScore: number;                      // 0 to 100
  evidence: string[];
}

export type ThreatIntentCategory =
  | 'CREDENTIAL_THEFT'
  | 'CREDENTIAL_HARVESTING'
  | 'FINANCIAL_FRAUD'
  | 'SENSITIVE_DATA_COLLECTION'
  | 'DATA_EXFILTRATION'
  | 'MALWARE_DELIVERY'
  | 'MALICIOUS_LINK_REDIRECTION'
  | 'IMPERSONATION'
  | 'SOCIAL_ENGINEERING'
  | 'PROMPT_MANIPULATION'
  | 'PROMPT_INJECTION_EXPLOIT'
  | 'BENIGN_COMMUNICATION'
  | 'UNKNOWN';

export interface IntentAnalysis {
  status: 'available' | 'unavailable';
  primaryIntent: ThreatIntentCategory;
  intentConfidence: number;               // 0 to 100
  evidence: string[];
}

export interface ActionRiskAnalysis {
  detectedAction: ActionType;
  actionRisk: ActionRiskLevel;
  contentRisk?: ActionRiskLevel;          // Separation of Content Risk from Action Risk
  targetDestination?: string | null;
  evidence: string[];
  preventiveIntervention: string;
}

export interface TechnicalEvidenceAnalysis {
  status: 'available' | 'unavailable';
  statusReason?: string;
  urlsEvaluated: number;
  reverseTunnelDetected: boolean;
  reverseTunnelProviders?: string[];
  nrdDetected?: boolean;                  // Newly registered domain (< 30 days)
  typosquattingDetected?: boolean;
  suspiciousTldDetected?: boolean;
  excessiveSubdomainsDetected?: boolean;
  encodedUrlDetected?: boolean;
  bareIpUrlDetected?: boolean;
  spfStatus?: 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL' | 'NONE' | 'UNAVAILABLE';
  dkimStatus?: 'PASS' | 'FAIL' | 'NONE' | 'UNAVAILABLE';
  dmarcStatus?: 'PASS' | 'FAIL' | 'NONE' | 'UNAVAILABLE';
  ipIntelligence?: {
    ip?: string;
    country?: string;
    asn?: string;
    isHostingOrProxy?: boolean;
  } | null;
  riskScore: number;                      // 0 to 100
  evidence: string[];
}

export interface PromptInjectionAnalysis {
  status: 'available' | 'unavailable';
  statusReason?: string;
  detected: boolean;
  overrideTokens: string[];
  adversarialRiskScore: number;           // 0 to 100
  evidence: string[];
}

export interface SensitiveDataAnalysis {
  status: 'available' | 'unavailable';
  statusReason?: string;
  detected: boolean;                      // Phase 3 schema requirement
  categories: string[];                   // Phase 3 schema requirement
  risk: number;                           // Phase 3 schema requirement
  demandsCredentials: boolean;
  demandsOtp: boolean;
  demandsPayment: boolean;
  demandsPii: boolean;
  demandsApiKeys?: boolean;
  demandsConfidentialOrgData?: boolean;
  matchedCategories: string[];
  maskedItems: Array<{ originalType: string; maskedValue: string }>;
  riskScore: number;                      // 0 to 100
  evidence: string[];
}

/**
 * Central Correlated Evidence Object (Phase 3 requirement)
 */
export interface CorrelatedEvidenceMap {
  identity: string[];
  relationship: string[];
  behaviour: string[];
  intent: string[];
  action: string[];
  technical: string[];
  prompt_injection: string[];
  sensitive_data: string[];
}

/**
 * Attack Sequence Foundation (Phase 3 differentiator)
 */
export type AttackStage =
  | 'NEW_CONTACT'
  | 'IDENTITY_CLAIM'
  | 'TRUST_BUILDING'
  | 'TOPIC_PIVOT'
  | 'URGENCY'
  | 'SENSITIVE_REQUEST'
  | 'FINANCIAL_ACTION'
  | 'UNFAMILIAR_DESTINATION'
  | 'MALWARE_DELIVERY'
  | 'CREDENTIAL_PROMPT'
  | 'BENIGN_INTERACTION';

export interface AttackSequenceEvent {
  step: number;
  stage: AttackStage;
  timestamp?: string;
  source?: ThreatSource;
  channel?: ThreatSource;
  entity?: string;
  description: string;
  actionObserved?: string;
  action?: string;
  evidence?: string;
  riskChange?: number;
  riskContribution?: number;
  risk_contribution?: number;
}

export interface AttackSequenceAnalysis {
  isSequenceProgression: boolean;
  sequenceType: 'SINGLE_EVENT' | 'MULTI_STAGE_PROGRESSION';
  sequence_status?: 'SINGLE_EVENT' | 'PROGRESSION_OBSERVED' | 'UNAVAILABLE';
  sequence_depth: number;
  context_status: 'LIMITED' | 'PROGRESSION_OBSERVED' | 'SINGLE_EVENT';
  summary: string;
  stagesDetected: AttackStage[];
  events: AttackSequenceEvent[];
  escalationRate: 'NONE' | 'GRADUAL' | 'RAPID_ESCALATION';
  compoundSequenceRisk: number;
  evidence: string[];
}

/**
 * Forensic Evidence Graph Foundation (Phase 3 & Phase 7.5 requirement)
 */
export type EvidenceGraphNodeType =
  | 'Person'
  | 'Account'
  | 'Email'
  | 'Phone'
  | 'Domain'
  | 'URL'
  | 'IP'
  | 'Organization'
  | 'PaymentDestination'
  | 'Incident'
  | 'Action'
  | 'ThreatIndicator';

export type EvidenceGraphEdgeType =
  | 'SENT'
  | 'REPLIED_TO'
  | 'HOSTED_ON'
  | 'RESOLVES_TO'
  | 'CLAIMS_IDENTITY'
  | 'REQUESTS'
  | 'REDIRECTS_TO'
  | 'ASSOCIATED_WITH'
  | 'USES_PHONE'
  | 'TARGETS'
  | 'CORRELATED_WITH'
  | 'PAYMENT_TO';

export interface EvidenceGraphNode {
  id: string;
  type: EvidenceGraphNodeType;
  label: string;
  attributes?: Record<string, any>;
}

export interface EvidenceGraphEdge {
  id: string;
  source: string;
  target: string;
  type: EvidenceGraphEdgeType;
  label?: string;
  attributes?: Record<string, any>;
}

export interface ForensicEvidenceGraphData {
  nodes: EvidenceGraphNode[];
  edges: EvidenceGraphEdge[];
  summary: {
    nodeCount: number;
    edgeCount: number;
    focalEntities: string[];
  };
}

/**
 * Structured Feature Vector for Model/XGBoost Integration (Version 2.0 Specification)
 */
export interface RiskFeatureVector {
  identity_risk: number;
  relationship_risk: number;
  behaviour_risk: number;
  intent_risk: number;
  action_risk: number;
  content_risk: number;
  technical_risk: number;
  url_risk: number;
  prompt_injection_risk: number;
  sensitive_data_risk: number;
  sequence_risk: number;
  evidence_count: number;
  analysis_coverage: number;
  feature_vector_version?: string;
}

export type GuardState = 'SAFE' | 'SUSPICIOUS' | 'HIGH_RISK' | 'BLOCKED';

export interface SafeAlternative {
  title: string;
  action_label: string;
  guidance: string;
  safe_url?: string;
  requires_independent_verification: boolean;
}

export interface GuardWarningCard {
  state: GuardState;
  title: string;
  summary: string;
  risk_detected: string;
  required_action: string;
  safe_alternative: SafeAlternative;
  primary_button_label: string;
  secondary_button_label: string;
}

export interface IncidentFeedbackObject {
  incident_id: string;
  feedback: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'MISSED_THREAT';
  user_comment?: string;
  timestamp: string;
  source: ThreatSource | 'audio' | 'unknown';
}

export interface RecommendedAction {
  action: 'ALLOW' | 'WARN' | 'BLOCK' | 'GUIDE';
  summary: string;
  steps: string[];
  interventions: string[];
  circuitBreakers: string[];
  safe_alternative?: SafeAlternative;
  warning_card?: GuardWarningCard;
}

export interface IncidentProtectionDecision {
  decision: ProtectionDecision;
  protectionDecision?: ProtectionDecision;
  enforcementLevel?: string;
  enforcementStatus?: EnforcementStatus;
  authoritativeDecision?: AuthoritativeProtectionDecision;
  recommended_action: string;
  steps: string[];
  interventions: string[];
  circuit_breakers: string[];
  safe_alternative?: SafeAlternative;
  warning_card?: GuardWarningCard;
}

export interface AnalysisCoverage {
  available: string[];
  unavailable: Array<{ component: string; reason: string }>;
  failed: Array<{ component: string; error: string }>;
  coverageRatio: number;                  // 0.0 to 1.0 (portion of relevant detectors executed)
  confidenceRating: 'LOW' | 'MEDIUM' | 'HIGH';
  detectorsRun?: string[];
  detectorsUnavailable?: Array<{ detector: string; reason: string }>;
}

/**
 * 2. UNIFIED INCIDENT OBJECT (Canonical Phase 4 Contract)
 * Standardized threat intelligence and action protection incident representation.
 */
export interface EvasionAnalysis {
  status: 'available' | 'unavailable';
  detected: boolean;
  evasionRiskScore: number;
  techniques: string[];
  homoglyphsDetected: boolean;
  punycodeDetected: boolean;
  urlObfuscationDetected: boolean;
  redirectChainDetected: boolean;
  htmlObfuscationDetected: boolean;
  hiddenLinksDetected: boolean;
  mixedScriptDetected: boolean;
  evidence: string[];
}

export interface CampaignFingerprint {
  fingerprint_hash: string;
  normalized_domain: string | null;
  infrastructure_indicators: string[];
  sender_indicators: string[];
  action_type: ActionType;
  attack_category: AttackCategory;
  evidence_signature: string;
  attribution_note: string;
}

export interface UnifiedIncidentObject {
  incident_id: string;
  source: ThreatSource;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  risk_level: RiskLevel;
  risk_score: number;                     // 0 to 100 (SITUATION SEVERITY)
  confidence: number;                     // 0 to 100 (EVIDENCE COVERAGE / COMPLETENESS)

  attack_types: AttackCategory[];

  content_risk: ContentRiskAssessment;
  action_risk: ActionRiskAnalysis & ActionRiskAssessment;
  combined_risk: CombinedRiskAssessment;

  identity: IdentityAnalysis;
  identity_continuity?: IdentityContinuityEvidence;
  dynamic_trust?: DynamicTrustModel;
  relationship: RelationshipAnalysis;
  behaviour: BehaviourAnalysis;
  intent: IntentAnalysis;
  action: ActionRiskAnalysis;

  technical_evidence: TechnicalEvidenceAnalysis;
  evasion?: EvasionAnalysis;
  prompt_injection: PromptInjectionAnalysis;
  sensitive_data: SensitiveDataAnalysis;

  attack_sequence: AttackSequenceAnalysis;
  campaign_fingerprint?: CampaignFingerprint;
  evidence: any[];
  evidence_provenance?: EvidenceItemWithProvenance[];
  conflicts: ConflictResolution[];

  cross_channel?: CrossChannelAnalysis;

  analysis_coverage: AnalysisCoverage;

  protection: IncidentProtectionDecision;

  // Phase 4 Authoritative Protection Decision & Real Enforcement Status
  protectionDecision?: 'ALLOW' | 'WARN' | 'BLOCK_ACTION' | 'BLOCK_VIEW' | ProtectionDecision;
  enforcementLevel?: string;
  enforcementStatus?: EnforcementStatus;
  enforcedAt?: string;
  blockedAction?: ActionType | null;
  client?: string;
  failureReason?: string;
  authoritativeProtectionDecision?: AuthoritativeProtectionDecision;

  forensics?: Record<string, any>;        // Deep forensic details (e.g. RFC 5322 dossier)
  feature_vector: RiskFeatureVector;

  // Phase 2 / Phase 3 backward compatibility fields
  threats: string[];
  whyRiskIncreased?: string[];            // Explains why multi-signal correlation raised the risk
  correlated_evidence?: CorrelatedEvidenceMap;
  evidence_graph?: ForensicEvidenceGraphData;
  recommended_action: RecommendedAction;

  timestamp: string;
  evaluationTimeMs: number;
}

export type UnifiedThreatAnalysis = UnifiedIncidentObject;
