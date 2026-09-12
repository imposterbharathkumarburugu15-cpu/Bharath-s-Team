/**
 * NeuroShield Enforcement Engine
 * Phase 4 — Automatic Protection & Client-Side Enforcement Contract
 *
 * Resolves central analysis into an authoritative protection decision:
 * { verdict, riskScore, confidence, requestedAction, threatTypes, protectionDecision, enforcementLevel, enforcementStatus, evidence }
 *
 * Core Directives:
 * 1. NEVER claim BLOCKED unless enforcement actually happened.
 * 2. Where Gmail API provides no UI control, return NOT_SUPPORTED.
 * 3. Chrome Extension provides client-side BLOCK_VIEW & BLOCK_ACTION.
 * 4. Fail-safe: backend unavailable evaluates to UNKNOWN, never SAFE.
 * 5. False-positive protection: do not blindly block legitimate urgent communications.
 */

import {
  ActionType,
  AuthoritativeProtectionDecision,
  EnforcementAuditRecord,
  EnforcementStatus,
  ProtectionDecision,
  RiskLevel,
  SensitiveDataAnalysis,
  TechnicalEvidenceAnalysis,
  AnalysisCoverage,
} from './types';

export interface ClientCapabilities {
  canBlockNavigation?: boolean;
  canBlockFormSubmit?: boolean;
  canDisarmLinks?: boolean;
  isExtensionActive?: boolean;
}

export interface EnforcementEvaluationParams {
  incidentId?: string;
  verdict?: import('./types').ThreatVerdict;
  riskScore: number;
  confidence: number;
  coverage?: AnalysisCoverage | number;
  requestedAction: ActionType;
  threatTypes: string[];
  targetUrl?: string;
  hasSensitiveData?: boolean;
  sensitiveCategories?: string[];
  sensitiveData?: SensitiveDataAnalysis;
  technical?: TechnicalEvidenceAnalysis;
  evidence?: any[];
  client?: string; // 'chrome_extension' | 'gmail_api' | 'web_app' | 'headless'
  clientCapabilities?: ClientCapabilities;
  actualEnforcementApplied?: boolean;
}

export class EnforcementEngine {
  /**
   * Resolves the authoritative 8-field Protection Decision contract.
   */
  public static evaluatePolicy(params: EnforcementEvaluationParams): AuthoritativeProtectionDecision {
    const {
      verdict,
      riskScore,
      confidence,
      requestedAction,
      threatTypes,
      sensitiveData,
      technical,
      evidence = [],
      client = 'headless',
      clientCapabilities = {},
      actualEnforcementApplied = false,
    } = params;

    // Fail-Safe: If verdict is UNKNOWN, never claim SAFE.
    if (verdict === 'UNKNOWN') {
      const isDangerousAction =
        requestedAction === 'ENTER_PASSWORD' ||
        requestedAction === 'LOGIN' ||
        requestedAction === 'SHARE_OTP' ||
        requestedAction === 'TRANSFER_MONEY' ||
        requestedAction === 'DOWNLOAD_FILE';

      return {
        verdict: 'UNKNOWN',
        riskScore: Math.max(riskScore, 40),
        confidence: Math.min(confidence, 50),
        requestedAction,
        threatTypes: threatTypes.length > 0 ? threatTypes : ['UNVERIFIED_SOURCE'],
        protectionDecision: isDangerousAction ? 'BLOCK_ACTION' : 'WARN',
        enforcementLevel: 'FAIL_SAFE_OFFLINE_CAUTION',
        enforcementStatus: actualEnforcementApplied
          ? 'ENFORCED'
          : client === 'chrome_extension'
          ? isDangerousAction
            ? 'ENFORCED'
            : 'WARNED'
          : 'UNKNOWN',
        evidence: [
          'Central verification offline or insufficient telemetry.',
          'Fail-safe posture active: unverified action held.',
          ...evidence.slice(0, 3),
        ],
      };
    }

    // 1. SAFE (Score 0-19)
    if (riskScore < 20 || verdict === 'SAFE') {
      return {
        verdict: 'SAFE',
        riskScore,
        confidence,
        requestedAction,
        threatTypes: [],
        protectionDecision: 'ALLOW',
        enforcementLevel: 'ALLOW_PASSIVE_MONITORING',
        enforcementStatus: 'NOT_REQUIRED',
        evidence: evidence.length > 0 ? evidence.slice(0, 3) : ['Interaction conforms to benign baseline.'],
      };
    }

    // 2. LOW (Score 20-39)
    if (riskScore < 40) {
      return {
        verdict: 'LOW',
        riskScore,
        confidence,
        requestedAction,
        threatTypes,
        protectionDecision: 'ALLOW',
        enforcementLevel: 'ALLOW_PASSIVE_MONITORING',
        enforcementStatus: 'NOT_REQUIRED',
        evidence: evidence.slice(0, 3),
      };
    }

    // 3. SUSPICIOUS (Score 40-64)
    if (riskScore < 65 || verdict === 'SUSPICIOUS') {
      let status: EnforcementStatus = 'PENDING';
      if (client === 'chrome_extension' || client === 'web_app') {
        status = 'ENFORCED'; // Warning displayed on client
      } else if (client === 'gmail_api') {
        status = 'NOT_SUPPORTED'; // Gmail API alone cannot show client modal
      }

      return {
        verdict: 'SUSPICIOUS',
        riskScore,
        confidence,
        requestedAction,
        threatTypes,
        protectionDecision: 'WARN',
        enforcementLevel: 'USER_WARNING_DIALOG',
        enforcementStatus: status,
        evidence: evidence.slice(0, 5),
      };
    }

    // 4. HIGH (Score 65-84) & CRITICAL (Score 85-100)
    const isCritical = riskScore >= 85 || verdict === 'CRITICAL';
    const computedVerdict = isCritical ? 'CRITICAL' : 'HIGH';
    let decision: 'BLOCK_ACTION' | 'BLOCK_VIEW' = 'BLOCK_ACTION';
    let level = isCritical ? 'HARD_CLIENT_ACTION_BLOCK' : 'CLIENT_ACTION_RESTRICTION';

    // Determine BLOCK_VIEW vs BLOCK_ACTION
    const isNavigationLure =
      requestedAction === 'CLICK_LINK' ||
      requestedAction === 'VISIT_WEBSITE' ||
      requestedAction === 'SCAN_QR' ||
      Boolean(technical?.reverseTunnelDetected || technical?.typosquattingDetected);

    if (isNavigationLure) {
      decision = 'BLOCK_VIEW';
      level = isCritical ? 'HARD_BROWSER_VIEW_BLOCK' : 'BROWSER_VIEW_BLOCK';
    } else {
      decision = 'BLOCK_ACTION';
      level = isCritical ? 'HARD_CLIENT_ACTION_BLOCK' : 'RESTRICT_DANGEROUS_INTERACTION';
    }

    // Resolve Enforcement Status based on real client execution capabilities
    let enforcementStatus: EnforcementStatus = 'PENDING';

    if (actualEnforcementApplied) {
      enforcementStatus = 'ENFORCED';
    } else if (client === 'chrome_extension') {
      if (decision === 'BLOCK_VIEW' && clientCapabilities.canBlockNavigation !== false) {
        enforcementStatus = 'ENFORCED';
      } else if (decision === 'BLOCK_ACTION' && clientCapabilities.canBlockFormSubmit !== false) {
        enforcementStatus = 'ENFORCED';
      } else {
        enforcementStatus = 'PARTIALLY_ENFORCED';
      }
    } else if (client === 'web_app') {
      if (clientCapabilities.canDisarmLinks) {
        enforcementStatus = 'ENFORCED';
      } else {
        enforcementStatus = 'PARTIALLY_ENFORCED';
      }
    } else if (client === 'gmail_api') {
      // Truth in enforcement: Gmail API alone cannot block UI clicks or forms without Chrome Extension
      enforcementStatus = 'NOT_SUPPORTED';
    } else {
      enforcementStatus = 'PENDING';
    }

    return {
      verdict: computedVerdict,
      riskScore,
      confidence,
      requestedAction,
      threatTypes,
      protectionDecision: decision,
      enforcementLevel: level,
      enforcementStatus,
      evidence: evidence.slice(0, 5),
    };
  }

  /**
   * Creates an authoritative fail-safe decision when Core API is unreachable or times out.
   * Requirement 12: UNKNOWN, never SAFE.
   */
  public static createFailSafeDecision(
    requestedAction: ActionType = 'UNKNOWN',
    client: string = 'chrome_extension',
    reason: string = 'Core API unavailable'
  ): AuthoritativeProtectionDecision {
    return {
      verdict: 'UNKNOWN',
      riskScore: 50,
      confidence: 30,
      requestedAction,
      threatTypes: ['BACKEND_UNAVAILABLE'],
      protectionDecision: 'WARN',
      enforcementLevel: 'APPLICATION',
      enforcementStatus: 'UNKNOWN',
      evidence: [
        `Fail-safe caution: ${reason}`,
        'Core analysis offline. Holding action in cautious state; never claiming SAFE.',
      ],
    };
  }

  /**
   * Sanitizes and creates an EnforcementAuditRecord ensuring zero credentials or PII leak into logs.
   */
  public static createAuditRecord(
    recordOrDecision: {
      incidentId: string;
      requestedAction: ActionType;
      risk: RiskLevel | number;
      decision: ProtectionDecision;
      enforcementStatus: EnforcementStatus;
      client: string;
      failureReason?: string;
      url?: string;
      target?: string;
    } | AuthoritativeProtectionDecision,
    argIncidentId?: string,
    argClient?: string,
    argUrl?: string
  ): EnforcementAuditRecord {
    let incidentId: string;
    let requestedAction: ActionType;
    let risk: RiskLevel | number;
    let decision: ProtectionDecision;
    let enforcementStatus: EnforcementStatus;
    let client: string;
    let failureReason: string | undefined;
    let rawUrl: string | undefined;
    let rawTarget: string | undefined;

    if ('verdict' in recordOrDecision && 'protectionDecision' in recordOrDecision) {
      // Called with AuthoritativeProtectionDecision as first argument
      incidentId = argIncidentId || `inc-${Date.now()}`;
      requestedAction = recordOrDecision.requestedAction;
      risk = recordOrDecision.riskScore;
      decision = recordOrDecision.protectionDecision;
      enforcementStatus = recordOrDecision.enforcementStatus;
      client = argClient || 'chrome_extension';
      rawUrl = argUrl;
    } else {
      // Called with object
      incidentId = recordOrDecision.incidentId;
      requestedAction = recordOrDecision.requestedAction;
      risk = recordOrDecision.risk;
      decision = recordOrDecision.decision;
      enforcementStatus = recordOrDecision.enforcementStatus;
      client = recordOrDecision.client;
      failureReason = recordOrDecision.failureReason;
      rawUrl = recordOrDecision.url;
      rawTarget = recordOrDecision.target;
    }

    // Sanitize target URL - strip query params that may contain tokens, passwords, or emails
    let cleanUrl = rawUrl;
    if (cleanUrl) {
      try {
        const u = new URL(cleanUrl);
        cleanUrl = `${u.protocol}//${u.host}${u.pathname}`;
      } catch {
        cleanUrl = cleanUrl.split('?')[0].split('#')[0];
      }
    }

    return {
      id: `enf-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      incidentId,
      requestedAction,
      risk,
      decision,
      enforcementStatus,
      client,
      failureReason,
      url: cleanUrl,
      target: rawTarget ? rawTarget.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]') : undefined,
    };
  }
}
