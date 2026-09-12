/**
 * NeuroShield URL Sandbox Fusion Engine
 * Intelligently combines existing ML phishing/scam detection scores with
 * live sandbox behavioral evidence from urlscan.io.
 * 
 * Rules:
 * 1. Low-risk URLs bypass the sandbox to conserve API quota and eliminate latency.
 * 2. Suspicious or uncertain URLs (configurable threshold 35-85) trigger deep sandbox analysis.
 * 3. High sandbox malicious signals corroborate and elevate the final risk score.
 * 4. Benign sandbox findings provide corroboration to resolve uncertain false positives.
 * 5. If sandbox fails or times out, gracefully degrades to local ML inference.
 */

import { config } from '../../config';
import { logger } from '../../utils/logger';
import { NormalizedSandboxResult, FusedSandboxDecision } from './types';

export interface FusionInput {
  url: string;
  mlRiskScore: number;
  mlVerdict: 'SAFE' | 'SUSPICIOUS' | 'PHISHING' | 'MALICIOUS' | 'UNKNOWN';
  mlThreats?: string[];
  mlConfidence?: number;
  sandboxResult?: NormalizedSandboxResult;
  forceSandbox?: boolean;
}

export class SandboxFusionEngine {
  /**
   * Evaluates whether a URL requires urlscan.io sandbox inspection.
   * Checks thresholds, URL presence, and service readiness.
   */
  public static shouldTriggerSandbox(
    url: string | undefined,
    mlRiskScore: number,
    options?: { forceSandbox?: boolean; confidence?: number }
  ): { shouldTrigger: boolean; reason: string } {
    if (!url || typeof url !== 'string' || !url.trim()) {
      return { shouldTrigger: false, reason: 'No URL target provided in analysis payload' };
    }

    const minThreshold = config.urlscanMinRiskScore ?? 35;
    const maxThreshold = config.urlscanMaxRiskScore ?? 85;

    // Rule: Low-risk verified safe URLs do not need sandbox
    if (mlRiskScore < minThreshold && !options?.forceSandbox) {
      return {
        shouldTrigger: false,
        reason: `ML risk score (${mlRiskScore}) is below sandbox trigger threshold (${minThreshold})`,
      };
    }

    // Force scan option (e.g., explicit manual analyst trigger or automated test)
    if (options?.forceSandbox) {
      if (!config.urlscanApiKey || config.urlscanApiKey.trim() === '') {
        return { shouldTrigger: false, reason: 'URLSCAN_API_KEY is not configured; running in local ML mode' };
      }
      return { shouldTrigger: true, reason: 'Explicit analyst force sandbox requested' };
    }

    // Check API Key readiness for suspicious URLs
    if (!config.urlscanApiKey || config.urlscanApiKey.trim() === '') {
      return { shouldTrigger: false, reason: 'URLSCAN_API_KEY is not configured; running in local ML mode' };
    }


    // Rule: Suspicious or uncertain URLs within trigger boundary
    if (mlRiskScore >= minThreshold && mlRiskScore <= maxThreshold) {
      return {
        shouldTrigger: true,
        reason: `ML risk score (${mlRiskScore}) is in suspicious/uncertain range [${minThreshold}, ${maxThreshold}]`,
      };
    }

    // Rule: Very low confidence on borderline scores
    if (options?.confidence !== undefined && options.confidence < 50) {
      return {
        shouldTrigger: true,
        reason: `ML confidence is low (${options.confidence}%), sandbox validation required`,
      };
    }

    // Above max threshold: high confidence known threat, but can still verify if desired
    return {
      shouldTrigger: false,
      reason: `ML risk score (${mlRiskScore}) already exceeds upper threshold (${maxThreshold}); high-confidence threat`,
    };
  }

  /**
   * Combines existing ML output with normalized sandbox findings.
   * Conforms to Requirement 8 & Requirement 9.
   */
  public static fuse(input: FusionInput): FusedSandboxDecision {
    const { url, mlRiskScore, mlVerdict, mlThreats = [], mlConfidence = 75, sandboxResult } = input;

    // Default fallback state (if sandbox was not triggered or is unavailable)
    const baseVerdict: 'SAFE' | 'SUSPICIOUS' | 'PHISHING' = 
      mlVerdict === 'SAFE' ? 'SAFE' : mlVerdict === 'PHISHING' || mlVerdict === 'MALICIOUS' ? 'PHISHING' : 'SUSPICIOUS';

    let defaultProtection: 'ALLOW' | 'WARN' | 'BLOCK_VIEW' | 'BLOCK_ACTION' = 'ALLOW';
    if (baseVerdict === 'PHISHING') defaultProtection = 'BLOCK_VIEW';
    else if (baseVerdict === 'SUSPICIOUS') defaultProtection = 'WARN';

    // Case 1: Sandbox was NOT run, was bypassed, or is unavailable/timed out/failed
    if (!sandboxResult || sandboxResult.sandbox_status !== 'completed' || sandboxResult.scan_id === 'bypassed') {
      const sandboxNote = sandboxResult?.scan_id === 'bypassed'
        ? '[Sandbox: BYPASSED_SAFE]'
        : sandboxResult 
        ? `[Sandbox: ${sandboxResult.sandbox_status.toUpperCase()}${sandboxResult.error_message ? ` - ${sandboxResult.error_message}` : ''}]`
        : '[Sandbox: BYPASSED_SAFE]';

      return {
        finalVerdict: baseVerdict,
        finalRiskScore: mlRiskScore,
        confidence: mlConfidence,
        sandboxTriggered: Boolean(sandboxResult && sandboxResult.scan_id !== 'bypassed'),
        sandboxReason: sandboxResult?.error_message || 'Sandbox analysis bypassed',
        sandboxResult,
        mlScore: mlRiskScore,
        combinedEvidence: Array.from(new Set([...mlThreats, sandboxNote])),
        protectionDecision: defaultProtection,
      };
    }

    // Case 2: Sandbox completed successfully — merge telemetry!
    const sandboxScore = sandboxResult.risk_score;
    const sandboxVerdict = sandboxResult.verdict;
    const isSandboxMalicious = sandboxVerdict === 'MALICIOUS' || (sandboxResult.engines_flagged || 0) > 0;
    const isSandboxSuspicious = sandboxVerdict === 'SUSPICIOUS' || sandboxResult.threat_indicators.length > 0;

    let finalRiskScore = mlRiskScore;
    let finalVerdict: 'SAFE' | 'SUSPICIOUS' | 'PHISHING' = baseVerdict;
    let protectionDecision: 'ALLOW' | 'WARN' | 'BLOCK_VIEW' | 'BLOCK_ACTION' = defaultProtection;
    let confidence = Math.min(99, mlConfidence + 15); // Sandbox increases certainty

    const newEvidence: string[] = [...mlThreats];

    // Add sandbox telemetry to evidence list
    if (sandboxResult.page_title) {
      newEvidence.push(`Sandbox Page Title: "${sandboxResult.page_title}"`);
    }
    if (sandboxResult.final_url && sandboxResult.final_url !== url) {
      newEvidence.push(`Sandbox Redirect: ${url} -> ${sandboxResult.final_url}`);
    }
    if (sandboxResult.threat_indicators.length > 0) {
      newEvidence.push(...sandboxResult.threat_indicators.map((ti) => `Sandbox IoC: ${ti}`));
    }
    if ((sandboxResult.engines_flagged || 0) > 0) {
      newEvidence.push(`Sandbox Detection: ${sandboxResult.engines_flagged} security engine(s) flagged this target`);
    }

    if (isSandboxMalicious) {
      // Sandbox confirms high-risk malice
      finalRiskScore = Math.max(mlRiskScore, sandboxScore, 90);
      finalVerdict = 'PHISHING';
      protectionDecision = 'BLOCK_VIEW';
      confidence = Math.max(90, confidence);
    } else if (isSandboxSuspicious) {
      // Sandbox indicates suspicious activity
      finalRiskScore = Math.max(mlRiskScore, Math.round(mlRiskScore * 0.4 + sandboxScore * 0.6));
      finalVerdict = finalRiskScore >= 80 ? 'PHISHING' : 'SUSPICIOUS';
      protectionDecision = finalVerdict === 'PHISHING' ? 'BLOCK_VIEW' : 'WARN';
    } else {
      // Sandbox reports SAFE (0 engines flagged, clean domain, safe resources)
      if (mlRiskScore <= 60) {
        // Corroborated clean: reduce false positive score
        finalRiskScore = Math.min(mlRiskScore, 20);
        finalVerdict = 'SAFE';
        protectionDecision = 'ALLOW';
        newEvidence.push('Sandbox Verification: Verified clean by urlscan.io behavioral sandbox');
      } else {
        // ML detected strong deceptive content in email/chat body, but URL itself has clean reputation
        finalRiskScore = Math.max(35, mlRiskScore - 15);
        finalVerdict = 'SUSPICIOUS';
        protectionDecision = 'WARN';
        newEvidence.push('Sandbox Verification: URL sandbox shows clean reputation, but message content exhibits high deception risk');
      }
    }

    logger.info('[Urlscan Fusion] Fused ML and Sandbox verdicts', {
      action: 'final risk decision',
      url,
      mlScore: mlRiskScore,
      sandboxScore,
      finalRiskScore,
      finalVerdict,
    });

    return {
      finalVerdict,
      finalRiskScore,
      confidence,
      sandboxTriggered: true,
      sandboxReason: 'Sandbox completed and signals fused',
      sandboxResult,
      mlScore: mlRiskScore,
      combinedEvidence: Array.from(new Set(newEvidence)),
      protectionDecision,
    };
  }
}
