/**
 * urlscan.io Dedicated Backend Sandbox Service
 * Direct integration with the official urlscan.io API.
 * Provides secure URL sanitization, SSRF protection, asynchronous polling with backoff,
 * rich signal extraction, and normalized internal threat contracts.
 */

import { config } from '../../config';
import { logger } from '../../utils/logger';
import { validateUrlForSecurity } from '../../utils/urlSecurity';
import {
  NormalizedSandboxResult,
  SandboxStatus,
  SandboxRiskLevel,
  UrlscanSubmissionResponse,
  UrlscanResultResponse,
} from './types';

// Sensitive query parameter keys that MUST never be leaked to third-party sandbox
const SENSITIVE_QUERY_PARAMS = new Set([
  'token',
  'access_token',
  'auth',
  'auth_token',
  'authorization',
  'key',
  'api_key',
  'apikey',
  'secret',
  'password',
  'passwd',
  'pwd',
  'code',
  'passcode',
  'otp',
  'jwt',
  'id_token',
  'refresh_token',
  'session',
  'session_id',
  'sessionid',
  'sig',
  'signature',
  'state',
  'nonce',
  'credential',
]);

export class UrlscanService {
  private apiUrl: string;
  private apiKey: string | null;
  private visibility: 'public' | 'unlisted' | 'private';
  private pollTimeoutMs: number;
  private maxRetries: number;

  constructor(customConfig?: {
    apiKey?: string | null;
    apiUrl?: string;
    visibility?: 'public' | 'unlisted' | 'private';
    pollTimeoutMs?: number;
    maxRetries?: number;
  }) {
    this.apiUrl = (customConfig?.apiUrl || config.urlscanApiUrl || 'https://urlscan.io/api/v1').replace(/\/+$/, '');
    this.apiKey = customConfig?.apiKey !== undefined ? customConfig.apiKey : config.urlscanApiKey;
    this.visibility = customConfig?.visibility || config.urlscanVisibility || 'unlisted';
    this.pollTimeoutMs = customConfig?.pollTimeoutMs || config.urlscanPollTimeoutMs || 25000;
    this.maxRetries = customConfig?.maxRetries || config.urlscanMaxRetries || 10;
  }

  /**
   * Returns true if a live API key is configured.
   */
  public isConfigured(): boolean {
    return Boolean(this.apiKey && this.apiKey.trim().length > 0);
  }

  /**
   * Sanitizes a URL before transmission:
   * 1. Strips sensitive tokens / credentials from query parameters.
   * 2. Preserves structure required for legitimate sandbox behavioral analysis.
   */
  public sanitizeUrlForScan(rawUrl: string): { safeUrl: string; sanitized: boolean; removedParams: string[] } {
    try {
      const parsed = new URL(rawUrl.includes('://') ? rawUrl : `https://${rawUrl}`);
      const removedParams: string[] = [];
      const keysToDelete: string[] = [];

      parsed.searchParams.forEach((_val, key) => {
        const lowerKey = key.toLowerCase();
        if (SENSITIVE_QUERY_PARAMS.has(lowerKey) || lowerKey.includes('token') || lowerKey.includes('secret') || lowerKey.includes('password')) {
          keysToDelete.push(key);
          removedParams.push(key);
        }
      });

      keysToDelete.forEach(k => parsed.searchParams.delete(k));

      return {
        safeUrl: parsed.toString(),
        sanitized: removedParams.length > 0,
        removedParams,
      };
    } catch {
      return {
        safeUrl: rawUrl,
        sanitized: false,
        removedParams: [],
      };
    }
  }

  /**
   * Submits a suspicious URL to urlscan.io scanning API.
   * Enforces SSRF defense, URL validation, and credential hygiene.
   */
  public async submitUrl(
    targetUrl: string,
    options?: { visibility?: 'public' | 'unlisted' | 'private'; tags?: string[] }
  ): Promise<UrlscanSubmissionResponse> {
    const startTime = Date.now();

    // 1. SSRF and Protocol Security Validation
    const securityCheck = validateUrlForSecurity(targetUrl);
    if (!securityCheck.safe) {
      logger.warn('[Urlscan] SSRF prevention blocked submission', {
        targetUrl,
        reason: securityCheck.blockedReason,
        isPrivate: securityCheck.isPrivateOrLoopback,
      });
      throw new Error(`[SSRF Blocked] Cannot submit internal or disallowed URL: ${securityCheck.blockedReason}`);
    }

    // 2. Check API Key presence
    if (!this.isConfigured()) {
      logger.warn('[Urlscan] Submission aborted: URLSCAN_API_KEY is not configured');
      throw new Error('urlscan.io API key is not configured');
    }

    // 3. Sanitize URL to strip sensitive tokens/passwords (Privacy Requirement)
    const { safeUrl, removedParams } = this.sanitizeUrlForScan(securityCheck.normalizedUrl || targetUrl);
    if (removedParams.length > 0) {
      logger.info('[Urlscan] Sanitized sensitive parameters before sandbox submission', {
        removedParams,
      });
    }

    const payload = {
      url: safeUrl,
      visibility: options?.visibility || this.visibility,
      tags: options?.tags || ['neuroshield', 'phishing-analysis'],
    };

    logger.info('[Urlscan] Submitting URL for sandbox inspection', {
      action: 'scan requested',
      targetHost: securityCheck.hostname,
      visibility: payload.visibility,
    });

    // 4. Dispatch HTTP POST to urlscan.io
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s submission timeout

    try {
      const response = await fetch(`${this.apiUrl}/scan/`, {
        method: 'POST',
        headers: {
          'API-Key': this.apiKey as string,
          'Content-Type': 'application/json',
          'User-Agent': 'NeuroShield-Threat-Defense/2.0',
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Handle Rate Limiting (HTTP 429)
      if (response.status === 429) {
        logger.warn('[Urlscan] API Rate limit reached on submission', {
          status: 429,
          action: 'API rate limit',
        });
        const errJson = await response.json().catch(() => ({}));
        const err = new Error(errJson?.message || 'urlscan.io rate limit exceeded (HTTP 429)');
        (err as any).statusCode = 429;
        throw err;
      }

      if (!response.ok) {
        const errorText = await response.text();
        logger.error('[Urlscan] API submission failed', {
          status: response.status,
          error: errorText,
          action: 'scan failed',
        });
        throw new Error(`urlscan.io submission failed with HTTP ${response.status}: ${errorText}`);
      }

      const submission = (await response.json()) as UrlscanSubmissionResponse;

      logger.info('[Urlscan] Scan submitted successfully', {
        action: 'scan submitted',
        scanId: submission.uuid,
        api: submission.api,
        latencyMs: Date.now() - startTime,
      });

      return submission;
    } catch (err: any) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        throw new Error('urlscan.io submission request timed out after 10000ms');
      }
      throw err;
    }
  }

  /**
   * Retrieves scan result using scan UUID with safe asynchronous polling,
   * retry limits, and exponential backoff.
   */
  public async pollScanResult(
    uuid: string,
    timeoutMs: number = this.pollTimeoutMs,
    maxRetries: number = this.maxRetries
  ): Promise<{
    raw?: UrlscanResultResponse;
    status: SandboxStatus;
    pollAttempts: number;
    latencyMs: number;
    errorMessage?: string;
  }> {
    const startTime = Date.now();
    let delayMs = 2000; // Initial wait: 2.0 seconds
    let attempts = 0;

    while (attempts < maxRetries) {
      attempts++;
      const elapsed = Date.now() - startTime;
      if (elapsed >= timeoutMs) {
        logger.warn('[Urlscan] Polling timed out waiting for sandbox result', {
          action: 'scan failed',
          scanId: uuid,
          attempts,
          elapsedMs: elapsed,
          timeoutMs,
        });
        return {
          status: 'timeout',
          pollAttempts: attempts,
          latencyMs: elapsed,
          errorMessage: `Sandbox analysis timed out after ${elapsed}ms (${attempts} attempts)`,
        };
      }

      // Safe sleep before polling
      await new Promise((resolve) => setTimeout(resolve, delayMs));

      try {
        const controller = new AbortController();
        const callTimeout = setTimeout(() => controller.abort(), 8000);

        const response = await fetch(`${this.apiUrl}/result/${encodeURIComponent(uuid)}/`, {
          headers: this.apiKey ? { 'API-Key': this.apiKey } : {},
          signal: controller.signal,
        });
        clearTimeout(callTimeout);

        // HTTP 200: Scan complete!
        if (response.status === 200) {
          const rawResult = (await response.json()) as UrlscanResultResponse;
          logger.info('[Urlscan] Scan completed successfully', {
            action: 'scan completed',
            scanId: uuid,
            attempts,
            latencyMs: Date.now() - startTime,
          });
          return {
            raw: rawResult,
            status: 'completed',
            pollAttempts: attempts,
            latencyMs: Date.now() - startTime,
          };
        }

        // HTTP 404 / 400: Scan still pending / processing (normal urlscan.io behavior)
        if (response.status === 404 || response.status === 400) {
          logger.debug('[Urlscan] Scan pending in sandbox queue', {
            scanId: uuid,
            attempt: attempts,
            status: response.status,
          });
          // Exponential backoff: back up by 1.5x, max 5000ms
          delayMs = Math.min(Math.round(delayMs * 1.5), 5000);
          continue;
        }

        // HTTP 429: Rate limited
        if (response.status === 429) {
          logger.warn('[Urlscan] Rate limited during result polling', {
            action: 'API rate limit',
            scanId: uuid,
            status: 429,
          });
          return {
            status: 'rate_limited',
            pollAttempts: attempts,
            latencyMs: Date.now() - startTime,
            errorMessage: 'urlscan.io rate limit reached during result retrieval',
          };
        }

        // Other HTTP error
        logger.warn('[Urlscan] Result fetch received unexpected HTTP status', {
          action: 'scan failed',
          scanId: uuid,
          status: response.status,
        });
        return {
          status: 'failed',
          pollAttempts: attempts,
          latencyMs: Date.now() - startTime,
          errorMessage: `urlscan.io returned HTTP ${response.status} during result retrieval`,
        };
      } catch (err: any) {
        logger.warn('[Urlscan] Network exception during result polling', {
          scanId: uuid,
          attempt: attempts,
          error: err?.message,
        });
        // Backoff and retry unless out of time
        delayMs = Math.min(Math.round(delayMs * 1.5), 5000);
      }
    }

    return {
      status: 'timeout',
      pollAttempts: attempts,
      latencyMs: Date.now() - startTime,
      errorMessage: `Maximum poll retries (${maxRetries}) reached before scan completed`,
    };
  }

  /**
   * Normalizes raw urlscan.io output into NeuroShield's canonical sandbox contract.
   * Conforms strictly to Requirement 6 and Requirement 7.
   */
  public normalizeResult(
    raw: UrlscanResultResponse | undefined,
    originalUrl: string,
    scanId: string,
    status: SandboxStatus,
    meta?: { pollAttempts?: number; latencyMs?: number; errorMessage?: string }
  ): NormalizedSandboxResult {
    // If scan did not complete cleanly or was bypassed, return normalized status structure
    if (status !== 'completed' || !raw) {
      const isBypassed = scanId === 'bypassed';
      return {
        url: originalUrl,
        scan_id: scanId,
        sandbox_status: isBypassed ? 'completed' : status,
        final_url: originalUrl,
        redirects: [],
        threat_indicators: isBypassed 
          ? [] 
          : status === 'rate_limited' 
          ? ['SANDBOX_RATE_LIMITED'] 
          : status === 'timeout' 
          ? ['SANDBOX_TIMED_OUT'] 
          : ['SANDBOX_UNAVAILABLE'],
        risk_score: 0.0,
        risk_level: 'low',
        verdict: isBypassed ? 'SAFE' : 'UNKNOWN',
        error_message: meta?.errorMessage || (isBypassed ? 'Sandbox analysis bypassed for low-risk URL' : `Sandbox execution status: ${status}`),
        poll_attempts: meta?.pollAttempts,
        latency_ms: meta?.latencyMs,
      };
    }

    const page = raw.page || {};
    const task = raw.task || { uuid: scanId, time: new Date().toISOString(), url: originalUrl, visibility: this.visibility };
    const verdicts = raw.verdicts || {};
    const data = raw.data || {};

    // 1. Final URL and Redirect Chain
    const finalUrl = page.url || task.url || originalUrl;
    const redirects: string[] = [];
    if (data.requests && data.requests.length > 0) {
      for (const req of data.requests) {
        const reqUrl = req.response?.response?.url;
        const status = req.response?.response?.status;
        if (reqUrl && status && (status >= 300 && status < 400)) {
          redirects.push(reqUrl);
        }
      }
    }
    if (redirects.length === 0 && finalUrl !== originalUrl) {
      redirects.push(finalUrl);
    }

    // 2. Threat Indicators extraction
    const threatIndicators: string[] = [];
    const overallVerdicts = verdicts.overall || {};
    const urlscanVerdicts = verdicts.urlscan || {};
    const engineVerdicts = verdicts.engines || {};

    // Overall categories
    if (Array.isArray(overallVerdicts.categories)) {
      overallVerdicts.categories.forEach(c => threatIndicators.push(`CATEGORY_${c.toUpperCase().replace(/\s+/g, '_')}`));
    }
    if (Array.isArray(overallVerdicts.tags)) {
      overallVerdicts.tags.forEach(t => threatIndicators.push(`TAG_${t.toUpperCase().replace(/\s+/g, '_')}`));
    }

    // Engine malicious flags
    let enginesFlagged = 0;
    if (Array.isArray(engineVerdicts.verdicts)) {
      engineVerdicts.verdicts.forEach((ev) => {
        if (ev.malicious) {
          enginesFlagged++;
          threatIndicators.push(`ENGINE_${ev.engine.toUpperCase()}_FLAGGED`);
        }
      });
    }

    // Suspicious resource checks in network logs
    const suspiciousResources: string[] = [];
    if (Array.isArray(data.requests)) {
      data.requests.forEach((r) => {
        const reqUrl = r.response?.response?.url || '';
        const mime = r.response?.response?.mimeType || '';
        if (
          reqUrl.endsWith('.exe') ||
          reqUrl.endsWith('.scr') ||
          reqUrl.endsWith('.bat') ||
          reqUrl.endsWith('.apk') ||
          mime.includes('application/x-msdownload')
        ) {
          suspiciousResources.push(reqUrl);
          threatIndicators.push('SUSPICIOUS_EXECUTABLE_DOWNLOAD');
        }
      });
    }

    // 3. Compute Normalized Sandbox Risk Score (0.0 to 100.0)
    // urlscan overall.score ranges from 0 to 100, or negative for benign.
    let baseScore = 0;
    if (typeof overallVerdicts.score === 'number') {
      baseScore = Math.max(0, Math.min(100, overallVerdicts.score));
    }
    if (typeof urlscanVerdicts.score === 'number' && urlscanVerdicts.score > baseScore) {
      baseScore = Math.max(0, Math.min(100, urlscanVerdicts.score));
    }

    // Corroborate with engine detections
    if (overallVerdicts.malicious || urlscanVerdicts.malicious || enginesFlagged > 0) {
      baseScore = Math.max(baseScore, 85 + (enginesFlagged * 3));
    }

    // Penalize evasive redirect chains (>2 redirects)
    if (redirects.length >= 2) {
      baseScore = Math.min(100, baseScore + 15);
      threatIndicators.push('MULTI_HOP_REDIRECT_CHAIN');
    }

    // Cap score
    const riskScore = Math.min(100, Math.max(0, Math.round(baseScore * 10) / 10));

    // 4. Derive Risk Level and Verdict
    let riskLevel: SandboxRiskLevel = 'low';
    let verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN' = 'SAFE';

    if (riskScore >= 80 || enginesFlagged >= 1 || overallVerdicts.malicious) {
      riskLevel = riskScore >= 90 ? 'critical' : 'high';
      verdict = 'MALICIOUS';
    } else if (riskScore >= 40 || threatIndicators.length > 0) {
      riskLevel = 'medium';
      verdict = 'SUSPICIOUS';
    } else {
      riskLevel = 'low';
      verdict = 'SAFE';
    }

    return {
      url: originalUrl,
      scan_id: scanId,
      sandbox_status: 'completed',
      final_url: finalUrl,
      redirects,
      threat_indicators: Array.from(new Set(threatIndicators)),
      risk_score: riskScore,
      risk_level: riskLevel,
      verdict,
      screenshot_url: task.screenshotURL,
      dom_url: task.domURL,
      report_url: task.reportURL,
      page_title: page.title,
      status_code: page.status,
      domain_info: {
        domain: page.domain,
        apexDomain: page.apexDomain,
        asn: page.asn,
        asnname: page.asnname,
        country: page.country,
        ip: page.ip,
        server: page.server,
      },
      network_requests_count: raw.stats?.requests || data.requests?.length || 0,
      suspicious_resources: suspiciousResources,
      targeted_brands: overallVerdicts.brands || [],
      engines_flagged: enginesFlagged,
      poll_attempts: meta?.pollAttempts,
      latency_ms: meta?.latencyMs,
    };
  }

  /**
   * High-level scan execution orchestration:
   * 1. SSRF check + URL sanitization
   * 2. Submission to urlscan.io API
   * 3. Asynchronous polling with exponential backoff
   * 4. Signal normalization
   * 5. Fallback on any failure without throwing
   */
  public async scanUrl(targetUrl: string): Promise<NormalizedSandboxResult> {
    const startTime = Date.now();

    // Check if configured
    if (!this.isConfigured()) {
      logger.info('[Urlscan] Service disabled or URLSCAN_API_KEY absent, marking sandbox unavailable');
      return this.normalizeResult(undefined, targetUrl, 'unconfigured', 'unavailable', {
        errorMessage: 'URLSCAN_API_KEY is not set in environment',
        latencyMs: 0,
      });
    }

    try {
      // 1. Submit
      const submission = await this.submitUrl(targetUrl);

      // 2. Poll for asynchronous results
      const poll = await this.pollScanResult(submission.uuid);

      // 3. Normalize
      return this.normalizeResult(poll.raw, targetUrl, submission.uuid, poll.status, {
        pollAttempts: poll.pollAttempts,
        latencyMs: Date.now() - startTime,
        errorMessage: poll.errorMessage,
      });
    } catch (err: any) {
      const latencyMs = Date.now() - startTime;
      const isRateLimited = err?.statusCode === 429 || (err?.message && err.message.includes('429'));
      const status: SandboxStatus = isRateLimited ? 'rate_limited' : 'failed';

      logger.warn('[Urlscan] scanUrl fell back to safe error state', {
        action: 'scan failed',
        status,
        error: err?.message || 'Unknown error',
        latencyMs,
      });

      return this.normalizeResult(undefined, targetUrl, `err-${Date.now()}`, status, {
        errorMessage: err?.message || 'Sandbox scan execution failed',
        latencyMs,
      });
    }
  }
}

// Export singleton instance initialized with runtime configuration
export const urlscanService = new UrlscanService();
