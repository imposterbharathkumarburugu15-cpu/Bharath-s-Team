/**
 * urlscan.io Integration Type Definitions
 * Strict contracts for submission, polling, signal extraction, and risk normalization.
 */

export type SandboxStatus = 
  | 'completed'
  | 'pending'
  | 'timeout'
  | 'rate_limited'
  | 'failed'
  | 'unavailable';

export type SandboxRiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface UrlscanSubmissionResponse {
  message: string;
  uuid: string;
  result: string;
  api: string;
  visibility: string;
  options?: {
    useragent?: string;
  };
  url: string;
  country?: string;
}

export interface UrlscanPageInfo {
  url?: string;
  domain?: string;
  apexDomain?: string;
  country?: string;
  city?: string;
  server?: string;
  ip?: string;
  asn?: string;
  asnname?: string;
  title?: string;
  status?: number;
  tlsValidDays?: number;
  tlsIssuer?: string;
  umbrellaRank?: number;
}

export interface UrlscanVerdictEngine {
  score?: number;
  malicious?: boolean;
  categories?: string[];
  brands?: string[];
  tags?: string[];
}

export interface UrlscanVerdicts {
  overall?: {
    score?: number;
    malicious?: boolean;
    categories?: string[];
    brands?: string[];
    tags?: string[];
    hasVerdicts?: boolean;
  };
  urlscan?: UrlscanVerdictEngine;
  engines?: {
    score?: number;
    malicious?: boolean;
    categories?: string[];
    enginesTotal?: number;
    verdicts?: Array<{
      engine: string;
      score: number;
      category?: string;
      malicious: boolean;
    }>;
  };
  community?: {
    score?: number;
    votes?: number;
    votesMalicious?: number;
    votesBenign?: number;
  };
}

export interface UrlscanResultData {
  requests?: Array<{
    response?: {
      response?: {
        url?: string;
        status?: number;
        mimeType?: string;
        remoteIPAddress?: string;
        asn?: {
          asn?: string;
          name?: string;
        };
      };
    };
    initiator?: {
      type?: string;
    };
  }>;
  links?: Array<{
    href?: string;
    text?: string;
  }>;
}

export interface UrlscanResultResponse {
  task?: {
    uuid: string;
    time: string;
    url: string;
    visibility: string;
    method?: string;
    source?: string;
    screenshotURL?: string;
    reportURL?: string;
    domURL?: string;
  };
  page?: UrlscanPageInfo;
  verdicts?: UrlscanVerdicts;
  data?: UrlscanResultData;
  stats?: {
    uniqIPs?: number;
    uniqCountries?: number;
    dataLength?: number;
    encodedDataLength?: number;
    requests?: number;
  };
  meta?: {
    processors?: {
      umbrella?: {
        rank?: number;
      };
    };
  };
}

/**
 * Normalized Internal Sandbox Contract (Requirement 7)
 */
export interface NormalizedSandboxResult {
  url: string;
  scan_id: string;
  sandbox_status: SandboxStatus;
  final_url: string;
  redirects: string[];
  threat_indicators: string[];
  risk_score: number; // 0.0 - 100.0
  risk_level: SandboxRiskLevel;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  screenshot_url?: string;
  dom_url?: string;
  report_url?: string;
  page_title?: string;
  status_code?: number;
  domain_info?: {
    domain?: string;
    apexDomain?: string;
    asn?: string;
    asnname?: string;
    country?: string;
    ip?: string;
    server?: string;
  };
  network_requests_count?: number;
  suspicious_resources?: string[];
  targeted_brands?: string[];
  engines_flagged?: number;
  error_message?: string;
  poll_attempts?: number;
  latency_ms?: number;
}

/**
 * Fusion Result combining ML inference with Sandbox Findings (Requirement 8 & 9)
 */
export interface FusedSandboxDecision {
  finalVerdict: 'SAFE' | 'SUSPICIOUS' | 'PHISHING';
  finalRiskScore: number;
  confidence: number;
  sandboxTriggered: boolean;
  sandboxReason?: string;
  sandboxResult?: NormalizedSandboxResult;
  mlScore: number;
  combinedEvidence: string[];
  protectionDecision: 'ALLOW' | 'WARN' | 'BLOCK_VIEW' | 'BLOCK_ACTION';
}
