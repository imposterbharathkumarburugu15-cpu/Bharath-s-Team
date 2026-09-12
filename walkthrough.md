# urlscan.io Secure URL Sandbox-Analysis Layer Integration

## 1. Overview
The `urlscan.io` URL sandbox-analysis layer has been integrated into NeuroShield as a secondary behavioral inspection subsystem. The existing ML and heuristic phishing-detection architecture is preserved in full. Only suspicious or uncertain URLs are sent to `urlscan.io` for deep browser and DOM sandbox analysis.

---

## 2. Architecture & Data Flow

```
Chrome Extension / Gmail / Ingestion Channels
                    ↓
           NeuroShield Backend
                    ↓
         Existing ML Detection Engine
                    ↓
           Risk Decision Check
          ┌─────────┴─────────┐
    SAFE (<35)           SUSPICIOUS / UNCERTAIN (35 - 85)
          ↓                           ↓
   Bypasses Sandbox        urlscan.io Scanning API (POST /api/v1/scan/)
          ↓                           ↓
   Instant Response        Asynchronous Polling with Backoff (GET /api/v1/result/{uuid}/)
                                      ↓
                               Normalized Sandbox Result
                                      ↓
                           NeuroShield Fusion Engine
                                      ↓
                           Authoritative Decision:
                        SAFE / SUSPICIOUS / PHISHING
```

---

## 3. Key Components Implemented

### A. Dedicated Backend Service Module (`src/services/urlscan/`)
- [`types.ts`](file:///c:/Users/bhara/Downloads/sentinel360-ai-phishing-&-scam-defense-platform/src/services/urlscan/types.ts): Canonical definitions for `NormalizedSandboxResult`, `UrlscanSubmissionResponse`, `UrlscanResultResponse`, and `FusedSandboxDecision`.
- [`urlscanService.ts`](file:///c:/Users/bhara/Downloads/sentinel360-ai-phishing-&-scam-defense-platform/src/services/urlscan/urlscanService.ts):
  - `submitUrl(url)`: Direct HTTP integration with `https://urlscan.io/api/v1/scan/`.
  - `pollScanResult(uuid)`: Safe asynchronous polling with exponential backoff (2s → 3s → 4.5s → 5s max), timeout limits, and HTTP 429 rate limit handling.
  - `normalizeResult(...)`: Normalizes raw responses into a consistent internal structure containing final destination URL, redirect hops, domain info, page title, screenshot URL, and engine detections.
  - `sanitizeUrlForScan(url)`: Strips sensitive query params (`token`, `password`, `key`, `session`, `auth`) to preserve user privacy.
  - SSRF Protection: Calls `validateUrlForSecurity` to block loopback (`127.0.0.1`), RFC 1918 subnets, and cloud metadata (`169.254.169.254`).
- [`sandboxFusionEngine.ts`](file:///c:/Users/bhara/Downloads/sentinel360-ai-phishing-&-scam-defense-platform/src/services/urlscan/sandboxFusionEngine.ts):
  - `shouldTriggerSandbox(url, mlRiskScore)`: Configurable trigger thresholds (`minRiskScore=35`, `maxRiskScore=85`).
  - `fuse(...)`: Combines ML risk scores with sandbox behavioral evidence. Corroborates suspicious links, raises malicious scores to 95+ (BLOCK_VIEW), and de-escalates false positives on verified clean domains.
- [`index.ts`](file:///c:/Users/bhara/Downloads/sentinel360-ai-phishing-&-scam-defense-platform/src/services/urlscan/index.ts): Barrel export.

### B. Configuration System Updates
- [`src/config/index.ts`](file:///c:/Users/bhara/Downloads/sentinel360-ai-phishing-&-scam-defense-platform/src/config/index.ts):
  - Added `urlscanApiKey`, `urlscanApiUrl`, `urlscanVisibility`, `urlscanMinRiskScore`, `urlscanMaxRiskScore`, `urlscanPollTimeoutMs`, `urlscanMaxRetries`.
- [`.env.example`](file:///c:/Users/bhara/Downloads/sentinel360-ai-phishing-&-scam-defense-platform/.env.example):
  - Documented `URLSCAN_API_KEY=""`, `URLSCAN_VISIBILITY="unlisted"`, and operational thresholds.

### C. Server Endpoints in [`server.ts`](file:///c:/Users/bhara/Downloads/sentinel360-ai-phishing-&-scam-defense-platform/server.ts)
- `POST /api/sandbox/urlscan/scan`: Analyzes target URL via ML, selectively triggers urlscan sandbox, and returns fused verdict.
- `GET /api/sandbox/urlscan/result/:uuid`: Polls or retrieves scan results by UUID.
- `GET /api/sandbox/urlscan/status`: Reports service configuration and operational readiness.
- `POST /api/guard/policy-check`: Enhanced to automatically trigger urlscan sandbox on suspicious/uncertain candidate URLs and enrich the authoritative 8-field decision contract with sandbox telemetry.

---

## 4. Verification & Testing

### A. Dedicated Sandbox Test Suite (`test/urlscan_sandbox.test.ts`)
Run command:
```bash
node ./node_modules/tsx/dist/cli.mjs test/urlscan_sandbox.test.ts
```
**Results: 12 / 12 PASSED (100%)**
1. Successful URL submission to urlscan.io API
2. Successful asynchronous result retrieval & signal extraction
3. In-progress polling retries (404 -> 200)
4. Polling timeout limits and graceful non-blocking fallback
5. urlscan.io API failure returns failed status without crash
6. HTTP 429 rate limit triggers rate_limited status gracefully
7. SSRF defense rejects RFC 1918, loopback, and metadata before API call
8. Unconfigured API key cleanly defaults to unavailable without error
9. Fusion elevates suspicious ML score (55) to PHISHING (95) on malicious sandbox
10. Fusion lowers borderline ML score (42) to SAFE (20) on verified sandbox
11. Sanitization strips tokens, passwords, and secrets before submission
12. Sandbox trigger thresholds: low-risk bypasses, suspicious triggers

### B. Regression Test Suites
- `test/phase4_enforcement.test.ts`: **15 / 15 PASSED (100%)**
- `test/phase5_dashboard_firestore.test.ts`: **15 / 15 PASSED (100%)**
- `test/phase3_gmail_ingestion.test.ts`: **18 / 18 PASSED (100%)**
- `test/neuroshield_deterministic.test.ts`: **18 / 18 PASSED (100%)**
- `npm run build`: **Compiled cleanly with 0 errors**
