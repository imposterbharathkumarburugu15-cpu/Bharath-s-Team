# NeuroShield AI Phishing & Scam Defense Platform

NeuroShield is an enterprise-grade threat defense platform engineered for automatic real-time detection, forensic analysis, and authoritative enforcement against sophisticated multi-channel phishing, executive smishing, brand impersonation, and evasive credential harvesting.

---

## urlscan.io Secure URL Sandbox-Analysis Layer

### 1. What the Sandbox Layer Does
The sandbox-analysis layer integrates [urlscan.io](https://urlscan.io/) as a secondary, automated behavioral analysis engine. When suspicious, unfamiliar, or uncertain URLs are encountered by NeuroShield, they are submitted to a dedicated sandbox where a headless browser visits the target page in a safe, isolated container to inspect:
- **Final Destination URL & Redirect Chains**: Uncovers multi-hop redirects and evasive cloaking mechanisms.
- **Page DOM & Assets**: Detects brand logos, fake login forms, password inputs, and obfuscated JavaScript.
- **Network Requests**: Monitors external resources, IP addresses, and executable binary downloads (`.exe`, `.apk`).
- **Engine Threat Intelligence**: Extracts verdicts from multiple security vendors, Google Safe Browsing, PhishTank, and urlscan community votes.
- **Visual Evidence**: Retrieves automated screenshots of the page as rendered in the isolated browser.

---

### 2. Why urlscan.io is Used
NeuroShield uses a multi-layered detection approach:
1. **Primary Layer**: The local NeuroShield ML and heuristic detection engine processes URLs in sub-millisecond time.
2. **Secondary Sandbox Layer**: Static heuristics cannot always predict dynamic runtime behavior (e.g., JavaScript redirects, client-side IP fingerprinting, or post-load credential forms). urlscan.io executes the target in a real sandbox browser, providing behavioral ground truth.
3. **Selective Sandbox Invocation**: Low-risk URLs bypass the sandbox completely to eliminate unnecessary latency and conserve API quota. Only suspicious or uncertain URLs (configurable threshold, default 35–85 risk score) or unverified new domains trigger urlscan.io.

---

### 3. Architecture & Request Flow

```
Chrome Extension / Gmail / API Input
               ↓
       NeuroShield Backend
               ↓
    Existing ML & Heuristic Engine
               ↓
     Initial Risk Assessment
      ┌────────┴────────┐
   SAFE (<35)    SUSPICIOUS / UNCERTAIN (35 - 85)
      ↓                 ↓
 Bypasses       urlscan.io REST API (POST /api/v1/scan/)
 Sandbox                ↓
                Asynchronous Polling with Backoff (GET /api/v1/result/{uuid}/)
                        ↓
                Normalized Sandbox Telemetry
                        ↓
                NeuroShield Fusion Engine
                        ↓
             Final Authoritative Verdict:
              SAFE / SUSPICIOUS / PHISHING
```

---

### 4. How to Obtain & Configure the API Key

1. Create a free account at [https://urlscan.io/user/signup](https://urlscan.io/user/signup).
2. Navigate to your profile settings: [https://urlscan.io/user/profile](https://urlscan.io/user/profile).
3. Under **API Keys**, click **Create New API Key**.
4. Copy the generated key.
5. In your local `.env` file, configure `URLSCAN_API_KEY`:

```env
URLSCAN_API_KEY="your-urlscan-api-key-here"
```

> **Security Note**: Never commit your real API key to source control. Never expose `URLSCAN_API_KEY` to the Chrome extension or frontend clients. All urlscan requests are mediated server-side through the NeuroShield backend.

---

### 5. Environment Configuration (`.env`)

Configure the following variables in your `.env` file:

```env
# urlscan.io API Key (leave empty to run in offline local ML fallback mode)
URLSCAN_API_KEY=""

# urlscan.io API Base URL (defaults to official v1 endpoint)
URLSCAN_API_URL="https://urlscan.io/api/v1"

# Visibility mode: 'unlisted' (recommended for privacy), 'private', or 'public'
URLSCAN_VISIBILITY="unlisted"

# Trigger Thresholds: URLs within this ML risk score range trigger sandbox analysis
URLSCAN_MIN_RISK_SCORE=35
URLSCAN_MAX_RISK_SCORE=85

# Polling configuration: Max timeout and retry attempts for asynchronous completion
URLSCAN_POLL_TIMEOUT_MS=25000
URLSCAN_MAX_RETRIES=10
```

---

### 6. Privacy & Security Safeguards

- **No PII or Secret Transmission**: NeuroShield automatically sanitizes URLs before submission, stripping sensitive query parameters (e.g. `token`, `password`, `auth`, `jwt`, `key`, `session`, `credential`). Email bodies, personal messages, and user secrets are NEVER sent to urlscan.io.
- **Unlisted Visibility**: Scans default to `visibility: 'unlisted'`. Unlisted scans are never indexed in public search feeds or search engine listings.
- **SSRF Defense**: Strict pre-flight validation blocks RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopbacks (`127.0.0.1`, `::1`), cloud metadata services (`169.254.169.254`, `metadata.google.internal`), and dangerous protocols (`file:`, `javascript:`, `data:`).
- **Graceful Fail-Safe**: If urlscan.io is down, times out, or hits a rate limit (HTTP 429), NeuroShield falls back seamlessly to the existing ML model. It records `sandbox_status: 'unavailable'` or `'timeout'` without crashing or stalling client traffic.

---

### 7. Dedicated Sandbox Endpoints

- `POST /api/sandbox/urlscan/scan`: Submits a URL for analysis, waits for completion with backoff, and returns the normalized sandbox telemetry fused with ML findings.
  ```json
  {
    "url": "https://example.com",
    "force": false
  }
  ```
- `GET /api/sandbox/urlscan/result/:uuid`: Polls or retrieves scan results by UUID.
- `GET /api/sandbox/urlscan/status`: Inspects operational readiness, API key presence, and active trigger thresholds.

---

## Run Locally

### Prerequisites
- Node.js (v18+ recommended)
- npm

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment
Create `.env` or update `.env.local`:
```bash
cp .env.example .env
```
Add your `GEMINI_API_KEY` and optional `URLSCAN_API_KEY`.

### 3. Start Development Server
```bash
npm run dev
# or
node ./node_modules/tsx/dist/cli.mjs server.ts
```
The server will start on `http://localhost:3000`.

---

## Automated Verification & Testing

Run the dedicated urlscan sandbox test suite:
```bash
node ./node_modules/tsx/dist/cli.mjs test/urlscan_sandbox.test.ts
```

Run comprehensive regression suites:
```bash
# Phase 4 Enforcement Acceptance Suite
node ./node_modules/tsx/dist/cli.mjs test/phase4_enforcement.test.ts

# Phase 5 Dashboard & Incident Repository Suite
node ./node_modules/tsx/dist/cli.mjs test/phase5_dashboard_firestore.test.ts

# Phase 3 Gmail API & Ingestion Suite
node ./node_modules/tsx/dist/cli.mjs test/phase3_gmail_ingestion.test.ts

# Deterministic Pipeline Suite (18/18 Scenarios)
node ./node_modules/tsx/dist/cli.mjs test/neuroshield_deterministic.test.ts
```

Verify production TypeScript build:
```bash
npm run build
```
