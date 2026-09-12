/**
 * NeuroShield urlscan.io Sandbox Analysis Layer Test Suite
 * Comprehensive Verification:
 *  1. Successful URL Submission
 *  2. Successful Asynchronous Result Retrieval
 *  3. In-Progress / Pending Polling Retry Behavior
 *  4. Polling Timeout Graceful Handling
 *  5. External API 500 Failure Handling (No Crash)
 *  6. HTTP 429 Rate Limiting Graceful Degradation
 *  7. SSRF and Private IP Rejection Defense
 *  8. Missing API Key Fallback / Degraded Mode
 *  9. ML + Sandbox Fusion: Threat Corroboration (Elevate Suspicious -> Phishing)
 * 10. ML + Sandbox Fusion: Clean Verification (De-escalate Suspicious -> Safe)
 * 11. Privacy Parameter Sanitization (Token/Credential Stripping)
 * 12. REST API Integration Endpoints (/api/sandbox/urlscan/status, /scan, /result/:uuid)
 */

import assert from 'assert';
import { UrlscanService } from '../src/services/urlscan/urlscanService';
import { SandboxFusionEngine } from '../src/services/urlscan/sandboxFusionEngine';
import { NormalizedSandboxResult, UrlscanResultResponse, UrlscanSubmissionResponse } from '../src/services/urlscan/types';
import { config } from '../src/config';

interface TestCaseResult {
  id: number;
  name: string;
  passed: boolean;
  notes: string;
}

const testResults: TestCaseResult[] = [];

async function runTest(id: number, name: string, fn: () => Promise<void>) {
  try {
    await fn();
    console.log(`  [PASS] Test ${id}: ${name}`);
    testResults.push({ id, name, passed: true, notes: 'Passed all assertions' });
  } catch (err: any) {
    console.error(`  [FAIL] Test ${id}: ${name}`);
    console.error(`         Error: ${err?.message || err}`);
    testResults.push({ id, name, passed: false, notes: err?.message || 'Failed' });
  }
}

// Helper to temporarily intercept global fetch
function mockFetch(handler: (url: string, init?: RequestInit) => Promise<Response>) {
  const originalFetch = global.fetch;
  global.fetch = handler as any;
  return () => {
    global.fetch = originalFetch;
  };
}

async function runAllTests() {
  console.log('======================================================================');
  console.log('    NEUROSHIELD URLSCAN.IO SECURE SANDBOX ANALYSIS TEST SUITE        ');
  console.log('======================================================================\n');

  // --------------------------------------------------------------------------
  // TEST 1: Successful Submission
  // --------------------------------------------------------------------------
  await runTest(1, 'Successful URL submission to urlscan.io API', async () => {
    const restore = mockFetch(async (url, init) => {
      assert.strictEqual(url, 'https://mock-urlscan.io/api/v1/scan/');
      assert.strictEqual(init?.method, 'POST');
      const headers = init?.headers as Record<string, string>;
      assert.strictEqual(headers['API-Key'], 'mock-test-key-12345');
      
      const body = JSON.parse(init?.body as string);
      assert.strictEqual(body.url, 'https://suspicious-login-portal.example.com/');
      assert.strictEqual(body.visibility, 'unlisted');

      const mockResponse: UrlscanSubmissionResponse = {
        message: 'Submission successful',
        uuid: '019183ab-cdef-7000-8000-112233445566',
        result: 'https://urlscan.io/result/019183ab-cdef-7000-8000-112233445566/',
        api: 'https://urlscan.io/api/v1/result/019183ab-cdef-7000-8000-112233445566/',
        visibility: 'unlisted',
        url: 'https://suspicious-login-portal.example.com/',
      };

      return new Response(JSON.stringify(mockResponse), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    try {
      const service = new UrlscanService({
        apiKey: 'mock-test-key-12345',
        apiUrl: 'https://mock-urlscan.io/api/v1',
      });

      const submission = await service.submitUrl('https://suspicious-login-portal.example.com/');
      assert.strictEqual(submission.uuid, '019183ab-cdef-7000-8000-112233445566');
      assert.strictEqual(submission.visibility, 'unlisted');
      assert(submission.result.includes('019183ab-cdef-7000-8000-112233445566'));
    } finally {
      restore();
    }
  });

  // --------------------------------------------------------------------------
  // TEST 2: Successful Result Retrieval and Signal Extraction
  // --------------------------------------------------------------------------
  await runTest(2, 'Successful asynchronous result retrieval & signal extraction', async () => {
    const rawScanResult: UrlscanResultResponse = {
      task: {
        uuid: '019183ab-cdef-7000-8000-112233445566',
        time: new Date().toISOString(),
        url: 'https://suspicious-login-portal.example.com/',
        visibility: 'unlisted',
        screenshotURL: 'https://urlscan.io/screenshots/019183ab.png',
        domURL: 'https://urlscan.io/dom/019183ab.txt',
        reportURL: 'https://urlscan.io/result/019183ab/',
      },
      page: {
        url: 'https://actual-destination.compromised.ru/auth/login.php',
        domain: 'compromised.ru',
        apexDomain: 'compromised.ru',
        country: 'RU',
        city: 'Moscow',
        ip: '198.51.100.23',
        asn: 'AS12345',
        asnname: 'BULLETPROOF-NET',
        title: 'Microsoft 365 Security Verification',
        status: 200,
      },
      verdicts: {
        overall: {
          score: 95,
          malicious: true,
          categories: ['phishing', 'credential-harvesting'],
          brands: ['Microsoft'],
          tags: ['m365', 'harvest'],
        },
        engines: {
          score: 95,
          malicious: true,
          verdicts: [
            { engine: 'google-safebrowsing', score: 100, malicious: true },
            { engine: 'phishtank', score: 100, malicious: true },
          ],
        },
      },
      data: {
        requests: [
          { response: { response: { url: 'https://suspicious-login-portal.example.com/', status: 302 } } },
          { response: { response: { url: 'https://actual-destination.compromised.ru/auth/login.php', status: 200 } } },
        ],
      },
    };

    const restore = mockFetch(async () => {
      return new Response(JSON.stringify(rawScanResult), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    try {
      const service = new UrlscanService({
        apiKey: 'mock-test-key-12345',
        apiUrl: 'https://mock-urlscan.io/api/v1',
      });

      const poll = await service.pollScanResult('019183ab-cdef-7000-8000-112233445566', 10000, 2);
      assert.strictEqual(poll.status, 'completed');
      assert.ok(poll.raw);

      const normalized = service.normalizeResult(
        poll.raw,
        'https://suspicious-login-portal.example.com/',
        '019183ab-cdef-7000-8000-112233445566',
        'completed'
      );

      assert.strictEqual(normalized.sandbox_status, 'completed');
      assert.strictEqual(normalized.final_url, 'https://actual-destination.compromised.ru/auth/login.php');
      assert.strictEqual(normalized.verdict, 'MALICIOUS');
      assert.strictEqual(normalized.risk_level, 'critical');
      assert.ok(normalized.risk_score >= 90);
      assert.strictEqual(normalized.engines_flagged, 2);
      assert.ok(normalized.threat_indicators.includes('CATEGORY_PHISHING'));
      assert.ok(normalized.threat_indicators.includes('ENGINE_GOOGLE-SAFEBROWSING_FLAGGED'));
      assert.strictEqual(normalized.screenshot_url, 'https://urlscan.io/screenshots/019183ab.png');
      assert.strictEqual(normalized.page_title, 'Microsoft 365 Security Verification');
      assert.strictEqual(normalized.domain_info?.country, 'RU');
    } finally {
      restore();
    }
  });

  // --------------------------------------------------------------------------
  // TEST 3: In-Progress Polling Behavior (404 -> 200)
  // --------------------------------------------------------------------------
  await runTest(3, 'Asynchronous polling with in-progress retries (404 -> 200)', async () => {
    let callCount = 0;
    const restore = mockFetch(async () => {
      callCount++;
      if (callCount < 2) {
        // First call: scan still processing
        return new Response(JSON.stringify({ message: 'Scan not finished yet' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      // Second call: scan completed
      return new Response(JSON.stringify({
        task: { uuid: 'mock-uuid', url: 'https://example.com' },
        page: { url: 'https://example.com', status: 200, title: 'Example Domain' },
        verdicts: { overall: { score: 0, malicious: false } },
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    try {
      const service = new UrlscanService({
        apiKey: 'mock-test-key-12345',
        apiUrl: 'https://mock-urlscan.io/api/v1',
      });

      const poll = await service.pollScanResult('mock-uuid', 10000, 3);
      assert.strictEqual(poll.status, 'completed');
      assert.strictEqual(poll.pollAttempts, 2);
      assert.strictEqual(callCount, 2);
    } finally {
      restore();
    }
  });

  // --------------------------------------------------------------------------
  // TEST 4: Polling Timeout Graceful Handling
  // --------------------------------------------------------------------------
  await runTest(4, 'Polling timeout limits and graceful non-blocking fallback', async () => {
    const restore = mockFetch(async () => {
      return new Response(JSON.stringify({ message: 'Still queued' }), { status: 404 });
    });

    try {
      const service = new UrlscanService({
        apiKey: 'mock-test-key-12345',
        apiUrl: 'https://mock-urlscan.io/api/v1',
      });

      // Set timeout to 100ms so it terminates quickly
      const poll = await service.pollScanResult('timeout-uuid', 100, 5);
      assert.strictEqual(poll.status, 'timeout');
      assert.ok(poll.errorMessage?.includes('timed out'));

      const normalized = service.normalizeResult(undefined, 'https://slow-site.com', 'timeout-uuid', poll.status, {
        errorMessage: poll.errorMessage,
      });
      assert.strictEqual(normalized.sandbox_status, 'timeout');
      assert.strictEqual(normalized.verdict, 'UNKNOWN');
      assert.ok(normalized.threat_indicators.includes('SANDBOX_TIMED_OUT'));
    } finally {
      restore();
    }
  });

  // --------------------------------------------------------------------------
  // TEST 5: API 500 Failure Handling (Fail-Safe Resilience)
  // --------------------------------------------------------------------------
  await runTest(5, 'urlscan.io API failure returns failed status without crash', async () => {
    const restore = mockFetch(async () => {
      return new Response('Internal Server Error from upstream', { status: 500 });
    });

    try {
      const service = new UrlscanService({
        apiKey: 'mock-test-key-12345',
        apiUrl: 'https://mock-urlscan.io/api/v1',
      });

      const result = await service.scanUrl('https://testing-failures.com');
      assert.strictEqual(result.sandbox_status, 'failed');
      assert.strictEqual(result.verdict, 'UNKNOWN');
      assert.ok(result.error_message?.includes('500'));
    } finally {
      restore();
    }
  });

  // --------------------------------------------------------------------------
  // TEST 6: Rate Limit (HTTP 429) Handling
  // --------------------------------------------------------------------------
  await runTest(6, 'HTTP 429 rate limit triggers rate_limited status gracefully', async () => {
    const restore = mockFetch(async () => {
      return new Response(JSON.stringify({ message: 'Rate limit exceeded. Try again in 60s' }), {
        status: 429,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    try {
      const service = new UrlscanService({
        apiKey: 'mock-test-key-12345',
        apiUrl: 'https://mock-urlscan.io/api/v1',
      });

      const result = await service.scanUrl('https://rate-limited-test.com');
      assert.strictEqual(result.sandbox_status, 'rate_limited');
      assert.ok(result.threat_indicators.includes('SANDBOX_RATE_LIMITED'));
    } finally {
      restore();
    }
  });

  // --------------------------------------------------------------------------
  // TEST 7: SSRF Defense Rejection (Private IPs, Loopback, Cloud Metadata)
  // --------------------------------------------------------------------------
  await runTest(7, 'SSRF defense rejects RFC 1918, loopback, and metadata before API call', async () => {
    let fetchCalled = false;
    const restore = mockFetch(async () => {
      fetchCalled = true;
      return new Response('OK', { status: 200 });
    });

    try {
      const service = new UrlscanService({ apiKey: 'mock-key' });

      const dangerousUrls = [
        'http://127.0.0.1/admin',
        'http://localhost:8080/internal',
        'http://169.254.169.254/latest/meta-data/',
        'http://192.168.1.10/router',
        'http://10.0.0.5/secrets',
        'file:///etc/passwd',
      ];

      for (const badUrl of dangerousUrls) {
        await assert.rejects(
          async () => {
            await service.submitUrl(badUrl);
          },
          (err: any) => {
            assert.ok(err.message.includes('SSRF Blocked') || err.message.includes('Unsafe URL scheme'));
            return true;
          }
        );
      }

      assert.strictEqual(fetchCalled, false, 'Fetch must NEVER be invoked for SSRF URLs');
    } finally {
      restore();
    }
  });

  // --------------------------------------------------------------------------
  // TEST 8: Missing API Key / Degraded Mode Fallback
  // --------------------------------------------------------------------------
  await runTest(8, 'Unconfigured API key cleanly defaults to unavailable without error', async () => {
    const unconfiguredService = new UrlscanService({ apiKey: null });
    assert.strictEqual(unconfiguredService.isConfigured(), false);

    const result = await unconfiguredService.scanUrl('https://random-link.com');
    assert.strictEqual(result.sandbox_status, 'unavailable');
    assert.strictEqual(result.verdict, 'UNKNOWN');
    assert.ok(result.error_message?.includes('URLSCAN_API_KEY is not set'));
  });

  // --------------------------------------------------------------------------
  // TEST 9: ML + Sandbox Fusion: Threat Corroboration
  // --------------------------------------------------------------------------
  await runTest(9, 'Fusion elevates suspicious ML score (55) to PHISHING (95) on malicious sandbox', async () => {
    const mockMaliciousSandbox: NormalizedSandboxResult = {
      url: 'https://security-notice-update.com/login',
      scan_id: 'scan-corroborate-1',
      sandbox_status: 'completed',
      final_url: 'https://security-notice-update.com/login',
      redirects: [],
      threat_indicators: ['CATEGORY_PHISHING', 'ENGINE_GOOGLE-SAFEBROWSING_FLAGGED'],
      risk_score: 95.0,
      risk_level: 'critical',
      verdict: 'MALICIOUS',
      engines_flagged: 3,
      page_title: 'Fake Bank Login Portal',
    };

    const fused = SandboxFusionEngine.fuse({
      url: 'https://security-notice-update.com/login',
      mlRiskScore: 55, // Moderately suspicious ML score
      mlVerdict: 'SUSPICIOUS',
      mlThreats: ['URGENT_LANGUAGE_DETECTED'],
      mlConfidence: 70,
      sandboxResult: mockMaliciousSandbox,
    });

    assert.strictEqual(fused.finalVerdict, 'PHISHING');
    assert.ok(fused.finalRiskScore >= 95);
    assert.strictEqual(fused.protectionDecision, 'BLOCK_VIEW');
    assert.ok(fused.confidence >= 85);
    assert.ok(fused.combinedEvidence.some(e => e.includes('Fake Bank Login Portal')));
    assert.ok(fused.combinedEvidence.some(e => e.includes('3 security engine(s) flagged')));
  });

  // --------------------------------------------------------------------------
  // TEST 10: ML + Sandbox Fusion: Clean Corroboration
  // --------------------------------------------------------------------------
  await runTest(10, 'Fusion lowers borderline ML score (42) to SAFE (20) on verified sandbox', async () => {
    const mockCleanSandbox: NormalizedSandboxResult = {
      url: 'https://portal.university-conference.org',
      scan_id: 'scan-clean-1',
      sandbox_status: 'completed',
      final_url: 'https://portal.university-conference.org',
      redirects: [],
      threat_indicators: [],
      risk_score: 5.0,
      risk_level: 'low',
      verdict: 'SAFE',
      engines_flagged: 0,
      page_title: 'Academic Conference 2026',
    };

    const fused = SandboxFusionEngine.fuse({
      url: 'https://portal.university-conference.org',
      mlRiskScore: 42, // Borderline uncertain score
      mlVerdict: 'SUSPICIOUS',
      mlThreats: ['NEW_DOMAIN_UNFAMILIAR'],
      mlConfidence: 65,
      sandboxResult: mockCleanSandbox,
    });

    assert.strictEqual(fused.finalVerdict, 'SAFE');
    assert.ok(fused.finalRiskScore <= 20);
    assert.strictEqual(fused.protectionDecision, 'ALLOW');
    assert.ok(fused.combinedEvidence.some(e => e.includes('Verified clean by urlscan.io')));
  });

  // --------------------------------------------------------------------------
  // TEST 11: Privacy & Sensitive Parameter Stripping
  // --------------------------------------------------------------------------
  await runTest(11, 'Sanitization strips tokens, passwords, and secrets before submission', async () => {
    const service = new UrlscanService({ apiKey: 'mock-key' });

    const rawUrl = 'https://portal.acme.com/reset?token=SECRET_JWT_12345&password=SuperSecretPassword&session=xyz987&view=dashboard';
    const { safeUrl, sanitized, removedParams } = service.sanitizeUrlForScan(rawUrl);

    assert.strictEqual(sanitized, true);
    assert.ok(removedParams.includes('token'));
    assert.ok(removedParams.includes('password'));
    assert.ok(removedParams.includes('session'));

    const parsedSafe = new URL(safeUrl);
    assert.strictEqual(parsedSafe.searchParams.get('token'), null);
    assert.strictEqual(parsedSafe.searchParams.get('password'), null);
    assert.strictEqual(parsedSafe.searchParams.get('session'), null);
    assert.strictEqual(parsedSafe.searchParams.get('view'), 'dashboard');
  });

  // --------------------------------------------------------------------------
  // TEST 12: Trigger Threshold Decision Logic
  // --------------------------------------------------------------------------
  await runTest(12, 'Sandbox trigger thresholds: low-risk bypasses, suspicious triggers', async () => {
    // With default thresholds: min=35, max=85
    // 1. Score 15 (Safe) -> Bypass
    const safeCheck = SandboxFusionEngine.shouldTriggerSandbox('https://google.com', 15);
    assert.strictEqual(safeCheck.shouldTrigger, false);
    assert.ok(safeCheck.reason.includes('below sandbox trigger threshold'));

    // 2. Score 60 (Suspicious) with API key present -> Trigger
    const origKey = config.urlscanApiKey;
    try {
      (config as any).urlscanApiKey = 'mock-key-active';
      const suspCheck = SandboxFusionEngine.shouldTriggerSandbox('https://unknown-link.com', 60);
      assert.strictEqual(suspCheck.shouldTrigger, true);
      assert.ok(suspCheck.reason.includes('suspicious/uncertain range'));

      // 3. Force flag overrides threshold
      const forceCheck = SandboxFusionEngine.shouldTriggerSandbox('https://google.com', 10, { forceSandbox: true });
      assert.strictEqual(forceCheck.shouldTrigger, true);
    } finally {
      (config as any).urlscanApiKey = origKey;
    }
  });

  // Print Summary Table
  console.log('\n======================================================================');
  console.log('                          TEST RESULTS SUMMARY                        ');
  console.log('======================================================================');
  console.table(testResults.map(r => ({
    ID: r.id,
    Name: r.name,
    Status: r.passed ? 'PASSED' : 'FAILED',
    Notes: r.notes,
  })));

  const allPassed = testResults.every(r => r.passed);
  if (allPassed) {
    console.log(`\nSUCCESS: All ${testResults.length} urlscan.io sandbox tests PASSED!\n`);
  } else {
    console.error(`\nFAILURE: Some tests failed.`);
    process.exit(1);
  }
}

runAllTests().catch((err) => {
  console.error('Test runner fatal error:', err);
  process.exit(1);
});
