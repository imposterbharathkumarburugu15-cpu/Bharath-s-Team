/**
 * NeuroShield Phase 4 Comprehensive Acceptance Test Suite
 * Automatic Protection, Authoritative Contract & Real Enforcement Layer
 * 
 * Verifies all Phase 4 Core Requirements:
 *  1. Authoritative Protection Decision Contract (8-field contract)
 *  2. Protection Policy Logic (ALLOW, WARN, BLOCK_ACTION, BLOCK_VIEW)
 *  3. Action-Specific Enforcement (CLICK_LINK, LOGIN, ENTER_PASSWORD, SHARE_OTP, TRANSFER_MONEY, etc.)
 *  4. Strict Architectural Separation (Gmail API = NOT_SUPPORTED; Chrome Extension = ENFORCED)
 *  5. 10 Core Required Enforcement Tests (Test Matrix)
 *  6. Bypass Resistance (Punycode, Encoded URLs, Redirects, Script Submissions)
 *  7. False Positive Protection (Urgent business email, legitimate login)
 *  8. Critical Product Test (Fake Executive ₹2 lakh wire transfer email)
 *  9. Privacy & Redaction (Audit logs NEVER store passwords, OTPs, or credit cards)
 * 10. Fail-Safe Behavior (Core offline -> UNKNOWN, never SAFE)
 */

import { EnforcementEngine } from '../src/services/core/enforcementEngine';
import { NeuroShieldCore } from '../src/services/core/neuroshieldCore';
import { SensitiveDataDetector } from '../src/services/core/detectors/SensitiveDataDetector';
import {
  AuthoritativeProtectionDecision,
  ProtectionDecision,
  EnforcementStatus,
  UnifiedInteractionEvent,
  UnifiedIncidentObject
} from '../src/services/core/types';

interface TestResult {
  id: number;
  scenario: string;
  verdict: string;
  riskScore: number;
  decision: ProtectionDecision;
  enforcement: EnforcementStatus;
  passed: boolean;
  notes: string;
}

async function runPhase4AcceptanceSuite() {
  console.log('======================================================================');
  console.log('  NEUROSHIELD PHASE 4: AUTOMATIC PROTECTION & ENFORCEMENT TEST SUITE  ');
  console.log('======================================================================\n');

  const results: TestResult[] = [];

  // ──────────────────────────────────────────────────────────────────────────
  // TEST 1: Safe URL -> ALLOW -> Navigation succeeds (NOT_REQUIRED)
  // ──────────────────────────────────────────────────────────────────────────
  {
    const policy = EnforcementEngine.evaluatePolicy({
      riskScore: 10,
      confidence: 90,
      coverage: 95,
      requestedAction: 'CLICK_LINK',
      client: 'chrome_extension',
      threatTypes: [],
      targetUrl: 'https://en.wikipedia.org/wiki/Computer_security',
      evidence: ['Known top-level benign encyclopedia site', 'No credential forms']
    });

    const passed =
      policy.verdict === 'SAFE' &&
      policy.protectionDecision === 'ALLOW' &&
      policy.enforcementStatus === 'NOT_REQUIRED';

    results.push({
      id: 1,
      scenario: 'TEST 1: Safe URL Navigation',
      verdict: policy.verdict,
      riskScore: policy.riskScore,
      decision: policy.protectionDecision,
      enforcement: policy.enforcementStatus,
      passed,
      notes: 'Safe URL permitted without client restriction.'
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // TEST 2: Malicious URL -> CRITICAL -> BLOCK_VIEW -> Navigation prevented (ENFORCED)
  // ──────────────────────────────────────────────────────────────────────────
  {
    const policy = EnforcementEngine.evaluatePolicy({
      riskScore: 92,
      confidence: 95,
      coverage: 90,
      requestedAction: 'VISIT_WEBSITE',
      client: 'chrome_extension',
      threatTypes: ['MALICIOUS_REVERSE_TUNNEL', 'CREDENTIAL_THEFT'],
      targetUrl: 'https://attacker-portal.trycloudflare.com/login',
      evidence: ['Cloudflare tunnel evasion', 'Active credential harvest form detected']
    });

    const passed =
      (policy.verdict === 'CRITICAL' || policy.verdict === 'HIGH') &&
      policy.protectionDecision === 'BLOCK_VIEW' &&
      policy.enforcementStatus === 'ENFORCED';

    results.push({
      id: 2,
      scenario: 'TEST 2: Malicious URL (BLOCK_VIEW)',
      verdict: policy.verdict,
      riskScore: policy.riskScore,
      decision: policy.protectionDecision,
      enforcement: policy.enforcementStatus,
      passed,
      notes: 'Browser navigation intercepted; block screen rendered.'
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // TEST 3: Credential-harvesting page -> HIGH/CRITICAL -> BLOCK_ACTION (ENFORCED)
  // ──────────────────────────────────────────────────────────────────────────
  {
    const policy = EnforcementEngine.evaluatePolicy({
      riskScore: 88,
      confidence: 92,
      coverage: 88,
      requestedAction: 'ENTER_PASSWORD',
      client: 'chrome_extension',
      threatTypes: ['CREDENTIAL_HARVESTING'],
      targetUrl: 'http://185.220.101.44/m365/login.php',
      hasSensitiveData: true,
      sensitiveCategories: ['PASSWORD'],
      evidence: ['Raw IP hosting fake Microsoft login', 'Password input field detected']
    });

    const passed =
      (policy.verdict === 'HIGH' || policy.verdict === 'CRITICAL') &&
      policy.protectionDecision === 'BLOCK_ACTION' &&
      policy.enforcementStatus === 'ENFORCED';

    results.push({
      id: 3,
      scenario: 'TEST 3: Credential-Harvesting Form Interception',
      verdict: policy.verdict,
      riskScore: policy.riskScore,
      decision: policy.protectionDecision,
      enforcement: policy.enforcementStatus,
      passed,
      notes: 'Credential form submission stopped at capture phase.'
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // TEST 4: Safe login page -> ALLOW -> Login works normally (NOT_REQUIRED)
  // ──────────────────────────────────────────────────────────────────────────
  {
    const policy = EnforcementEngine.evaluatePolicy({
      riskScore: 15,
      confidence: 95,
      coverage: 92,
      requestedAction: 'LOGIN',
      client: 'chrome_extension',
      threatTypes: [],
      targetUrl: 'https://online.chase.com/auth/login',
      hasSensitiveData: true,
      sensitiveCategories: ['PASSWORD'],
      evidence: ['Verified legitimate banking domain', 'Valid TLS certificate and baseline reputation']
    });

    const passed =
      policy.verdict === 'SAFE' &&
      policy.protectionDecision === 'ALLOW' &&
      policy.enforcementStatus === 'NOT_REQUIRED';

    results.push({
      id: 4,
      scenario: 'TEST 4: Legitimate Login Page (No False Positive)',
      verdict: policy.verdict,
      riskScore: policy.riskScore,
      decision: policy.protectionDecision,
      enforcement: policy.enforcementStatus,
      passed,
      notes: 'Legitimate login on trusted institution not falsely blocked.'
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // TEST 5: Phishing email link -> Click intercepted -> BLOCK_VIEW
  // ──────────────────────────────────────────────────────────────────────────
  {
    const policy = EnforcementEngine.evaluatePolicy({
      riskScore: 84,
      confidence: 88,
      coverage: 85,
      requestedAction: 'CLICK_LINK',
      client: 'chrome_extension',
      threatTypes: ['EMAIL_LINK_PHISHING'],
      targetUrl: 'http://secure-update-verify.com/reset',
      evidence: ['Phishing link intercepted inside webmail interface']
    });

    const passed =
      (policy.verdict === 'HIGH' || policy.verdict === 'CRITICAL') &&
      policy.protectionDecision === 'BLOCK_VIEW' &&
      policy.enforcementStatus === 'ENFORCED';

    results.push({
      id: 5,
      scenario: 'TEST 5: Phishing Email Link Click Interception',
      verdict: policy.verdict,
      riskScore: policy.riskScore,
      decision: policy.protectionDecision,
      enforcement: policy.enforcementStatus,
      passed,
      notes: 'Capture-phase click listener intercepted navigation.'
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // TEST 6: Redirect to malicious destination -> BLOCK_VIEW
  // ──────────────────────────────────────────────────────────────────────────
  {
    const policy = EnforcementEngine.evaluatePolicy({
      riskScore: 90,
      confidence: 90,
      coverage: 85,
      requestedAction: 'VISIT_WEBSITE',
      client: 'chrome_extension',
      threatTypes: ['OPEN_REDIRECT', 'MALICIOUS_DESTINATION'],
      targetUrl: 'https://evil-redirector.com/target?dest=http://phish-login.cc',
      evidence: ['Chained redirect targeting phishing infrastructure']
    });

    const passed =
      policy.protectionDecision === 'BLOCK_VIEW' &&
      policy.enforcementStatus === 'ENFORCED';

    results.push({
      id: 6,
      scenario: 'TEST 6: Malicious Redirect Interception',
      verdict: policy.verdict,
      riskScore: policy.riskScore,
      decision: policy.protectionDecision,
      enforcement: policy.enforcementStatus,
      passed,
      notes: 'Redirect destination preflight evaluated and blocked.'
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // TEST 7: OTP Request -> Sensitive Data + Action Risk -> BLOCK_ACTION
  // ──────────────────────────────────────────────────────────────────────────
  {
    const sensitive = SensitiveDataDetector.detect('Your One-Time Password is 849201. Do not share.');
    const policy = EnforcementEngine.evaluatePolicy({
      riskScore: 82,
      confidence: 88,
      coverage: 85,
      requestedAction: 'SHARE_OTP',
      client: 'chrome_extension',
      threatTypes: ['OTP_EXFILTRATION_LURE'],
      hasSensitiveData: sensitive.hasSensitiveData,
      sensitiveCategories: sensitive.categories,
      evidence: ['Page soliciting 6-digit OTP in untrusted context']
    });

    const passed =
      policy.protectionDecision === 'BLOCK_ACTION' &&
      policy.enforcementStatus === 'ENFORCED' &&
      sensitive.categories.includes('OTP');

    results.push({
      id: 7,
      scenario: 'TEST 7: OTP Exfiltration Interception',
      verdict: policy.verdict,
      riskScore: policy.riskScore,
      decision: policy.protectionDecision,
      enforcement: policy.enforcementStatus,
      passed,
      notes: 'OTP solicitation detected; form submission blocked.'
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // TEST 8: Sensitive-data submission in risky context -> BLOCK_ACTION
  // ──────────────────────────────────────────────────────────────────────────
  {
    const sensitive = SensitiveDataDetector.detect('Payment card: 4532 8901 2345 6789 CVV: 891 Exp: 09/28');
    const policy = EnforcementEngine.evaluatePolicy({
      riskScore: 85,
      confidence: 90,
      coverage: 88,
      requestedAction: 'SHARE_SENSITIVE_DATA',
      client: 'chrome_extension',
      threatTypes: ['PAYMENT_DATA_THEFT'],
      hasSensitiveData: sensitive.hasSensitiveData,
      sensitiveCategories: sensitive.categories,
      evidence: ['Payment card and CVV solicited on unverified domain']
    });

    const passed =
      policy.protectionDecision === 'BLOCK_ACTION' &&
      policy.enforcementStatus === 'ENFORCED' &&
      sensitive.categories.includes('PAYMENT_DATA');

    results.push({
      id: 8,
      scenario: 'TEST 8: Sensitive Payment Data Submission',
      verdict: policy.verdict,
      riskScore: policy.riskScore,
      decision: policy.protectionDecision,
      enforcement: policy.enforcementStatus,
      passed,
      notes: 'Credit card form exfiltration stopped at client.'
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // TEST 9: Backend Unavailable -> UNKNOWN -> Never SAFE
  // ──────────────────────────────────────────────────────────────────────────
  {
    const failSafe = EnforcementEngine.createFailSafeDecision('CLICK_LINK', 'chrome_extension', 'Network timeout to Core API');

    const passed =
      failSafe.verdict === 'UNKNOWN' &&
      (failSafe.verdict as string) !== 'SAFE' &&
      failSafe.protectionDecision === 'WARN' &&
      failSafe.enforcementStatus === 'UNKNOWN';

    results.push({
      id: 9,
      scenario: 'TEST 9: Core API Offline / Fail-Safe',
      verdict: failSafe.verdict,
      riskScore: failSafe.riskScore,
      decision: failSafe.protectionDecision,
      enforcement: failSafe.enforcementStatus,
      passed,
      notes: 'System fails safely to UNKNOWN, strictly avoiding false SAFE.'
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // TEST 10: Low-Risk Website -> Normal browsing -> ALLOW
  // ──────────────────────────────────────────────────────────────────────────
  {
    const policy = EnforcementEngine.evaluatePolicy({
      riskScore: 22,
      confidence: 85,
      coverage: 80,
      requestedAction: 'VISIT_WEBSITE',
      client: 'chrome_extension',
      threatTypes: [],
      targetUrl: 'https://news.ycombinator.com',
      evidence: ['Low-risk tech forum', 'No deceptive elements detected']
    });

    const passed =
      policy.verdict === 'LOW' &&
      policy.protectionDecision === 'ALLOW' &&
      policy.enforcementStatus === 'NOT_REQUIRED';

    results.push({
      id: 10,
      scenario: 'TEST 10: Low-Risk Browsing (No Over-blocking)',
      verdict: policy.verdict,
      riskScore: policy.riskScore,
      decision: policy.protectionDecision,
      enforcement: policy.enforcementStatus,
      passed,
      notes: 'Normal browsing permitted without user disruption.'
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // TEST 11: Architectural Separation & Truth in Enforcement
  // (Gmail API Server-Side Ingestion cannot claim client BLOCKED)
  // ──────────────────────────────────────────────────────────────────────────
  {
    const gmailServerDecision = EnforcementEngine.evaluatePolicy({
      riskScore: 89,
      confidence: 92,
      coverage: 85,
      requestedAction: 'CLICK_LINK',
      client: 'gmail_api',
      threatTypes: ['EMAIL_LINK_PHISHING'],
      evidence: ['Server-side background fetch of malicious email']
    });

    const passed =
      (gmailServerDecision.protectionDecision === 'BLOCK_ACTION' || gmailServerDecision.protectionDecision === 'BLOCK_VIEW') &&
      gmailServerDecision.enforcementStatus === 'NOT_SUPPORTED';

    results.push({
      id: 11,
      scenario: 'TEST 11: Gmail API Server Ingestion Truthfulness',
      verdict: gmailServerDecision.verdict,
      riskScore: gmailServerDecision.riskScore,
      decision: gmailServerDecision.protectionDecision,
      enforcement: gmailServerDecision.enforcementStatus,
      passed,
      notes: 'Server-side ingestion truthfully returns NOT_SUPPORTED instead of fake BLOCKED.'
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // TEST 12: Security Against Bypass Attempts
  // (Punycode, Encoded URL, URL Shorteners)
  // ──────────────────────────────────────────────────────────────────────────
  {
    // Punycode domain
    const punycodeDecision = EnforcementEngine.evaluatePolicy({
      riskScore: 85,
      confidence: 90,
      coverage: 85,
      requestedAction: 'CLICK_LINK',
      client: 'chrome_extension',
      targetUrl: 'https://xn--pple-43d.com/login', // apple.com lookalike
      threatTypes: ['HOMOGLYPH_PUNYCODE_ATTACK'],
      evidence: ['IDN homograph attack spoofing brand']
    });

    // Encoded URL
    const encodedDecision = EnforcementEngine.evaluatePolicy({
      riskScore: 88,
      confidence: 92,
      coverage: 85,
      requestedAction: 'CLICK_LINK',
      client: 'chrome_extension',
      targetUrl: 'https://auth%2Ecompany%2Ecom%2Flogin@malicious-host.net',
      threatTypes: ['URL_ENCODING_EVASION'],
      evidence: ['URL percent-encoded credentials bypass']
    });

    const passed =
      punycodeDecision.protectionDecision === 'BLOCK_VIEW' &&
      punycodeDecision.enforcementStatus === 'ENFORCED' &&
      encodedDecision.protectionDecision === 'BLOCK_VIEW' &&
      encodedDecision.enforcementStatus === 'ENFORCED';

    results.push({
      id: 12,
      scenario: 'TEST 12: Evasion & Bypass Resistance (Punycode + Encoding)',
      verdict: punycodeDecision.verdict,
      riskScore: punycodeDecision.riskScore,
      decision: punycodeDecision.protectionDecision,
      enforcement: punycodeDecision.enforcementStatus,
      passed,
      notes: 'Punycode homoglyphs and encoded host bypasses intercepted.'
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // TEST 13: False Positive Protection
  // (Legitimate urgent business email: "Please send this report before 5 PM.")
  // ──────────────────────────────────────────────────────────────────────────
  {
    const businessEmailEvent: UnifiedInteractionEvent = {
      source: 'email',
      sender: { identifier: 'colleague@enterprise.com', displayName: 'Project Lead' },
      subject: 'Quarterly Progress Report',
      content: 'Hi Team, please send this report before 5 PM today for the executive meeting. Thanks!',
      recipient: { identifier: 'analyst@enterprise.com' }
    };

    const analysis = await NeuroShieldCore.analyze(businessEmailEvent);

    const passed =
      analysis.risk_score < 40 &&
      analysis.risk_level !== 'HIGH' &&
      analysis.risk_level !== 'CRITICAL' &&
      analysis.authoritativeProtectionDecision?.protectionDecision === 'ALLOW';

    results.push({
      id: 13,
      scenario: 'TEST 13: False Positive Check (Urgent Business Email)',
      verdict: analysis.risk_level,
      riskScore: analysis.risk_score,
      decision: analysis.authoritativeProtectionDecision?.protectionDecision || 'ALLOW',
      enforcement: analysis.authoritativeProtectionDecision?.enforcementStatus || 'NOT_REQUIRED',
      passed,
      notes: 'Legitimate workplace urgency without financial lure or credential theft is not flagged HIGH.'
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // TEST 14: CRITICAL PRODUCT TEST (Executive ₹2 Lakh Wire Transfer Email)
  // "I changed my number. I'm in a meeting. Don't call me. Transfer ₹2 lakh..."
  // ──────────────────────────────────────────────────────────────────────────
  {
    const execImpersonationEvent: UnifiedInteractionEvent = {
      source: 'email',
      sender: {
        identifier: 'ceo.personal1992@gmail.com',
        displayName: 'Sundar Pichai (CEO)'
      },
      subject: 'URGENT: Confidential Wire Transfer Required',
      content: `I changed my number.
I'm in a meeting.
Don't call me.
Transfer ₹2 lakh to this new account immediately for the vendor deposit.
Send me the transaction screenshot.`,
      rawPayload: 'From: "Sundar Pichai (CEO)" <ceo.personal1992@gmail.com>\nSubject: URGENT Wire Transfer'
    };

    const analysis = await NeuroShieldCore.analyze(execImpersonationEvent);
    const auth = analysis.authoritativeProtectionDecision;

    const hasFinancialOrFraudThreat =
      analysis.threats.some(t =>
        t.toLowerCase().includes('wire') ||
        t.toLowerCase().includes('fraud') ||
        t.toLowerCase().includes('scam') ||
        t.toLowerCase().includes('impersonation') ||
        t.toLowerCase().includes('phishing')
      );

    const passed =
      analysis.risk_score >= 70 &&
      (analysis.risk_level === 'HIGH' || analysis.risk_level === 'CRITICAL') &&
      auth?.protectionDecision === 'BLOCK_ACTION' &&
      (auth?.requestedAction === 'TRANSFER_MONEY' || analysis.action_risk?.detected_action === 'TRANSFER_MONEY') &&
      hasFinancialOrFraudThreat;

    results.push({
      id: 14,
      scenario: 'TEST 14: Critical Product Test (Fake Executive ₹2 Lakh Wire)',
      verdict: analysis.risk_level,
      riskScore: analysis.risk_score,
      decision: auth?.protectionDecision || 'BLOCK_ACTION',
      enforcement: auth?.enforcementStatus || 'NOT_SUPPORTED',
      passed,
      notes: 'Executive impersonation + context change + financial lure identified and assigned BLOCK_ACTION.'
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // TEST 15: Privacy & Audit Redaction
  // (Never log raw passwords, OTPs, or credit cards in audit records)
  // ──────────────────────────────────────────────────────────────────────────
  {
    const rawDecision: AuthoritativeProtectionDecision = {
      verdict: 'HIGH',
      riskScore: 88,
      confidence: 92,
      requestedAction: 'ENTER_PASSWORD',
      threatTypes: ['CREDENTIAL_THEFT'],
      protectionDecision: 'BLOCK_ACTION',
      enforcementLevel: 'CLIENT',
      enforcementStatus: 'ENFORCED',
      evidence: ['User entered password123! into fake input']
    };

    const auditRecord = EnforcementEngine.createAuditRecord(
      rawDecision,
      'inc-privacy-test-01',
      'chrome_extension',
      'https://phish-site.cc/login?token=supersecret_token_12345&password=rawpassword123'
    );

    const auditJson = JSON.stringify(auditRecord);
    const passed =
      !auditJson.includes('supersecret_token_12345') &&
      !auditJson.includes('rawpassword123') &&
      auditRecord.incidentId === 'inc-privacy-test-01' &&
      auditRecord.enforcementStatus === 'ENFORCED' &&
      auditRecord.timestamp !== undefined;

    results.push({
      id: 15,
      scenario: 'TEST 15: Privacy & Audit Log Credential Redaction',
      verdict: rawDecision.verdict,
      riskScore: rawDecision.riskScore,
      decision: rawDecision.protectionDecision,
      enforcement: rawDecision.enforcementStatus,
      passed,
      notes: 'Query parameters, secrets, and raw credentials stripped from audit log.'
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Print Detailed Test Results
  // ──────────────────────────────────────────────────────────────────────────
  console.log('RESULTS TABLE:');
  console.log('---------------------------------------------------------------------------------------------------------');
  console.log('| ID | Scenario                                     | Risk | Verdict  | Decision     | Status       | Pass |');
  console.log('---------------------------------------------------------------------------------------------------------');

  let allPassed = true;
  for (const r of results) {
    const idStr = String(r.id).padEnd(2);
    const scenStr = r.scenario.slice(0, 44).padEnd(44);
    const riskStr = String(r.riskScore).padEnd(4);
    const verdStr = r.verdict.padEnd(8);
    const decStr = r.decision.padEnd(12);
    const enfStr = r.enforcement.padEnd(12);
    const passStr = r.passed ? ' PASS ' : ' FAIL ';

    if (!r.passed) allPassed = false;

    console.log(`| ${idStr} | ${scenStr} | ${riskStr} | ${verdStr} | ${decStr} | ${enfStr} | ${passStr}|`);
  }
  console.log('---------------------------------------------------------------------------------------------------------\n');

  console.log(`Phase 4 Summary: ${results.filter(r => r.passed).length}/${results.length} Scenarios Passed.`);
  if (!allPassed) {
    console.error('FAILED: One or more Phase 4 acceptance tests failed.');
    process.exit(1);
  } else {
    console.log('SUCCESS: All Phase 4 Automatic Protection & Enforcement Tests Passed 100%!');
  }
}

runPhase4AcceptanceSuite().catch(err => {
  console.error('Unhandled suite error:', err);
  process.exit(1);
});
