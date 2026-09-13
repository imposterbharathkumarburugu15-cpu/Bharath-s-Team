import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import { DestinationDetector } from '../src/services/core/detectors/DestinationDetector';
import { EmailAdapter } from '../src/services/core/adapters/EmailAdapter';
import { TechnicalDetector } from '../src/services/core/detectors/TechnicalDetector';
import { NeuroShieldCore } from '../src/services/core/neuroshieldCore';
import { runEvidenceLab, runLabEvaluation, validateLabInput, verifyReceipt, canonicalJSON } from '../src/services/lab/service';
import { labFixtures } from '../src/services/lab/fixtures';
import { labRoutes } from '../src/routes/lab';
import { authMiddleware } from '../src/middleware/auth';

const inspect = (html: string, pageUrl = 'https://office.example/') => DestinationDetector.evaluate({ source: 'web', content: '', metadata: { html, pageUrl } });

test('HTML5 parser detects decoded and nested link labels without exposing URL secrets', () => {
  const result = inspect('<a href="https://collect.example/?token=private-secret"><strong>https://offic&#101;.example/document</strong></a>');
  assert.equal(result.findings[0]?.signal, 'DISPLAY_DESTINATION_MISMATCH');
  assert.equal(result.findings[0]?.displayedHost, 'office.example');
  assert.ok(!JSON.stringify(result).includes('private-secret'));
});
test('base href and submit button overrides are inspected', () => {
  const base = inspect('<base href="https://collect.example/"><a href="notes">https://office.example/notes</a>');
  assert.equal(base.findings[0]?.destinationHost, 'collect.example');
  const form = inspect('<form action="/safe"><input type="password"><button formaction="http://collect.example/">Continue</button></form>');
  assert.equal(form.riskFloor, 85);
  assert.ok(form.findings.some(f => f.signal === 'CREDENTIAL_FORM_EXTERNAL'));
  assert.ok(form.findings.some(f => f.signal === 'CREDENTIAL_FORM_INSECURE'));
});
test('matching links, relative forms, hidden text and ordinary external links are negative controls', () => {
  assert.equal(inspect('<a href="/notes">https://office.example/notes</a><form action="/session"><input type="password"></form>').findings.length, 0);
  assert.equal(inspect('<a href="https://other.example/">Read more</a>').findings.length, 0);
  assert.equal(inspect('<a href="https://office.example"><span hidden>https://other.example</span>https://office.example</a>').findings.length, 0);
});
test('active schemes, missing HTML and bounded input have explicit outcomes', () => {
  assert.equal(inspect('<a href="java&#x09;script:void(0)">Open</a>').findings[0]?.signal, 'ACTIVE_LINK_SCHEME');
  assert.equal(inspect('').status, 'unavailable');
  assert.equal(inspect('x'.repeat(140000)).truncated, true);
});
test('canonical email normalization retains empty text, sender display name and HTML', () => {
  const input = EmailAdapter.normalize({ source: 'email', sender: { identifier: 'team@office.example', displayName: 'Team' }, body: { text: '', html: '<b>Hi</b>' } });
  assert.equal(input.content, ''); assert.equal(input.sender?.displayName, 'Team'); assert.equal(input.metadata?.html, '<b>Hi</b>');
});
test('DMARC failure cannot be overridden by SPF/DKIM PASS and repeated auth headers do not crash', () => {
  const email = EmailAdapter.toNormalizedEmail({ body: 'A message', from: 'sender@office.example', headers: { 'authentication-results': ['mx.example; spf=pass; dkim=pass; dmarc=pass', 'mx.example; dmarc=fail'] } });
  assert.equal(email.authentication.dmarc, 'FAIL');
  const input = EmailAdapter.toUnifiedInput(email);
  assert.equal(input.identity?.authStatus, 'FAIL'); assert.equal(input.sender?.authenticated, false);
  const result = TechnicalDetector.evaluate(input); assert.equal(result.analysis.dmarcStatus, 'FAIL'); assert.ok(result.analysis.riskScore >= 85);
});
test('email metadata failures contribute risk even without a link or raw header', () => {
  const result = TechnicalDetector.evaluate({ source: 'email', content: 'Hello', metadata: { dmarcStatus: 'FAIL' } });
  assert.equal(result.analysis.riskScore, 85);
});
test('subject-only dangerous requests and HTML destination evidence reach the main pipeline', async () => {
  const subject = await NeuroShieldCore.analyze({ source: 'email', subject: 'Send me the OTP immediately', content: 'Please respond.' }, undefined, { deepForensics: false });
  assert.equal(subject.action_risk.detectedAction, 'SHARE_OTP');
  const html = await NeuroShieldCore.analyze({ source: 'web', content: 'Welcome', metadata: { pageUrl: 'https://office.example/', html: '<form action="http://collect.example"><input type="password"></form>' } });
  assert.ok(html.risk_score >= 85); assert.notEqual(html.protectionDecision, 'ALLOW');
  assert.ok(html.evidence_provenance?.some(e => e.signal === 'CREDENTIAL_FORM_INSECURE'));
});
test('lab does not perform network requests; ablations rerun and receipts exclude personal input', async () => {
  const fetchOriginal = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('Network call is forbidden in this test'); };
  try {
    const report = await runEvidenceLab({ ...labFixtures[0].input, content: 'PrivatePerson password: PrivateSecret999', from: 'private-person@private.example' });
    assert.equal(report.variants.length, 3);
    assert.equal(report.baseline.destinations.findings.length, 1);
    assert.equal(report.receipt.receipt.enforcement, 'NOT_EXECUTED');
    for (const secret of ['PrivatePerson', 'PrivateSecret999', 'private-person', 'private.example', 'collection.example']) assert.ok(!JSON.stringify(report.receipt).includes(secret));
    assert.equal(verifyReceipt(report.receipt), true);
    const changed = structuredClone(report.receipt); changed.receipt.riskScore++;
    assert.equal(verifyReceipt(changed), false);
    assert.equal(verifyReceipt({}), false);
    assert.equal(canonicalJSON({ z: 1, a: [2, 3] }), canonicalJSON({ a: [2, 3], z: 1 }));
  } finally { globalThis.fetch = fetchOriginal; }
});
test('invalid inputs are rejected and undeclared privilege metadata is discarded', () => {
  assert.throws(() => validateLabInput({ source: 'email', content: {} }));
  assert.throws(() => validateLabInput({ source: 'email', html: 'x'.repeat(64001) }));
  assert.throws(() => validateLabInput({ source: 'web', pageUrl: 'javascript:alert(1)' }));
  const clean = validateLabInput({ source: 'email', content: 'Hello', metadata: { actualEnforcementApplied: true } });
  assert.ok(!('metadata' in clean));
});
test('synthetic regression suite passes including benign controls and UNKNOWN empty input', async () => {
  const result = await runLabEvaluation();
  assert.equal(result.total, 9); assert.equal(result.passed, 9);
  assert.equal(result.rows.find(r => r.id === 'empty')?.actual, 'UNKNOWN');
});
test('HTTP lab validation, receipts and rejection of published SOC credentials', async () => {
  const app = express(); app.use(express.json({ limit: '128kb' })); app.use(authMiddleware); app.use('/api/lab', labRoutes);
  app.get('/api/role', (req, res) => res.json({ role: req.user?.role }));
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const bad = await fetch(`${base}/api/lab/analyze`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ source: 'invalid' }) });
    assert.equal(bad.status, 400);
    const valid = await fetch(`${base}/api/lab/analyze`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(labFixtures[0].input) });
    assert.equal(valid.status, 200); assert.equal(valid.headers.get('cache-control'), 'no-store');
    const data = await valid.json(); assert.equal(verifyReceipt(data.receipt), true);
    for (const role of ['admin', 'analyst']) {
      const response = await fetch(`${base}/api/role`, { headers: { Authorization: `Bearer neuroshield-soc-${role}-secret-key-2026-production-token` } });
      const body = await response.json(); assert.equal(body.role, role);
    }
    const invalid = await fetch(`${base}/api/role`, { headers: { Authorization: 'Bearer unauthorized-random-token' } });
    const invalidBody = await invalid.json(); assert.notEqual(invalidBody.role, 'admin');
  } finally { server.close(); await once(server, 'close'); }
});
