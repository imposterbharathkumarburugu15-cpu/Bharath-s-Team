import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { IntelligenceStore } from '../src/services/intelligence/store';
import { CampaignService } from '../src/services/intelligence/campaigns';
import { extractDNA, correlate } from '../src/services/intelligence/features';
import { normalizeDomain, publicIP, urlStructure } from '../src/services/intelligence/indicators';
import { DeceptionService, eligibleIncident, type DeceptionSession } from '../src/services/deception/service';
import { EnforcementEngine } from '../src/services/core/enforcementEngine';
import type { IntelligenceIncident, Campaign, ConfirmedIOC } from '../src/services/intelligence/types';
import type { SandboxRunner } from '../src/services/deception/dockerRunner';

const fixture = (id: string, domain = 'ns-fixture-one.com', source = 'email'): IntelligenceIncident => ({
  id, source, timestamp: new Date().toISOString(), riskScore: 93, confidence: 94, verdict: 'MALICIOUS', fingerprint: id,
  features: [
    { family: 'url', key: 'domain', value: domain, weight: 4, provenance: 'observed', source: id },
    { family: 'url', key: 'path_structure', value: '/account/verify', weight: 3, provenance: 'observed', source: id },
    { family: 'web', key: 'domHash', value: 'b'.repeat(64), weight: 5, provenance: 'observed', source: id },
    { family: 'web', key: 'scriptPatternHash', value: 'c'.repeat(64), weight: 5, provenance: 'observed', source: id },
    { family: 'email', key: 'dmarc', value: 'fail', weight: 0.5, provenance: 'observed', source: id },
    { family: 'behavior', key: 'credential_request', value: 'true', weight: 1, provenance: 'inferred', source: id },
  ],
  indicators: [{ type: 'domain', value: domain, eligibleForBlocking: true, source: id, provenance: 'observed' }],
});

test('public address checks reject private, mapped, reserved, transition and invalid inputs', () => {
  for (const ip of ['127.0.0.2', '10.1.2.3', '100.64.1.1', '169.254.169.254', '172.31.4.5', '192.168.1.2', '198.51.100.1', '0.0.0.0', '255.255.255.255', '999.1.1.1', '::1', '::ffff:127.0.0.1', 'fc00::1', 'fe80::1', '2001:db8::1', '2002:7f00:1::', '64:ff9b::7f00:1']) assert.equal(publicIP(ip), false, ip);
  assert.equal(publicIP('8.8.8.8'), true); assert.equal(publicIP('2606:4700:4700::1111'), true);
});
test('domain and URL structures exclude credentials, query values and private targets', () => {
  assert.equal(normalizeDomain('https://EXAMPLE.COM/login'), 'example.com');
  for (const v of ['http://localhost', 'http://127.0.0.1', 'http://2130706433', 'https://user:pass@example.com', 'https://example.com:8443', 'https://[::1]', 'file:///tmp/a', 'foo.internal', 'a'.repeat(64) + '.com']) assert.equal(normalizeDomain(v), null);
  const u = urlStructure('https://example.com/account/alice@example.com?password=secret&otp=123456#token');
  assert.equal(u!.path, '/account/:segment'); assert.ok(!JSON.stringify(u).includes('secret')); assert.ok(!JSON.stringify(u).includes('123456'));
});
test('DNA uses actual input evidence and excludes raw PII, secret query values and bodies', () => {
  const a: any = { incident_id: 'a', source: 'email', timestamp: new Date().toISOString(), risk_score: 91, confidence: 92, verdict: 'MALICIOUS', identity: {} };
  const dna = extractDNA({ source: 'email', content: 'Urgent verify password for Alice https://ns-fixture-one.com/login?secret=hunter99', rawHeaders: 'Authentication-Results: mx; spf=fail; dmarc=fail', sender: { identifier: 'alice@ns-fixture-one.com', displayName: 'Alice' }, metadata: { webObservation: { credentialFields: true, domHash: 'a'.repeat(64), password: 'do-not-store' } } }, a);
  const stored = JSON.stringify(dna);
  for (const value of ['hunter99', 'alice@', 'do-not-store', 'Urgent verify password']) assert.ok(!stored.includes(value));
  assert.ok(dna.features.some(f => f.key === 'dmarc' && f.value === 'fail'));
  assert.ok(dna.features.some(f => f.key === 'domHash'));
});
test('cross-domain and cross-channel DNA exposes support and never names an actor', () => {
  const edge = correlate(fixture('a'), fixture('b', 'ns-fixture-two.com', 'web'));
  assert.ok(edge && edge.score >= 0.6); assert.equal(edge.provenance, 'inferred');
  assert.ok(edge.evidence.some(f => f.key === 'domHash'));
  assert.ok(!JSON.stringify(edge).includes('actor'));
});
test('shared hosting and urgency alone do not create a campaign', () => {
  const a = fixture('a'), b = fixture('b');
  a.features = b.features = [{ family: 'infrastructure', key: 'asn', value: 'AS13335', weight: 1, source: 'provider', provenance: 'externally_reported' }, { family: 'behavior', key: 'urgency', value: 'true', weight: 1, source: 'rules', provenance: 'inferred' }];
  assert.equal(correlate(a, b), null);
});
test('campaign review gates IOC propagation, rejects fabricated selections and retracts rejection', () => {
  const db = new IntelligenceStore(':memory:'); const service = new CampaignService(db);
  service.ingest(fixture('a')); const b = service.ingest(fixture('b', 'ns-fixture-two.com', 'web'));
  assert.ok(b.campaignId); assert.equal(service.match(fixture('a').indicators).length, 0);
  assert.throws(() => service.review(b.campaignId!, 'confirmed', ['domain:invented.com'], 'reviewer', 'reviewed'));
  const campaign = service.review(b.campaignId!, 'confirmed', ['domain:ns-fixture-one.com'], 'reviewer', 'Supported by page and script evidence');
  assert.equal(campaign.status, 'confirmed'); assert.equal(service.match(fixture('a').indicators).length, 1);
  assert.equal(service.match(fixture('b', 'ns-fixture-two.com').indicators).length, 0);
  service.review(b.campaignId!, 'rejected', [], 'reviewer', 'False correlation');
  assert.equal(service.match(fixture('a').indicators).length, 0); db.close();
});
test('new campaign members require review and cannot silently publish new domains', () => {
  const db = new IntelligenceStore(':memory:'); const service = new CampaignService(db);
  service.ingest(fixture('a')); const b = service.ingest(fixture('b', 'ns-fixture-two.com'));
  service.review(b.campaignId!, 'confirmed', ['domain:ns-fixture-one.com'], 'soc', 'Observed');
  const c = service.ingest(fixture('c', 'ns-fixture-three.com'));
  assert.equal(db.get<Campaign>('campaign', c.campaignId!)!.status, 'pending');
  assert.equal(service.match(c.indicators).length, 0); db.close();
});
test('repeated observations refresh risk while distinct message IDs remain separate', () => {
  const db = new IntelligenceStore(':memory:'); const service = new CampaignService(db);
  const first = { ...fixture('first'), observationKey: 'message-one' };
  service.ingest(first);
  const refreshed = service.ingest({ ...first, id: 'rescan', riskScore: 99 });
  assert.equal(refreshed.id, 'first'); assert.equal(refreshed.riskScore, 99);
  assert.equal(db.list('incident').length, 1);
  const second = service.ingest({ ...fixture('second'), fingerprint: first.fingerprint, observationKey: 'message-two' });
  assert.equal(db.list('incident').length, 2); assert.ok(second.campaignId); db.close();
});
test('expired and contextual infrastructure IOCs cannot auto-block', () => {
  const db = new IntelligenceStore(':memory:'); const service = new CampaignService(db);
  const [ioc] = service.confirmIndicators('source', fixture('a').indicators, ['domain:ns-fixture-one.com'], 'soc');
  db.put('ioc', { ...ioc, expiresAt: new Date(0).toISOString() });
  assert.equal(service.match(fixture('a').indicators).length, 0);
  const ip = { type: 'ip' as const, value: '8.8.8.8', source: 'DNS', provenance: 'observed' as const, eligibleForBlocking: false };
  service.confirmIndicators('dns', [ip], ['ip:8.8.8.8'], 'soc'); assert.equal(service.match([ip]).length, 0); db.close();
});
test('intelligence survives store restart and writes roll back atomically', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'ns-intel-')); const file = path.join(dir, 'db.sqlite');
  let db = new IntelligenceStore(file); db.put('incident', fixture('a'));
  assert.throws(() => db.transaction(() => { db.put('incident', fixture('b')); throw new Error('rollback'); }));
  db.close(); db = new IntelligenceStore(file); assert.ok(db.get('incident', 'a')); assert.equal(db.get('incident', 'b'), undefined); db.close(); rmSync(dir, { recursive: true });
});
test('high detector confidence alone is not sufficient for deception eligibility', () => {
  assert.equal(eligibleIncident(fixture('a')), true);
  for (const patch of [{ riskScore: 84 }, { confidence: 89 }, { verdict: 'SAFE' }, { features: [] }, { timestamp: new Date(0).toISOString() }]) assert.equal(eligibleIncident({ ...fixture('a'), ...patch }), false);
});
function fakeRunner(available = true) {
  let stops = 0;
  const runner: SandboxRunner = { available: async () => available, start: () => ({ ready: Promise.resolve({ canary: 'NS-SYNTHETIC-test-only', persona: { name: 'Synthetic', email: 'research@example.invalid', organization: 'Fixture' } }), command: async v => ({ ok: true, outcome: `${v.action} synthetic resource served` }), stop: async () => { stops++; } }) };
  return { runner, stopped: () => stops };
}
test('deception is disabled by default and cannot enable without a container runtime', async () => {
  const db = new IntelligenceStore(':memory:'); db.put('incident', fixture('a'));
  const s = new DeceptionService(db, fakeRunner(false).runner);
  assert.equal((await s.status()).enabled, false);
  await assert.rejects(s.start('a', 60, 'admin'), /disabled/);
  await assert.rejects(s.configure(true, 'admin'), /Docker/); db.close();
});
test('synthetic-only ingress, observed telemetry, kill switch and revoked capability', async () => {
  const db = new IntelligenceStore(':memory:'); db.put('incident', fixture('a')); const f = fakeRunner(); const s = new DeceptionService(db, f.runner);
  await s.configure(true, 'admin');
  await assert.rejects(s.start('a', 121, 'admin')); await assert.rejects(s.start('missing', 60, 'admin'));
  const created = await s.start('a', 60, 'admin');
  assert.equal(s.authorize(created.session.id, created.ingressToken), true);
  assert.equal(s.authorize(created.session.id, 'bad'), false);
  await assert.rejects(s.interact(created.session.id, { action: 'canary', password: 'NEVER_STORE_ME' }, 'capability_ingress'), /Only/);
  await assert.rejects(s.interact(created.session.id, { action: 'canary', canary: 'REAL_SECRET' }, 'capability_ingress'), /rejected/);
  await s.interact(created.session.id, { action: 'portal' }, 'soc_probe', '8.8.8.8');
  assert.equal(db.get<DeceptionSession>('deception', created.session.id)!.indicators.length, 0);
  await s.interact(created.session.id, { action: 'canary', canary: created.syntheticCanary }, 'capability_ingress', '9.9.9.9');
  const stored = db.get<DeceptionSession>('deception', created.session.id)!;
  assert.equal(stored.indicators[0].value, '9.9.9.9'); assert.equal(stored.indicators[0].eligibleForBlocking, false);
  assert.ok(!JSON.stringify(stored).includes('REAL_SECRET')); assert.ok(!JSON.stringify(stored).includes(created.ingressToken));
  await s.kill('admin'); assert.equal(f.stopped(), 1); assert.equal(s.authorize(created.session.id, created.ingressToken), false);
  await assert.rejects(s.interact(created.session.id, { action: 'portal' }, 'soc_probe'), /not active/); db.close();
});
test('deadlines and restarts invalidate active research sessions', async () => {
  const db = new IntelligenceStore(':memory:'); db.put('incident', fixture('a')); const s = new DeceptionService(db, fakeRunner().runner);
  await s.configure(true, 'admin'); const created = await s.start('a', 60, 'admin');
  db.put('deception', { ...created.session, expiresAt: new Date(0).toISOString() });
  await assert.rejects(s.interact(created.session.id, { action: 'portal' }, 'soc_probe'), /not active/);
  await s.stopAll(); const restarted = new DeceptionService(db, fakeRunner().runner); assert.equal((await restarted.status()).enabled, false); db.close();
});
test('backend never claims enforcement from a declared browser capability', () => {
  const args: any = { verdict: 'MALICIOUS', riskScore: 90, confidence: 95, requestedAction: 'CLICK_LINK', threatTypes: ['PHISHING'], client: 'chrome_extension', clientCapabilities: { canBlockNavigation: true } };
  assert.equal(EnforcementEngine.evaluatePolicy(args).enforcementStatus, 'PENDING');
  assert.equal(EnforcementEngine.evaluatePolicy({ ...args, actualEnforcementApplied: true }).enforcementStatus, 'ENFORCED');
  assert.equal(EnforcementEngine.evaluatePolicy({ ...args, client: 'gmail_api' }).enforcementStatus, 'NOT_SUPPORTED');
});
test('sandbox worker accepts only its own synthetic data (protocol test, not isolation verification)', async () => {
  const child = spawn(process.execPath, ['sandbox/honeytrap/worker.mjs'], { env: { ...process.env, NS_DEADLINE_MS: String(Date.now() + 3000) } });
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  try {
    const first = await lines.next(); const ready = JSON.parse(first.value!); assert.ok(ready.canary.startsWith('NS-SYNTHETIC-')); assert.ok(ready.persona.email.endsWith('@example.invalid'));
    child.stdin.write(JSON.stringify({ action: 'canary', canary: 'INVALID_SECRET' }) + '\n');
    assert.equal(JSON.parse((await lines.next()).value!).ok, false);
    child.stdin.write(JSON.stringify({ action: 'canary', canary: ready.canary }) + '\n');
    assert.equal(JSON.parse((await lines.next()).value!).ok, true);
  } finally { child.stdin.end(); child.kill(); }
});
