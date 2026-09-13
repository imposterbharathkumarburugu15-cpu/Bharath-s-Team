import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';

test('SOC routes enforce real roles and exact reviewed IOCs affect future backend decisions', async () => {
  process.env.NEUROSHIELD_INTEL_DB = ':memory:';
  process.env.NEUROSHIELD_ADMIN_KEY = randomBytes(32).toString('hex');
  process.env.NEUROSHIELD_ANALYST_KEY = randomBytes(32).toString('hex');
  const { authMiddleware } = await import('../src/middleware/auth');
  const { intelligenceRoutes, deceptionIngress, deception } = await import('../src/routes/intelligence');
  const { campaigns, intelligenceStore, analyzeWithIntelligence } = await import('../src/services/intelligence/runtime');
  const app = express(); app.use(express.json()); app.use(deceptionIngress); app.use(authMiddleware); app.use('/api', intelligenceRoutes);
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const request = async (endpoint: string, key = '', body?: any) => {
    const r = await fetch(base + '/api/' + endpoint, { method: body ? 'POST' : 'GET', headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, data: await r.json() };
  };
  try {
    assert.equal((await request('intelligence/campaigns')).status, 403);
    assert.equal((await request('soc/session', 'untrusted')).status, 403);
    assert.equal((await request('soc/session', process.env.NEUROSHIELD_ANALYST_KEY)).data.role, 'analyst');
    assert.equal((await request('soc/session', process.env.NEUROSHIELD_ADMIN_KEY)).data.role, 'admin');
    assert.equal((await request('deception/config', process.env.NEUROSHIELD_ANALYST_KEY, { enabled: true })).status, 403);
    const state = await request('deception/status', process.env.NEUROSHIELD_ADMIN_KEY);
    assert.equal(state.data.enabled, false);
    assert.equal((await request('deception/sessions', process.env.NEUROSHIELD_ADMIN_KEY, { incidentId: 'forged', durationSeconds: 60, riskScore: 100, confidence: 100 })).status, 400);
    assert.equal((await request('deception/ingress/forged', 'x'.repeat(64), { action: 'portal' })).status, 403);
    assert.equal((await request('osint/domain', '', { domain: 'http://169.254.169.254' })).status, 400);
    const input = { id: 'real-backend-fixture', source: 'web', content: 'Visit https://ns-fixture-observed.com/account', urls: ['https://ns-fixture-observed.com/account'], user_action: 'CLICK_LINK', metadata: { client: 'chrome_extension', webObservation: { domHash: 'a'.repeat(64), credentialFields: true } } };
    const before = await analyzeWithIntelligence(input);
    assert.ok(before.intelligence.incidentId); assert.ok(before.intelligence.fingerprint);
    campaigns.confirmIndicators('reviewed-fixture', [{ type: 'domain', value: 'ns-fixture-observed.com', provenance: 'observed', source: 'backend-test', eligibleForBlocking: true }], ['domain:ns-fixture-observed.com'], 'test-analyst');
    const after = await analyzeWithIntelligence(input);
    assert.equal(after.verdict, 'MALICIOUS'); assert.ok(after.risk_score >= 85);
    assert.equal(after.authoritativeProtectionDecision?.protectionDecision, 'BLOCK_VIEW');
    assert.equal(after.authoritativeProtectionDecision?.enforcementStatus, 'PENDING');
    assert.equal(after.intelligence.matches.length, 1);
    assert.ok(after.evidence_provenance?.some(e => e.signal === 'CONFIRMED_IOC_MATCH'));
    const stored = await request('intelligence/incidents', process.env.NEUROSHIELD_ANALYST_KEY);
    assert.ok(stored.data.length > 0);
    const [ioc] = (await request('intelligence/iocs', process.env.NEUROSHIELD_ANALYST_KEY)).data;
    assert.equal((await request(`intelligence/iocs/${ioc.id}/revoke`, process.env.NEUROSHIELD_ANALYST_KEY, {})).status, 200);
    const revoked = await analyzeWithIntelligence(input); assert.equal(revoked.intelligence.matches.length, 0);
  } finally {
    await deception.stopAll(); server.close(); await once(server, 'close'); intelligenceStore.close();
  }
});
