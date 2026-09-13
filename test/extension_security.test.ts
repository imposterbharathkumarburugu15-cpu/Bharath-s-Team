import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';

function background(fetcher: typeof fetch, settings: any = {}) {
  let message: any; let navigate: any;
  const chrome = {
    runtime: { onInstalled: { addListener() {} }, onMessage: { addListener(fn: any) { message = fn; } }, getURL: (p: string) => `chrome-extension://fixture/${p}` },
    contextMenus: { create() {}, onClicked: { addListener() {} } },
    storage: { local: { get: async () => settings, set: async () => {}, remove: async () => {} } },
    webNavigation: { onBeforeNavigate: { addListener(fn: any) { navigate = fn; } } },
    tabs: { get: async () => ({ url: 'https://ns-fixture-one.com' }), update: async () => {}, sendMessage: async () => {} },
  };
  vm.runInNewContext(readFileSync('extension/background.js', 'utf8'), { chrome, fetch: fetcher, console: { log() {}, warn() {} }, URL, AbortSignal, setTimeout, clearTimeout, Map, Date });
  const send = (request: any) => new Promise<any>(resolve => message(request, {}, resolve));
  return { send, navigate };
}
test('extension offline Gmail and URL checks never become SAFE or ALLOW', async () => {
  const bg = background(async () => { throw new Error('offline'); });
  const email = await bg.send({ type: 'ANALYZE_GMAIL_MESSAGE', data: { content: 'Meeting at noon', links: [] } });
  assert.equal(email.verdict, 'UNKNOWN'); assert.equal(email.protectionDecision, 'WARN');
  const url = await bg.send({ type: 'ANALYZE_URL', url: 'https://ns-fixture-one.com', userAction: 'VISIT_WEBSITE' });
  assert.equal(url.verdict, 'UNKNOWN'); assert.equal(url.protectionDecision, 'WARN');
});
test('spam folder placement cannot override the authoritative backend verdict', async () => {
  const bg = background(async () => new Response(JSON.stringify({ verdict: 'SAFE', riskScore: 5, protectionDecision: 'ALLOW' }), { headers: { 'Content-Type': 'application/json' } }));
  const email = await bg.send({ type: 'ANALYZE_GMAIL_MESSAGE', data: { content: 'Meeting at noon', isInSpamFolder: true, links: [] } });
  assert.equal(email.verdict, 'SAFE'); assert.equal(email.riskScore, 5); assert.equal(email.protectionDecision, 'ALLOW');
});
test('disabled automatic navigation checks do not contact the backend', async () => {
  let requests = 0;
  const bg = background(async () => { requests++; throw new Error('unexpected request'); }, { autoCheckUrls: false });
  await bg.navigate({ frameId: 0, tabId: 1, url: 'https://ns-fixture-one.com' });
  assert.equal(requests, 0);
});
test('browser structural observations reach policy evaluation with a deadline', async () => {
  let sent: any, hasDeadline = false;
  const bg = background(async (_url, init) => { sent = JSON.parse(String(init?.body)); hasDeadline = Boolean(init?.signal); return new Response(JSON.stringify({ verdict: 'MALICIOUS', riskScore: 93, protectionDecision: 'BLOCK_ACTION' })); });
  const observation = { domHash: 'a'.repeat(64), credentialFields: true, externalFormAction: true };
  const result = await bg.send({ type: 'ANALYZE_URL', url: 'https://ns-fixture-one.com', userAction: 'ENTER_PASSWORD', webObservation: observation });
  assert.deepEqual(sent.metadata.webObservation, observation); assert.ok(hasDeadline); assert.equal(result.protectionDecision, 'BLOCK_ACTION');
});
