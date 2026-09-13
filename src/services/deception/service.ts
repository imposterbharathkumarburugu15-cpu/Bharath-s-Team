import { randomUUID, randomBytes, timingSafeEqual } from 'node:crypto';
import { IntelligenceStore } from '../intelligence/store';
import { digest, publicIP } from '../intelligence/indicators';
import type { IntelligenceIncident, Indicator } from '../intelligence/types';
import { DockerRunner, type SandboxRunner, type SandboxHandle } from './dockerRunner';

export interface DeceptionSession {
  id: string; incidentId: string; state: 'starting' | 'running' | 'stopped' | 'expired' | 'failed';
  createdAt: string; expiresAt: string; createdBy: string; confidence: number;
  persona?: { name: string; email: string; organization: string };
  timeline: { timestamp: string; action: string; provenance: 'observed' | 'inferred'; source: 'system' | 'soc_probe' | 'capability_ingress'; detail: string }[];
  indicators: Indicator[]; reviewStatus: 'pending' | 'confirmed' | 'rejected';
  reviewedBy?: string;
}
export function eligibleIncident(incident: IntelligenceIncident | undefined): boolean {
  // Confidence alone is detector coverage, not proof. Require independent technical and behavior evidence too.
  if (!incident || incident.verdict !== 'MALICIOUS' || incident.riskScore < 85 || incident.confidence < 90 || Date.now() - Date.parse(incident.timestamp) > 86400000) return false;
  const behavior = incident.features.some(f => f.family === 'behavior' && ['credential_request', 'payment_request'].includes(f.key));
  const technical = incident.features.some(f => (['spf', 'dkim', 'dmarc'].includes(f.key) && f.value === 'fail') || f.key === 'externalFormAction' || f.key === 'confirmed_ioc');
  return behavior && technical;
}
export class DeceptionService {
  private enabled = false; // Never restored on restart, including after a crash.
  private killed = false;
  private active = new Map<string, { handle: SandboxHandle; tokenHash: string; canary: string; timer: NodeJS.Timeout; count: number }>();
  constructor(readonly store: IntelligenceStore, readonly runner: SandboxRunner = new DockerRunner()) {
    for (const s of store.list<DeceptionSession>('deception')) if (['starting', 'running'].includes(s.state)) { s.state = 'stopped'; this.event(s, 'Restart recovery', 'system', 'Session expired on server restart.'); }
  }
  async status() { return { enabled: this.enabled, killSwitch: this.killed, runtimeAvailable: await this.runner.available(), activeSessions: this.active.size, maxDurationSeconds: 120, mode: 'Passive isolated synthetic workspace', outboundNetwork: false }; }
  async configure(enabled: boolean, admin: string) {
    if (enabled && !await this.runner.available()) throw new Error('Build the isolated HoneyTrap image and start Docker before enabling this module.');
    this.enabled = enabled; if (enabled) this.killed = false;
    if (!enabled) await this.stopAll();
    this.store.put('audit', { id: randomUUID(), actor: admin, action: enabled ? 'deception_enabled' : 'deception_disabled', timestamp: new Date().toISOString() });
  }
  async kill(admin: string) {
    this.killed = true; this.enabled = false; await this.stopAll();
    this.store.put('audit', { id: randomUUID(), actor: admin, action: 'deception_kill_switch', timestamp: new Date().toISOString() });
  }
  private event(s: DeceptionSession, action: string, source: 'system' | 'soc_probe' | 'capability_ingress', detail: string, provenance: 'observed' | 'inferred' = 'observed') {
    s.timeline.push({ timestamp: new Date().toISOString(), action, source, detail, provenance });
    this.store.put('deception', s);
  }
  async start(incidentId: string, duration: number, admin: string) {
    if (!this.enabled || this.killed) throw new Error('Controlled deception is disabled.');
    const incident = this.store.get<IntelligenceIncident>('incident', incidentId);
    if (!eligibleIncident(incident)) throw new Error('Requires a recent stored malicious incident, risk ≥85, confidence ≥90 and independent technical plus behavioral evidence.');
    if (!Number.isInteger(duration) || duration < 10 || duration > 120) throw new Error('Duration must be 10–120 seconds.');
    if (this.active.size >= 3) throw new Error('Maximum of three concurrent sandboxes.');
    const s: DeceptionSession = { id: `NS-TRAP-${randomUUID()}`, incidentId, createdBy: admin, state: 'starting', confidence: incident!.confidence, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + duration * 1000).toISOString(), timeline: [], indicators: [], reviewStatus: 'pending' };
    this.event(s, 'Confidence validated', 'system', 'Stored high-confidence evidence passed the independent-signal gate.');
    const token = randomBytes(32).toString('hex');
    const handle = this.runner.start(s.id, duration);
    const timer = setTimeout(() => void this.stop(s.id, 'expired'), duration * 1000);
    this.active.set(s.id, { handle, tokenHash: digest(token), canary: '', timer, count: 0 });
    try {
      const ready = await handle.ready;
      const active = this.active.get(s.id);
      if (!active || !this.enabled || this.killed) throw new Error('Session stopped during startup');
      if (typeof ready.canary !== 'string' || !ready.canary.startsWith('NS-SYNTHETIC-')) throw new Error('Invalid synthetic sandbox response');
      active.canary = ready.canary; s.persona = ready.persona; s.state = 'running';
      this.event(s, 'Sandbox ready', 'system', 'Network disabled, non-root container. Synthetic persona and canary issued.');
      return { session: s, ingressToken: token, ingressEndpoint: `/api/deception/ingress/${s.id}`, syntheticCanary: ready.canary };
    } catch (e) { await this.stop(s.id, 'failed'); throw e; }
  }
  authorize(id: string, token: string): boolean {
    const active = this.active.get(id);
    return Boolean(active && typeof token === 'string' && token.length === 64 && timingSafeEqual(Buffer.from(active.tokenHash), Buffer.from(digest(token))));
  }
  async interact(id: string, body: any, source: 'soc_probe' | 'capability_ingress', remoteIP?: string) {
    const s = this.store.get<DeceptionSession>('deception', id);
    const a = this.active.get(id);
    if (!this.enabled || this.killed || !s || !a || s.state !== 'running' || Date.parse(s.expiresAt) <= Date.now()) throw new Error('Session is not active.');
    if (!body || Object.keys(body).some(k => !['action', 'canary'].includes(k)) || !['portal', 'canary', 'script'].includes(body.action)) throw new Error('Only a synthetic resource action and issued canary are accepted.');
    if (body.canary !== undefined && body.canary !== a.canary) throw new Error('Real or unknown data is rejected and never recorded.');
    if (++a.count > 60) { await this.stop(id); throw new Error('Interaction limit reached.'); }
    let result: any;
    try { result = await a.handle.command(body); }
    catch (e) { await this.stop(id, 'failed'); throw e; }
    if (!result.ok) throw new Error('Sandbox rejected the synthetic action.');
    // Kill/deadline may have occurred while the container was processing.
    if (!this.active.has(id) || !this.enabled || Date.parse(s.expiresAt) <= Date.now()) throw new Error('Session stopped.');
    this.event(s, body.action, source, result.outcome);
    if (source === 'capability_ingress' && remoteIP && publicIP(remoteIP) && !s.indicators.some(i => i.value === remoteIP)) {
      s.indicators.push({ type: 'ip', value: remoteIP, source: 'Observed direct transport peer (may be proxy infrastructure)', provenance: 'observed', eligibleForBlocking: false });
      this.store.put('deception', s);
    }
    if (source === 'capability_ingress' && body.action === 'canary') this.event(s, 'Canary access pattern', source, 'Possible collection behavior; canary access alone does not establish malicious intent or actor identity.', 'inferred');
    return result;
  }
  async stop(id: string, state: 'stopped' | 'expired' | 'failed' = 'stopped') {
    const active = this.active.get(id); this.active.delete(id);
    if (active) { clearTimeout(active.timer); await active.handle.stop(); }
    const s = this.store.get<DeceptionSession>('deception', id);
    if (s && ['running', 'starting'].includes(s.state)) { s.state = state; this.event(s, `Sandbox ${state}`, 'system', 'Capability revoked and container termination requested.'); }
  }
  async stopAll() { await Promise.allSettled([...this.active.keys()].map(id => this.stop(id))); }
}
