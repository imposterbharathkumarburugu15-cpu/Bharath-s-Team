import { Router, type RequestHandler } from 'express';
import { campaigns, intelligenceStore, appendInfrastructure } from '../services/intelligence/runtime';
import { domainOSINT } from '../services/intelligence/osint';
import { DeceptionService, eligibleIncident, type DeceptionSession } from '../services/deception/service';
import type { Campaign, IntelligenceIncident, ConfirmedIOC } from '../services/intelligence/types';

export const deception = new DeceptionService(intelligenceStore);
export const requireSOC: RequestHandler = (req, res, next) => {
  if (!req.user || !['admin', 'analyst'].includes(req.user.role)) { res.status(403).json({ error: 'Sign in with an authorized SOC analyst or administrator key.' }); return; }
  next();
};
export const requireAdmin: RequestHandler = (req, res, next) => {
  if (req.user?.role !== 'admin') { res.status(403).json({ error: 'An authorized security administrator is required.' }); return; }
  next();
};
const action = (fn: (req: any, res: any) => Promise<any> | any): RequestHandler => async (req, res) => {
  try { await fn(req, res); } catch (e: any) { res.status(400).json({ error: e.message || 'Operation failed' }); }
};

// Mounted before general API-key middleware; only a per-session expiring capability is accepted.
export const deceptionIngress = Router();
deceptionIngress.post('/api/deception/ingress/:id', action(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const token = (req.get('Authorization') || '').replace(/^Bearer /, '');
  if (!deception.authorize(req.params.id, token)) return res.status(403).json({ error: 'Invalid or expired research capability.' });
  res.json(await deception.interact(req.params.id, req.body, 'capability_ingress', req.socket.remoteAddress?.replace(/^::ffff:/, '')));
}));

export const intelligenceRoutes = Router();
intelligenceRoutes.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
intelligenceRoutes.post('/osint/domain', action(async (req, res) => {
  const report = await domainOSINT(req.body.domain);
  intelligenceStore.put('osint', { ...report, id: report.domain });
  // Enrich existing incidents from this observed domain, without auto-confirming relationships.
  for (const incident of intelligenceStore.list<IntelligenceIncident>('incident').filter(i => i.indicators.some(v => v.type === 'domain' && v.value === report.domain))) {
    appendInfrastructure(incident, report); intelligenceStore.put('incident', incident);
  }
  res.json(report);
}));
intelligenceRoutes.get('/soc/session', requireSOC, (req, res) => res.json({ role: req.user!.role, id: req.user!.id }));
intelligenceRoutes.get('/intelligence/incidents', requireSOC, (_req, res) => res.json(intelligenceStore.list<IntelligenceIncident>('incident').slice(0, 200).map(i => ({ ...i, deceptionEligible: eligibleIncident(i) }))));
intelligenceRoutes.get('/intelligence/campaigns', requireSOC, (_req, res) => res.json(intelligenceStore.list<Campaign>('campaign').map(c => ({ ...c, indicators: campaigns.candidates(c), graph: campaigns.graph(c) }))));
intelligenceRoutes.post('/intelligence/campaigns/:id/review', requireSOC, action((req, res) => {
  if (typeof req.body.note !== 'string' || req.body.note.length < 3 || req.body.note.length > 1000) throw new Error('Add a short review rationale (3–1000 characters).');
  res.json(campaigns.review(req.params.id, req.body.status, req.body.indicators || [], req.user.id, req.body.note));
}));
intelligenceRoutes.get('/intelligence/iocs', requireSOC, (_req, res) => res.json(intelligenceStore.list<ConfirmedIOC>('ioc')));
intelligenceRoutes.post('/intelligence/iocs/:id/revoke', requireSOC, action((req, res) => {
  const ioc = intelligenceStore.get<ConfirmedIOC>('ioc', req.params.id);
  if (!ioc) return res.status(404).json({ error: 'IOC not found.' });
  intelligenceStore.put('ioc', { ...ioc, active: false });
  res.json({ revoked: true });
}));
intelligenceRoutes.get('/deception/status', requireSOC, action(async (_req, res) => res.json(await deception.status())));
intelligenceRoutes.post('/deception/config', requireAdmin, action(async (req, res) => {
  if (typeof req.body.enabled !== 'boolean') throw new Error('enabled must be true or false');
  await deception.configure(req.body.enabled, req.user.id); res.json(await deception.status());
}));
intelligenceRoutes.post('/deception/kill', requireAdmin, action(async (req, res) => { await deception.kill(req.user.id); res.json(await deception.status()); }));
intelligenceRoutes.get('/deception/sessions', requireSOC, (_req, res) => res.json(intelligenceStore.list<DeceptionSession>('deception').slice(0, 100)));
intelligenceRoutes.post('/deception/sessions', requireAdmin, action(async (req, res) => res.status(201).json(await deception.start(req.body.incidentId, req.body.durationSeconds ?? 60, req.user.id))));
intelligenceRoutes.post('/deception/sessions/:id/stop', requireAdmin, action(async (req, res) => { await deception.stop(req.params.id); res.json({ stopped: true }); }));
intelligenceRoutes.post('/deception/sessions/:id/probe', requireAdmin, action(async (req, res) => res.json(await deception.interact(req.params.id, req.body, 'soc_probe'))));
intelligenceRoutes.post('/deception/sessions/:id/review', requireSOC, action((req, res) => {
  const s = intelligenceStore.get<DeceptionSession>('deception', req.params.id);
  if (!s) return res.status(404).json({ error: 'Session not found.' });
  if (['running', 'starting'].includes(s.state)) throw new Error('Stop the sandbox before SOC review.');
  if (!['confirmed', 'rejected'].includes(req.body.status)) throw new Error('Invalid review decision.');
  intelligenceStore.transaction(() => {
    for (const i of intelligenceStore.list<ConfirmedIOC>('ioc').filter(i => i.sourceId === s.id)) intelligenceStore.put('ioc', { ...i, active: false });
    if (req.body.status === 'confirmed') campaigns.confirmIndicators(s.id, s.indicators, req.body.indicators || [], req.user.id);
    s.reviewStatus = req.body.status; s.reviewedBy = req.user.id; intelligenceStore.put('deception', s);
  });
  res.json(s);
}));
