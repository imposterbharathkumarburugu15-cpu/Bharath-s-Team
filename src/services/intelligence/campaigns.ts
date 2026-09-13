import { randomUUID } from 'node:crypto';
import { IntelligenceStore } from './store';
import { correlate } from './features';
import { validIndicator, digest } from './indicators';
import type { Campaign, ConfirmedIOC, IntelligenceIncident, Indicator } from './types';

export class CampaignService {
  constructor(readonly store: IntelligenceStore) {}
  ingest(incident: IntelligenceIncident): IntelligenceIncident {
    return this.store.transaction(() => {
      const prior = this.store.list<IntelligenceIncident>('incident', 1000).filter(i => Date.now() - Date.parse(i.timestamp) < 30 * 86400000);
      const duplicate = prior.find(p => p.source === incident.source && Boolean(incident.observationKey) && p.observationKey === incident.observationKey && Date.now() - Date.parse(p.timestamp) < 300000);
      if (duplicate) {
        // Refresh the backend assessment (including IOC revocation) without inventing another incident.
        incident = { ...incident, id: duplicate.id, timestamp: duplicate.timestamp, campaignId: duplicate.campaignId };
        this.store.put('incident', incident);
        if (incident.campaignId) return incident;
      }
      this.store.put('incident', incident);
      if (incident.riskScore < 40) return incident;
      const matches = prior.filter(p => p.id !== incident.id).map(p => ({ p, edge: correlate(incident, p) })).filter(m => m.edge).sort((a, b) => b.edge!.score - a.edge!.score);
      for (const { p, edge } of matches) {
        let campaign = p.campaignId ? this.store.get<Campaign>('campaign', p.campaignId) : undefined;
        if (campaign?.status === 'rejected') continue;
        if (campaign && campaign.incidentIds.length >= 100) continue;
        // Complete-link admission prevents an unrelated transitive chain from growing a cluster.
        if (campaign && !campaign.incidentIds.every(id => {
          const member = this.store.get<IntelligenceIncident>('incident', id);
          return member && correlate(incident, member);
        })) continue;
        const now = new Date().toISOString();
        if (!campaign) {
          campaign = { id: `NS-CAMP-${randomUUID().slice(0, 8).toUpperCase()}`, status: 'pending', incidentIds: [p.id], correlations: [], confidence: edge!.score, createdAt: now, updatedAt: now };
          p.campaignId = campaign.id;
          this.store.put('incident', p);
        }
        for (const id of campaign.incidentIds) {
          const member = this.store.get<IntelligenceIncident>('incident', id)!;
          const correlation = correlate(incident, member);
          if (correlation) campaign.correlations.push(correlation);
        }
        campaign.incidentIds.push(incident.id);
        campaign.confidence = Math.min(...campaign.correlations.map(c => c.score));
        campaign.updatedAt = now;
        // A new member needs its own review. Existing confirmed IOCs retain their reviewed provenance.
        campaign.status = 'pending';
        incident.campaignId = campaign.id;
        this.store.put('campaign', campaign);
        this.store.put('incident', incident);
        break;
      }
      return incident;
    });
  }
  candidates(campaign: Campaign): Indicator[] {
    return [...new Map(campaign.incidentIds.flatMap(id => this.store.get<IntelligenceIncident>('incident', id)?.indicators || []).map(i => [`${i.type}:${i.value}`, i])).values()];
  }
  confirmIndicators(sourceId: string, candidates: Indicator[], selected: string[], reviewer: string): ConfirmedIOC[] {
    if (!Array.isArray(selected) || selected.length > 100 || !selected.every(v => typeof v === 'string')) throw new Error('Select valid observed indicators.');
    const chosen = selected.map(key => candidates.find(i => `${i.type}:${i.value}` === key));
    if (chosen.some(i => !i || !validIndicator(i.type, i.value))) throw new Error('Only validated observed indicators can be confirmed.');
    return chosen.map(i => {
      const record: ConfirmedIOC = { ...i!, id: digest(`${sourceId}:${i!.type}:${i!.value}`), sourceId, reviewedBy: reviewer,
        confirmedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(), active: true };
      this.store.put('ioc', record);
      return record;
    });
  }
  review(id: string, status: 'confirmed' | 'rejected', selected: string[], reviewer: string, note = ''): Campaign {
    return this.store.transaction(() => {
      const c = this.store.get<Campaign>('campaign', id);
      if (!c) throw new Error('Campaign not found.');
      if (!['confirmed', 'rejected'].includes(status)) throw new Error('Invalid review decision.');
      // Re-review replaces the prior selection and rejection retracts propagated intelligence.
      for (const ioc of this.store.list<ConfirmedIOC>('ioc').filter(i => i.sourceId === id)) this.store.put('ioc', { ...ioc, active: false });
      if (status === 'confirmed') this.confirmIndicators(id, this.candidates(c), selected, reviewer);
      Object.assign(c, { status, reviewedBy: reviewer, reviewedAt: new Date().toISOString(), reviewNote: note.slice(0, 1000) });
      this.store.put('campaign', c);
      return c;
    });
  }
  match(indicators: Indicator[]): ConfirmedIOC[] {
    const keys = new Set(indicators.filter(i => i.eligibleForBlocking).map(i => `${i.type}:${i.value}`));
    return this.store.list<ConfirmedIOC>('ioc').filter(i => i.active && i.eligibleForBlocking && Date.parse(i.expiresAt) > Date.now() && keys.has(`${i.type}:${i.value}`));
  }
  graph(campaign: Campaign) {
    const nodes = new Map<string, { id: string; label: string; type: string }>();
    const edges: { from: string; to: string; label: string; provenance: string }[] = [];
    for (const id of campaign.incidentIds) {
      const incident = this.store.get<IntelligenceIncident>('incident', id);
      if (!incident) continue;
      nodes.set(id, { id, label: `${incident.source} · ${id.slice(-8)}`, type: 'incident' });
      for (const i of incident.indicators) {
        const key = `${i.type}:${i.value}`;
        nodes.set(key, { id: key, label: i.value, type: i.type });
        edges.push({ from: id, to: key, label: 'contains', provenance: i.provenance });
      }
      for (const f of incident.features.filter(f => f.key === 'dns_ip' || f.key === 'asn')) {
        const domain = f.source;
        const from = `domain:${domain}`;
        const to = `${f.key}:${f.value}`;
        nodes.set(from, { id: from, label: domain, type: 'domain' });
        nodes.set(to, { id: to, label: f.value, type: f.key });
        edges.push({ from, to, label: f.key === 'dns_ip' ? 'resolves to' : 'reported network', provenance: f.provenance });
      }
    }
    for (const c of campaign.correlations) edges.push({ from: c.incidentA, to: c.incidentB, label: `similarity ${Math.round(c.score * 100)}%`, provenance: 'inferred' });
    return { nodes: [...nodes.values()], edges };
  }
}
