import type { UnifiedIncidentObject } from '../core/types';
import type { DNAFeature, Indicator, IntelligenceIncident, Correlation } from './types';
import { digest, normalizeDomain, publicIP, urlStructure } from './indicators';

export function extractDNA(input: any, analysis: UnifiedIncidentObject): IntelligenceIncident {
  const features: DNAFeature[] = [];
  const indicators: Indicator[] = [];
  const add = (family: DNAFeature['family'], key: string, value: unknown, weight: number, provenance: DNAFeature['provenance'] = 'observed', source = 'Submitted incident') => {
    if (value === undefined || value === null || value === '' || value === 'UNKNOWN' || value === 'unknown') return;
    features.push({ family, key, value: String(value).slice(0, 256), weight, provenance, source });
  };
  const indicator = (type: Indicator['type'], value: string, eligibleForBlocking = false) => indicators.push({ type, value, eligibleForBlocking, source: analysis.incident_id, provenance: 'observed' });
  const content = typeof input.content === 'string' ? input.content : typeof input.body === 'string' ? input.body : input.body?.text || '';
  const raw = input.rawHeaders || input.metadata?.rawHeaders || input.rawPayload || '';
  const headerText = typeof raw === 'string' ? raw.slice(0, 100000) : '';
  const urls = [...(Array.isArray(input.urls) ? input.urls : []), ...(content.match(/https?:\/\/[^\s<>"']+/gi) || []), ...(input.url ? [input.url] : [])].filter(v => typeof v === 'string').slice(0, 40);
  for (const url of urls) {
    const u = urlStructure(url);
    if (!u) continue;
    add('url', 'domain', u.domain, 4);
    add('url', 'domain_shape', u.domain.split('.').slice(0, -1).join('.').replace(/[0-9-]/g, ''), 1, 'inferred', 'Normalized domain similarity candidate');
    if (u.path !== '/') add('url', 'path_structure', u.path, 3);
    if (u.queryKeys.length) add('url', 'query_key_structure', u.queryKeys.join(':'), 2);
    indicator('domain', u.domain, true);
    indicator('url', u.origin, true);
  }
  const sender = input.sender?.identifier || input.sender?.address || input.from || '';
  const senderDomain = normalizeDomain(input.sender?.domain || sender.match(/@([^>\s]+)/)?.[1] || '');
  if (senderDomain) { add('email', 'sender_domain', senderDomain, 3); indicator('domain', senderDomain); }
  if (sender.includes('@')) add('email', 'sender_pattern', digest(sender.split('@')[0].toLowerCase().replace(/[0-9]+/g, '#')), 1, 'inferred', 'Hashed sender pattern');
  if (input.sender?.displayName) add('email', 'display_name_pattern', digest(input.sender.displayName.toLowerCase().replace(/\d+/g, '#')), 1);
  if (analysis.identity?.fromReplyToMismatch) add('email', 'reply_to_mismatch', true, 1);
  for (const method of ['spf', 'dkim', 'dmarc']) {
    const result = headerText.match(new RegExp(`\\b${method}=(pass|fail|softfail|none|neutral|temperror|permerror)`, 'i'))?.[1];
    if (result) add('email', method, result.toLowerCase(), 0.5, 'observed', 'Authentication-Results header (reported, not cryptographically reverified)');
  }
  const received = headerText.match(/^Received:[\s\S]*?(?=\n[^\s]|$)/gim) || [];
  const headerNames = [...new Set((headerText.match(/^[a-z][a-z0-9-]*(?=:)/gim) || []).map(h => h.toLowerCase()))].sort();
  if (headerNames.length) add('email', 'header_structure', digest(headerNames.join('|')), 1);
  if (received.length) add('email', 'relay_count', Math.min(received.length, 10), 0.5);
  for (const h of received.slice(0, 12)) {
    for (const ip of h.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []) {
      if (publicIP(ip)) { add('infrastructure', 'reported_relay_ip', ip, 1, 'observed', 'Received header; sender-controlled hops may be forged'); indicator('ip', ip); }
    }
  }
  // Store hashes of wording, never subjects, names, message bodies, or attachment names.
  const words = content.toLowerCase().replace(/https?:\/\/\S+|\S+@\S+|\d+/g, ' ').match(/[a-z]{3,}/g) || [];
  for (let i = 0; i + 3 < Math.min(words.length, 160); i += 4) add('behavior', 'wording_shingle', digest(words.slice(i, i + 4).join(' ')), 0.4, 'inferred', 'Normalized wording pattern');
  for (const [key, re] of [['urgency', /urgent|immediately|suspend|expire/i], ['credential_request', /password|sign.?in|log.?in|otp|credential/i], ['payment_request', /wire|transfer|payment|invoice|gift card/i]] as [string, RegExp][]) {
    if (re.test(content)) add('behavior', key, true, 1, 'inferred', 'Local intent rules');
  }
  for (const a of (input.attachments || []).slice(0, 20)) {
    if (/^[a-f0-9]{64}$/i.test(a.hash || '')) { add('email', 'attachment_sha256', a.hash.toLowerCase(), 6); indicator('sha256', a.hash.toLowerCase()); }
    if (typeof a.mimeType === 'string' && /^[\w.+-]+\/[\w.+-]+$/.test(a.mimeType)) add('email', 'attachment_mime', a.mimeType, 1);
  }
  const sequence = Array.isArray(input.metadata?.events) ? input.metadata.events : [];
  const sequenceActions = sequence.slice(0, 20).map((e: any) => String(e.action || e.stage || '')).filter((s: string) => /^(NEW_CONTACT|IDENTITY_CLAIM|TRUST_BUILDING|URGENCY|SENSITIVE_REQUEST|PAYMENT_CREDENTIAL_ACTION|CLICK_LINK|ENTER_PASSWORD|SHARE_OTP|TRANSFER_MONEY)$/.test(s));
  if (sequenceActions.length > 1) add('behavior', 'social_engineering_sequence', sequenceActions.join('>'), 2, 'inferred', 'Observed interaction sequence interpreted by local detectors');
  // Client observation schema contains structures only, never input values or full DOM/text.
  const web = input.metadata?.webObservation;
  if (web && typeof web === 'object') {
    for (const key of ['domHash', 'scriptPatternHash', 'certificateSha256']) {
      if (/^[a-f0-9]{64}$/.test(web[key] || '')) add('web', key, web[key], 5, 'observed', 'Browser sensor report');
    }
    for (const key of ['credentialFields', 'externalFormAction', 'obfuscationIndicator']) {
      if (web[key] === true) add('web', key, true, 1, 'observed', 'Browser sensor report');
    }
    for (const url of (Array.isArray(web.redirects) ? web.redirects : []).slice(0, 8)) {
      const u = typeof url === 'string' && urlStructure(url);
      if (u) { add('url', 'redirect_domain', u.domain, 4, 'observed', 'Browser sensor report'); indicator('domain', u.domain); }
    }
  }
  const uniqueFeatures = [...new Map(features.map(f => [`${f.family}:${f.key}:${f.value}`, f])).values()];
  return {
    id: analysis.incident_id, source: analysis.source, timestamp: analysis.timestamp,
    riskScore: analysis.risk_score, confidence: analysis.confidence, verdict: analysis.verdict,
    observationKey: digest(`${analysis.source}:${input.id || input.messageId || content + headerText + JSON.stringify(urls)}`),
    fingerprint: digest(uniqueFeatures.map(f => `${f.family}:${f.key}:${f.value}`).sort().join('|')),
    features: uniqueFeatures, indicators: [...new Map(indicators.map(i => [`${i.type}:${i.value}`, i])).values()],
  };
}

export function correlate(a: IntelligenceIncident, b: IntelligenceIncident): Correlation | null {
  if (a.id === b.id || a.riskScore < 40 || b.riskScore < 40) return null;
  const keys = new Set(b.features.map(f => `${f.family}:${f.key}:${f.value}`));
  const evidence = a.features.filter(f => keys.has(`${f.family}:${f.key}:${f.value}`));
  const families = new Set(evidence.map(f => f.family));
  // Shared hosting, authentication results or urgency alone cannot form a campaign.
  const specific = evidence.some(f => f.weight >= 3 && !['sender_domain'].includes(f.key));
  if (families.size < 2 || !specific) return null;
  const weight = (fs: DNAFeature[]) => fs.reduce((sum, f) => sum + f.weight, 0);
  const shared = weight(evidence);
  const union = weight(a.features) + weight(b.features) - shared;
  const score = Math.min(0.97, (shared / Math.max(1, union)) * 0.7 + Math.min(families.size, 3) * 0.1);
  if (score < 0.6) return null;
  return { incidentA: a.id, incidentB: b.id, score: Number(score.toFixed(3)), provenance: 'inferred', evidence };
}
