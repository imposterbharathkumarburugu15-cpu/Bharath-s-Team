import { parse } from 'parse5';
import type { UnifiedThreatInput } from '../types';

export interface DestinationFinding {
  signal: 'DISPLAY_DESTINATION_MISMATCH' | 'CREDENTIAL_FORM_EXTERNAL' | 'CREDENTIAL_FORM_INSECURE' | 'ACTIVE_LINK_SCHEME';
  severity: 'medium' | 'high' | 'critical';
  displayedHost?: string;
  destinationHost?: string;
  explanation: string;
  // A structural observation, not a claim that a destination is confirmed malicious.
  status: 'OBSERVED';
}
export interface DestinationAnalysis {
  status: 'available' | 'unavailable';
  linksInspected: number;
  formsInspected: number;
  truncated: boolean;
  riskFloor: number;
  findings: DestinationFinding[];
  limitations: string[];
}

type Node = { nodeName: string; tagName?: string; value?: string; attrs?: { name: string; value: string }[]; childNodes?: Node[] };
const attr = (node: Node, name: string) => node.attrs?.find(a => a.name === name)?.value || '';
const httpURL = (value: string, base?: string): URL | undefined => {
  try { const u = new URL(value, base); return /^https?:$/.test(u.protocol) ? u : undefined; } catch { return undefined; }
};
const host = (url: URL) => url.hostname.toLowerCase().replace(/\.$/, '');
function descendants(root: Node, max = 5000): { nodes: Node[]; truncated: boolean } {
  const stack = [root], nodes: Node[] = [];
  while (stack.length && nodes.length < max) {
    const current = stack.pop()!; nodes.push(current);
    if (current.childNodes) stack.push(...current.childNodes.slice().reverse());
  }
  return { nodes, truncated: stack.length > 0 };
}
function visibleText(root: Node): string {
  // Attribute values, CSS and scripts are not visible anchor text.
  const stack = [root]; let value = '', count = 0;
  while (stack.length && count++ < 5000) {
    const node = stack.pop()!;
    if (['script', 'style', 'template'].includes(node.tagName || '') || node.attrs?.some(a => a.name === 'hidden') || /display\s*:\s*none|visibility\s*:\s*hidden/i.test(attr(node, 'style'))) continue;
    if (node.nodeName === '#text') value += node.value || '';
    if (node.childNodes) stack.push(...node.childNodes.slice().reverse());
  }
  return value.trim();
}

/** Passive HTML5 parsing. Never renders, fetches destinations or executes JavaScript. */
export class DestinationDetector {
  static evaluate(input: UnifiedThreatInput): DestinationAnalysis {
    const html = typeof input.metadata?.html === 'string' ? input.metadata.html : /<(?:a|form|input)\b/i.test(input.content) ? input.content : '';
    const result: DestinationAnalysis = {
      status: html ? 'available' : 'unavailable', linksInspected: 0, formsInspected: 0, truncated: html.length > 131072,
      riskFloor: 0, findings: [],
      limitations: ['Static HTML only; scripts, CSS layout, images and redirects are not executed.', 'Different hosts may be legitimate SSO or tracking services; mismatch alone requires review.'],
    };
    if (!html) { result.limitations.push('No HTML supplied; hidden destinations and forms could not be inspected.'); return result; }
    const parsed = descendants(parse(html.slice(0, 131072)) as unknown as Node);
    result.truncated ||= parsed.truncated;
    const page = httpURL(input.metadata?.pageUrl || '');
    const baseTag = parsed.nodes.find(n => n.tagName === 'base' && attr(n, 'href'));
    const base = (baseTag && httpURL(attr(baseTag, 'href'), page?.href)) || page;
    const add = (finding: Omit<DestinationFinding, 'status'>, floor: number) => {
      if (result.findings.length < 50) result.findings.push({ ...finding, status: 'OBSERVED' });
      else result.truncated = true;
      result.riskFloor = Math.max(result.riskFloor, floor);
    };
    for (const node of parsed.nodes) {
      if (node.tagName === 'a' && attr(node, 'href')) {
        result.linksInspected++;
        const href = attr(node, 'href').replace(/[\u0000-\u0020]/g, '');
        if (/^(?:javascript|data|vbscript):/i.test(href)) {
          add({ signal: 'ACTIVE_LINK_SCHEME', severity: 'high', explanation: 'Link uses an active-content scheme instead of an HTTP destination.' }, 65);
          continue;
        }
        const target = httpURL(href, base?.href);
        const text = visibleText(node);
        const label = /^(?:https?:\/\/|www\.)[^\s]+$/i.test(text) ? httpURL(text.startsWith('www.') ? `https://${text}` : text) : undefined;
        if (target && label && host(target) !== host(label)) add({ signal: 'DISPLAY_DESTINATION_MISMATCH', severity: 'medium', displayedHost: host(label), destinationHost: host(target), explanation: 'The visible URL and actual link destination name different hosts.' }, 45);
      }
      if (node.tagName === 'form') {
        result.formsInspected++;
        const children = descendants(node).nodes;
        if (!children.some(n => n.tagName === 'input' && attr(n, 'type').toLowerCase() === 'password')) continue;
        // A submit button can override a form action; inspect both destinations.
        const actions = new Set([attr(node, 'action'), ...children.filter(n => ['button', 'input'].includes(n.tagName || '') && attr(n, 'formaction')).map(n => attr(n, 'formaction'))]);
        for (const action of actions) {
          const target = action ? httpURL(action, base?.href) : page;
          if (!target) continue;
          if (target.protocol === 'http:') add({ signal: 'CREDENTIAL_FORM_INSECURE', severity: 'critical', destinationHost: host(target), explanation: 'A password form sends credentials over unencrypted HTTP.' }, 85);
          if (page && target.origin !== page.origin) add({ signal: 'CREDENTIAL_FORM_EXTERNAL', severity: 'high', displayedHost: host(page), destinationHost: host(target), explanation: 'A password form sends data to a different origin. Verify that this destination is authorized.' }, 65);
        }
      }
    }
    return result;
  }
}
