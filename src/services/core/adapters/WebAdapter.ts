/**
 * NeuroShield Web Adapter
 * Normalizes Web / URL navigation inputs into UnifiedThreatInput
 */

import { UnifiedThreatInput } from '../types';
import { extractDomainFromEmail } from '../forensicsEngineProxy';

export interface RawWebInput {
  url: string;
  pageTitle?: string;
  textContent?: string;
  referer?: string;
  userAgent?: string;
  metadata?: Record<string, any>;
  history?: any;
}

export class WebAdapter {
  static normalize(input: string | RawWebInput): UnifiedThreatInput {
    if (typeof input === 'string') {
      const cleanUrl = input.trim();
      let domain = '';
      try {
        const parsed = new URL(cleanUrl.startsWith('http') ? cleanUrl : `https://${cleanUrl}`);
        domain = parsed.hostname;
      } catch {
        domain = extractDomainFromEmail(cleanUrl);
      }

      return {
        source: 'web',
        content: cleanUrl,
        rawPayload: cleanUrl,
        sender: domain ? {
          identifier: domain,
          displayName: domain,
          domain,
        } : null,
        recipient: null,
        urls: [cleanUrl.startsWith('http') ? cleanUrl : `https://${cleanUrl}`],
        attachments: [],
        metadata: {
          destinationDomain: domain,
        },
        history: null, // Unknown by default
        user_action: 'CLICK_LINK',
      };
    }

    const cleanUrl = (input.url || '').trim();
    let domain = '';
    try {
      const parsed = new URL(cleanUrl.startsWith('http') ? cleanUrl : `https://${cleanUrl}`);
      domain = parsed.hostname;
    } catch {
      domain = extractDomainFromEmail(cleanUrl);
    }

    const pageContent = [
      input.pageTitle ? `Title: ${input.pageTitle}` : '',
      cleanUrl ? `URL: ${cleanUrl}` : '',
      input.textContent || '',
    ].filter(Boolean).join('\n');

    return {
      source: 'web',
      content: pageContent || cleanUrl,
      rawPayload: cleanUrl,
      sender: domain ? {
        identifier: domain,
        displayName: input.pageTitle || domain,
        domain,
      } : null,
      recipient: null,
      urls: [cleanUrl.startsWith('http') ? cleanUrl : `https://${cleanUrl}`],
      attachments: [],
      metadata: {
        pageTitle: input.pageTitle,
        referer: input.referer,
        userAgent: input.userAgent,
        destinationDomain: domain,
        ...(input.metadata || {}),
      },
      history: input.history || null,
      user_action: 'CLICK_LINK',
    };
  }
}
