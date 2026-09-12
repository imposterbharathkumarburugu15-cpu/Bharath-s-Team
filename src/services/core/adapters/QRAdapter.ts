/**
 * NeuroShield QR Adapter
 * Normalizes QR-code / Quishing inputs into UnifiedThreatInput
 */

import { UnifiedThreatInput } from '../types';
import { extractDomainFromEmail } from '../forensicsEngineProxy';

export interface RawQrInput {
  rawQrData: string;
  scanLocation?: string;
  timestamp?: string;
  metadata?: Record<string, any>;
  history?: any;
}

export class QRAdapter {
  static normalize(input: string | RawQrInput): UnifiedThreatInput {
    const rawData = (typeof input === 'string' ? input : input.rawQrData || '').trim();
    const qrType = QRAdapter.detectQrType(rawData);
    const extractedUrls = QRAdapter.extractUrls(rawData);

    let domain = '';
    if (extractedUrls.length > 0) {
      try {
        const parsed = new URL(extractedUrls[0]);
        domain = parsed.hostname;
      } catch {
        domain = extractDomainFromEmail(extractedUrls[0]);
      }
    }

    const metadata = typeof input === 'string' ? {} : (input.metadata || {});

    return {
      source: 'qr',
      content: rawData,
      rawPayload: rawData,
      sender: domain ? {
        identifier: domain,
        displayName: `QR Destination: ${domain}`,
        domain,
      } : null,
      recipient: null,
      urls: extractedUrls,
      attachments: [],
      metadata: {
        qrType,
        destinationDomain: domain || undefined,
        scanLocation: typeof input === 'object' ? input.scanLocation : undefined,
        timestamp: typeof input === 'object' ? input.timestamp : undefined,
        ...metadata,
      },
      history: (typeof input === 'object' && input.history) ? input.history : null,
      user_action: extractedUrls.length > 0 ? 'CLICK_LINK' : 'UNKNOWN',
    };
  }

  private static detectQrType(data: string): 'URL' | 'WIFI' | 'CRYPTO' | 'VCARD' | 'PAYMENT' | 'TEXT' {
    if (/^https?:\/\//i.test(data) || /^www\./i.test(data)) return 'URL';
    if (/^WIFI:/i.test(data)) return 'WIFI';
    if (/^(bitcoin|ethereum|litecoin|usdt|tron):/i.test(data)) return 'CRYPTO';
    if (/^BEGIN:VCARD/i.test(data)) return 'VCARD';
    if (/^(upi|payto|monzo|venmo|alipay):/i.test(data)) return 'PAYMENT';
    return 'TEXT';
  }

  private static extractUrls(text: string): string[] {
    if (!text) return [];
    const urlRegex = /https?:\/\/[^\s<>"'{}|\\^`\[\]]+|www\.[^\s<>"'{}|\\^`\[\]]+/gi;
    const matches = text.match(urlRegex) || [];
    return Array.from(new Set(matches.map((u) => {
      const clean = u.replace(/[.,;!?)]+$/, '');
      return clean.startsWith('http') ? clean : `https://${clean}`;
    })));
  }
}
