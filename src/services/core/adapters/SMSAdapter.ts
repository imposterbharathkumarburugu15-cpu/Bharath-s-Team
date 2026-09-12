/**
 * NeuroShield SMS Adapter
 * Normalizes SMS / Smishing inputs into UnifiedThreatInput
 */

import { UnifiedThreatInput, SenderInfo, RecipientInfo } from '../types';

export interface RawSmsInput {
  text: string;
  senderPhone?: string;
  senderName?: string;
  recipientPhone?: string;
  timestamp?: string;
  history?: any;
}

export class SMSAdapter {
  static normalize(input: string | RawSmsInput): UnifiedThreatInput {
    if (typeof input === 'string') {
      const extractedUrls = SMSAdapter.extractUrls(input);
      const inferredSender = SMSAdapter.inferSender(input);

      return {
        source: 'sms',
        content: input,
        rawPayload: input,
        sender: inferredSender,
        recipient: null,
        urls: extractedUrls,
        attachments: [],
        metadata: {
          channelType: 'cellular_sms',
        },
        history: null, // Unknown/Not provided by default
        user_action: null,
      };
    }

    const extractedUrls = Array.from(new Set([
      ...SMSAdapter.extractUrls(input.text || ''),
    ]));

    const sender: SenderInfo | null = input.senderPhone || input.senderName ? {
      identifier: input.senderPhone || input.senderName,
      displayName: input.senderName || input.senderPhone,
      phone: input.senderPhone,
    } : null;

    const recipient: RecipientInfo | null = input.recipientPhone ? {
      identifier: input.recipientPhone,
      phone: input.recipientPhone,
    } : null;

    return {
      source: 'sms',
      content: input.text || '',
      rawPayload: input.text,
      sender,
      recipient,
      urls: extractedUrls,
      attachments: [],
      metadata: {
        timestamp: input.timestamp,
        channelType: 'cellular_sms',
      },
      history: input.history || null,
      user_action: null,
    };
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

  private static inferSender(text: string): SenderInfo | null {
    // Detect alphanumeric SMS sender tags like [HDFCBK], [SBIINB], [AMAZON], [NETFLX]
    const alphaTag = text.match(/^\[([A-Z0-9_-]{3,12})\]/i) || text.match(/\bFrom:\s*([A-Za-z0-9+]+)/i);
    if (alphaTag) {
      const tag = alphaTag[1];
      return {
        identifier: tag,
        displayName: tag,
      };
    }
    // Check if phone number is present at beginning
    const phoneMatch = text.match(/^\+?[1-9]\d{7,14}\b/);
    if (phoneMatch) {
      return {
        identifier: phoneMatch[0],
        phone: phoneMatch[0],
      };
    }
    return null;
  }
}
