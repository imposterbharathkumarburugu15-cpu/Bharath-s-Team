/**
 * NeuroShield Email Adapter
 * Normalizes email inputs (RFC 5322 raw text, Gmail API responses, or structured fields)
 * into NormalizedEmail and UnifiedThreatInput.
 */

import {
  UnifiedThreatInput,
  SenderInfo,
  RecipientInfo,
  NormalizedEmail,
  NormalizedEmailSender,
  NormalizedEmailRecipient,
  NormalizedEmailAttachment,
  NormalizedEmailAuth,
  NormalizedEmailContext,
  ActionType,
} from '../types';
import { parseRawHeaders, extractDomainFromEmail } from '../forensicsEngineProxy';

export interface RawEmailInput {
  id?: string;
  threadId?: string;
  rawHeaders?: string;
  rawEmail?: string;
  body?: string;
  from?: string;
  to?: string;
  subject?: string;
  date?: string;
  urls?: string[];
  attachments?: Array<{
    filename: string;
    mimeType: string;
    sizeBytes?: number;
    hash?: string;
  }>;
  authentication?: Partial<NormalizedEmailAuth>;
  context?: Partial<NormalizedEmailContext>;
  history?: any;
  metadata?: Record<string, any>;
}

export class EmailAdapter {
  /**
   * Converts any raw, parsed, or provider email structure into the standard NormalizedEmail contract.
   */
  static toNormalizedEmail(input: string | RawEmailInput | NormalizedEmail | any): NormalizedEmail {
    // Already conforms to NormalizedEmail
    if (
      input &&
      typeof input === 'object' &&
      input.source === 'email' &&
      input.sender?.address &&
      input.body?.text !== undefined &&
      input.authentication
    ) {
      return input as NormalizedEmail;
    }

    const timestamp = input?.date || input?.timestamp || new Date().toISOString();
    const id = input?.id || `email-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const threadId = input?.threadId;

    // Case 1: RFC 5322 or string
    if (typeof input === 'string') {
      const isRfcLike = /^(From|Received|Return-Path|Subject|Date|To):/im.test(input);
      let headers: Record<string, any> = {};
      let bodyText = input;
      let subject = 'No Subject';
      let fromRaw = '';
      let toRaw = '';
      let replyToRaw = '';

      if (isRfcLike) {
        const parsed = parseRawHeaders(input);
        headers = parsed.headers || {};
        bodyText = parsed.body || input;
        fromRaw = (Array.isArray(headers['from']) ? headers['from'][0] : headers['from']) || '';
        toRaw = (Array.isArray(headers['to']) ? headers['to'][0] : headers['to']) || '';
        subject = (Array.isArray(headers['subject']) ? headers['subject'][0] : headers['subject']) || 'No Subject';
        replyToRaw = (Array.isArray(headers['reply-to']) ? headers['reply-to'][0] : headers['reply-to']) || '';
      }

      const sender = EmailAdapter.parseSenderDetails(fromRaw, replyToRaw);
      const recipients = EmailAdapter.parseRecipients(toRaw);
      const urls = EmailAdapter.extractUrls(bodyText + ' ' + input);
      const auth = EmailAdapter.extractAuthFromHeaders(headers);

      return {
        id,
        threadId,
        timestamp,
        source: 'email',
        sender,
        recipients,
        subject,
        body: {
          text: bodyText,
          snippet: bodyText.substring(0, 160).replace(/\s+/g, ' ').trim(),
        },
        headers,
        urls,
        attachments: [],
        authentication: auth,
        context: {
          isFirstContact: null,
          relationshipStatus: 'UNKNOWN',
          previousInteractionsCount: null,
        },
        requestedActions: [],
        metadata: {
          rawHeaders: isRfcLike ? input : undefined,
        },
      };
    }

    // Case 2: Structured object input
    const bodyContent =
      input.body?.text ||
      input.body ||
      input.content ||
      input.snippet ||
      '';
    const subject = input.subject || 'No Subject';
    const fullText = (typeof bodyContent === 'string' ? bodyContent : '') + ' ' + subject;
    const combinedUrls = Array.from(new Set([...(input.urls || []), ...EmailAdapter.extractUrls(fullText)]));

    const fromVal = input.sender?.address || input.from || (typeof input.sender === 'string' ? input.sender : '') || '';
    const replyToVal = input.sender?.replyTo || input.replyTo || '';
    const sender = EmailAdapter.parseSenderDetails(fromVal, replyToVal);

    let recipients: NormalizedEmailRecipient[] = [];
    if (Array.isArray(input.recipients) && input.recipients.length > 0) {
      recipients = input.recipients.map((r: any) =>
        typeof r === 'string' ? { address: r.toLowerCase() } : { address: r.address || '', displayName: r.displayName }
      );
    } else if (input.to) {
      recipients = EmailAdapter.parseRecipients(input.to);
    }

    const attachments: NormalizedEmailAttachment[] = (input.attachments || []).map((att: any) => ({
      filename: att.filename || 'attachment',
      mimeType: att.mimeType || 'application/octet-stream',
      sizeBytes: att.sizeBytes,
      hash: att.hash,
      isExecutable: att.isExecutable ?? /\.(exe|scr|bat|cmd|vbs|js|ps1|iso|img|hta|jar|msi)$/i.test(att.filename || ''),
    }));

    const rawHeadersStr = input.rawHeaders || input.rawEmail || '';
    let parsedHeaders: Record<string, any> = input.headers || {};
    if (rawHeadersStr && Object.keys(parsedHeaders).length === 0) {
      parsedHeaders = parseRawHeaders(rawHeadersStr).headers || {};
    }

    const auth: NormalizedEmailAuth = {
      spf: input.authentication?.spf || EmailAdapter.extractSpfStatus(parsedHeaders),
      dkim: input.authentication?.dkim || EmailAdapter.extractDkimStatus(parsedHeaders),
      dmarc: input.authentication?.dmarc || EmailAdapter.extractDmarcStatus(parsedHeaders),
      rawAuthResults: input.authentication?.rawAuthResults || (parsedHeaders['authentication-results'] as string) || undefined,
    };

    const context: NormalizedEmailContext = {
      isFirstContact: input.context?.isFirstContact ?? (input.history?.isKnownContact === false ? true : null),
      relationshipStatus:
        input.context?.relationshipStatus ||
        (input.history?.isKnownContact ? 'KNOWN_TRUSTED' : input.history?.previousInteractionsCount === 0 ? 'FIRST_CONTACT' : 'UNKNOWN'),
      previousInteractionsCount: input.context?.previousInteractionsCount ?? input.history?.previousInteractionsCount ?? null,
    };

    return {
      id,
      threadId,
      timestamp,
      source: 'email',
      sender,
      recipients,
      subject,
      body: {
        text: typeof bodyContent === 'string' ? bodyContent : JSON.stringify(bodyContent),
        html: input.body?.html,
        snippet: input.body?.snippet || (typeof bodyContent === 'string' ? bodyContent.substring(0, 160) : ''),
      },
      headers: parsedHeaders,
      urls: combinedUrls,
      attachments,
      authentication: auth,
      context,
      requestedActions: input.requestedActions || [],
      metadata: input.metadata || {},
    };
  }

  /**
   * Converts a NormalizedEmail into UnifiedThreatInput for the NeuroShield Core engine.
   */
  static toUnifiedInput(email: NormalizedEmail): UnifiedThreatInput {
    const rawHeadersStr = typeof email.metadata?.rawHeaders === 'string' ? email.metadata.rawHeaders : '';

    return {
      id: email.id,
      source: 'email',
      timestamp: email.timestamp,
      subject: email.subject,
      body: email.body.text,
      content: email.body.text,
      rawPayload: rawHeadersStr || email.body.text,
      headers: email.headers,
      sender: email.sender?.address && email.sender.address.trim() ? {
        identifier: email.sender.address,
        displayName: email.sender.displayName || email.sender.address,
        domain: email.sender.domain || extractDomainFromEmail(email.sender.address),
        authenticated: email.authentication.spf === 'PASS' && email.authentication.dkim === 'PASS',
      } : null,
      recipients: email.recipients.map(r => ({
        identifier: r.address,
        displayName: r.displayName || r.address,
        domain: extractDomainFromEmail(r.address),
      })),
      recipient: email.recipients[0] ? {
        identifier: email.recipients[0].address,
        displayName: email.recipients[0].displayName || email.recipients[0].address,
        domain: extractDomainFromEmail(email.recipients[0].address),
      } : null,
      urls: email.urls,
      attachments: email.attachments.map(att => ({
        filename: att.filename,
        mimeType: att.mimeType,
        sizeBytes: att.sizeBytes,
        hash: att.hash,
        isExecutable: att.isExecutable,
      })),
      identity: {
        claimedIdentity: email.sender.displayName || email.sender.address,
        verifiedDomain: email.sender.domain,
        authStatus:
          email.authentication.spf === 'PASS' && email.authentication.dkim === 'PASS'
            ? 'PASS'
            : email.authentication.spf === 'FAIL' || email.authentication.dkim === 'FAIL' || email.authentication.dmarc === 'FAIL'
            ? 'FAIL'
            : 'UNKNOWN',
      },
      history: email.context.relationshipStatus !== 'UNKNOWN' ? {
        previousInteractionsCount: email.context.previousInteractionsCount ?? 0,
        isKnownContact: email.context.relationshipStatus === 'KNOWN_TRUSTED' || email.context.relationshipStatus === 'KNOWN_PREVIOUS',
        firstContactDate: email.context.isFirstContact ? email.timestamp : undefined,
      } : null,
      metadata: {
        ...email.metadata,
        subject: email.subject,
        replyTo: email.sender.replyTo,
        headers: email.headers,
        authentication: email.authentication,
        spfStatus: email.authentication.spf,
        dkimStatus: email.authentication.dkim,
        dmarcStatus: email.authentication.dmarc,
        threadId: email.threadId,
      },
    };
  }

  /**
   * Authoritative entrypoint to normalize any incoming email data into UnifiedThreatInput.
   */
  static normalize(input: string | RawEmailInput | NormalizedEmail | any): UnifiedThreatInput {
    const normalizedEmail = EmailAdapter.toNormalizedEmail(input);
    return EmailAdapter.toUnifiedInput(normalizedEmail);
  }

  private static parseSenderDetails(rawAddr: string, replyTo?: string): NormalizedEmailSender {
    if (!rawAddr || !rawAddr.trim()) {
      return { address: '', displayName: 'Unknown Sender', domain: '', replyTo: replyTo || undefined };
    }
    const trimmed = rawAddr.trim();
    // Case A: Contains bracketed email e.g. "John Doe" <john@corp.com>
    const bracketMatch = trimmed.match(/^(?:["']?([^"<>]*)["']?\s*)?<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>$/);
    if (bracketMatch) {
      const displayName = bracketMatch[1]?.trim() || '';
      const email = bracketMatch[2]?.trim().toLowerCase();
      const domain = extractDomainFromEmail(email);
      return {
        address: email,
        displayName: displayName || email,
        domain,
        replyTo: replyTo || undefined,
      };
    }
    // Case B: Bare email address e.g. john@corp.com
    const bareMatch = trimmed.match(/^([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$/);
    if (bareMatch) {
      const email = bareMatch[1].toLowerCase();
      const domain = extractDomainFromEmail(email);
      return {
        address: email,
        displayName: email,
        domain,
        replyTo: replyTo || undefined,
      };
    }
    // Case C: Fallback
    const domain = extractDomainFromEmail(trimmed);
    return {
      address: trimmed.toLowerCase(),
      displayName: trimmed,
      domain,
      replyTo: replyTo || undefined,
    };
  }

  private static parseRecipients(rawAddr: string): NormalizedEmailRecipient[] {
    if (!rawAddr || !rawAddr.trim()) return [];
    return rawAddr.split(',').map((part) => {
      const trimmed = part.trim();
      const bracketMatch = trimmed.match(/^(?:["']?([^"<>]*)["']?\s*)?<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>$/);
      if (bracketMatch) {
        return {
          address: bracketMatch[2]?.trim().toLowerCase(),
          displayName: bracketMatch[1]?.trim() || undefined,
        };
      }
      const bareMatch = trimmed.match(/^([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$/);
      if (bareMatch) {
        return { address: bareMatch[1].toLowerCase() };
      }
      return { address: trimmed.toLowerCase() };
    });
  }

  private static extractUrls(text: string): string[] {
    if (!text) return [];
    const urlRegex = /https?:\/\/[^\s<>"'{}|\\^`\[\]]+/gi;
    const matches = text.match(urlRegex) || [];
    return Array.from(new Set(matches.map((u) => u.replace(/[.,;!?)]+$/, ''))));
  }

  private static extractAuthFromHeaders(headers: Record<string, any>): NormalizedEmailAuth {
    return {
      spf: EmailAdapter.extractSpfStatus(headers),
      dkim: EmailAdapter.extractDkimStatus(headers),
      dmarc: EmailAdapter.extractDmarcStatus(headers),
      rawAuthResults: (headers['authentication-results'] as string) || undefined,
    };
  }

  private static extractSpfStatus(
    headers: Record<string, any>
  ): 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL' | 'NONE' | 'UNAVAILABLE' {
    const authResults = headers['authentication-results'] || '';
    const receivedSpf = headers['received-spf'] || '';
    const combined = `${authResults} ${receivedSpf}`.toLowerCase();

    if (!combined.trim()) return 'UNAVAILABLE';
    if (combined.includes('spf=pass') || combined.includes('pass (')) return 'PASS';
    if (combined.includes('spf=fail')) return 'FAIL';
    if (combined.includes('spf=softfail')) return 'SOFTFAIL';
    if (combined.includes('spf=neutral')) return 'NEUTRAL';
    if (combined.includes('spf=none')) return 'NONE';

    return 'UNAVAILABLE';
  }

  private static extractDkimStatus(
    headers: Record<string, any>
  ): 'PASS' | 'FAIL' | 'NONE' | 'UNAVAILABLE' {
    const authResults = (headers['authentication-results'] || '').toLowerCase();
    const dkimSig = headers['dkim-signature'] || '';

    if (!authResults.trim() && !dkimSig) return 'UNAVAILABLE';
    if (authResults.includes('dkim=pass')) return 'PASS';
    if (authResults.includes('dkim=fail')) return 'FAIL';
    if (authResults.includes('dkim=none')) return 'NONE';

    return dkimSig ? 'NONE' : 'UNAVAILABLE';
  }

  private static extractDmarcStatus(
    headers: Record<string, any>
  ): 'PASS' | 'FAIL' | 'NONE' | 'UNAVAILABLE' {
    const authResults = (headers['authentication-results'] || '').toLowerCase();

    if (!authResults.trim()) return 'UNAVAILABLE';
    if (authResults.includes('dmarc=pass')) return 'PASS';
    if (authResults.includes('dmarc=fail')) return 'FAIL';
    if (authResults.includes('dmarc=none')) return 'NONE';

    return 'UNAVAILABLE';
  }
}
