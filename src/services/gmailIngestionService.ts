import { apiFetch as fetch } from '../lib/apiClient';
/**
 * NeuroShield Gmail Ingestion Service
 * Centralized Gmail API interaction, email analysis orchestration, and background polling.
 * Extracted from EmailPhishing.tsx inline logic to enable auto-ingestion architecture.
 */

import { executeEmailForensics, ForensicDossier } from './forensicsEngine';
import { InboxEmailItem } from '@/data/inboxEmails';
import { invalidateToken } from './googleAuth';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface GmailRawMessage {
  id: string;
  threadId?: string;
}

export interface GmailMessageDetail {
  id: string;
  snippet?: string;
  payload?: {
    headers?: Array<{ name: string; value: string }>;
    body?: { data?: string };
    parts?: any[];
    mimeType?: string;
  };
  internalDate?: string;
  labelIds?: string[];
}

export interface IngestionResult {
  emails: InboxEmailItem[];
  nextPageToken: string | null;
  totalFetched: number;
  totalAnalyzed: number;
  errors: Array<{ messageId: string; error: string }>;
}

export interface IngestionStats {
  totalScanned: number;
  highRiskCount: number;
  suspiciousCount: number;
  safeCount: number;
  lastScanTimestamp: string | null;
  isMonitoring: boolean;
}

// ─── Base64 URL Decoding ────────────────────────────────────────────────────

function decodeBase64Url(str: string): string {
  try {
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    return decodeURIComponent(escape(atob(base64)));
  } catch {
    try {
      const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
      return atob(base64);
    } catch {
      return '';
    }
  }
}

// ─── Extract Body Text from Gmail Payload ───────────────────────────────────

export function extractGmailBodyText(payload: any, fallbackSnippet?: string): string {
  if (!payload) return fallbackSnippet || '';

  if (payload.body?.data) {
    const decoded = decodeBase64Url(payload.body.data);
    if (decoded) return decoded;
  }

  const findTextInParts = (parts: any[]): string => {
    if (!Array.isArray(parts)) return '';
    // Prefer text/plain
    for (const part of parts) {
      if (part.mimeType === 'text/plain' && part.body?.data) {
        const decoded = decodeBase64Url(part.body.data);
        if (decoded) return decoded;
      }
      if (part.parts) {
        const nested = findTextInParts(part.parts);
        if (nested) return nested;
      }
    }
    // Fallback to text/html
    for (const part of parts) {
      if (part.mimeType === 'text/html' && part.body?.data) {
        const decoded = decodeBase64Url(part.body.data);
        if (decoded) return decoded;
      }
    }
    return '';
  };

  const extracted = payload.parts ? findTextInParts(payload.parts) : '';
  return extracted || fallbackSnippet || '';
}

// ─── Parse Sender Name + Email ──────────────────────────────────────────────

export function parseSender(senderRaw: string): { name: string; email: string } {
  if (!senderRaw) return { name: 'Unknown Sender', email: '' };
  const nameMatch = senderRaw.match(/^"?([^"<]+)"?\s*<.*>$/);
  const emailMatch = senderRaw.match(/<([^>]+)>/);
  const email = emailMatch ? emailMatch[1] : (senderRaw.includes('@') ? senderRaw.trim() : '');
  const name = nameMatch && nameMatch[1].trim() ? nameMatch[1].trim() : (email || senderRaw);
  return { name, email };
}

// ─── Fetch Gmail Messages ───────────────────────────────────────────────────

export async function fetchGmailMessageList(
  token: string,
  pageToken?: string,
  maxResults: number = 30
): Promise<{ messages: GmailRawMessage[]; nextPageToken: string | null }> {
  const url = pageToken
    ? `https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=${maxResults}&pageToken=${encodeURIComponent(pageToken)}`
    : `https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=${maxResults}`;

  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const data = await response.json();

  if (!response.ok) {
    const errorMsg = data?.error?.message || JSON.stringify(data);
    if (
      response.status === 401 ||
      data?.error?.status === 'UNAUTHENTICATED' ||
      errorMsg.includes('invalid authentication credentials') ||
      errorMsg.includes('OAuth 2')
    ) {
      invalidateToken();
      const authErr = new Error('Your Google session has expired. Please click "Reconnect Gmail" to refresh authentication.');
      (authErr as any).isAuthExpired = true;
      throw authErr;
    }
    throw new Error(errorMsg);
  }

  return {
    messages: data.messages || [],
    nextPageToken: data.nextPageToken || null
  };
}

// ─── Fetch Single Gmail Message Detail ──────────────────────────────────────

export async function fetchGmailMessageDetail(
  token: string,
  messageId: string
): Promise<GmailMessageDetail> {
  const cleanId = encodeURIComponent(messageId.trim());

  const requestWithRetry = async (format: 'full' | 'metadata') => {
    let retries = 2;
    let delay = 500;
    while (retries >= 0) {
      try {
        const res = await fetch(
          `https://gmail.googleapis.com/gmail/v1/users/me/messages/${cleanId}?format=${format}`,
          { headers: { Authorization: `Bearer ${token}` } }
        );
        if ((res.status === 429 || res.status >= 500) && retries > 0) {
          await new Promise(r => setTimeout(r, delay));
          delay *= 2;
          retries--;
          continue;
        }
        return res;
      } catch (err) {
        if (retries > 0) {
          await new Promise(r => setTimeout(r, delay));
          delay *= 2;
          retries--;
          continue;
        }
        throw err;
      }
    }
    throw new Error(`Failed to fetch message ${messageId}`);
  };

  // 1. Attempt format=full first
  let response = await requestWithRetry('full');

  // 2. If 403 Forbidden (e.g. metadata-only scope) or 400 Bad Request, fall back gracefully to format=metadata
  if (!response.ok && (response.status === 403 || response.status === 400)) {
    console.warn(`[Gmail] format=full returned ${response.status} for ${messageId}, falling back to format=metadata`);
    response = await requestWithRetry('metadata');
  }

  const detail = await response.json();
  if (!response.ok) {
    const errorMsg = detail?.error?.message || `Gmail fetch error (${response.status})`;
    if (
      response.status === 401 ||
      detail?.error?.status === 'UNAUTHENTICATED' ||
      errorMsg.includes('invalid authentication credentials') ||
      errorMsg.includes('OAuth 2')
    ) {
      invalidateToken();
      const authErr = new Error('Your Google session has expired. Please click "Reconnect Gmail" to refresh authentication.');
      (authErr as any).isAuthExpired = true;
      throw authErr;
    }
    throw new Error(errorMsg);
  }

  return detail;
}

// ─── Convert Gmail Message to InboxEmailItem ────────────────────────────────

export function gmailMessageToInboxItem(
  detail: GmailMessageDetail,
  dossier?: ForensicDossier
): InboxEmailItem {
  const headers = detail.payload?.headers || [];
  const subject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || 'No Subject';
  const senderRaw = headers.find(h => h.name?.toLowerCase() === 'from')?.value || 'Unknown Sender';
  const dateStr = headers.find(h => h.name?.toLowerCase() === 'date')?.value ||
    (detail.internalDate ? new Date(Number(detail.internalDate)).toISOString() : '');
  const rawHeaderArr = headers.map(h => `${h.name}: ${h.value}`).join('\n');
  const body = extractGmailBodyText(detail.payload, detail.snippet || '');
  const { name, email } = parseSender(senderRaw);

  const score = dossier?.classification?.riskScore ?? 0;
  const isVerified = score <= 30 &&
    dossier?.authentication?.spf?.status === 'PASS' &&
    dossier?.authentication?.dkim?.status === 'PASS';

  const riskCategory: 'HIGH RISK' | 'SUSPICIOUS' | 'LOW RISK' =
    score >= 71 ? 'HIGH RISK' : score >= 31 ? 'SUSPICIOUS' : 'LOW RISK';

  // Generate tags from dossier signals
  const tags: InboxEmailItem['tags'] = [];
  if (dossier) {
    const signals = dossier.contentAnalysis?.signals || [];
    const authFail = dossier.authentication?.spf?.status === 'FAIL' ||
      dossier.authentication?.dkim?.status === 'FAIL' ||
      dossier.authentication?.dmarc?.status === 'FAIL';

    if (authFail) {
      tags.push({ text: '🚫 Auth Failure', type: 'red' });
    }
    if (score >= 71) {
      const threatType = dossier.classification?.threatType || 'High Risk';
      tags.push({ text: threatType, type: 'red' });
    }
    if (signals.some(s => s.description?.toLowerCase().includes('urgency') || s.description?.toLowerCase().includes('urgent'))) {
      tags.push({ text: 'Urgency', type: 'red' });
    }
    if (signals.some(s => s.description?.toLowerCase().includes('impersonation'))) {
      tags.push({ text: 'Impersonation', type: 'amber' });
    }
    if (score >= 31 && score < 71 && tags.length === 0) {
      tags.push({ text: '⚠️ Suspicious', type: 'amber' });
    }
    if (score <= 30) {
      if (isVerified) {
        tags.push({ text: '✓ Verified Sender', type: 'emerald' });
      }
      tags.push({ text: 'No Threats Detected', type: 'emerald' });
    }
  }

  // Format time string
  let timeString = dateStr;
  if (dateStr) {
    try {
      const d = new Date(dateStr);
      if (!isNaN(d.getTime())) {
        const now = new Date();
        const diffMs = now.getTime() - d.getTime();
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        if (diffDays === 0) {
          timeString = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        } else if (diffDays === 1) {
          timeString = 'Yesterday ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        } else if (diffDays < 7) {
          timeString = `${diffDays} days ago`;
        } else {
          timeString = d.toLocaleDateString();
        }
      }
    } catch {
      // Keep raw dateStr
    }
  }

  return {
    id: detail.id,
    senderName: name,
    senderEmail: email,
    isVerified,
    avatarLetter: (name.trim().charAt(0) || '?').toUpperCase(),
    subject,
    snippet: (detail.snippet || body.substring(0, 120)).replace(/\s+/g, ' ').trim(),
    timeString,
    score,
    riskCategory,
    tags,
    rawHeaders: rawHeaderArr,
    body: body || detail.snippet || '',
    dossier,
    analyzedAt: new Date().toISOString()
  };
}

async function analyzeInboxMessage(detail: GmailMessageDetail): Promise<InboxEmailItem> {
  const headers = detail.payload?.headers || [];
  const rawHeaders = headers.map(h => `${h.name}: ${h.value}`).join('\n');
  const from = headers.find(h => h.name.toLowerCase() === 'from')?.value || '';
  const subject = headers.find(h => h.name.toLowerCase() === 'subject')?.value || 'No Subject';
  const content = extractGmailBodyText(detail.payload, detail.snippet || '');
  const sender = parseSender(from);

  const effectiveContent = (content && content.trim()) || detail.snippet || subject || '(No message content)';
  const effectivePayload = (rawHeaders && rawHeaders.trim()) || `From: ${from}\nSubject: ${subject}`;

  const response = await fetch('/api/neuroshield/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      id: detail.id,
      source: 'email',
      content: effectiveContent,
      rawPayload: effectivePayload,
      sender: { identifier: sender.email || 'unknown@domain.local', displayName: sender.name || 'Unknown' },
      subject,
      metadata: { client: 'gmail_api' }
    }),
    signal: AbortSignal.timeout(30000),
  });

  if (!response.ok) {
    throw new Error(`Backend analysis failed (${response.status}); message remains unverified.`);
  }

  const analysis = await response.json();
  const item = gmailMessageToInboxItem(detail, analysis.forensics);
  item.score = analysis.risk_score ?? analysis.score ?? 0;
  item.riskCategory = (item.score >= 71 || analysis.verdict === 'MALICIOUS')
    ? 'HIGH RISK'
    : (item.score >= 35 || analysis.verdict === 'SUSPICIOUS')
      ? 'SUSPICIOUS'
      : 'LOW RISK';
  item.isVerified = analysis.verdict === 'SAFE' && (analysis.confidence ?? 0) >= 70;
  if (analysis.verdict === 'UNKNOWN' && item.tags.length === 0) {
    item.tags.push({ text: 'Unverified', type: 'amber' });
  }
  return item;
}

// ─── Full Ingestion Pipeline ────────────────────────────────────────────────

export async function ingestGmailEmails(
  token: string,
  pageToken?: string,
  maxResults: number = 30
): Promise<IngestionResult> {
  const errors: Array<{ messageId: string; error: string }> = [];

  // 1. Fetch message list
  const { messages, nextPageToken } = await fetchGmailMessageList(token, pageToken, maxResults);

  if (messages.length === 0) {
    return {
      emails: [],
      nextPageToken: null,
      totalFetched: 0,
      totalAnalyzed: 0,
      errors: []
    };
  }

  // 2. Fetch details and analyze with concurrency control (batches of 4) to avoid rate limits
  const CONCURRENCY = 4;
  const analyzedEmails: InboxEmailItem[] = [];

  for (let i = 0; i < messages.length; i += CONCURRENCY) {
    const chunk = messages.slice(i, i + CONCURRENCY);
    const chunkResults = await Promise.all(
      chunk.map(async (msg) => {
        let detail: GmailMessageDetail | null = null;
        try {
          detail = await fetchGmailMessageDetail(token, msg.id);
        } catch (fetchErr: any) {
          console.warn('[Ingestion] Fetch error for', msg.id, fetchErr?.message);
          errors.push({ messageId: msg.id, error: fetchErr?.message || 'Fetch failed' });
        }

        if (detail) {
          try {
            return await analyzeInboxMessage(detail);
          } catch (analysisErr: any) {
            console.warn('[Ingestion] Analysis skipped for', msg.id, analysisErr?.message);
            // CRITICAL: Preserve real email headers, sender, subject, and snippet!
            const fallbackItem = gmailMessageToInboxItem(detail);
            fallbackItem.score = 20; // Default benign baseline
            fallbackItem.riskCategory = 'LOW RISK';
            fallbackItem.tags = [{ text: 'Analysis Pending', type: 'amber' }];
            return fallbackItem;
          }
        }

        // Only when message detail completely fails to fetch from Gmail API
        return {
          id: msg.id,
          senderName: 'Unknown Sender',
          senderEmail: '',
          avatarLetter: '?',
          subject: '(Message details unavailable)',
          snippet: '',
          timeString: '',
          score: 50,
          riskCategory: 'SUSPICIOUS' as const,
          tags: [{ text: 'Unverified / analysis unavailable', type: 'amber' as const }],
          rawHeaders: '',
          body: '',
          analyzedAt: new Date().toISOString()
        };
      })
    );
    analyzedEmails.push(...chunkResults);
  }

  return {
    emails: analyzedEmails,
    nextPageToken,
    totalFetched: messages.length,
    totalAnalyzed: analyzedEmails.filter(e => e.subject !== '(Message details unavailable)').length,
    errors
  };
}


// ─── Background Polling ─────────────────────────────────────────────────────

export class EmailPollingController {
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private knownMessageIds = new Set<string>();
  private isRunning = false;

  constructor(
    private token: string,
    private onNewEmails: (emails: InboxEmailItem[]) => void,
    private onError: (error: string) => void,
    private intervalMs: number = 5 * 60 * 1000 // 5 minutes default
  ) {}

  start(existingIds?: string[]) {
    if (this.isRunning) return;
    this.isRunning = true;

    // Seed known IDs from already-loaded emails
    if (existingIds) {
      existingIds.forEach(id => this.knownMessageIds.add(id));
    }

    this.intervalId = setInterval(() => this.poll(), this.intervalMs);
  }

  stop() {
    this.isRunning = false;
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  updateToken(newToken: string) {
    this.token = newToken;
  }

  getNextPollTimestamp(): number {
    // Returns approximate next poll time for countdown UI
    return Date.now() + this.intervalMs;
  }

  private async poll() {
    if (!this.isRunning) return;

    try {
      // Only fetch the latest 10 messages to check for new ones
      const { messages } = await fetchGmailMessageList(this.token, undefined, 10);
      const newMessageIds = messages
        .map(m => m.id)
        .filter(id => !this.knownMessageIds.has(id));

      if (newMessageIds.length === 0) return;

      // Fetch and analyze only new messages
      const newEmails: InboxEmailItem[] = [];
      for (const msgId of newMessageIds) {
        try {
          const detail = await fetchGmailMessageDetail(this.token, msgId);
          const item = await analyzeInboxMessage(detail);
          newEmails.push(item);
          this.knownMessageIds.add(msgId);
        } catch {
          // Skip failed messages
        }
      }

      if (newEmails.length > 0) {
        this.onNewEmails(newEmails);
      }
    } catch (err: any) {
      this.onError(err?.message || 'Polling failed');
    }
  }
}

// ─── Compute Ingestion Stats ────────────────────────────────────────────────

export function computeIngestionStats(
  emails: InboxEmailItem[],
  isMonitoring: boolean,
  lastScan: string | null
): IngestionStats {
  return {
    totalScanned: emails.length,
    highRiskCount: emails.filter(e => e.score >= 71).length,
    suspiciousCount: emails.filter(e => e.score >= 31 && e.score < 71).length,
    safeCount: emails.filter(e => e.score <= 30).length,
    lastScanTimestamp: lastScan,
    isMonitoring
  };
}
