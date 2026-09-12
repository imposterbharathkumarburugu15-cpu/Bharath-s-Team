/**
 * NeuroShield Gmail Ingestion Service
 * Centralized Gmail API interaction, email analysis orchestration, and background polling.
 * Extracted from EmailPhishing.tsx inline logic to enable auto-ingestion architecture.
 */

import { executeEmailForensics, ForensicDossier } from './forensicsEngine';
import { InboxEmailItem } from '@/data/inboxEmails';

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
    throw new Error(data?.error?.message || JSON.stringify(data));
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
  const response = await fetch(
    `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=full`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  const detail = await response.json();

  if (!response.ok) {
    throw new Error(detail?.error?.message || JSON.stringify(detail));
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
  const dateStr = headers.find(h => h.name?.toLowerCase() === 'date')?.value || '';
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
      tags.push({ text: '\u{1f6ab} Auth Failure', type: 'red' });
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
      tags.push({ text: '\u26a0\ufe0f Suspicious', type: 'amber' });
    }
    if (score <= 30) {
      if (isVerified) {
        tags.push({ text: '\u2713 Verified Sender', type: 'emerald' });
      }
      tags.push({ text: 'No Threats Detected', type: 'emerald' });
    }
  }

  // Format time string
  let timeString = dateStr;
  if (dateStr) {
    try {
      const d = new Date(dateStr);
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
    } catch {
      // Keep raw dateStr
    }
  }

  return {
    id: detail.id,
    senderName: name,
    senderEmail: email,
    isVerified,
    avatarLetter: name.charAt(0).toUpperCase(),
    subject,
    snippet: (detail.snippet || body.substring(0, 120)).replace(/\s+/g, ' ').trim(),
    timeString,
    score,
    riskCategory,
    tags,
    rawHeaders: rawHeaderArr,
    body,
    dossier,
    analyzedAt: new Date().toISOString()
  };
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

  // 2. Fetch details + analyze each email
  const analyzedEmails: InboxEmailItem[] = await Promise.all(
    messages.map(async (msg) => {
      try {
        const detail = await fetchGmailMessageDetail(token, msg.id);
        const headers = detail.payload?.headers || [];
        const rawHeaderArr = headers.map(h => `${h.name}: ${h.value}`).join('\n');
        const body = extractGmailBodyText(detail.payload, detail.snippet || '');

        // Run NeuroShield forensic analysis
        let dossier: ForensicDossier | undefined;
        try {
          dossier = await executeEmailForensics(rawHeaderArr, body);
        } catch (analysisErr: any) {
          console.warn('[Ingestion] Analysis warning for', msg.id, analysisErr?.message);
          errors.push({ messageId: msg.id, error: analysisErr?.message || 'Analysis failed' });
        }

        return gmailMessageToInboxItem(detail, dossier);
      } catch (fetchErr: any) {
        console.warn('[Ingestion] Fetch error for', msg.id, fetchErr?.message);
        errors.push({ messageId: msg.id, error: fetchErr?.message || 'Fetch failed' });
        return {
          id: msg.id,
          senderName: 'Unknown Sender',
          senderEmail: '',
          avatarLetter: '?',
          subject: '(Message details unavailable)',
          snippet: '',
          timeString: '',
          score: 0,
          riskCategory: 'LOW RISK' as const,
          tags: [],
          rawHeaders: '',
          body: '',
          analyzedAt: new Date().toISOString()
        };
      }
    })
  );

  return {
    emails: analyzedEmails,
    nextPageToken,
    totalFetched: messages.length,
    totalAnalyzed: messages.length - errors.length,
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
          const headers = detail.payload?.headers || [];
          const rawHeaderArr = headers.map(h => `${h.name}: ${h.value}`).join('\n');
          const body = extractGmailBodyText(detail.payload, detail.snippet || '');

          let dossier: ForensicDossier | undefined;
          try {
            dossier = await executeEmailForensics(rawHeaderArr, body);
          } catch {
            // Continue without dossier
          }

          const item = gmailMessageToInboxItem(detail, dossier);
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
