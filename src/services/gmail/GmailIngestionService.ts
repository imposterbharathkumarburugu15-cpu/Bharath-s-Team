/**
 * NeuroShield Gmail Ingestion Service
 * Orchestrates automatic email ingestion from the Gmail API, normalizes raw
 * messages into NormalizedEmail, feeds into NeuroShield Core, and manages background polling & push events.
 */

import { GmailConnector, GmailMessageResource } from './GmailConnector';
import { NormalizedEmail, UnifiedEmailAnalysisResult } from '../core/types';
import { EmailAdapter } from '../core/adapters/EmailAdapter';
import { NeuroShieldCore } from '../core/neuroshieldCore';
import { EnforcementEngine } from '../core/enforcementEngine';
import { repository } from '../../db/repository';

export interface IngestBatchResult {
  analyzedIncidents: UnifiedEmailAnalysisResult[];
  totalFetched: number;
  totalAnalyzed: number;
  nextPageToken?: string;
  errors: Array<{ messageId: string; error: string }>;
}

export class GmailIngestionService {
  private static pollingInterval: NodeJS.Timeout | null = null;
  private static knownMessageIds = new Set<string>();
  private static lastKnownHistoryId: string | null = null;

  private static analyzedIncidentsCache = new Map<string, UnifiedEmailAnalysisResult>();

  /**
   * Translates a Gmail REST API message resource into our canonical NormalizedEmail contract.
   */
  public static gmailResourceToNormalizedEmail(msg: GmailMessageResource): NormalizedEmail {
    const headers = msg.payload?.headers || [];
    const headerMap: Record<string, string | string[]> = {};
    for (const h of headers) {
      if (h.name) {
        const key = h.name.toLowerCase();
        if (headerMap[key]) {
          if (Array.isArray(headerMap[key])) {
            (headerMap[key] as string[]).push(h.value);
          } else {
            headerMap[key] = [headerMap[key] as string, h.value];
          }
        } else {
          headerMap[key] = h.value;
        }
      }
    }

    const fromVal = (headerMap['from'] as string) || 'Unknown Sender';
    const toVal = (headerMap['to'] as string) || '';
    const subject = (headerMap['subject'] as string) || 'No Subject';
    const dateVal = (headerMap['date'] as string) || (msg.internalDate ? new Date(Number(msg.internalDate)).toISOString() : new Date().toISOString());
    const replyToVal = (headerMap['reply-to'] as string) || undefined;

    // Body extraction
    const { text, html } = this.extractBodyContent(msg);

    // Attachments extraction
    const attachments = this.extractAttachments(msg);

    // Raw headers string reconstruction for deep forensic analysis if needed
    const rawHeaders = headers.map((h) => `${h.name}: ${h.value}`).join('\n');

    return EmailAdapter.toNormalizedEmail({
      id: msg.id,
      threadId: msg.threadId,
      date: dateVal,
      from: fromVal,
      to: toVal,
      replyTo: replyToVal,
      subject,
      body: {
        text,
        html,
        snippet: msg.snippet || text.substring(0, 160).replace(/\s+/g, ' ').trim(),
      },
      headers: headerMap,
      attachments,
      metadata: {
        rawHeaders,
        labelIds: msg.labelIds,
        historyId: msg.historyId,
      },
    });
  }

  /**
   * Ingests a batch of recent messages from Gmail, normalizes, analyzes, and persists incidents.
   */
  public static async ingestRecentMessages(
    accessToken: string,
    maxResults = 25,
    pageToken?: string
  ): Promise<IngestBatchResult> {
    const listRes = await GmailConnector.listMessages(accessToken, { maxResults, pageToken });
    const messageRefs = listRes.messages || [];

    if (messageRefs.length === 0) {
      return {
        analyzedIncidents: [],
        totalFetched: 0,
        totalAnalyzed: 0,
        nextPageToken: undefined,
        errors: [],
      };
    }

    const errors: Array<{ messageId: string; error: string }> = [];
    const analyzedIncidents: UnifiedEmailAnalysisResult[] = [];

    await Promise.all(
      messageRefs.map(async (ref) => {
        try {
          const analysis = await this.ingestSingleMessage(accessToken, ref.id, false);
          analyzedIncidents.push(analysis);
        } catch (err: any) {
          errors.push({ messageId: ref.id, error: err?.message || 'Ingestion failed' });
        }
      })
    );

    return {
      analyzedIncidents,
      totalFetched: messageRefs.length,
      totalAnalyzed: analyzedIncidents.length,
      nextPageToken: listRes.nextPageToken,
      errors,
    };
  }

  /**
   * Ingests and analyzes a single specific Gmail message by ID.
   * Includes duplicate event deduplication and optional thread history sequence analysis.
   */
  public static async ingestSingleMessage(
    accessToken: string,
    messageId: string,
    useThreadHistory = true
  ): Promise<UnifiedEmailAnalysisResult> {
    // Deduplication check: do not recreate duplicate incidents for the same message
    if (this.analyzedIncidentsCache.has(messageId)) {
      return this.analyzedIncidentsCache.get(messageId)!;
    }

    const detail = await GmailConnector.getMessage(accessToken, messageId, 'full');
    const normalized = this.gmailResourceToNormalizedEmail(detail);

    let analysis: UnifiedEmailAnalysisResult;

    // Check for real thread history if available and requested
    if (useThreadHistory && detail.threadId) {
      try {
        const threadData = await GmailConnector.getThread(accessToken, detail.threadId, 'full');
        const threadMessages = threadData.messages || [];

        if (threadMessages.length > 1) {
          // Sort messages chronologically
          threadMessages.sort((a, b) => Number(a.internalDate || 0) - Number(b.internalDate || 0));

          // Convert each message to UnifiedInteractionEvent
          const sequence = threadMessages.map((m) => {
            const norm = this.gmailResourceToNormalizedEmail(m);
            return EmailAdapter.toUnifiedInput(norm);
          });

          // Execute multi-stage sequence attack transition analysis
          const seqAnalysis = await NeuroShieldCore.analyzeSequence(sequence);

          const authDecision = EnforcementEngine.evaluatePolicy({
            incidentId: seqAnalysis.incident_id,
            verdict: seqAnalysis.verdict,
            riskScore: seqAnalysis.risk_score,
            confidence: seqAnalysis.confidence,
            coverage: seqAnalysis.analysis_coverage,
            requestedAction: seqAnalysis.action_risk?.detectedAction || 'UNKNOWN',
            threatTypes: seqAnalysis.attack_types,
            sensitiveData: seqAnalysis.sensitive_data,
            technical: seqAnalysis.technical_evidence,
            evidence: seqAnalysis.evidence_provenance || seqAnalysis.evidence || [],
            client: 'gmail_api',
            clientCapabilities: { canBlockNavigation: false, canBlockFormSubmit: false },
          });

          analysis = {
            incidentId: seqAnalysis.incident_id,
            verdict: seqAnalysis.verdict,
            riskScore: seqAnalysis.risk_score,
            confidence: seqAnalysis.confidence,
            analysisCoverage: seqAnalysis.analysis_coverage,
            threatTypes: seqAnalysis.attack_types,
            identity: seqAnalysis.identity,
            context: seqAnalysis.relationship,
            behaviour: seqAnalysis.behaviour,
            intent: seqAnalysis.intent,
            sensitiveData: seqAnalysis.sensitive_data,
            actionRisk: seqAnalysis.action_risk,
            technicalEvidence: seqAnalysis.technical_evidence,
            adversarialEvidence: seqAnalysis.evasion || {
              status: 'available',
              detected: false,
              evasionRiskScore: 0,
              techniques: [],
              homoglyphsDetected: false,
              punycodeDetected: false,
              urlObfuscationDetected: false,
              redirectChainDetected: false,
              htmlObfuscationDetected: false,
              hiddenLinksDetected: false,
              mixedScriptDetected: false,
              evidence: [],
            },
            attackSequence: seqAnalysis.attack_sequence,
            protectionDecision: (seqAnalysis.protection.protectionDecision as any) || seqAnalysis.protection.decision,
            enforcementLevel: authDecision.enforcementLevel,
            enforcementStatus: authDecision.enforcementStatus,
            authoritativeProtectionDecision: authDecision,
            blockedAction: authDecision.protectionDecision.startsWith('BLOCK') ? authDecision.requestedAction : null,
            client: 'gmail_api',
            evidence: seqAnalysis.evidence_provenance || seqAnalysis.evidence || [],
            normalizedEmail: normalized,
            summary: seqAnalysis.recommended_action?.summary,
            whyRiskIncreased: seqAnalysis.whyRiskIncreased,
            recommendedAction: seqAnalysis.recommended_action,
            timestamp: seqAnalysis.timestamp,
          };
        } else {
          analysis = await NeuroShieldCore.analyzeEmail(normalized);
        }
      } catch (threadErr) {
        console.warn(`[GmailIngestion] Thread retrieval failed for ${detail.threadId}, falling back to single event:`, threadErr);
        analysis = await NeuroShieldCore.analyzeEmail(normalized);
      }
    } else {
      analysis = await NeuroShieldCore.analyzeEmail(normalized);
    }

    this.knownMessageIds.add(messageId);
    this.analyzedIncidentsCache.set(messageId, analysis);

    // Persist incident (sanitized, no raw sensitive content)
    await this.persistIncident(analysis);

    return analysis;
  }

  /**
   * Persists an analyzed email incident in the repository without storing raw sensitive content.
   */
  public static async persistIncident(analysis: UnifiedEmailAnalysisResult): Promise<string> {
    return repository.saveIncident({
      incident_id: analysis.incidentId,
      source: 'email',
      verdict: analysis.verdict,
      risk_level: analysis.verdict === 'MALICIOUS' ? 'CRITICAL' : analysis.verdict === 'SUSPICIOUS' ? 'MEDIUM' : 'SAFE',
      risk_score: analysis.riskScore,
      confidence: analysis.confidence,
      attack_types: analysis.threatTypes,
      content_risk: { level: analysis.actionRisk.actionRisk, score: analysis.riskScore, indicators: [] },
      action_risk: {
        ...analysis.actionRisk,
        detected_action: analysis.actionRisk.detectedAction,
        level: analysis.actionRisk.actionRisk,
        score: analysis.riskScore,
        target_destination: analysis.actionRisk.targetDestination || null,
      },
      combined_risk: { level: analysis.actionRisk.actionRisk, score: analysis.riskScore },
      identity: analysis.identity,
      relationship: analysis.context,
      behaviour: analysis.behaviour,
      intent: analysis.intent,
      action: analysis.actionRisk,
      technical_evidence: analysis.technicalEvidence,
      prompt_injection: { status: 'available', detected: false, overrideTokens: [], adversarialRiskScore: 0, evidence: [] },
      sensitive_data: analysis.sensitiveData,
      attack_sequence: analysis.attackSequence,
      evidence: analysis.evidence,
      conflicts: [],
      analysis_coverage: analysis.analysisCoverage,
      protection: {
        decision: analysis.protectionDecision,
        recommended_action: analysis.summary || 'Protection applied',
        steps: analysis.recommendedAction?.steps || [],
        interventions: analysis.recommendedAction?.interventions || [],
        circuit_breakers: analysis.recommendedAction?.circuitBreakers || [],
      },
      feature_vector: {
        identity_risk: analysis.identity.riskScore || 0,
        relationship_risk: analysis.context.riskScore || 0,
        behaviour_risk: analysis.behaviour.riskScore || 0,
        intent_risk: analysis.intent.intentConfidence || 0,
        action_risk: analysis.riskScore,
        content_risk: analysis.riskScore,
        technical_risk: analysis.technicalEvidence.riskScore || 0,
        url_risk: 0,
        prompt_injection_risk: 0,
        sensitive_data_risk: analysis.sensitiveData.riskScore || 0,
        sequence_risk: analysis.attackSequence.compoundSequenceRisk || 0,
        evidence_count: analysis.evidence.length,
        analysis_coverage: analysis.analysisCoverage.coverageRatio,
      },
      threats: analysis.threatTypes,
      recommended_action: analysis.recommendedAction || {
        action: (analysis.protectionDecision === 'STRONG_WARN' ? 'WARN' : analysis.protectionDecision) as 'ALLOW' | 'WARN' | 'BLOCK' | 'GUIDE',
        summary: analysis.summary || '',
        steps: [],
        interventions: [],
        circuitBreakers: [],
      },
      timestamp: analysis.timestamp,
      evaluationTimeMs: 12,
    });
  }

  /**
   * Handles real-time Google Cloud Pub/Sub push notification.
   * Decodes Pub/Sub data, extracts the email address and historyId, and syncs new messages.
   */
  public static async handlePushNotification(
    accessToken: string,
    pubSubMessage: { data?: string; messageId?: string; publishTime?: string }
  ): Promise<{ processed: number; newHistoryId?: string }> {
    if (!pubSubMessage?.data) {
      throw new Error('Invalid Pub/Sub push notification: missing message.data');
    }

    // PubSub data is base64 encoded JSON: { "emailAddress": "...", "historyId": "12345" }
    const decodedStr = Buffer.from(pubSubMessage.data, 'base64').toString('utf-8');
    const payload = JSON.parse(decodedStr);
    const incomingHistoryId = payload.historyId;

    if (!incomingHistoryId) {
      return { processed: 0 };
    }

    if (!this.lastKnownHistoryId) {
      this.lastKnownHistoryId = incomingHistoryId;
      // Fetch latest 10 messages
      const batch = await this.ingestRecentMessages(accessToken, 10);
      return { processed: batch.totalAnalyzed, newHistoryId: incomingHistoryId };
    }

    // Synchronize history
    const historyRes = await GmailConnector.getHistory(accessToken, this.lastKnownHistoryId);
    this.lastKnownHistoryId = incomingHistoryId;

    const newMessageIds: string[] = [];
    if (historyRes.history) {
      for (const record of historyRes.history) {
        if (record.messagesAdded) {
          for (const item of record.messagesAdded) {
            if (item.message?.id && !this.knownMessageIds.has(item.message.id)) {
              newMessageIds.push(item.message.id);
            }
          }
        }
      }
    }

    // Analyze new messages
    let processed = 0;
    for (const msgId of newMessageIds) {
      try {
        await this.ingestSingleMessage(accessToken, msgId);
        processed++;
      } catch (err) {
        console.warn(`[GmailIngestion] Push notification failed to ingest msg ${msgId}:`, err);
      }
    }

    return { processed, newHistoryId: incomingHistoryId };
  }

  /**
   * Starts background polling controller for environments without Pub/Sub push webhooks.
   */
  public static startPolling(
    accessToken: string,
    onNewIncidents: (incidents: UnifiedEmailAnalysisResult[]) => void,
    intervalMs = 3 * 60 * 1000 // 3 minutes default
  ) {
    if (this.pollingInterval) return;

    this.pollingInterval = setInterval(async () => {
      try {
        const list = await GmailConnector.listMessages(accessToken, { maxResults: 10 });
        const unseenRefs = (list.messages || []).filter((m) => !this.knownMessageIds.has(m.id));

        if (unseenRefs.length > 0) {
          const newIncidents: UnifiedEmailAnalysisResult[] = [];
          for (const ref of unseenRefs) {
            try {
              const res = await this.ingestSingleMessage(accessToken, ref.id);
              newIncidents.push(res);
            } catch (err) {
              console.warn(`[GmailIngestion] Polling failed to ingest ${ref.id}:`, err);
            }
          }
          if (newIncidents.length > 0) {
            onNewIncidents(newIncidents);
          }
        }
      } catch (err) {
        console.warn('[GmailIngestion] Polling iteration error:', err);
      }
    }, intervalMs);
  }

  /**
   * Stops active background polling.
   */
  public static stopPolling() {
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
      this.pollingInterval = null;
    }
  }

  /**
   * Helper to decode Base64Url string to UTF-8.
   */
  private static decodeBase64Url(str?: string): string {
    if (!str) return '';
    try {
      return Buffer.from(str, 'base64url').toString('utf-8');
    } catch {
      try {
        const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        return Buffer.from(base64, 'base64').toString('utf-8');
      } catch {
        return '';
      }
    }
  }

  /**
   * Recursively extracts plain text and HTML from multipart Gmail message payload.
   */
  private static extractBodyContent(msg: GmailMessageResource): { text: string; html?: string } {
    let plainText = '';
    let htmlText = '';

    // Direct body data
    if (msg.payload?.body?.data) {
      const decoded = this.decodeBase64Url(msg.payload.body.data);
      if (msg.payload.mimeType === 'text/html') htmlText = decoded;
      else plainText = decoded;
    }

    // Traverse parts
    const traverseParts = (parts?: any[]) => {
      if (!Array.isArray(parts)) return;
      for (const part of parts) {
        if (part.mimeType === 'text/plain' && part.body?.data && !plainText) {
          plainText = this.decodeBase64Url(part.body.data);
        } else if (part.mimeType === 'text/html' && part.body?.data && !htmlText) {
          htmlText = this.decodeBase64Url(part.body.data);
        }
        if (part.parts) {
          traverseParts(part.parts);
        }
      }
    };

    if (msg.payload?.parts) {
      traverseParts(msg.payload.parts);
    }

    return {
      text: plainText || msg.snippet || '',
      html: htmlText || undefined,
    };
  }

  /**
   * Extracts attachment descriptors from message payload.
   */
  private static extractAttachments(msg: GmailMessageResource): NormalizedEmail['attachments'] {
    const attachments: NormalizedEmail['attachments'] = [];

    const traverseParts = (parts?: any[]) => {
      if (!Array.isArray(parts)) return;
      for (const part of parts) {
        if (part.filename && part.filename.trim().length > 0) {
          attachments.push({
            filename: part.filename,
            mimeType: part.mimeType || 'application/octet-stream',
            sizeBytes: part.body?.size,
            isExecutable: /\.(exe|scr|bat|cmd|vbs|js|ps1|iso|img|hta|jar|msi)$/i.test(part.filename),
          });
        }
        if (part.parts) {
          traverseParts(part.parts);
        }
      }
    };

    if (msg.payload?.parts) {
      traverseParts(msg.payload.parts);
    }

    return attachments;
  }
}
