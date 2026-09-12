/**
 * NeuroShield Gmail Connector
 * Direct interface with the official Google Gmail REST API v1.
 * Provides resilient message retrieval, batching, pagination, history sync, and Pub/Sub push subscriptions.
 */

export interface GmailListOptions {
  maxResults?: number;
  pageToken?: string;
  q?: string;
  labelIds?: string[];
  includeSpamTrash?: boolean;
}

export interface GmailRawMessageHeader {
  name: string;
  value: string;
}

export interface GmailMessagePartBody {
  size?: number;
  data?: string; // base64url encoded
  attachmentId?: string;
}

export interface GmailMessagePart {
  partId?: string;
  mimeType?: string;
  filename?: string;
  headers?: GmailRawMessageHeader[];
  body?: GmailMessagePartBody;
  parts?: GmailMessagePart[];
}

export interface GmailMessagePayload {
  partId?: string;
  mimeType?: string;
  filename?: string;
  headers?: GmailRawMessageHeader[];
  body?: GmailMessagePartBody;
  parts?: GmailMessagePart[];
}

export interface GmailMessageResource {
  id: string;
  threadId: string;
  labelIds?: string[];
  snippet?: string;
  historyId?: string;
  internalDate?: string;
  payload?: GmailMessagePayload;
  raw?: string;
  sizeEstimate?: number;
}

export interface GmailWatchResponse {
  historyId: string;
  expiration: string;
}

export class GmailConnector {
  private static readonly BASE_URL = 'https://gmail.googleapis.com/gmail/v1/users/me';

  /**
   * Retrieves a list of message references matching query filters.
   */
  public static async listMessages(
    accessToken: string,
    options: GmailListOptions = {}
  ): Promise<{ messages: Array<{ id: string; threadId: string }>; nextPageToken?: string; resultSizeEstimate?: number }> {
    const params = new URLSearchParams();
    if (options.maxResults) params.set('maxResults', String(options.maxResults));
    if (options.pageToken) params.set('pageToken', options.pageToken);
    if (options.q) params.set('q', options.q);
    if (options.includeSpamTrash) params.set('includeSpamTrash', 'true');
    if (options.labelIds && options.labelIds.length > 0) {
      options.labelIds.forEach((label) => params.append('labelIds', label));
    }

    const url = `${this.BASE_URL}/messages?${params.toString()}`;
    const response = await this.fetchWithRetry(url, accessToken);

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data?.error?.message || `Gmail listMessages error (${response.status})`);
    }

    return {
      messages: data.messages || [],
      nextPageToken: data.nextPageToken || undefined,
      resultSizeEstimate: data.resultSizeEstimate,
    };
  }

  /**
   * Retrieves full details or raw RFC 5322 payload for a specific message ID.
   */
  public static async getMessage(
    accessToken: string,
    messageId: string,
    format: 'full' | 'raw' | 'metadata' = 'full'
  ): Promise<GmailMessageResource> {
    const url = `${this.BASE_URL}/messages/${encodeURIComponent(messageId)}?format=${format}`;
    const response = await this.fetchWithRetry(url, accessToken);

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data?.error?.message || `Gmail getMessage error for ${messageId} (${response.status})`);
    }

    return data as GmailMessageResource;
  }

  /**
   * Retrieves an entire conversation thread by threadId.
   */
  public static async getThread(
    accessToken: string,
    threadId: string,
    format: 'full' | 'metadata' = 'full'
  ): Promise<{ id: string; historyId: string; messages: GmailMessageResource[] }> {
    const url = `${this.BASE_URL}/threads/${encodeURIComponent(threadId)}?format=${format}`;
    const response = await this.fetchWithRetry(url, accessToken);

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data?.error?.message || `Gmail getThread error for ${threadId} (${response.status})`);
    }

    return data;
  }

  /**
   * Retrieves list of history records for incremental mailbox synchronization.
   */
  public static async getHistory(
    accessToken: string,
    startHistoryId: string,
    maxResults = 50
  ): Promise<{ history?: any[]; historyId?: string; nextPageToken?: string }> {
    const url = `${this.BASE_URL}/history?startHistoryId=${encodeURIComponent(startHistoryId)}&maxResults=${maxResults}`;
    const response = await this.fetchWithRetry(url, accessToken);

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data?.error?.message || `Gmail getHistory error (${response.status})`);
    }

    return data;
  }

  /**
   * Subscribes to real-time push notifications via Google Cloud Pub/Sub.
   * Google Cloud Pub/Sub topic must be granted publish permission to:
   * gmail-api-push@system.gserviceaccount.com
   */
  public static async watch(
    accessToken: string,
    topicName: string,
    labelIds: string[] = ['INBOX']
  ): Promise<GmailWatchResponse> {
    const url = `${this.BASE_URL}/watch`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        topicName,
        labelIds,
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data?.error?.message || `Gmail watch subscription failed (${response.status})`);
    }

    return data as GmailWatchResponse;
  }

  /**
   * Cancels active push notifications subscription for the authenticated user mailbox.
   */
  public static async stopWatch(accessToken: string): Promise<boolean> {
    const url = `${this.BASE_URL}/stop`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    return response.ok;
  }

  /**
   * Helper to perform HTTP requests with automatic backoff for rate limits (HTTP 429 / 503).
   */
  private static async fetchWithRetry(
    url: string,
    accessToken: string,
    maxRetries = 2
  ): Promise<Response> {
    let attempts = 0;
    let delay = 1000;

    while (attempts <= maxRetries) {
      attempts++;
      const response = await fetch(url, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Accept-Encoding': 'gzip, deflate',
        },
      });

      if (response.status === 401) {
        throw new Error('Gmail API 401: Access token has expired or is invalid. Re-authentication required.');
      }

      if ((response.status === 429 || response.status >= 500) && attempts <= maxRetries) {
        console.warn(`[GmailConnector] Backoff on ${response.status} retry ${attempts}/${maxRetries} after ${delay}ms`);
        await new Promise((resolve) => setTimeout(resolve, delay));
        delay *= 2;
        continue;
      }

      return response;
    }

    throw new Error(`GmailConnector failed after ${maxRetries} retries.`);
  }
}
