/**
 * NeuroShield Gmail Authentication Service
 * Implements standard Google OAuth 2.0 with least-privilege readonly scope,
 * cryptographically secure state verification, token refresh, and revocation.
 */

import crypto from 'crypto';

export interface OAuthTokens {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
  expiry_date?: number;
}

export interface GoogleUserIdentity {
  email: string;
  name?: string;
  picture?: string;
}

export class GmailAuthService {
  private static readonly OAUTH_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
  private static readonly OAUTH_TOKEN_URL = 'https://oauth2.googleapis.com/token';
  private static readonly OAUTH_REVOKE_URL = 'https://oauth2.googleapis.com/revoke';
  private static readonly USERINFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo';

  // Least privilege scope: strictly read-only access to user email messages
  public static readonly REQUIRED_SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'email',
    'profile',
  ];

  private static stateStore = new Map<string, { createdAt: number }>();
  private static readonly STATE_TTL_MS = 15 * 60 * 1000; // 15 minutes

  /**
   * Reads OAuth client configuration from environment variables.
   */
  public static getConfig(): { clientId: string; clientSecret: string; redirectUri: string } {
    const clientId = process.env.GMAIL_CLIENT_ID || process.env.GOOGLE_CLIENT_ID || '';
    const clientSecret = process.env.GMAIL_CLIENT_SECRET || process.env.GOOGLE_CLIENT_SECRET || '';
    const redirectUri =
      process.env.GMAIL_REDIRECT_URI ||
      process.env.GOOGLE_REDIRECT_URI ||
      'http://localhost:3000/api/auth/google/callback';

    return { clientId, clientSecret, redirectUri };
  }

  /**
   * Generates a cryptographically protected OAuth 2.0 Authorization URL with CSRF protection.
   */
  public static generateAuthUrl(customState?: string): { url: string; state: string } {
    const { clientId, redirectUri } = this.getConfig();
    if (!clientId) {
      console.warn('[GmailAuthService] GMAIL_CLIENT_ID is not configured. Set environment variable.');
    }

    const state = customState || crypto.randomBytes(24).toString('hex');
    this.cleanupStates();
    this.stateStore.set(state, { createdAt: Date.now() });

    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: this.REQUIRED_SCOPES.join(' '),
      access_type: 'offline', // Demands refresh_token
      prompt: 'consent',     // Ensures consent screen displays to grant refresh_token
      include_granted_scopes: 'true',
      state,
    });

    return {
      url: `${this.OAUTH_AUTH_URL}?${params.toString()}`,
      state,
    };
  }

  /**
   * Validates the returned OAuth state parameter against our cryptographic store to prevent CSRF.
   */
  public static verifyState(state: string): boolean {
    if (!state) return false;
    const stored = this.stateStore.get(state);
    if (!stored) return false;
    this.stateStore.delete(state);
    return Date.now() - stored.createdAt < this.STATE_TTL_MS;
  }

  /**
   * Exchanges an authorization code for OAuth tokens.
   */
  public static async exchangeCodeForTokens(code: string, state?: string): Promise<OAuthTokens> {
    if (state && !this.verifyState(state)) {
      throw new Error('OAuth state verification failed. Potential CSRF detected.');
    }

    const { clientId, clientSecret, redirectUri } = this.getConfig();
    if (!clientId || !clientSecret) {
      throw new Error('GMAIL_CLIENT_ID or GMAIL_CLIENT_SECRET is missing from environment.');
    }

    const body = new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    });

    const response = await fetch(this.OAUTH_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data?.error_description || data?.error || 'Failed to exchange OAuth code for tokens');
    }

    return {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_in: data.expires_in,
      scope: data.scope,
      token_type: data.token_type,
      expiry_date: data.expires_in ? Date.now() + data.expires_in * 1000 : undefined,
    };
  }

  /**
   * Refreshes an expired access token using the refresh token.
   */
  public static async refreshAccessToken(refreshToken: string): Promise<OAuthTokens> {
    if (!refreshToken) {
      throw new Error('Refresh token is required to refresh access token');
    }

    const { clientId, clientSecret } = this.getConfig();
    const body = new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token',
    });

    const response = await fetch(this.OAUTH_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data?.error_description || data?.error || 'Failed to refresh OAuth token');
    }

    return {
      access_token: data.access_token,
      refresh_token: data.refresh_token || refreshToken, // Google might not return a new refresh token
      expires_in: data.expires_in,
      token_type: data.token_type,
      scope: data.scope,
      expiry_date: data.expires_in ? Date.now() + data.expires_in * 1000 : undefined,
    };
  }

  /**
   * Revokes an existing OAuth token (access token or refresh token) when user logs out.
   */
  public static async revokeToken(token: string): Promise<boolean> {
    if (!token) return true;
    try {
      const response = await fetch(`${this.OAUTH_REVOKE_URL}?token=${encodeURIComponent(token)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      return response.ok;
    } catch (err) {
      console.warn('[GmailAuthService] Error revoking token:', err);
      return false;
    }
  }

  /**
   * Fetches user profile for authenticated user.
   */
  public static async fetchUserInfo(accessToken: string): Promise<GoogleUserIdentity> {
    const response = await fetch(this.USERINFO_URL, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) {
      throw new Error('Failed to retrieve user profile with access token');
    }
    const data = await response.json();
    return {
      email: data.email,
      name: data.name,
      picture: data.picture,
    };
  }

  private static cleanupStates() {
    const now = Date.now();
    for (const [state, info] of this.stateStore.entries()) {
      if (now - info.createdAt > this.STATE_TTL_MS) {
        this.stateStore.delete(state);
      }
    }
  }
}
