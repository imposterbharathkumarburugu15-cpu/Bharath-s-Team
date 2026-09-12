/**
 * NeuroShield Production Configuration Management
 * Phase 7 Production Hardening
 */

import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });
dotenv.config();

export interface AppConfig {
  env: 'development' | 'production' | 'test';
  port: number;
  host: string;
  corsOrigins: string[];
  databaseUrl: string;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  maxPayloadBytes: number;
  enableSsrfProtection: boolean;
  rateLimitWindowMs: number;
  rateLimitMaxRequests: number;
  apiKeySecret: string | null;
  requireAuth: boolean;
  geminiApiKey: string | null;
  ipGeolocationApiKey: string | null;
  urlscanApiKey: string | null;
  urlscanApiUrl: string;
  urlscanVisibility: 'public' | 'unlisted' | 'private';
  urlscanMinRiskScore: number;
  urlscanMaxRiskScore: number;
  urlscanPollTimeoutMs: number;
  urlscanMaxRetries: number;
}

function parseOrigins(val?: string): string[] {
  if (!val || val.trim() === '' || val === '*') {
    return ['*'];
  }
  return val.split(',').map(s => s.trim()).filter(Boolean);
}

export const config: AppConfig = {
  env: (process.env.NODE_ENV as any) || 'development',
  port: parseInt(process.env.PORT || '3000', 10),
  host: process.env.API_HOST || '0.0.0.0',
  corsOrigins: parseOrigins(process.env.CORS_ORIGINS),
  databaseUrl: process.env.DATABASE_URL || 'sqlite://local.db',
  logLevel: (process.env.LOG_LEVEL as any) || 'info',
  maxPayloadBytes: parseInt(process.env.MAX_PAYLOAD_BYTES || '524288', 10), // 512 KB
  enableSsrfProtection: process.env.ENABLE_SSRF_PROTECTION !== 'false',
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10), // 1 min
  rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '120', 10),
  apiKeySecret: process.env.API_KEY_SECRET || null,
  requireAuth: process.env.REQUIRE_AUTH === 'true',
  geminiApiKey: (process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY') ? process.env.GEMINI_API_KEY : null,
  ipGeolocationApiKey: process.env.IPGEOLOCATION_API_KEY || process.env.IP_GEOLOCATION_API_KEY || null,
  urlscanApiKey: process.env.URLSCAN_API_KEY || null,
  urlscanApiUrl: process.env.URLSCAN_API_URL || 'https://urlscan.io/api/v1',
  urlscanVisibility: (process.env.URLSCAN_VISIBILITY as any) || 'unlisted',
  urlscanMinRiskScore: parseInt(process.env.URLSCAN_MIN_RISK_SCORE || '35', 10),
  urlscanMaxRiskScore: parseInt(process.env.URLSCAN_MAX_RISK_SCORE || '85', 10),
  urlscanPollTimeoutMs: parseInt(process.env.URLSCAN_POLL_TIMEOUT_MS || '25000', 10),
  urlscanMaxRetries: parseInt(process.env.URLSCAN_MAX_RETRIES || '10', 10),
};
