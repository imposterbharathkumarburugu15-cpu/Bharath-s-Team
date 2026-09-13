/**
 * NeuroShield Authentication & Authorization Foundation
 * Provides a clean boundary for API Key and Bearer token verification.
 * In development/demo mode, public scans are enabled by default.
 * In production/enterprise mode (REQUIRE_AUTH=true), valid credentials are required.
 */

import { Request, Response, NextFunction } from 'express';
import { config } from '../config';
import { createHash, timingSafeEqual } from 'node:crypto';

function matchesKey(value: string, secret?: string): boolean {
  if (!secret || secret.length < 32 || !value) return false;
  return timingSafeEqual(createHash('sha256').update(value).digest(), createHash('sha256').update(secret).digest());
}

export interface AuthenticatedUser {
  id: string;
  role: 'admin' | 'analyst' | 'client' | 'anonymous';
  apiKeyId?: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}

export function authMiddleware(req: Request, res: Response, next: NextFunction) {
  // Non-API routes (frontend pages, static assets, Vite modules) never require auth
  const isApi = req.path.startsWith('/api') || req.path === '/scan' || req.path.startsWith('/scan/');
  if (!isApi) {
    return next();
  }

  // Public routes that never require auth
  const publicPaths = [
    '/health',
    '/api/health',
    '/model-status',
    '/api/neuroshield/model-status',
    '/api/core/model-status',
  ];

  if (publicPaths.includes(req.path)) {
    req.user = { id: 'public-monitor', role: 'anonymous' };
    return next();
  }

  const supplied = (req.headers.authorization || '').replace(/^Bearer /, '') || String(req.headers['x-api-key'] || '');
  const adminSecret = process.env.NEUROSHIELD_ADMIN_KEY;
  const analystSecret = process.env.NEUROSHIELD_ANALYST_KEY;

  for (const [role, secret] of [['admin', adminSecret], ['analyst', analystSecret]] as const) {
    if (matchesKey(supplied, secret)) {
      req.user = { id: `${role}-${createHash('sha256').update(supplied).digest('hex').slice(0, 12)}`, role };
      return next();
    }
  }
  // If auth is not strictly required by environment configuration
  if (!config.requireAuth) {
    req.user = { id: 'demo-user', role: 'anonymous' };
    return next();
  }

  // Check for X-API-Key header or Authorization: Bearer
  const apiKey = req.headers['x-api-key'] as string;
  const authHeader = req.headers['authorization'] as string;

  if (apiKey) {
    if (matchesKey(apiKey, config.apiKeySecret || undefined)) {
      req.user = { id: 'api-key-client', role: 'client', apiKeyId: 'primary' };
      return next();
    }
  } else if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7).trim();
    if (matchesKey(token, config.apiKeySecret || undefined)) {
      req.user = { id: 'bearer-client', role: 'client' };
      return next();
    }
  }

  return res.status(401).json({
    error: 'Unauthorized',
    message: 'Valid API key (X-API-Key) or Bearer token (Authorization) is required to access this endpoint.',
    code: 'AUTHENTICATION_REQUIRED',
  });
}
