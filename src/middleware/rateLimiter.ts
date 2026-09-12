/**
 * NeuroShield Rate Limiter Middleware
 * Memory-efficient sliding-window algorithm.
 * Protects endpoints from flooding, DoS, and automated scraping.
 */

import { Request, Response, NextFunction } from 'express';
import { config } from '../config';

interface ClientWindow {
  count: number;
  resetTime: number;
}

const clientWindows = new Map<string, ClientWindow>();

// Clean up expired entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, win] of clientWindows.entries()) {
    if (win.resetTime <= now) {
      clientWindows.delete(ip);
    }
  }
}, 300000);

export function rateLimiter(options?: {
  windowMs?: number;
  maxRequests?: number;
}) {
  const windowMs = options?.windowMs || config.rateLimitWindowMs;
  const maxRequests = options?.maxRequests || config.rateLimitMaxRequests;

  return (req: Request, res: Response, next: NextFunction) => {
    // Only rate limit API routes and scan endpoints; exempt static assets and health checks
    const isApi = req.path.startsWith('/api') || req.path === '/scan' || req.path.startsWith('/scan/');
    if (!isApi || req.path === '/health' || req.path === '/api/health') {
      return next();
    }

    const clientIp =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() ||
      req.socket.remoteAddress ||
      '127.0.0.1';

    const now = Date.now();
    let win = clientWindows.get(clientIp);

    if (!win || win.resetTime <= now) {
      win = {
        count: 1,
        resetTime: now + windowMs,
      };
      clientWindows.set(clientIp, win);
    } else {
      win.count++;
    }

    const remaining = Math.max(0, maxRequests - win.count);
    const resetSeconds = Math.ceil((win.resetTime - now) / 1000);

    // Standard rate limit headers
    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', remaining);
    res.setHeader('X-RateLimit-Reset', resetSeconds);

    if (win.count > maxRequests) {
      res.setHeader('Retry-After', resetSeconds);
      return res.status(429).json({
        error: 'Too Many Requests',
        message: `Rate limit of ${maxRequests} requests per minute exceeded. Please retry in ${resetSeconds} seconds.`,
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: resetSeconds,
      });
    }

    next();
  };
}
