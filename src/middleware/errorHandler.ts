/**
 * NeuroShield Safe Error Handler Middleware
 * Prevents internal stack trace leakage in client-facing HTTP responses.
 */

import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { config } from '../config';

export function errorHandler(err: any, req: Request, res: Response, _next: NextFunction) {
  const requestId = (req.headers['x-request-id'] as string) || `req-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
  
  logger.error('Unhandled server error during request processing', err, {
    requestId,
    path: req.path,
    method: req.method,
  });

  const statusCode = err.status || err.statusCode || 500;
  const isDev = config.env === 'development';

  res.status(statusCode).json({
    error: err.name || 'Internal Server Error',
    message: statusCode === 500 && !isDev 
      ? 'An unexpected error occurred while processing the request. Investigation ID has been logged.' 
      : (err.message || 'Internal server error'),
    code: err.code || 'SERVER_ERROR',
    requestId,
    timestamp: new Date().toISOString(),
  });
}
