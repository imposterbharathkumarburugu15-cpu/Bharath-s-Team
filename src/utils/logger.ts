/**
 * NeuroShield Structured Operational Logger
 * Hardened for SOC / SecOps observability.
 * Guarantees zero sensitive data leakage into logs.
 */

import { sanitizeText, sanitizeObject } from './sanitizer';
import { config } from '../config';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_WEIGHTS: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export interface StructuredLogContext {
  requestId?: string;
  channel?: string;
  sourceIp?: string;
  latencyMs?: number;
  status?: string | number;
  modelStatus?: string;
  errorCategory?: string;
  [key: string]: any;
}

export class Logger {
  private minLevel: LogLevel;

  constructor(minLevel: LogLevel = config.logLevel || 'info') {
    this.minLevel = minLevel;
  }

  private shouldLog(level: LogLevel): boolean {
    return LEVEL_WEIGHTS[level] >= LEVEL_WEIGHTS[this.minLevel];
  }

  private formatEntry(level: LogLevel, message: string, context?: StructuredLogContext): string {
    const timestamp = new Date().toISOString();
    const cleanMsg = sanitizeText(message).sanitized;
    const cleanContext = context ? sanitizeObject(context) : undefined;

    if (config.env === 'production') {
      // Production JSON log format for Datadog / Google Cloud Logging / Splunk
      return JSON.stringify({
        timestamp,
        level: level.toUpperCase(),
        service: 'neuroshield-core',
        message: cleanMsg,
        ...cleanContext,
      });
    }

    // Development readable format
    const metaStr = cleanContext ? ` | ${JSON.stringify(cleanContext)}` : '';
    const color = level === 'error' ? '\x1b[31m' : level === 'warn' ? '\x1b[33m' : level === 'info' ? '\x1b[36m' : '\x1b[90m';
    const reset = '\x1b[0m';
    return `${color}[${timestamp}] [${level.toUpperCase()}]${reset} ${cleanMsg}${metaStr}`;
  }

  debug(message: string, context?: StructuredLogContext): void {
    if (this.shouldLog('debug')) {
      console.debug(this.formatEntry('debug', message, context));
    }
  }

  info(message: string, context?: StructuredLogContext): void {
    if (this.shouldLog('info')) {
      console.info(this.formatEntry('info', message, context));
    }
  }

  warn(message: string, context?: StructuredLogContext): void {
    if (this.shouldLog('warn')) {
      console.warn(this.formatEntry('warn', message, context));
    }
  }

  error(message: string, error?: any, context?: StructuredLogContext): void {
    if (this.shouldLog('error')) {
      const errMsg = error ? (error.message || String(error)) : '';
      const fullMsg = errMsg ? `${message}: ${errMsg}` : message;
      console.error(this.formatEntry('error', fullMsg, { ...context, errorCategory: error?.name || 'RUNTIME_ERROR' }));
    }
  }
}

export const logger = new Logger();
