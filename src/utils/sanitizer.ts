/**
 * NeuroShield Sensitive Data Sanitizer & Redaction Engine
 * Hardens logging, error messages, and database records.
 * Prevents accidental leak of Passwords, OTPs, API Keys, Tokens, and PII.
 */

export interface SanitizedOutput {
  sanitized: string;
  redactedCount: number;
  categoriesFound: string[];
}

// Regex patterns for sensitive tokens
const PATTERNS = [
  // API Keys (OpenAI, Gemini, GitHub, AWS, Stripe, generic sk-)
  { name: 'API_KEY', regex: /\b(sk-[a-zA-Z0-9_-]{20,}|AIza[0-9A-Za-z-_]{35}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|xox[baprs]-[0-9a-zA-Z]{10,48})\b/gi, replacement: '[REDACTED_API_KEY]' },
  
  // Bearer Tokens / JWT
  { name: 'BEARER_TOKEN', regex: /Bearer\s+([a-zA-Z0-9_\-\.]{20,})/gi, replacement: 'Bearer [REDACTED_TOKEN]' },
  { name: 'JWT_TOKEN', regex: /\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g, replacement: '[REDACTED_JWT]' },
  
  // Passwords in key-value / URL query strings
  { name: 'PASSWORD', regex: /(password|passwd|pwd|secret|auth_key|access_token|private_key)\s*[:=]\s*["']?([^\s"',;}&]+)["']?/gi, replacement: '$1=[REDACTED_PASSWORD]' },
  
  // OTP / Verification codes (4-8 digits near keywords)
  { name: 'OTP_CODE', regex: /(otp|code|pin|verification\s*code|security\s*code)\s*(?:is|:|=)?\s*(\b\d{4,8}\b)/gi, replacement: '$1: [REDACTED_OTP]' },
  
  // Credit / Debit Card Numbers (13-19 digits with spaces or hyphens)
  { name: 'PAYMENT_CARD', regex: /\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{15,16}\b/g, replacement: '[REDACTED_CARD_NUMBER]' },
  
  // Social Security Numbers (US SSN: AAA-GG-SSSS)
  { name: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[REDACTED_SSN]' },
  
  // Private Key Headers
  { name: 'PRIVATE_KEY', regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g, replacement: '[REDACTED_PRIVATE_KEY_BLOCK]' },
];

/**
 * Redact sensitive tokens from raw text string.
 */
export function sanitizeText(text: string): SanitizedOutput {
  if (!text || typeof text !== 'string') {
    return { sanitized: text || '', redactedCount: 0, categoriesFound: [] };
  }

  let result = text;
  let totalRedacted = 0;
  const categories = new Set<string>();

  for (const { name, regex, replacement } of PATTERNS) {
    const matches = result.match(regex);
    if (matches && matches.length > 0) {
      totalRedacted += matches.length;
      categories.add(name);
      result = result.replace(regex, replacement as any);
    }
  }

  return {
    sanitized: result,
    redactedCount: totalRedacted,
    categoriesFound: Array.from(categories),
  };
}

/**
 * Deep recursive object sanitizer for structured logging and persistence.
 */
export function sanitizeObject<T = any>(obj: T, maxDepth = 6): T {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return sanitizeText(obj).sanitized as unknown as T;
  if (typeof obj !== 'object' || maxDepth <= 0) return obj;

  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item, maxDepth - 1)) as unknown as T;
  }

  const sanitizedObj: Record<string, any> = {};
  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase();
    // Immediate masking for known sensitive keys
    if (
      lowerKey.includes('password') ||
      lowerKey.includes('secret') ||
      lowerKey.includes('apikey') ||
      lowerKey.includes('api_key') ||
      lowerKey.includes('token') ||
      lowerKey.includes('otp') ||
      lowerKey.includes('privatekey') ||
      lowerKey.includes('authorization')
    ) {
      if (typeof value === 'string' && value.length > 0) {
        sanitizedObj[key] = `[MASKED_${key.toUpperCase()}]`;
        continue;
      }
    }
    sanitizedObj[key] = sanitizeObject(value, maxDepth - 1);
  }

  return sanitizedObj as T;
}
