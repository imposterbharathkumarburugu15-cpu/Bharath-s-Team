/**
 * NeuroShield Local Privacy Filter & Data Minimization Preprocessor
 * Section 28: LOCAL-FIRST PRIVACY
 *
 * Ensures that sensitive payloads (passwords, OTPs, financial card data, API keys, national IDs)
 * are sanitized and redacted before logging or deeper processing.
 * Never leaks raw secrets.
 */

export interface MaskedFieldItem {
  originalType: string;
  maskedValue: string;
}

export interface PrivacySanitizationResult {
  sanitizedContent: string;
  maskedFields: MaskedFieldItem[];
  sensitiveDataDetected: boolean;
  categoriesFound: string[];
}

export class PrivacyFilter {
  /**
   * Sanitizes plain text content by redacting high-risk secrets and credentials.
   */
  static sanitize(text: string): PrivacySanitizationResult {
    if (!text || typeof text !== 'string') {
      return {
        sanitizedContent: '',
        maskedFields: [],
        sensitiveDataDetected: false,
        categoriesFound: [],
      };
    }

    let sanitized = text;
    const maskedFields: MaskedFieldItem[] = [];
    const categoriesFound = new Set<string>();

    // 1. Credit / Debit Card Numbers (13 to 19 digits, with optional hyphens/spaces)
    const cardRegex = /\b(?:\d{4}[-\s]?){3}\d{1,4}\b/g;
    sanitized = sanitized.replace(cardRegex, (match) => {
      categoriesFound.add('financial_cards');
      const clean = match.replace(/[-\s]/g, '');
      const masked = '**** **** **** ' + clean.slice(-4);
      maskedFields.push({ originalType: 'PAYMENT_CARD', maskedValue: masked });
      return masked;
    });

    // 2. API Keys, Access Tokens & Private Keys
    // Generic high-entropy API key patterns (e.g. sk-..., AIza..., bearer tokens)
    const apiKeyRegex = /\b(?:sk-[a-zA-Z0-9_-]{20,}|AIzaSy[a-zA-Z0-9_-]{33}|bearer\s+[a-zA-Z0-9_.-]{20,}|ghp_[a-zA-Z0-9]{36})\b/gi;
    sanitized = sanitized.replace(apiKeyRegex, (match) => {
      categoriesFound.add('api_keys');
      maskedFields.push({ originalType: 'API_KEY', maskedValue: '[REDACTED_API_KEY]' });
      return '[REDACTED_API_KEY]';
    });

    // 3. Cleartext Passwords (e.g. "password: Secret123", "passwd=xyz")
    const passwordPattern = /(?:password|passwd|pwd)\s*[:=]\s*([^\s,;]+)/gi;
    sanitized = sanitized.replace(passwordPattern, (_match, pwd) => {
      categoriesFound.add('passwords');
      maskedFields.push({ originalType: 'PASSWORD', maskedValue: '**********' });
      return `password: **********`;
    });

    // 4. One-Time Passwords (OTPs / 2FA verification codes)
    // 4 to 8 digit codes adjacent to words like "code", "otp", "pin"
    const otpPattern = /\b(?:code|otp|pin|verification)\s*(?:is|:)?\s*([0-9]{4,8})\b/gi;
    sanitized = sanitized.replace(otpPattern, (match, code) => {
      categoriesFound.add('otp');
      maskedFields.push({ originalType: 'OTP', maskedValue: '******' });
      return match.replace(code, '******');
    });

    // 5. Government PII (US SSN or similar 9-digit formats)
    const ssnRegex = /\b\d{3}-\d{2}-\d{4}\b/g;
    sanitized = sanitized.replace(ssnRegex, (_match) => {
      categoriesFound.add('government_id');
      maskedFields.push({ originalType: 'NATIONAL_ID', maskedValue: '***-**-****' });
      return '***-**-****';
    });

    return {
      sanitizedContent: sanitized,
      maskedFields,
      sensitiveDataDetected: maskedFields.length > 0,
      categoriesFound: Array.from(categoriesFound),
    };
  }

  /**
   * Sanitizes an entire UnifiedInteractionEvent in-place or copies it.
   */
  static apply(event: any): any {
    if (!event) return event;
    const { sanitizedContent, maskedFields, sensitiveDataDetected, categoriesFound } = PrivacyFilter.sanitize(
      event.content || event.body || ''
    );

    return {
      ...event,
      content: sanitizedContent,
      body: event.body ? PrivacyFilter.sanitize(event.body).sanitizedContent : undefined,
      privacy_level: sensitiveDataDetected ? 'MASKED' : 'RAW',
      sensitive_data: {
        ...(event.sensitive_data || {}),
        categoriesRequested: [
          ...((event.sensitive_data?.categoriesRequested) || []),
          ...categoriesFound,
        ],
        maskedFields: [
          ...((event.sensitive_data?.maskedFields) || []),
          ...maskedFields,
        ],
      },
    };
  }
}
