/**
 * NeuroShield Sensitive Data & Exfiltration Risk Detector
 * Phase 7.5 — Advanced Security Intelligence
 *
 * Detects attempts to harvest passwords, OTPs, API keys, financial credentials,
 * confidential documents, and PII.
 * Evaluates BOTH content requested AND context (identity, channel, action).
 * STRICT PRIVACY DIRECTIVE: Always mask sensitive records with asterisks; never leak raw secrets.
 */

import { UnifiedThreatInput, SensitiveDataAnalysis, DetectorEvidence } from '../types';

export class SensitiveDataDetector {
  static evaluate(input: UnifiedThreatInput): {
    analysis: SensitiveDataAnalysis;
    evidence: DetectorEvidence;
  } {
    const text = input.content + ' ' + (input.metadata?.subject || '') + ' ' + (input.rawPayload || '');
    const lower = text.toLowerCase();
    const evidenceList: string[] = [];
    const matchedCategories: string[] = [];
    const maskedItems: Array<{ originalType: string; maskedValue: string }> = [];
    const categories: string[] = [];

    // Contextual factors
    const isUnknownSender = !input.history || input.history.previousInteractionsCount === 0;
    const isSmsChannel = input.source === 'sms';

    // 1. Demands OTP / 2FA / Authentication Secrets
    const otpKeywords = [
      'otp', 'one-time password', 'verification code', '2fa pin', 'security code',
      'sms code', 'authenticator code', 'auth token', 'session token', 'mfa code',
      'send me the code', 'share the pin', 'enter the 6-digit', 'provide the code'
    ];
    const demandsOtp = otpKeywords.some((k) => lower.includes(k));
    if (demandsOtp) {
      categories.push('otp');
      categories.push('authentication_secrets');
      categories.push('OTP');
      matchedCategories.push('OTP / 2FA / Authentication Tokens');
      evidenceList.push('EXFILTRATION RISK: Solicits one-time authentication code (OTP/MFA) to compromise active multi-factor session.');

      if (isUnknownSender) {
        evidenceList.push('CONTEXT HAZARD: OTP demanded by unknown origin with no historical communication baseline.');
      }
      if (isSmsChannel) {
        evidenceList.push('CHANNEL HAZARD: Out-of-band SMS code solicited via text message channel.');
      }
    }

    // 2. Demands Credentials / Passwords
    const credKeywords = [
      'password', 'enter your credentials', 'current password', 'login credentials',
      'account password', 'reset password link', 'verify your password', 'confirm your password'
    ];
    const demandsCredentials = credKeywords.some((k) => lower.includes(k));
    if (demandsCredentials) {
      categories.push('credentials');
      categories.push('passwords');
      categories.push('PASSWORD');
      matchedCategories.push('Account Credentials / Passwords');
      evidenceList.push('EXFILTRATION RISK: Direct solicitation of secret account login credentials or passwords.');
    }

    // 3. Demands API Keys / Cryptographic Secrets
    const apiKeyKeywords = [
      'api key', 'secret key', 'private key', 'api token', 'bearer token',
      'client secret', 'ssh key', 'access token', 'aws secret', 'github token'
    ];
    const demandsApiKeys = apiKeyKeywords.some((k) => lower.includes(k));
    if (demandsApiKeys) {
      categories.push('api_keys');
      categories.push('API_KEY');
      if (lower.includes('token') || lower.includes('bearer')) {
        categories.push('ACCESS_TOKEN');
      }
      matchedCategories.push('API Keys & Cryptographic Secrets');
      evidenceList.push('EXFILTRATION RISK: Attempts to harvest developer API keys or cryptographic private credentials.');
    }

    // 4. Demands Payment / Banking Credentials
    const paymentKeywords = [
      'credit card', 'cvv', 'card number', 'bank account', 'routing number',
      'wire transfer', 'ach details', 'banking pin', 'card expiry', 'payment details'
    ];
    const demandsPayment = paymentKeywords.some((k) => lower.includes(k));
    if (demandsPayment) {
      categories.push('financial_information');
      categories.push('PAYMENT_DATA');
      categories.push('BANKING_DATA');
      matchedCategories.push('Financial & Banking Data');
      evidenceList.push('EXFILTRATION RISK: Demands financial payment instruments, card security codes, or wire routing.');
    }

    // 5. Demands Government PII & Personal Identifiers
    const piiKeywords = [
      'social security', 'ssn', 'tax id', 'passport copy', 'driver license',
      'date of birth', 'national id', 'pan card', 'aadhaar', 'id card scan'
    ];
    const demandsPii = piiKeywords.some((k) => lower.includes(k));
    if (demandsPii) {
      categories.push('identity_information');
      categories.push('PERSONAL_IDENTIFIER');
      matchedCategories.push('Government PII & Identity Records');
      evidenceList.push('EXFILTRATION RISK: Solicits high-value government identification numbers or identity documents.');
    }

    // 6. Demands Confidential Organizational Information & Documents
    const orgDataKeywords = [
      'client list', 'customer database', 'salary roster', 'internal roadmap',
      'confidential financial statement', 'board minutes', 'w-2 form', 'employee records',
      'payroll spreadsheet', 'source code repository'
    ];
    const demandsConfidentialOrgData = orgDataKeywords.some((k) => lower.includes(k));
    if (demandsConfidentialOrgData) {
      categories.push('confidential_organizational_information');
      categories.push('CONFIDENTIAL_DATA');
      matchedCategories.push('Confidential Organizational Information');
      evidenceList.push('EXFILTRATION RISK: Solicits confidential enterprise documents, employee rosters, or internal records.');
    }

    // PRIVACY PRESERVATION: Mask detected card numbers (13-16 digits)
    const ccMatches = text.match(/\b(?:\d{4}[ -]?){3}\d{4}\b/g) || [];
    for (const cc of ccMatches) {
      const clean = cc.replace(/[\s-]/g, '');
      maskedItems.push({
        originalType: 'Credit Card',
        maskedValue: '****-****-****-' + clean.slice(-4),
      });
    }

    // PRIVACY PRESERVATION: Mask detected SSNs (XXX-XX-XXXX)
    const ssnMatches = text.match(/\b\d{3}-\d{2}-\d{4}\b/g) || [];
    for (const ssn of ssnMatches) {
      maskedItems.push({
        originalType: 'SSN',
        maskedValue: '***-**-' + ssn.slice(-4),
      });
    }

    // PRIVACY PRESERVATION: Mask detected raw API tokens
    const tokenMatches = text.match(/(?:bearer\s+[a-zA-Z0-9._-]{20,}|(?:ghp|sk|ak)_[a-zA-Z0-9]{20,})/gi) || [];
    for (const tok of tokenMatches) {
      maskedItems.push({
        originalType: 'API Token',
        maskedValue: tok.slice(0, 6) + '********************',
      });
    }

    const detected = categories.length > 0;
    let riskScore = 0;
    if (demandsOtp) {
      riskScore = isUnknownSender ? 98 : 92;
    } else if (demandsCredentials || demandsApiKeys) {
      riskScore = 95;
    } else if (demandsPayment) {
      riskScore = 90;
    } else if (demandsPii || demandsConfidentialOrgData) {
      riskScore = 85;
    }

    if (!detected) {
      evidenceList.push('No unauthorized harvesting of credentials, OTPs, API keys, financial information, or PII identified.');
    }

    return {
      analysis: {
        status: 'available',
        detected,
        categories,
        risk: riskScore,
        demandsCredentials,
        demandsOtp,
        demandsPayment,
        demandsPii,
        demandsApiKeys,
        demandsConfidentialOrgData,
        matchedCategories,
        maskedItems,
        riskScore,
        evidence: evidenceList,
      },
      evidence: {
        detector: 'sensitive_data',
        score: riskScore,
        status: 'available',
        evidence: evidenceList,
      },
    };
  }

  /**
   * Convenience helper for fast textual string scanning
   */
  static detect(text: string): {
    hasSensitiveData: boolean;
    categories: string[];
    riskScore: number;
    explanation: string;
    maskedItems: Array<{ originalType: string; maskedValue: string }>;
  } {
    const res = this.evaluate({ content: text, source: 'web' });
    return {
      hasSensitiveData: res.analysis.detected,
      categories: res.analysis.categories,
      riskScore: res.analysis.riskScore,
      explanation: res.analysis.evidence.join('; ') || '',
      maskedItems: res.analysis.maskedItems,
    };
  }
}

