/**
 * NeuroShield Intent Engine
 * Classifies the adversary's primary strategic objective.
 */

import { UnifiedThreatInput, IntentAnalysis, DetectorEvidence } from '../types';

export class IntentDetector {
  static evaluate(input: UnifiedThreatInput): {
    analysis: IntentAnalysis;
    evidence: DetectorEvidence;
  } {
    const text = (input.content + ' ' + (input.metadata?.subject || '')).toLowerCase();
    const evidenceList: string[] = [];

    // Prompt injection check first (AI attack)
    if (/(\[system instruction|ignore (all )?previous instructions|you are now dan|assistant:\s*ignore)/i.test(text)) {
      evidenceList.push('Adversarial intent identified: AI instruction override and policy subversion.');
      return {
        analysis: {
          status: 'available',
          primaryIntent: 'PROMPT_MANIPULATION',
          intentConfidence: 95,
          evidence: evidenceList,
        },
        evidence: {
          detector: 'intent_engine',
          score: 95,
          status: 'available',
          evidence: evidenceList,
        },
      };
    }

    // Impersonation Intent
    if (input.sender?.displayName && /(security team|it support|helpdesk|payroll|administrator|ceo|cfo|executive)/i.test(input.sender.displayName)) {
      const senderId = (input.sender.identifier || '').toLowerCase();
      if (!senderId.includes('corp') && !senderId.includes('internal') && !senderId.includes('company')) {
        evidenceList.push(`Impersonation intent: sender asserts authority persona ('${input.sender.displayName}') with external routing address.`);
        if (text.includes('urgent') || text.includes('verify')) {
          return {
            analysis: {
              status: 'available',
              primaryIntent: 'IMPERSONATION',
              intentConfidence: 85,
              evidence: evidenceList,
            },
            evidence: {
              detector: 'intent_engine',
              score: 85,
              status: 'available',
              evidence: evidenceList,
            },
          };
        }
      }
    }

    // Credential Theft / Harvesting
    const credentialTerms = ['login', 'sign in', 'password', 'verify credentials', 're-authenticate', 'auth portal', 'session expired', '2fa'];
    const matchedCreds = credentialTerms.filter((t) => text.includes(t));
    if (matchedCreds.length >= 1 && (input.urls && input.urls.length > 0)) {
      const isStrong = matchedCreds.length >= 2 || text.includes('password') || text.includes('verify credentials');
      evidenceList.push(`Credential theft intent: links authentication prompt [${matchedCreds.slice(0, 3).join(', ')}] to external destination.`);
      return {
        analysis: {
          status: 'available',
          primaryIntent: 'CREDENTIAL_THEFT',
          intentConfidence: isStrong ? 92 : 68,
          evidence: evidenceList,
        },
        evidence: {
          detector: 'intent_engine',
          score: isStrong ? 92 : 68,
          status: 'available',
          evidence: evidenceList,
        },
      };
    }

    // Financial Fraud
    const financialTerms = ['wire transfer', 'ach', 'invoice overdue', 'remit payment', 'crypto', 'bitcoin', 'gift card', 'payroll routing', 'payment confirmation'];
    const matchedFin = financialTerms.filter((t) => text.includes(t));
    if (matchedFin.length >= 1 && /(urgent|immediately|overdue|penalty|action required|pay now)/i.test(text)) {
      evidenceList.push(`Financial fraud intent: coercive demand for payment disbursement [${matchedFin.join(', ')}].`);
      return {
        analysis: {
          status: 'available',
          primaryIntent: 'FINANCIAL_FRAUD',
          intentConfidence: 88,
          evidence: evidenceList,
        },
        evidence: {
          detector: 'intent_engine',
          score: 88,
          status: 'available',
          evidence: evidenceList,
        },
      };
    }

    // Sensitive Data Collection
    const dataTerms = ['client access list', 'employee contact sheet', 'w-2', 'ssn report', 'upload files to link', 'confidential roster'];
    const matchedData = dataTerms.filter((t) => text.includes(t));
    if (matchedData.length >= 1) {
      evidenceList.push(`Sensitive data collection intent: targets proprietary records [${matchedData.join(', ')}].`);
      return {
        analysis: {
          status: 'available',
          primaryIntent: 'SENSITIVE_DATA_COLLECTION',
          intentConfidence: 86,
          evidence: evidenceList,
        },
        evidence: {
          detector: 'intent_engine',
          score: 86,
          status: 'available',
          evidence: evidenceList,
        },
      };
    }

    // Malware Delivery
    const hasExecutable = (input.attachments || []).some((a) => a.isExecutable);
    if (hasExecutable || /(enable editing|enable content|run setup|open attached zip|invoice\.iso)/i.test(text)) {
      evidenceList.push('Malware delivery intent: attachment or payload download mechanism detected.');
      return {
        analysis: {
          status: 'available',
          primaryIntent: 'MALWARE_DELIVERY',
          intentConfidence: 90,
          evidence: evidenceList,
        },
        evidence: {
          detector: 'intent_engine',
          score: 90,
          status: 'available',
          evidence: evidenceList,
        },
      };
    }

    // Malicious Link Redirection
    if (input.urls && input.urls.length > 0 && /(redirect=|url=|dest=|target=|tinyurl|bit\.ly)/i.test(text)) {
      evidenceList.push('Malicious link redirection intent: deceptive intermediate hop or URL shortener detected.');
      return {
        analysis: {
          status: 'available',
          primaryIntent: 'MALICIOUS_LINK_REDIRECTION',
          intentConfidence: 75,
          evidence: evidenceList,
        },
        evidence: {
          detector: 'intent_engine',
          score: 75,
          status: 'available',
          evidence: evidenceList,
        },
      };
    }

    // Social Engineering
    if (/(strictly confidential|favor for me|in a meeting|cannot call|need a quick favour)/i.test(text)) {
      evidenceList.push('Social engineering intent: psychological pretexting and relationship leverage detected.');
      return {
        analysis: {
          status: 'available',
          primaryIntent: 'SOCIAL_ENGINEERING',
          intentConfidence: 72,
          evidence: evidenceList,
        },
        evidence: {
          detector: 'intent_engine',
          score: 72,
          status: 'available',
          evidence: evidenceList,
        },
      };
    }

    // Benign / Routine
    if (text.length > 10 && !/(urgent|verify|password|transfer|suspended|invoice|click here|otp)/i.test(text)) {
      evidenceList.push('Benign communication intent: standard conversational or operational discourse.');
      return {
        analysis: {
          status: 'available',
          primaryIntent: 'BENIGN_COMMUNICATION',
          intentConfidence: 85,
          evidence: evidenceList,
        },
        evidence: {
          detector: 'intent_engine',
          score: 5,
          status: 'available',
          evidence: evidenceList,
        },
      };
    }

    evidenceList.push('Indeterminate intent based on weak/scanty interaction text.');
    return {
      analysis: {
        status: 'available',
        primaryIntent: 'UNKNOWN',
        intentConfidence: 30,
        evidence: evidenceList,
      },
      evidence: {
        detector: 'intent_engine',
        score: 20,
        status: 'available',
        evidence: evidenceList,
      },
    };
  }
}
