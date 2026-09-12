/**
 * NeuroShield Action Risk Detector
 * Phase 7.5 — Advanced Security Intelligence
 *
 * Evaluates: "What is the attacker trying to make the user do?"
 * Makes action risk a first-class security signal, assessing the severity of the
 * requested action in relationship to identity, target, and payment destination.
 *
 * Supported Actions:
 * - CLICK_LINK
 * - LOGIN
 * - ENTER_PASSWORD
 * - SHARE_OTP
 * - TRANSFER_MONEY
 * - SHARE_SENSITIVE_DATA
 * - DOWNLOAD_FILE
 * - EXECUTE_INSTRUCTION
 * - SCAN_QR
 * - CALL_NUMBER
 * - VISIT_WEBSITE
 */

import { UnifiedThreatInput, ActionRiskAnalysis, ActionType, ActionRiskLevel, DetectorEvidence } from '../types';

export class ActionRiskDetector {
  static evaluate(input: UnifiedThreatInput): {
    analysis: ActionRiskAnalysis;
    evidence: DetectorEvidence;
  } {
    const text = (input.content + ' ' + (input.metadata?.subject || '') + ' ' + (input.rawPayload || '')).toLowerCase();
    const evidenceList: string[] = [];
    let detectedAction: ActionType = input.user_action || 'UNKNOWN';
    let actionRisk: ActionRiskLevel = 'NONE';
    let targetDestination: string | null = null;
    let score = 0;

    // Contextual factors
    const isUnknownSender = !input.history || input.history.previousInteractionsCount === 0;
    const hasPaymentDetails = /(?:routing\s*#?|account\s*#?|iban|swift|bic|wallet\s*address|new\s*bank|updated\s*payment|new\s*account|beneficiary|remittance\s*account)/i.test(text);

    // 1. SHARE_OTP / 2FA INTERCEPTION
    const otpKeywords = [
      'one-time password', 'otp', 'verification code', '2fa code', 'security code',
      'auth code', 'pin code', 'share the code', 'read back the code', 'enter the 6-digit',
      'sms code', 'send me the otp', 'provide the pin'
    ];
    const hasOtpRequest = otpKeywords.some((k) => text.includes(k));
    if (hasOtpRequest) {
      if (!input.user_action || input.user_action === 'UNKNOWN') {
        detectedAction = 'SHARE_OTP';
      }
      actionRisk = 'CRITICAL';
      score = 98;
      evidenceList.push('ACTION RISK (CRITICAL): Surrendering multi-factor OTP/2FA codes grants attacker immediate account session hijacking.');
      if (isUnknownSender) {
        evidenceList.push('ACTION HAZARD: Out-of-band authentication code requested by unverified or new sender.');
      }
    }

    // 2. TRANSFER_MONEY / FINANCIAL DISBURSEMENT
    const moneyKeywords = [
      'wire transfer', 'wire $', 'wire funds', 'wire to', 'ach routing', 'bank transfer',
      'gift card', 'crypto deposit', 'bitcoin address', 'urgent payment', 'remit payment',
      'remit $', 'direct deposit change', 'payroll account', 'invoice overdue', 'pay now',
      'western union', 'zelle payment', 'send money', 'purchase apple gift cards', 'transfer funds',
      'transfer ₹', 'transfer rs', 'send ₹', 'wire ₹', 'lakh', 'crore'
    ];
    const hasMoneyRegex = /\b(?:wire|remit|transfer|send)\s+(?:\$|₹|rs\.?|inr|\d+|funds|money|payment|lakh|crore)/i.test(text) || /\b(?:₹\s*\d+|\d+\s*lakh|\d+\s*crore)\b/i.test(text) || /\binvoice\b.*(?:overdue|remit|pay|settle)/i.test(text);
    const hasMoneyRequest = moneyKeywords.some((k) => text.includes(k)) || hasMoneyRegex;

    if (hasMoneyRequest && !hasOtpRequest) {
      if (!input.user_action || input.user_action === 'UNKNOWN') {
        detectedAction = 'TRANSFER_MONEY';
      }
      actionRisk = 'CRITICAL';
      score = Math.max(score, 92);
      evidenceList.push('ACTION RISK (CRITICAL): Coerces immediate financial remittance or wire transfer, causing irreversible monetary loss.');

      // Check for new payment destination + unknown identity anomaly
      if (hasPaymentDetails || isUnknownSender) {
        score = Math.max(score, 96);
        evidenceList.push('ACTION RISK ESCALATION: Financial transfer requested to a new/unverified payment destination under an unfamiliar identity.');
      }
    }

    // 3. ENTER_PASSWORD / LOGIN CREDENTIAL HARVESTING
    const credentialKeywords = [
      'login to verify', 'update your password', 'reset password', 'sign in with microsoft',
      'verify account credentials', 're-authenticate your 2fa', 'session expired login',
      'enter current password', 'identity portal', 'verify credentials', 'confirm your password',
      'enter your credentials', 'enter password', 'enter credentials', 'input password', 'submit password'
    ];
    const hasCredentialRegex = /(?:enter|submit|provide|input|type|update|reset|verify)\s+(?:your\s+)?(?:current\s+)?(?:credentials|password|passcode|secret)/i.test(text) || /\b(?:login|sign\s*in)\s+(?:to\s+)?(?:verify|access|authenticate|confirm)/i.test(text);
    const hasCredentialRequest = credentialKeywords.some((k) => text.includes(k)) || hasCredentialRegex;
    if (hasCredentialRequest && !hasOtpRequest && !hasMoneyRequest) {
      if (!input.user_action || input.user_action === 'UNKNOWN') {
        detectedAction = text.includes('password') ? 'ENTER_PASSWORD' : 'LOGIN';
      }
      actionRisk = 'HIGH';
      score = Math.max(score, 90);
      evidenceList.push('ACTION RISK (HIGH): Submitting primary account credentials on external target yields total credential compromise.');
    }

    // If explicit client action was provided, ensure risk level reflects it
    if (input.user_action && input.user_action !== 'UNKNOWN') {
      detectedAction = input.user_action;
      if (input.user_action === 'ENTER_PASSWORD' || input.user_action === 'LOGIN') {
        actionRisk = actionRisk === 'CRITICAL' ? 'CRITICAL' : 'HIGH';
        score = Math.max(score, 90);
        evidenceList.push(`CLIENT ACTION HOOK: Observed user interaction intercept for ${input.user_action}.`);
      }
    }

    // 4. SCAN_QR CODE
    if ((input.source === 'qr' || /(scan the qr|scan qr code|qr code below|open camera to scan|scan to pay)/i.test(text)) && !hasOtpRequest && !hasMoneyRequest && !hasCredentialRequest) {
      detectedAction = 'SCAN_QR';
      actionRisk = 'HIGH';
      score = Math.max(score, 82);
      evidenceList.push('ACTION RISK (HIGH): Scanning an unverified QR code bypasses perimeter proxies, forcing physical mobile browser navigation.');
    }

    // 5. CLICK_LINK / VISIT_WEBSITE
    const hasUrls = Boolean(input.urls && input.urls.length > 0);
    const hasClickPrompt = /(click|tap|visit|open|link|verify at|portal|update here)/i.test(text);
    if ((hasUrls || hasClickPrompt) && detectedAction === 'UNKNOWN' && !hasOtpRequest && !hasMoneyRequest && !hasCredentialRequest) {
      detectedAction = 'CLICK_LINK';
      actionRisk = 'MEDIUM';
      score = Math.max(score, 65);
      if (input.urls && input.urls.length > 0) {
        targetDestination = input.urls[0];
        evidenceList.push(`ACTION RISK (MEDIUM): Interacting with external hyperlink directs traffic to: ${targetDestination}`);
      } else {
        evidenceList.push('ACTION RISK (MEDIUM): Urges recipient to click external hyperlink.');
      }
    }

    // 6. CALL_NUMBER / VISHING
    const phoneCallKeywords = ['call us immediately', 'call our support line', 'call toll-free', 'dial this number', 'call +', 'call 1-800', 'ring our desk', 'call customer care'];
    const hasCallRequest = phoneCallKeywords.some((k) => text.includes(k));
    if (hasCallRequest) {
      if (detectedAction === 'UNKNOWN') {
        detectedAction = 'CALL_NUMBER';
        actionRisk = 'HIGH';
        score = Math.max(score, 75);
        evidenceList.push('ACTION RISK (HIGH): Calling phone numbers supplied directly inside untrusted communications connects victim to adversarial vishing agents.');
      } else {
        evidenceList.push('ACTION HAZARD: Alternative vishing/callback telephone channel provided alongside primary lure.');
      }
    }

    // 6. SHARE_SENSITIVE_DATA / DATA EXFILTRATION
    const sensitiveDataKeywords = [
      'send client list', 'upload client access', 'contact sheet', 'employee ssn',
      'tax form', 'w-2', 'confidential report', 'share private keys', 'send database backup',
      'customer records', 'send password file'
    ];
    const hasSensitiveDataRequest = sensitiveDataKeywords.some((k) => text.includes(k));
    if (hasSensitiveDataRequest && actionRisk === 'NONE') {
      detectedAction = 'SHARE_SENSITIVE_DATA';
      actionRisk = 'HIGH';
      score = Math.max(score, 86);
      evidenceList.push('ACTION RISK (HIGH): Transmitting proprietary records exposes confidential organization and consumer PII assets.');
    }

    // 7. DOWNLOAD_FILE / DOWNLOAD
    const downloadKeywords = [
      'download attachment', 'open invoice', 'extract zip', 'enable editing',
      'enable macros', 'run installer', 'setup.exe', 'download file'
    ];
    const suspiciousExts = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.iso', '.zip', '.rar', '.7z', '.jar', '.apk'];
    const hasSuspiciousExt = (input.attachments || []).some((a) => suspiciousExts.some(ext => a.filename.toLowerCase().endsWith(ext)));
    const hasExecutableAttachment = (input.attachments || []).some((a) => a.isExecutable) || hasSuspiciousExt;
    const hasCoerciveDownloadKeyword = downloadKeywords.some((k) => text.includes(k));
    const hasDownloadRequest = hasCoerciveDownloadKeyword || hasExecutableAttachment;
    if (hasDownloadRequest && actionRisk === 'NONE') {
      detectedAction = 'DOWNLOAD_FILE';
      actionRisk = hasExecutableAttachment ? 'CRITICAL' : 'MEDIUM';
      score = Math.max(score, hasExecutableAttachment ? 96 : 65);
      evidenceList.push(
        hasExecutableAttachment
          ? 'ACTION RISK (CRITICAL): Executing binary payload initiates direct host compromise and malware persistence.'
          : 'ACTION RISK (MEDIUM): Downloading untrusted attachments risks payload delivery or macro exploitation.'
      );
    }

    // 8. EXECUTE_INSTRUCTION
    const executeKeywords = [
      'powershell', 'terminal command', 'run script', 'curl http', 'regsvr32',
      'ignore previous instructions', '[system instruction', 'execute command'
    ];
    const hasExecuteRequest = executeKeywords.some((k) => text.includes(k));
    if (hasExecuteRequest && actionRisk === 'NONE') {
      detectedAction = 'EXECUTE_INSTRUCTION';
      actionRisk = 'HIGH';
      score = Math.max(score, 92);
      evidenceList.push('ACTION RISK (HIGH): Executing terminal scripts or adversarial prompt directives compromises host configuration or assistant guardrails.');
    }

    // Content Risk baseline estimation
    let contentRisk: ActionRiskLevel = 'NONE';
    if (/(urgent|immediately|action required|suspended|penalty|terminated|final notice)/i.test(text)) {
      contentRisk = 'HIGH';
    } else if (text.length > 20) {
      contentRisk = 'LOW';
    }

    if (evidenceList.length === 0) {
      evidenceList.push('No hostile user action or coercive transaction demand detected.');
      actionRisk = 'NONE';
      score = 0;
    }

    // Protective interventions & circuit breakers for Guard
    let preventiveIntervention = 'Proceed with normal verification precautions.';
    switch (detectedAction) {
      case 'SHARE_OTP':
        preventiveIntervention = 'CIRCUIT BREAKER: NEVER share OTP or one-time verification passcodes. Organizations will never call or message asking for your verification code.';
        break;
      case 'TRANSFER_MONEY':
        preventiveIntervention = 'CIRCUIT BREAKER: Do not transfer money. Verify the request through independent, established company channels (not phone/email from this message).';
        break;
      case 'ENTER_PASSWORD':
      case 'LOGIN':
        preventiveIntervention = 'CIRCUIT BREAKER: Do not enter credentials. Navigate to the official service website directly via trusted bookmarks.';
        break;
      case 'SCAN_QR':
        preventiveIntervention = 'CIRCUIT BREAKER: Do not scan the QR code. Access the destination service directly via the official web portal.';
        break;
      case 'CALL_NUMBER':
        preventiveIntervention = 'CIRCUIT BREAKER: Do not dial the telephone number provided. Look up official contact information on the organization\'s public website.';
        break;
      case 'SHARE_SENSITIVE_DATA':
        preventiveIntervention = 'CIRCUIT BREAKER: Refuse data transmission. Validate authorization through internal compliance or data protection leadership.';
        break;
      case 'DOWNLOAD':
      case 'DOWNLOAD_FILE':
        preventiveIntervention = 'CIRCUIT BREAKER: Do not open or download attachments. Submit file to your IT security quarantine sandbox.';
        break;
      case 'EXECUTE_INSTRUCTION':
        preventiveIntervention = 'CIRCUIT BREAKER: Terminate command execution. Reject prompt overrides or terminal execution directives.';
        break;
      case 'CLICK':
      case 'CLICK_LINK':
      case 'VISIT_WEBSITE':
        preventiveIntervention = 'CIRCUIT BREAKER: Do not open the link. Navigate directly to the official website domain manually.';
        break;
      default:
        preventiveIntervention = 'Standard operational posture: verify unfamiliar origins before interacting.';
        break;
    }

    return {
      analysis: {
        detectedAction,
        actionRisk,
        contentRisk,
        targetDestination,
        evidence: evidenceList,
        preventiveIntervention,
      },
      evidence: {
        detector: 'action_risk',
        score,
        status: 'available',
        evidence: evidenceList,
      },
    };
  }
}
