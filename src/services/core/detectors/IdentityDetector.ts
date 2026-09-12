/**
 * NeuroShield Identity Continuity Engine
 * Phase 7.5 — Advanced Security Intelligence
 *
 * Evaluates sender authenticity, display-name spoofing, routing consistency,
 * and historical identity continuity.
 *
 * CRITICAL PRIVACY & FORENSIC DIRECTIVES:
 * 1. Photo or name similarity alone MUST NEVER prove identity.
 * 2. If historical identity information is unavailable:
 *    historical_identity_analysis = 'UNAVAILABLE'. Never fabricate history.
 * 3. Evaluate identity consistency strictly across available observed signals.
 */

import { UnifiedThreatInput, IdentityAnalysis, DetectorEvidence, IdentityContinuityEvidence } from '../types';
import { checkDomainTyposquatting, extractDomainFromEmail } from '../forensicsEngineProxy';

export class IdentityDetector {
  static evaluate(input: UnifiedThreatInput): {
    analysis: IdentityAnalysis;
    evidence: DetectorEvidence;
  } {
    const sender = input.sender;
    const evidenceList: string[] = [];

    // Check if historical identity baseline is actually available
    const hasHistory = Boolean(
      input.history &&
      (input.history.previousInteractionsCount !== undefined ||
        input.history.knownSenderTrustScore !== undefined ||
        input.history.firstContactDate !== undefined)
    );
    const historical_identity_analysis: 'AVAILABLE' | 'UNAVAILABLE' = hasHistory ? 'AVAILABLE' : 'UNAVAILABLE';

    // If sender is completely missing/unprovided
    if (!sender || (!sender.identifier && !sender.displayName)) {
      const continuity: IdentityContinuityEvidence = {
        identity_match: null,
        identity_mismatch: false,
        identity_change: false,
        identity_novelty: false,
        identity_confidence: 0,
        historical_identity_analysis,
        evidence: ['Sender metadata was not provided; identity continuity analysis unavailable.'],
        signals: ['NO_SENDER_METADATA'],
      };

      return {
        analysis: {
          status: 'unavailable',
          statusReason: 'No sender metadata supplied in interaction payload',
          claimedIdentity: null,
          actualIdentity: null,
          domainMatch: null,
          isSpoofed: false,
          isAnomalousDisplay: false,
          identity_match: null,
          identity_mismatch: false,
          identity_change: false,
          identity_novelty: false,
          identity_confidence: 0,
          historical_identity_analysis,
          continuity,
          risk: 0,
          riskScore: 0,
          signals: [],
          evidence: ['Sender metadata was not provided; identity evaluation unavailable.'],
        },
        evidence: {
          detector: 'identity_engine',
          score: 0,
          status: 'unavailable',
          statusReason: 'No sender metadata supplied',
          evidence: ['Sender metadata was not provided.'],
        },
      };
    }

    let riskScore = 0;
    let isSpoofed = false;
    let isAnomalousDisplay = false;
    let fromReplyToMismatch = false;
    let newSender = false;
    let identity_novelty = false;
    let identity_change = false;
    let identity_mismatch = false;
    let identity_match: boolean | null = null;
    let identity_confidence = 50;

    const signals: string[] = [];
    const claimedIdentity = sender.displayName || null;
    const actualIdentity = sender.identifier || null;
    const domain = sender.domain || (actualIdentity ? extractDomainFromEmail(actualIdentity) : '');
    let domainMatch: boolean | null = null;

    // 1. HISTORICAL CONTINUITY EVALUATION
    if (hasHistory && input.history) {
      identity_confidence += 25;
      if (input.history.previousInteractionsCount === 0) {
        newSender = true;
        identity_novelty = true;
        signals.push('IDENTITY_NOVELTY');
        evidenceList.push('Historical baseline indicates initial contact: 0 prior interactions recorded for this identifier.');
      } else if ((input.history.previousInteractionsCount ?? 0) > 0) {
        evidenceList.push(`Historical continuity baseline available: ${input.history.previousInteractionsCount} prior interactions recorded.`);
        // Check for sudden identity deviation if known identity exists
        if (input.history.knownIdentity && claimedIdentity && input.history.knownIdentity !== claimedIdentity) {
          identity_change = true;
          signals.push('HISTORICAL_IDENTITY_CHANGE');
          riskScore = Math.max(riskScore, 75);
          evidenceList.push(
            `IDENTITY CONTINUITY DEVIATION: Historical identity was '${input.history.knownIdentity}', but current display name asserts '${claimedIdentity}'.`
          );
        }
      }
    } else {
      evidenceList.push('Historical identity telemetry unavailable: Evaluating observable interaction signals in isolation.');
    }

    // 2. SENDER IDENTITY VS DOMAIN & BRAND IMPERSONATION
    if (claimedIdentity && actualIdentity && actualIdentity.includes('@')) {
      const wellKnownBrands = [
        'paypal', 'microsoft', 'google', 'apple', 'amazon', 'netflix',
        'chase', 'bank of america', 'wells fargo', 'dropbox', 'meta', 'facebook',
        'dhl', 'fedex', 'usps', 'ups', 'adobe', 'linkedin', 'twitter', 'github'
      ];
      const lowerDisplay = claimedIdentity.toLowerCase();
      const lowerDomain = domain.toLowerCase();

      for (const brand of wellKnownBrands) {
        if (lowerDisplay.includes(brand) && !lowerDomain.includes(brand)) {
          isSpoofed = true;
          isAnomalousDisplay = true;
          identity_mismatch = true;
          signals.push('DISPLAY_NAME_BRAND_IMPERSONATION');
          riskScore = Math.max(riskScore, 92);
          evidenceList.push(`BRAND IMPERSONATION: Display name claims '${brand.toUpperCase()}', but sending domain is '${lowerDomain}'.`);
          domainMatch = false;
          break;
        }
      }

      // Check for Executive / VIP Authority Impersonation
      const executiveRoles = ['ceo', 'chief executive', 'cfo', 'vp finance', 'director', 'president', 'managing director', 'treasury'];
      const hasExecRole = executiveRoles.some((r) => lowerDisplay.includes(r));
      if (hasExecRole && !lowerDomain.includes('corp') && !lowerDomain.includes('enterprise') && !lowerDomain.includes('internal')) {
        signals.push('EXECUTIVE_IMPERSONATION_TAG');
        riskScore = Math.max(riskScore, 70);
        evidenceList.push(`AUTHORITY CLAIM: Sender asserts executive title ('${claimedIdentity}') originating from non-corporate domain '${domain}'.`);
      }

      // Check if display name embeds a fake email address
      const emailInDisplay = claimedIdentity.match(/[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
      if (emailInDisplay && emailInDisplay[1].toLowerCase() !== lowerDomain) {
        isAnomalousDisplay = true;
        identity_mismatch = true;
        signals.push('EMBEDDED_ADDRESS_DECEPTION');
        riskScore = Math.max(riskScore, 90);
        evidenceList.push(`EMBEDDED ADDRESS SPOOF: Display name displays '${emailInDisplay[0]}' while routing from '${actualIdentity}'.`);
      }
    }

    // 3. FROM / REPLY-TO MISMATCH (ROUTING DIVERSION)
    const replyTo = input.metadata?.replyTo || input.metadata?.headers?.['reply-to'];
    if (replyTo && typeof replyTo === 'string' && actualIdentity) {
      const replyDomain = extractDomainFromEmail(replyTo);
      if (replyDomain && domain && replyDomain.toLowerCase() !== domain.toLowerCase()) {
        fromReplyToMismatch = true;
        identity_mismatch = true;
        signals.push('FROM_REPLY_TO_MISMATCH');
        riskScore = Math.max(riskScore, 85);
        evidenceList.push(`ROUTING DIVERSION: From domain '${domain}' diverts user replies to separate destination '${replyTo}'.`);
      }
    }

    // 4. DOMAIN TYPOSQUATTING & HOMOGLYPH CHECK
    if (domain) {
      try {
        const typoResult = checkDomainTyposquatting(domain);
        if (typoResult.isTyposquat && typoResult.targetedBrand) {
          isSpoofed = true;
          identity_mismatch = true;
          signals.push('DOMAIN_TYPOSQUATTING');
          riskScore = Math.max(riskScore, 94);
          evidenceList.push(`TYPOSQUATTING: Domain '${domain}' deceptively mimics protected brand '${typoResult.targetedBrand}'.`);
        }
      } catch {
        // Fallback gracefully
      }
    }

    // 5. SMS IDENTITY SIGNALS
    if (input.source === 'sms') {
      if (sender.phone && !sender.phone.startsWith('+')) {
        signals.push('SMS_UNVERIFIED_PHONE_PREFIX');
        evidenceList.push(`SMS routing: Sender phone '${sender.phone}' lacks international standard E.164 prefix.`);
        riskScore = Math.max(riskScore, 40);
      } else if (sender.displayName && !sender.phone) {
        signals.push('SMS_ALPHANUMERIC_SENDER_ID');
        evidenceList.push(`Alphanumeric Sender ID '${sender.displayName}' used without verifiable two-way routing phone.`);
        riskScore = Math.max(riskScore, 50);
      }
    }

    // 6. CRYPTOGRAPHIC AUTHENTICATION CONTRIBUTION
    const headers = input.metadata?.headers;
    if (headers) {
      const auth = (headers['authentication-results'] || headers['received-spf'] || '').toLowerCase();
      if (auth.includes('spf=pass') && auth.includes('dkim=pass') && auth.includes('dmarc=pass')) {
        identity_confidence = Math.min(95, identity_confidence + 15);
        evidenceList.push('Cryptographic domain authentication (SPF/DKIM/DMARC) validated for sending infrastructure.');
      }
    }

    // 7. FINAL CONTINUITY SYNTHESIS
    if (identity_mismatch || isSpoofed) {
      identity_match = false;
    } else if (hasHistory && (input.history?.previousInteractionsCount ?? 0) > 0 && !identity_change) {
      identity_match = true;
      signals.push('IDENTITY_CONTINUITY_VERIFIED');
      evidenceList.push('Sender identity matches established interaction baseline.');
    } else {
      // Photo or name similarity alone MUST NEVER prove identity!
      identity_match = null;
      if (!isSpoofed && !fromReplyToMismatch) {
        signals.push('IDENTITY_UNCONFIRMED_NEUTRAL');
        evidenceList.push('Identity unconfirmed: Absence of spoofing does not prove authentic entity without historical or cryptographic attestation.');
      }
    }

    evidenceList.push('FORENSIC PRINCIPLE: Photo, name, or profile similarity alone must never be accepted as proof of authentic identity.');

    const continuity: IdentityContinuityEvidence = {
      identity_match,
      identity_mismatch,
      identity_change,
      identity_novelty,
      identity_confidence,
      historical_identity_analysis,
      evidence: evidenceList,
      signals,
    };

    return {
      analysis: {
        status: 'available',
        claimedIdentity,
        actualIdentity,
        domainMatch,
        isSpoofed,
        isAnomalousDisplay,
        fromReplyToMismatch,
        newSender,
        identity_match,
        identity_mismatch,
        identity_change,
        identity_novelty,
        identity_confidence,
        historical_identity_analysis,
        continuity,
        risk: riskScore,
        riskScore,
        signals,
        evidence: evidenceList,
      },
      evidence: {
        detector: 'identity_engine',
        score: riskScore,
        status: 'available',
        evidence: evidenceList,
      },
    };
  }
}
