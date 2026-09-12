/**
 * NeuroShield Technical Evidence Detector
 * Analyzes infrastructure properties: URLs, reverse tunnels, typosquatting, authentication (SPF/DKIM/DMARC), and IP origin.
 */

import { UnifiedThreatInput, TechnicalEvidenceAnalysis, DetectorEvidence } from '../types';
import { detectReverseTunnel, checkDomainTyposquatting } from '../forensicsEngineProxy';

export class TechnicalDetector {
  static evaluate(input: UnifiedThreatInput): {
    analysis: TechnicalEvidenceAnalysis;
    evidence: DetectorEvidence;
  } {
    const urls = input.urls || [];
    const evidenceList: string[] = [];
    let reverseTunnelDetected = false;
    const reverseTunnelProviders: string[] = [];
    let typosquattingDetected = false;
    let nrdDetected = false;
    let suspiciousTldDetected = false;
    let excessiveSubdomainsDetected = false;
    let encodedUrlDetected = false;
    let bareIpUrlDetected = false;
    let riskScore = 0;

    // 1. Evaluate URLs (URL / Web Intelligence Engine)
    for (const urlStr of urls) {
      try {
        const parsed = new URL(urlStr.startsWith('http') ? urlStr : `https://${urlStr}`);
        const hostname = parsed.hostname;

        // A. Reverse Tunnel Evasion Check
        const tunnelCheck = detectReverseTunnel(hostname, urlStr);
        if (tunnelCheck.isReverseTunnel) {
          reverseTunnelDetected = true;
          if (tunnelCheck.provider && !reverseTunnelProviders.includes(tunnelCheck.provider)) {
            reverseTunnelProviders.push(tunnelCheck.provider);
          }
          riskScore = Math.max(riskScore, 95);
          evidenceList.push(`EPHEMERAL REVERSE TUNNEL: URL destination '${urlStr}' leverages ${tunnelCheck.provider || 'reverse proxy'} to bypass domain reputation filters and mask origin infrastructure.`);
        }

        // B. Domain Typosquatting Check
        const typoResult = checkDomainTyposquatting(hostname);
        if (typoResult.isTyposquat && typoResult.targetedBrand) {
          typosquattingDetected = true;
          riskScore = Math.max(riskScore, 92);
          evidenceList.push(`TYPOSQUATTING: Hostname '${hostname}' mimics legitimate brand domain '${typoResult.targetedBrand}'.`);
        }

        // C. Excessive Subdomains (Domain Cloaking / Subdomain Stacking)
        const parts = hostname.split('.');
        if (parts.length >= 4) {
          excessiveSubdomainsDetected = true;
          riskScore = Math.max(riskScore, 78);
          evidenceList.push(`SUBDOMAIN STACKING: Hostname '${hostname}' contains excessive subdomain depth (${parts.length} levels) to cloak real registrar root.`);
        }

        // D. Suspicious / Abused TLDs
        const suspiciousTlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.work', '.icu', '.country', '.surf', '.zip', '.mov'];
        const matchedTld = suspiciousTlds.find((tld) => hostname.toLowerCase().endsWith(tld));
        if (matchedTld) {
          suspiciousTldDetected = true;
          riskScore = Math.max(riskScore, 70);
          evidenceList.push(`HIGH-ABUSE TLD: Hostname '${hostname}' uses top-level domain '${matchedTld}' with statistically elevated phishing incidence.`);
        }

        // E. Encoded / Obfuscated URLs
        if (/%[0-9a-fA-F]{2}/.test(urlStr) || urlStr.includes('base64') || (parsed.search && /(redirect=|url=|dest=|target=)/i.test(parsed.search))) {
          encodedUrlDetected = true;
          riskScore = Math.max(riskScore, 72);
          evidenceList.push(`URL OBFUSCATION / OPEN REDIRECT: URL contains hex-encoding or redirection parameter ('${urlStr.slice(0, 70)}...').`);
        }

        // F. URL Length Anomaly (> 120 chars)
        if (urlStr.length > 120) {
          riskScore = Math.max(riskScore, 65);
          evidenceList.push(`EXTENDED URL LENGTH: URL exceeds 120 characters (${urlStr.length} chars), characteristic of token stuffing or token cloaking.`);
        }

        // G. Suspicious Path / Authentication Target
        if (/(login|signin|verify|auth|session|update-billing|account-update)/i.test(parsed.pathname)) {
          riskScore = Math.max(riskScore, 60);
          evidenceList.push(`SUSPICIOUS AUTHENTICATION PATH: URL directs to sensitive authentication endpoint: ${parsed.pathname}`);
        }

        // H. Suspicious file extensions in URL
        if (/\.(exe|scr|bat|vbs|ps1|iso|apk|hta)($|\?)/i.test(parsed.pathname)) {
          riskScore = Math.max(riskScore, 96);
          evidenceList.push(`MALICIOUS PAYLOAD EXTENSION: Direct download link for executable file (${parsed.pathname}).`);
        }

        // I. IP Address in Hostname (Bare IP)
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
          bareIpUrlDetected = true;
          riskScore = Math.max(riskScore, 75);
          evidenceList.push(`BARE IP NAVIGATION: Hostname '${hostname}' uses direct numeric IPv4 address instead of registered domain.`);
        }
      } catch {
        // Handle malformed URL gracefully
        evidenceList.push(`MALFORMED URL: Unable to parse URL structure '${urlStr}'.`);
        riskScore = Math.max(riskScore, 40);
      }
    }

    // 2. Authentication signals (if email headers or auth metadata present)
    let spfStatus: TechnicalEvidenceAnalysis['spfStatus'] = input.metadata?.spfStatus || 'UNAVAILABLE';
    let dkimStatus: TechnicalEvidenceAnalysis['dkimStatus'] = input.metadata?.dkimStatus || 'UNAVAILABLE';
    let dmarcStatus: TechnicalEvidenceAnalysis['dmarcStatus'] = input.metadata?.dmarcStatus || 'UNAVAILABLE';

    if (input.source === 'email' || input.metadata?.headers || input.metadata?.authResults) {
      const headers = input.metadata?.headers || {};
      const authResults = headers['authentication-results'] || headers['received-spf'] || input.metadata?.authResults || '';
      const authStr = (Array.isArray(authResults) ? authResults.join(' ') : String(authResults)).toLowerCase();

      if (authStr.includes('spf=pass') || authStr.includes('spf pass')) spfStatus = 'PASS';
      else if (authStr.includes('spf=fail') || authStr.includes('spf fail')) { spfStatus = 'FAIL'; riskScore = Math.max(riskScore, 70); evidenceList.push('SPF validation failed.'); }
      else if (authStr.includes('spf=softfail') || authStr.includes('spf softfail')) { spfStatus = 'SOFTFAIL'; riskScore = Math.max(riskScore, 45); }

      if (authStr.includes('dkim=pass') || authStr.includes('dkim pass')) dkimStatus = 'PASS';
      else if (authStr.includes('dkim=fail') || authStr.includes('dkim fail')) { dkimStatus = 'FAIL'; riskScore = Math.max(riskScore, 75); evidenceList.push('DKIM cryptographic signature verification failed.'); }

      if (authStr.includes('dmarc=pass') || authStr.includes('dmarc pass')) dmarcStatus = 'PASS';
      else if (authStr.includes('dmarc=fail') || authStr.includes('dmarc fail')) { dmarcStatus = 'FAIL'; riskScore = Math.max(riskScore, 85); evidenceList.push('DMARC domain alignment policy failed.'); }

      // Detect SPF/DKIM/DMARC Conflict (e.g. SPF pass on third-party relay but DMARC fail or DKIM fail)
      if (spfStatus === 'PASS' && (dmarcStatus === 'FAIL' || dkimStatus === 'FAIL')) {
        riskScore = Math.max(riskScore, 80);
        evidenceList.push('AUTHENTICATION CONFLICT: SPF passes origin host but DMARC/DKIM alignment fails (indicative of third-party relay abuse or header spoofing).');
      }

      if (spfStatus === 'PASS' && dkimStatus === 'PASS' && dmarcStatus === 'PASS') {
        evidenceList.push('Technical note: SPF, DKIM, and DMARC passed cryptographic validation.');
      }
    }

    // Add forensic principle reminders as required by Phase 3
    evidenceList.push('Forensic baseline: SPF/DKIM/DMARC PASS does not mean the message is safe.');
    if (input.sender?.ip) {
      evidenceList.push('Forensic baseline: IP geolocation describes observed infrastructure, not the physical location of the attacker.');
    }

    if (urls.length === 0 && evidenceList.length <= 2) {
      evidenceList.unshift('No external hyperlinks, tunnels, or infrastructure anomalies detected.');
      riskScore = 0;
    }

    return {
      analysis: {
        status: 'available',
        urlsEvaluated: urls.length,
        reverseTunnelDetected,
        reverseTunnelProviders: reverseTunnelProviders.length > 0 ? reverseTunnelProviders : undefined,
        nrdDetected,
        typosquattingDetected,
        suspiciousTldDetected,
        excessiveSubdomainsDetected,
        encodedUrlDetected,
        bareIpUrlDetected,
        spfStatus,
        dkimStatus,
        dmarcStatus,
        ipIntelligence: input.sender?.ip ? {
          ip: input.sender.ip,
          country: input.metadata?.country,
          asn: input.metadata?.asn,
        } : null,
        riskScore,
        evidence: evidenceList,
      },
      evidence: {
        detector: 'technical_evidence',
        score: riskScore,
        status: 'available',
        evidence: evidenceList,
      },
    };
  }
}
