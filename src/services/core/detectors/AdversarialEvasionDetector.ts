/**
 * NeuroShield Adversarial & Evasion Detector
 * Phase 7.5 — Advanced Security Intelligence
 *
 * Detects deliberate evasion techniques employed by adversaries to bypass
 * automated security filters and deceive human targets:
 * - Homoglyph domains (Cyrillic, Greek, Latin lookalikes)
 * - IDN / Punycode abuse (xn-- prefixes)
 * - URL obfuscation (Hex/Octal IP encoding, double percent-encoding, userinfo spoofing)
 * - Suspicious shorteners and redirect chains
 * - HTML obfuscation (Zero-width characters, Bidi overrides, hidden CSS tags)
 * - Hidden links (Anchor text domain differing from destination href domain)
 * - Mixed-script domain deception
 */

import { UnifiedThreatInput, EvasionAnalysis, DetectorEvidence } from '../types';

export class AdversarialEvasionDetector {
  // Common Cyrillic & Greek homoglyphs mapped to ASCII equivalents
  private static readonly HOMOGLYPH_MAP: Record<string, string> = {
    '\u0430': 'a', // Cyrillic small letter a
    '\u0441': 'c', // Cyrillic small letter es
    '\u0435': 'e', // Cyrillic small letter ie
    '\u043E': 'o', // Cyrillic small letter o
    '\u0440': 'p', // Cyrillic small letter er
    '\u0445': 'x', // Cyrillic small letter ha
    '\u0443': 'y', // Cyrillic small letter u
    '\u0456': 'i', // Cyrillic small letter byelorussian-ukrainian i
    '\u0458': 'j', // Cyrillic small letter je
    '\u0455': 's', // Cyrillic small letter dze
    '\u03B1': 'a', // Greek small letter alpha
    '\u03BF': 'o', // Greek small letter omicron
    '\u03C1': 'p', // Greek small letter rho
    '\u03BD': 'v', // Greek small letter nu
  };

  private static readonly KNOWN_SHORTENERS = new Set([
    'bit.ly',
    'tinyurl.com',
    't.co',
    'is.gd',
    'ow.ly',
    'buff.ly',
    'rb.gy',
    'clck.ru',
    'v.gd',
    'cutt.ly',
    'shorturl.at',
    'tiny.cc',
  ]);

  static evaluate(input: UnifiedThreatInput): {
    analysis: EvasionAnalysis;
    evidence: DetectorEvidence;
  } {
    const evidenceList: string[] = [];
    const techniques: string[] = [];
    let homoglyphsDetected = false;
    let punycodeDetected = false;
    let urlObfuscationDetected = false;
    let redirectChainDetected = false;
    let htmlObfuscationDetected = false;
    let hiddenLinksDetected = false;
    let mixedScriptDetected = false;
    let evasionRiskScore = 0;

    const urls = input.urls || [];
    const rawContent = input.content + ' ' + (input.rawPayload || '');
    const senderDomain = input.sender?.domain || (input.sender?.identifier?.includes('@') ? input.sender.identifier.split('@')[1] : null);

    // 1. EVALUATE DOMAINS & URLS FOR HOMOGLYPHS & MIXED SCRIPT
    const domainsToCheck: string[] = [];
    if (senderDomain) domainsToCheck.push(senderDomain);

    for (const u of urls) {
      // Raw hostname extraction before URL parser converts to Punycode
      const rawHostMatch = u.match(/(?:https?:\/\/)?([^\/\s?#]+)/i);
      if (rawHostMatch && rawHostMatch[1] && !domainsToCheck.includes(rawHostMatch[1])) {
        domainsToCheck.push(rawHostMatch[1]);
      }

      try {
        const parsed = new URL(u.startsWith('http') ? u : `https://${u}`);
        if (parsed.hostname && !domainsToCheck.includes(parsed.hostname)) {
          domainsToCheck.push(parsed.hostname);
        }
      } catch {
        // Fallback for non-standard URI
        const match = u.match(/(?:https?:\/\/)?([a-zA-Z0-9.-]+)/);
        if (match && match[1] && !domainsToCheck.includes(match[1])) {
          domainsToCheck.push(match[1]);
        }
      }
    }

    for (const domain of domainsToCheck) {
      // A. Check for Punycode IDN
      if (domain.toLowerCase().includes('xn--')) {
        punycodeDetected = true;
        techniques.push('PUNYCODE_IDN_ABUSE');
        evasionRiskScore = Math.max(evasionRiskScore, 85);
        evidenceList.push(`Punycode IDN detected in domain '${domain}': Adversary uses internationalized domain name encoding, often leveraged for visual spoofing.`);
      }

      // B. Check for Cyrillic / Greek Homoglyphs & Mixed Script
      let hasLatin = false;
      let hasNonAsciiHomoglyph = false;
      const matchedHomoglyphs: string[] = [];

      for (let i = 0; i < domain.length; i++) {
        const char = domain[i];
        const code = char.charCodeAt(0);
        if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) {
          hasLatin = true;
        } else if (this.HOMOGLYPH_MAP[char] || (code >= 0x0400 && code <= 0x04FF) || (code >= 0x0370 && code <= 0x03FF)) {
          hasNonAsciiHomoglyph = true;
          const mapped = this.HOMOGLYPH_MAP[char] || 'Latin lookalike';
          matchedHomoglyphs.push(`'${char}' (mimics '${mapped}')`);
        }
      }

      if (hasNonAsciiHomoglyph) {
        homoglyphsDetected = true;
        techniques.push('HOMOGLYPH_ATTACK');
        evasionRiskScore = Math.max(evasionRiskScore, 95);
        evidenceList.push(
          `Homoglyph character substitution detected in '${domain}': Characters [${matchedHomoglyphs.join(', ')}] visually spoof Latin letters.`
        );

        if (hasLatin) {
          mixedScriptDetected = true;
          techniques.push('MIXED_SCRIPT_DOMAIN');
          evidenceList.push(`Mixed-script domain detected in '${domain}': Blends Latin and non-Latin character sets to bypass visual inspection.`);
        }
      }
    }

    // 2. URL OBFUSCATION & REDIRECT TECHNIQUES
    for (const u of urls) {
      // A. Hex / Octal IP Obfuscation
      if (/https?:\/\/(?:0x[0-9a-fA-F]+|0[0-7]+)(?:\.|$)/i.test(u) || /https?:\/\/0x[0-9a-fA-F]{8}/i.test(u)) {
        urlObfuscationDetected = true;
        techniques.push('HEX_OCTAL_IP_OBFUSCATION');
        evasionRiskScore = Math.max(evasionRiskScore, 92);
        evidenceList.push(`Obfuscated IP format in URL '${u}': Uses hex/octal numerical representation to hide true destination host.`);
      }

      // B. Double Percent Encoding (%25)
      if (/%25[0-9a-fA-F]{2}/i.test(u)) {
        urlObfuscationDetected = true;
        techniques.push('DOUBLE_URL_ENCODING');
        evasionRiskScore = Math.max(evasionRiskScore, 85);
        evidenceList.push(`Double percent-encoding (%25) detected in URL '${u}': Conceals malicious path parameters from inspection proxies.`);
      }

      // C. Userinfo Spoofing (https://trusted.com@malicious.com)
      try {
        const parsed = new URL(u.startsWith('http') ? u : `https://${u}`);
        if (parsed.username || (u.includes('@') && !u.startsWith('mailto:'))) {
          urlObfuscationDetected = true;
          techniques.push('USERINFO_URL_SPOOF');
          evasionRiskScore = Math.max(evasionRiskScore, 90);
          evidenceList.push(`Userinfo spoofing detected in URL '${u}': Embeds deceptive credentials or trusted brand before '@' symbol to mislead users.`);
        }

        // D. Known URL Shorteners
        const hostname = parsed.hostname.toLowerCase();
        if (this.KNOWN_SHORTENERS.has(hostname)) {
          redirectChainDetected = true;
          techniques.push('URL_SHORTENER_MASKING');
          evasionRiskScore = Math.max(evasionRiskScore, 65);
          evidenceList.push(`Suspicious URL shortener service '${hostname}' used to mask ultimate destination target.`);
        }

        // E. Open Redirect / Redirect Chains
        if (parsed.search && /(?:redirect|dest|destination|url|target|next|r|out|goto)=https?%3A/i.test(parsed.search)) {
          redirectChainDetected = true;
          techniques.push('OPEN_REDIRECT_CHAIN');
          evasionRiskScore = Math.max(evasionRiskScore, 80);
          evidenceList.push(`Open redirect chaining detected in query string '${parsed.search.slice(0, 60)}...': Exploits intermediary domains to forward traffic.`);
        }
      } catch {
        // Invalid URL format
      }
    }

    // 3. HTML OBFUSCATION (Zero-Width Characters, Bidi Overrides, Hidden CSS)
    // A. Zero-width spaces & invisible characters
    const zeroWidthRegex = /[\u200B\u200C\u200D\uFEFF\u2060]/g;
    const zeroWidthMatches = rawContent.match(zeroWidthRegex);
    if (zeroWidthMatches && zeroWidthMatches.length >= 2) {
      htmlObfuscationDetected = true;
      techniques.push('ZERO_WIDTH_CHARACTER_INJECTION');
      evasionRiskScore = Math.max(evasionRiskScore, 88);
      evidenceList.push(`Zero-width invisible characters detected (${zeroWidthMatches.length} occurrences): Adversary injects non-rendering glyphs to break keyword matching filters.`);
    }

    // B. Bi-directional (Bidi) Unicode Overrides
    const bidiRegex = /[\u202E\u202D\u2066\u2067\u2068\u2069]/;
    if (bidiRegex.test(rawContent)) {
      htmlObfuscationDetected = true;
      techniques.push('UNICODE_BIDI_OVERRIDE');
      evasionRiskScore = Math.max(evasionRiskScore, 95);
      evidenceList.push(`Unicode Right-to-Left (RTL) Bidi Override detected: Manipulates visual string rendering order to disguise executable extensions or URLs.`);
    }

    // C. Hidden text CSS tags
    if (
      /(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0(?:px)?|color\s*:\s*transparent)/i.test(rawContent)
    ) {
      htmlObfuscationDetected = true;
      techniques.push('CSS_HIDDEN_CONTENT_OBFUSCATION');
      evasionRiskScore = Math.max(evasionRiskScore, 75);
      evidenceList.push('CSS hidden content styling detected: Text is invisible to humans in browser but parsed by automated systems.');
    }

    // 4. HIDDEN LINKS / ANCHOR TEXT MISMATCH
    // Look for <a href="http://bad.com">https://good.com</a>
    const linkRegex = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
    let match: RegExpExecArray | null;
    while ((match = linkRegex.exec(rawContent)) !== null) {
      const href = match[1];
      const anchorText = match[2].trim();

      // Check if anchor text looks like a URL/domain
      if (/^(?:https?:\/\/)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i.test(anchorText)) {
        try {
          const displayedDomain = anchorText.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
          const targetDomain = new URL(href.startsWith('http') ? href : `https://${href}`).hostname.toLowerCase();

          if (displayedDomain && targetDomain && displayedDomain !== targetDomain && !targetDomain.endsWith('.' + displayedDomain)) {
            hiddenLinksDetected = true;
            techniques.push('ANCHOR_TEXT_DOMAIN_DECEPTION');
            evasionRiskScore = Math.max(evasionRiskScore, 94);
            evidenceList.push(
              `Deceptive hyperlink detected: Display text presents '${displayedDomain}' but underlying destination href routes to '${targetDomain}'.`
            );
          }
        } catch {
          // Ignore parse issues in malformed raw links
        }
      }
    }

    const detected = techniques.length > 0;
    if (!detected) {
      evidenceList.push('No homoglyphs, punycode abuse, URL obfuscation, hidden links, or HTML evasion techniques detected.');
    }

    const analysis: EvasionAnalysis = {
      status: 'available',
      detected,
      evasionRiskScore,
      techniques,
      homoglyphsDetected,
      punycodeDetected,
      urlObfuscationDetected,
      redirectChainDetected,
      htmlObfuscationDetected,
      hiddenLinksDetected,
      mixedScriptDetected,
      evidence: evidenceList,
    };

    const evidence: DetectorEvidence = {
      detector: 'evasion_detection',
      score: evasionRiskScore,
      status: 'available',
      evidence: evidenceList,
    };

    return { analysis, evidence };
  }
}
