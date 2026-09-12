/**
 * NeuroShield Adversarial Prompt Injection Detector
 * Phase 7.5 — Advanced Security Intelligence
 *
 * Treats ALL input as UNTRUSTED DATA.
 * Employs structural syntax analysis, regex patterns, and semantic indicator matching to detect:
 * 1. Instruction Override & Policy Reset
 * 2. Secret & System Prompt Extraction
 * 3. Security Control Disabling & Verdict Tampering
 * 4. System / Admin Role Impersonation & Jailbreaks
 * 5. AI Tool Hijacking & Command Induction
 */

import { UnifiedThreatInput, PromptInjectionAnalysis, DetectorEvidence } from '../types';

export class PromptInjectionDetector {
  static evaluate(input: UnifiedThreatInput): {
    analysis: PromptInjectionAnalysis;
    evidence: DetectorEvidence;
  } {
    const rawPayload = (input.content + '\n' + (input.rawPayload || '')).trim();
    const lower = rawPayload.toLowerCase();
    const evidenceList: string[] = [];
    const matchedTokens: string[] = [];
    const categories: string[] = [];

    // 1. INSTRUCTION OVERRIDE & POLICY RESET
    const overridePatterns = [
      /(?:ignore|disregard|forget|bypass|override|drop|disable)\s+(?:all\s+)?(?:previous|prior|above|existing|system|security)?\s*(?:instructions|directives|prompts|rules|policies|guidelines|filters|checks|guardrails)/i,
      /(?:reset|clear|discard)\s+(?:your\s+)?(?:context|memory|system\s+prompt|guidelines|initial\s+instructions)/i,
      /new\s+instructions\s+follow|start\s+new\s+session\s+(?:with\s+no\s+rules|in\s+developer\s+mode)/i,
      /do\s+not\s+(?:follow|adhere\s+to)\s+(?:your\s+)?(?:safety\s+rules|system\s+prompt)/i,
    ];

    for (const pattern of overridePatterns) {
      const match = rawPayload.match(pattern);
      if (match) {
        matchedTokens.push(match[0]);
        if (!categories.includes('INSTRUCTION_OVERRIDE')) {
          categories.push('INSTRUCTION_OVERRIDE');
          evidenceList.push(`SYSTEM INSTRUCTION OVERRIDE: Adversary explicitly instructs AI to discard prior constraints ('${match[0]}').`);
        }
      }
    }

    // 2. SECRET & SYSTEM PROMPT EXTRACTION
    const extractionPatterns = [
      /(?:reveal|print|show|output|echo|display|dump|leak|tell\s+me)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions?|hidden\s+prompt|developer\s+mode|api\s+keys?|secret\s+tokens?|operating\s+instructions)/i,
      /what\s+(?:are|were)\s+your\s+(?:initial|original|starting)\s+instructions/i,
      /repeat\s+the\s+(?:words|text|instructions)\s+above/i,
    ];

    for (const pattern of extractionPatterns) {
      const match = rawPayload.match(pattern);
      if (match) {
        matchedTokens.push(match[0]);
        if (!categories.includes('PROMPT_EXTRACTION')) {
          categories.push('PROMPT_EXTRACTION');
          evidenceList.push(`PROMPT EXFILTRATION ATTEMPT: Directive probes to dump hidden system instructions or developer secrets ('${match[0]}').`);
        }
      }
    }

    // 3. SECURITY CONTROL DISABLING & VERDICT TAMPERING
    const tamperingPatterns = [
      /(?:disable|turn\s+off|bypass|suspend|deactivate)\s+(?:security|safety|content\s+filters?|guardrails|scanning|safety\s+checks)/i,
      /(?:classify|label|mark|return|set\s+(?:risk\s+score|verdict))\s+(?:this\s+)?(?:message\s+|email\s+)?(?:as|to|=)\s*(?:safe|benign|zero\s+risk|not\s+phishing|0)/i,
      /threat\s+risk\s+score\s+(?:of|to|=)?\s*0|verdict\s*(?::|to|=)\s*"?safe"?/i,
      /(?:output|respond\s+with)\s+(?:only\s+)?(?:json\s*:\s*)?\{.*"(?:verdict|status|safe)"/i,
    ];

    for (const pattern of tamperingPatterns) {
      const match = rawPayload.match(pattern);
      if (match) {
        matchedTokens.push(match[0]);
        if (!categories.includes('SECURITY_TAMPERING')) {
          categories.push('SECURITY_TAMPERING');
          evidenceList.push(`SECURITY VERDICT TAMPERING: Direct attempt to coerce security classifier into outputting a false SAFE verdict ('${match[0]}').`);
        }
      }
    }

    // 4. SYSTEM / ADMIN ROLE IMPERSONATION & JAILBREAKS
    const impersonationPatterns = [
      /(?:^|\n|\s)\s*\[\s*(?:system\s+instruction|system|admin|root|developer|operator)\s*:[^\]]*\]/i,
      /(?:^|\n)\s*(?:\[\s*(?:system|admin|root|developer|operator)\s*\]|\<\s*(?:system|admin|sys)\s*\>|(?:system|admin|operator)\s*:)/i,
      /<\|im_start\|>system|<\|im_end\|>|<<sys>>|<\/s>|<!--\s*system:\s*ignore\s*-->/i,
      /---+\s*(?:begin|start)\s+(?:system|admin|override)\s*---+/i,
      /you\s+are\s+now\s+(?:an?\s+)?(?:unfiltered|jailbroken|dan|developer\s+mode|uncensored)\s+(?:ai|assistant|model|bot)/i,
      /jailbreak\s+activated|developer\s+mode\s+enabled/i,
    ];

    for (const pattern of impersonationPatterns) {
      const match = rawPayload.match(pattern);
      if (match) {
        matchedTokens.push(match[0]);
        if (!categories.includes('ROLE_IMPERSONATION')) {
          categories.push('ROLE_IMPERSONATION');
          evidenceList.push(`SYSTEM ROLE IMPERSONATION / JAILBREAK: Uses system markup tags or jailbreak personas to hijack context ('${match[0].slice(0, 30)}').`);
        }
      }
    }

    // 5. TOOL HIJACKING & UNCHECKED COMMAND INDUCTION
    const toolHijackingPatterns = [
      /(?:execute|run)\s+(?:terminal\s+command|powershell|bash|regsvr32|cmd\.exe|script)\s*:/i,
      /curl\s+https?:\/\/.*\|\s*(?:bash|sh)/i,
      /send\s+(?:prompt|conversation|history|data)\s+to\s+https?:\/\//i,
      /call\s+function\s*:\s*(?:execute_code|send_payment|delete_database)/i,
    ];

    for (const pattern of toolHijackingPatterns) {
      const match = rawPayload.match(pattern);
      if (match) {
        matchedTokens.push(match[0]);
        if (!categories.includes('TOOL_HIJACKING')) {
          categories.push('TOOL_HIJACKING');
          evidenceList.push(`UNSAFE EXECUTION DIRECTIVE: Attempts to induce command or script execution via assistant tools ('${match[0]}').`);
        }
      }
    }

    const detected = categories.length > 0;
    const adversarialRiskScore = detected ? (categories.length >= 2 ? 99 : 95) : 0;

    if (!detected) {
      evidenceList.push('No adversarial prompt injection tokens, system overrides, or jailbreak patterns detected.');
    }

    return {
      analysis: {
        status: 'available',
        detected,
        overrideTokens: Array.from(new Set(matchedTokens)),
        adversarialRiskScore,
        evidence: evidenceList,
      },
      evidence: {
        detector: 'prompt_injection',
        score: adversarialRiskScore,
        status: 'available',
        evidence: evidenceList,
      },
    };
  }
}
