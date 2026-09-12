/**
 * NeuroShield Baseline Comparison & Benchmarking Engine
 * Sections 34, 35, 36, 37 — Research Hypothesis Evaluation
 *
 * Compares:
 * 1. BASELINE: Simple message/content/URL-oriented keyword classifier
 * 2. NEUROSHIELD: Context + Sensitive Data + Action + Identity + Intent + Correlation + Attack Transition
 *
 * Measures:
 * - Dangerous-Action Interception Rate
 * - False Positive Rate (especially on Benign Urgency)
 * - Detection-Before-Action Rate
 * - Multi-Stage Gradual Attack Detection (Conversation A)
 */

import { UnifiedInteractionEvent, UnifiedThreatAnalysis } from './types';
import { NeuroShieldCore } from './neuroshieldCore';

export interface BenchmarkScenario {
  id: string;
  category: string;
  categoryCode: string; // 'A' through 'Q'
  title: string;
  input: UnifiedInteractionEvent | UnifiedInteractionEvent[];
  expectedVerdict: 'SAFE' | 'LOW' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL' | 'UNKNOWN';
  expectedDecision: 'ALLOW' | 'WARN' | 'BLOCK';
  dangerousActionMustBeIntercepted: boolean;
  description: string;
}

export interface ComparisonResult {
  scenarioId: string;
  categoryCode: string;
  title: string;
  baseline: {
    flaggedAsThreat: boolean;
    verdict: string;
    actionBlocked: boolean;
    reason: string;
  };
  neuroshield: {
    flaggedAsThreat: boolean;
    verdict: string;
    decision: string;
    riskScore: number;
    actionBlocked: boolean;
    whyRiskIncreased: string[];
  };
  neuroshieldAdvantage: string | null;
}

export class BaselineDetector {
  private static readonly PHISHING_KEYWORDS = [
    'phishing', 'verify account', 'suspended account', 'click here', 'login below',
    'bank account suspended', 'lottery winner', 'wire money immediately', 'act now'
  ];

  private static readonly KNOWN_BAD_DOMAINS = [
    'malicious-phish-portal.com', 'evil-hack.xyz', 'fake-bank-login.net'
  ];

  /**
   * Evaluates input using only naive message-level content and URL matching.
   * Lacks context, relationship history, sensitive data modeling, and action risk.
   */
  static evaluate(input: UnifiedInteractionEvent): {
    flaggedAsThreat: boolean;
    verdict: 'SAFE' | 'MALICIOUS';
    actionBlocked: boolean;
    reason: string;
  } {
    const text = (input.content + ' ' + (input.subject || '')).toLowerCase();
    const urls = input.urls || [];

    // Check bad domain
    const hasBadUrl = urls.some(u => BaselineDetector.KNOWN_BAD_DOMAINS.some(bad => u.toLowerCase().includes(bad)));
    if (hasBadUrl) {
      return {
        flaggedAsThreat: true,
        verdict: 'MALICIOUS',
        actionBlocked: true,
        reason: 'Known malicious URL domain found in message.',
      };
    }

    // Naive keyword match
    const matchedKeywords = BaselineDetector.PHISHING_KEYWORDS.filter(k => text.includes(k));
    if (matchedKeywords.length >= 2) {
      return {
        flaggedAsThreat: true,
        verdict: 'MALICIOUS',
        actionBlocked: true,
        reason: `Matched static keyword heuristics: [${matchedKeywords.join(', ')}]`,
      };
    }

    // False positive trap: flagging any message with urgency
    if (text.includes('urgent') && text.includes('immediately')) {
      return {
        flaggedAsThreat: true,
        verdict: 'MALICIOUS',
        actionBlocked: true,
        reason: 'Flagged solely on urgency keywords (prone to false positive).',
      };
    }

    return {
      flaggedAsThreat: false,
      verdict: 'SAFE',
      actionBlocked: false,
      reason: 'No obvious static phishing keywords or known blacklisted domains detected.',
    };
  }
}

export class BenchmarkEngine {
  /**
   * Executes the controlled 5-stage Conversation A experiment (Section 37).
   */
  static async runConversationAExperiment(): Promise<{
    steps: Array<{
      time: string;
      message: string;
      baselineResult: string;
      neuroshieldRisk: number;
      neuroshieldStage: string;
      neuroshieldDecision: string;
    }>;
    transitionDetected: boolean;
    finalActionIntercepted: boolean;
  }> {
    const conversationSteps: Array<{
      time: string;
      message: string;
      source: 'sms' | 'email';
      sender: string;
    }> = [
      { time: '09:00', message: 'Hi, are you available?', source: 'sms', sender: '+91-98765-43210' },
      { time: '11:00', message: "I'm using a new number.", source: 'sms', sender: '+91-98765-43210' },
      { time: '13:00', message: 'Please keep this confidential.', source: 'sms', sender: '+91-98765-43210' },
      { time: '13:05', message: 'Send me the OTP and employee file.', source: 'sms', sender: '+91-98765-43210' },
      { time: '13:06', message: 'Transfer ₹2 lakh urgently.', source: 'sms', sender: '+91-98765-43210' },
    ];

    const results: any[] = [];
    const eventSequence: UnifiedInteractionEvent[] = [];

    for (let i = 0; i < conversationSteps.length; i++) {
      const step = conversationSteps[i];
      const event: UnifiedInteractionEvent = {
        id: `conv_a_step_${i + 1}`,
        source: step.source,
        timestamp: `2026-09-12T${step.time}:00Z`,
        content: step.message,
        sender: { identifier: step.sender, displayName: 'Unverified Sender' },
        urls: [],
        attachments: [],
        history: {
          previousInteractionsCount: i,
          firstContactDate: '2026-09-12T09:00:00Z',
          isKnownContact: false,
        },
      };

      eventSequence.push(event);

      // Baseline evaluates each message individually
      const baselineRes = BaselineDetector.evaluate(event);

      // NeuroShield evaluates the progressive sequence
      const neuroAnalysis: UnifiedThreatAnalysis = await NeuroShieldCore.analyzeSequence([...eventSequence]);

      results.push({
        time: step.time,
        message: step.message,
        baselineResult: `${baselineRes.verdict} (${baselineRes.actionBlocked ? 'BLOCK' : 'ALLOW'})`,
        neuroshieldRisk: neuroAnalysis.risk_score,
        neuroshieldStage: neuroAnalysis.attack_sequence?.stagesDetected?.slice(-1)[0] || 'OBSERVED',
        neuroshieldDecision: neuroAnalysis.protection.decision,
      });
    }

    const finalResult = results[results.length - 1];
    const finalActionIntercepted = finalResult.neuroshieldDecision === 'BLOCK';
    const transitionDetected = results[3].neuroshieldRisk >= 80 && results[4].neuroshieldRisk >= 90;

    return {
      steps: results,
      transitionDetected,
      finalActionIntercepted,
    };
  }
}
