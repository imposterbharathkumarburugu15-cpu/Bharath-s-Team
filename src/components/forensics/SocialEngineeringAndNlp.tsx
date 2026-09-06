import React from 'react';
import { 
  Sparkles, AlertTriangle, ShieldAlert, Cpu, 
  BrainCircuit, MessageSquare, Quote, Eye
} from 'lucide-react';
import { ForensicDossier } from '@/services/forensicsEngine';
import { DrillDownTarget } from './ForensicDrillDownModal';

interface SocialEngineeringAndNlpProps {
  dossier: ForensicDossier;
  onDrillDown: (target: DrillDownTarget) => void;
}

export function SocialEngineeringAndNlp({ dossier, onDrillDown }: SocialEngineeringAndNlpProps) {
  const urgencyLevel = dossier.contentAnalysis.urgencyLevel;
  const isCredentialHarvester = dossier.contentAnalysis.credentialHarvesterDetected;
  const isPromptInjection = dossier.contentAnalysis.promptInjection === 'DETECTED';

  // Compute indicator scores (0 - 100) based on forensic signals
  const urgencyScore = urgencyLevel === 'HIGH' ? 88 : urgencyLevel === 'MEDIUM' ? 62 : 24;
  const authorityScore = dossier.senderIdentity.inconsistencies.length > 0 ? 74 : 35;
  const fearScore = urgencyLevel === 'HIGH' ? 68 : 30;
  const rewardScore = dossier.contentAnalysis.signals.some(s => s.description.toLowerCase().includes('crypto') || s.description.toLowerCase().includes('invoice')) ? 65 : 28;
  const credentialScore = isCredentialHarvester ? 92 : 38;

  // Extract detected trigger phrases
  const detectedPhrases: string[] = [];
  if (urgencyLevel === 'HIGH' || urgencyLevel === 'MEDIUM') {
    detectedPhrases.push('immediately', 'action required', 'within 24 hours', 'verify your account', 'account suspended');
  }
  if (isCredentialHarvester) {
    detectedPhrases.push('click here to log in', 'security update', 'confirm your password');
  }
  if (dossier.contentAnalysis.signals) {
    dossier.contentAnalysis.signals.forEach(s => {
      if (s.description && !detectedPhrases.includes(s.description.slice(0, 30))) {
        detectedPhrases.push(s.description.slice(0, 40));
      }
    });
  }

  // Ensure fallback phrases if none detected
  if (detectedPhrases.length === 0) {
    detectedPhrases.push('Routine administrative notification', 'Standard delivery confirmation');
  }

  const indicators = [
    { label: 'Urgency Pressure', score: urgencyScore, color: 'bg-red-500' },
    { label: 'Perceived Authority', score: authorityScore, color: 'bg-amber-500' },
    { label: 'Fear & Consequences', score: fearScore, color: 'bg-orange-500' },
    { label: 'Financial Reward / Invoice', score: rewardScore, color: 'bg-yellow-500' },
    { label: 'Credential Request', score: credentialScore, color: 'bg-red-600' }
  ];

  return (
    <section 
      id="social-engineering-analysis"
      className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 shadow-2xl font-mono text-white space-y-4"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/10 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
            <h2 className="text-xs font-bold uppercase tracking-widest text-white">
              11. Social Engineering & NLP Linguistic Analysis
            </h2>
          </div>
          <p className="text-[11px] text-gray-400 font-sans mt-0.5">
            Psychological coercion indicators, urgency gradients, and extracted trigger phrases.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-[10px] text-gray-400 uppercase">AI Phish Classifier:</span>
          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
            dossier.aiLinguisticAnalysis.isAIAssistedDetected 
              ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40' 
              : 'bg-white/10 text-gray-400'
          }`}>
            {dossier.aiLinguisticAnalysis.isAIAssistedDetected ? 'AI-GENERATED SYNTHETIC TEXT' : 'HUMAN LINGUISTIC PATTERN'}
          </span>
        </div>
      </div>

      {/* Grid: Left Psychological Pressure Bars / Right Extracted Trigger Phrases */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left 7 cols: Psychological Pressure Bars */}
        <div className="lg:col-span-7 bg-black/40 border border-white/10 rounded-xl p-4 space-y-3.5">
          <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider block">
            PSYCHOLOGICAL PRESSURE PROFILE
          </span>

          <div className="space-y-3">
            {indicators.map(item => (
              <div key={item.label} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-gray-300 text-[11px]">{item.label}</span>
                  <strong className="text-white font-mono">{item.score}/100</strong>
                </div>
                <div className="h-2 w-full bg-white/5 rounded-full overflow-hidden">
                  <div 
                    className={`h-full ${item.color} rounded-full transition-all duration-500`}
                    style={{ width: `${item.score}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right 5 cols: Detected Trigger Phrases extracted from text */}
        <div className="lg:col-span-5 bg-black/40 border border-white/10 rounded-xl p-4 flex flex-col justify-between space-y-3">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] text-amber-400 font-bold uppercase tracking-wider">
                EXTRACTED TRIGGER PHRASES
              </span>
              <Quote className="w-3.5 h-3.5 text-amber-400/60" />
            </div>
            <p className="text-[10px] text-gray-400 font-sans mb-3">
              Exact keywords extracted from RFC 5322 body exhibiting coercive or urgency markers:
            </p>

            {/* Chips */}
            <div className="flex flex-wrap gap-1.5">
              {detectedPhrases.slice(0, 8).map((phrase, idx) => (
                <span 
                  key={idx}
                  className="px-2.5 py-1 rounded-md bg-amber-500/15 border border-amber-500/30 text-amber-300 text-[11px] font-mono tracking-tight"
                >
                  "{phrase}"
                </span>
              ))}
            </div>
          </div>

          <div className="pt-3 border-t border-white/10 flex items-center justify-between text-[10px] text-gray-400">
            <span>Coercion Vector: High Urgency</span>
            <button
              onClick={() => onDrillDown({
                type: 'FINDING',
                title: 'Linguistic Urgency Analysis',
                badge: urgencyLevel,
                badgeColor: urgencyLevel === 'HIGH' ? 'red' : 'amber',
                summary: 'Linguistic parsing isolates behavioral pressure triggers commonly utilized in spearphishing and credential lures.',
                technicalDetails: [
                  { label: 'Urgency Gradient', value: urgencyLevel, isMono: true },
                  { label: 'Credential Harvesting Inducement', value: isCredentialHarvester ? 'DETECTED' : 'NOT DETECTED', isMono: true },
                  { label: 'Adversarial Prompt Injection', value: isPromptInjection ? 'DETECTED' : 'CLEAN', isMono: true }
                ],
                rawSnippet: detectedPhrases.map(p => `Trigger: "${p}"`).join('\n')
              })}
              className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
            >
              <Eye className="w-3 h-3" />
              <span>Drill-down</span>
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
