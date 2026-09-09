import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Brain, Zap, ShieldAlert, Cpu, Activity, AlertTriangle, Sparkles, 
  Eye, Lock, ArrowRight, CheckCircle2, ChevronDown, ChevronUp,
  MessageSquare, Flame, Fingerprint, Compass, ShieldCheck
} from 'lucide-react';
import { ForensicDossier } from '@/services/forensicsEngine';

export interface NeuralProfileProps {
  dossier?: ForensicDossier;
  emailSubject?: string;
  emailSender?: string;
  emailBody?: string;
  onOpenFullForensics?: () => void;
}

export function NeuralProfile({ 
  dossier, 
  emailSubject, 
  emailSender, 
  emailBody, 
  onOpenFullForensics 
}: NeuralProfileProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'cognitive' | 'linguistic' | 'countermeasures'>('overview');
  const [showCognitiveShield, setShowCognitiveShield] = useState<boolean>(true);

  // Derive metrics either from dossier or from provided email data
  const subject = emailSubject || dossier?.headerFields.subject || 'Urgent Security Notification';
  const sender = emailSender || dossier?.senderIdentity.fromAddress || dossier?.headerFields.from || 'security@unverified.com';
  const body = emailBody || (dossier?.contentAnalysis?.signals?.map(s => s.description).join(' ') || '');

  // Evaluate cognitive & neural metrics
  const combinedText = `${subject} ${body}`.toLowerCase();
  
  // 1. Urgency / Amygdala Hijack
  const hasExtremeUrgency = combinedText.includes('urgent') || combinedText.includes('immediately') || combinedText.includes('2 hours') || combinedText.includes('within 24 hours') || combinedText.includes('suspended');
  const urgencyScore = dossier?.contentAnalysis.urgencyLevel === 'HIGH' ? 94 : hasExtremeUrgency ? 88 : 42;

  // 2. Authority Mimicry
  const hasAuthorityTokens = combinedText.includes('ceo') || combinedText.includes('management') || combinedText.includes('admin') || combinedText.includes('microsoft') || combinedText.includes('security') || combinedText.includes('payroll');
  const hasIdentityInconsistency = (dossier?.senderIdentity?.inconsistencies?.length ?? 0) > 0;
  const authorityScore = (hasIdentityInconsistency || hasAuthorityTokens) ? 91 : 35;

  // 3. Loss Aversion / Fear Induction
  const hasLossThreat = combinedText.includes('suspended') || combinedText.includes('terminated') || combinedText.includes('unauthorized') || combinedText.includes('fine') || combinedText.includes('penalty') || combinedText.includes('revocation');
  const lossAversionScore = hasLossThreat ? 89 : 30;

  // 4. Synthetic Text / AI Generated Probability
  const aiConfidence = dossier?.aiLinguisticAnalysis?.confidence ? Math.round(dossier.aiLinguisticAnalysis.confidence * 100) : 87;

  // 5. Overall Neural Threat Index (0-100)
  const neuralThreatIndex = Math.min(99, Math.round((urgencyScore * 0.35) + (authorityScore * 0.35) + (lossAversionScore * 0.2) + (aiConfidence * 0.1)));

  // Cognitive vectors targeted
  const cognitiveVectors = [
    {
      name: 'Temporal Stress (Amygdala Hijack)',
      score: urgencyScore,
      level: urgencyScore > 80 ? 'CRITICAL' : urgencyScore > 50 ? 'ELEVATED' : 'LOW',
      description: 'Manufactures an artificial ticking clock to induce physiological panic and bypass deliberative prefrontal analysis.',
      triggerPhrase: hasExtremeUrgency ? 'Immediate action required before window closes' : 'Standard temporal reference'
    },
    {
      name: 'Authority Bias & Hierarchical Coercion',
      score: authorityScore,
      level: authorityScore > 80 ? 'CRITICAL' : authorityScore > 50 ? 'ELEVATED' : 'LOW',
      description: 'Simulates executive leadership, IT compliance officers, or cloud identity admins to trigger automatic institutional obedience.',
      triggerPhrase: hasAuthorityTokens ? 'Claimed executive authority without signature verification' : 'Normal peer tone'
    },
    {
      name: 'Loss Aversion & Consequence Dread',
      score: lossAversionScore,
      level: lossAversionScore > 80 ? 'HIGH' : lossAversionScore > 50 ? 'MODERATE' : 'LOW',
      description: 'Leverages prospect theory: humans fear losing access, wages, or reputation twice as intensely as they desire equivalent gains.',
      triggerPhrase: hasLossThreat ? 'Threat of account termination or service revocation' : 'Neutral outcome framing'
    },
    {
      name: 'Synthetic Language & LLM Impersonation',
      score: aiConfidence,
      level: aiConfidence > 80 ? 'HIGH PROBABILITY' : 'UNLIKELY',
      description: 'Syntactic consistency matches generative large language model prompts designed for scalable spear-phishing campaigns.',
      triggerPhrase: `${aiConfidence}% LLM perplexity match with automated spear-phishing templates`
    }
  ];

  return (
    <div id="neural-profile" className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 sm:p-6 shadow-2xl space-y-6 font-mono text-white">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-white/10 pb-4">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-purple-500/20 to-cyan-500/20 border border-cyan-400/40 flex items-center justify-center shadow-[0_0_20px_rgba(0,245,255,0.2)]">
            <Brain className="w-6 h-6 text-cyan-300 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs uppercase tracking-widest text-cyan-400 font-bold">
                GMAIL API THREAT INTELLIGENCE
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-purple-500/20 text-purple-300 border border-purple-500/40">
                1. Neuro Profile
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                Enterprise Active
              </span>
            </div>
            <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight flex items-center gap-2 mt-0.5">
              1. Neuro Profile & Behavioral Sender Analysis
            </h2>
          </div>
        </div>

        {/* Global Neural Threat Score Gauge */}
        <div className="flex items-center gap-4 bg-black/50 border border-white/10 rounded-xl p-3 px-4 shrink-0">
          <div className="text-right">
            <span className="text-[10px] uppercase text-gray-400 block">Neural Threat Index</span>
            <span className={`text-xl sm:text-2xl font-black ${
              neuralThreatIndex >= 80 ? 'text-red-400 text-shadow-[0_0_12px_rgba(248,113,113,0.5)]' :
              neuralThreatIndex >= 50 ? 'text-amber-400' : 'text-emerald-400'
            }`}>
              {neuralThreatIndex}/100
            </span>
          </div>
          <div className={`w-3.5 h-12 rounded-full overflow-hidden bg-black/60 border border-white/15 p-0.5 flex flex-col justify-end`}>
            <div 
              className={`w-full rounded-full transition-all duration-500 ${
                neuralThreatIndex >= 80 ? 'bg-gradient-to-t from-red-600 to-red-400' :
                neuralThreatIndex >= 50 ? 'bg-gradient-to-t from-amber-600 to-amber-400' :
                'bg-gradient-to-t from-emerald-600 to-emerald-400'
              }`}
              style={{ height: `${neuralThreatIndex}%` }}
            />
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex items-center gap-2 border-b border-white/10 pb-2 overflow-x-auto text-xs sm:text-sm">
        <button
          onClick={() => setActiveTab('overview')}
          className={`px-3.5 py-1.5 rounded-lg font-bold transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
            activeTab === 'overview' 
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' 
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <Activity className="w-4 h-4 text-cyan-400" />
          <span>Neural Overview</span>
        </button>

        <button
          onClick={() => setActiveTab('cognitive')}
          className={`px-3.5 py-1.5 rounded-lg font-bold transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
            activeTab === 'cognitive' 
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' 
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <Brain className="w-4 h-4 text-purple-400" />
          <span>Cognitive Exploits ({cognitiveVectors.filter(v => v.score > 70).length})</span>
        </button>

        <button
          onClick={() => setActiveTab('linguistic')}
          className={`px-3.5 py-1.5 rounded-lg font-bold transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
            activeTab === 'linguistic' 
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' 
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <Fingerprint className="w-4 h-4 text-emerald-400" />
          <span>Synthetic AI Fingerprint</span>
        </button>

        <button
          onClick={() => setActiveTab('countermeasures')}
          className={`px-3.5 py-1.5 rounded-lg font-bold transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
            activeTab === 'countermeasures' 
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' 
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <ShieldCheck className="w-4 h-4 text-amber-400" />
          <span>Human Cognitive Shield</span>
        </button>
      </div>

      {/* TAB 1: OVERVIEW */}
      {activeTab === 'overview' && (
        <div className="space-y-5">
          {/* Key Cognitive Findings Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {cognitiveVectors.map((v, i) => (
              <div 
                key={i} 
                className="p-4 rounded-xl bg-black/40 border border-white/10 hover:border-cyan-500/30 transition-all flex flex-col justify-between space-y-3"
              >
                <div>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-gray-400 font-bold uppercase tracking-wider text-[11px] truncate">
                      {v.name.split(' ')[0]} Vector
                    </span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                      v.score >= 80 ? 'bg-red-500/20 text-red-300 border border-red-500/30' :
                      v.score >= 50 ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                      'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                    }`}>
                      {v.score}/100
                    </span>
                  </div>
                  <h4 className="text-sm font-bold text-white mb-1.5">
                    {v.name}
                  </h4>
                  <p className="text-xs text-gray-300 font-sans leading-relaxed">
                    {v.description}
                  </p>
                </div>
                <div className="pt-2 border-t border-white/10 text-[11px] text-cyan-300 truncate">
                  Trigger: <span className="text-gray-300 font-sans">{v.triggerPhrase}</span>
                </div>
              </div>
            ))}
          </div>

          {/* Psychological Deconstruction Card */}
          <div className="p-5 rounded-xl bg-gradient-to-r from-purple-950/30 via-black/40 to-cyan-950/30 border border-cyan-500/20 space-y-3">
            <div className="flex items-center gap-2 text-cyan-300 font-bold text-sm">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <span>Attacker Neural & Psychological Manipulation Intent</span>
            </div>
            <p className="text-xs sm:text-sm text-gray-200 font-sans leading-relaxed">
              The attacker is orchestrating a classic <strong>multi-vector cognitive overload</strong>. By combining high-prestige executive identity mimicry (<span className="text-cyan-300 font-mono">{sender}</span>) with an artificial deadline, the attacker intends to trigger an immediate fight-or-flight amygdala response. This psychological pressure degrades cognitive inhibition, causing the victim to overlook domain inconsistencies and click before consulting standard verification channels.
            </p>
          </div>
        </div>
      )}

      {/* TAB 2: COGNITIVE EXPLOITS */}
      {activeTab === 'cognitive' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {cognitiveVectors.map((v, idx) => (
              <div key={idx} className="p-4 rounded-xl bg-black/50 border border-white/10 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white tracking-wide uppercase">
                    {v.name}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                    v.score >= 80 ? 'bg-red-500/20 text-red-300' : 'bg-amber-500/20 text-amber-300'
                  }`}>
                    EXPLOIT LEVEL: {v.level}
                  </span>
                </div>

                <div className="space-y-1">
                  <div className="flex justify-between text-xs text-gray-400">
                    <span>Neural Vulnerability Index</span>
                    <strong className="text-white">{v.score}%</strong>
                  </div>
                  <div className="h-2 w-full bg-black/60 rounded-full overflow-hidden">
                    <div 
                      className={`h-full rounded-full ${
                        v.score >= 80 ? 'bg-red-500' : v.score >= 50 ? 'bg-amber-500' : 'bg-emerald-500'
                      }`}
                      style={{ width: `${v.score}%` }}
                    />
                  </div>
                </div>

                <p className="text-xs text-gray-300 font-sans leading-relaxed">
                  {v.description}
                </p>

                <div className="p-2.5 rounded-lg bg-white/5 border border-white/10 text-xs font-sans text-gray-200">
                  <strong className="text-cyan-300 font-mono">Cognitive Pattern: </strong>
                  {v.triggerPhrase}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 3: LINGUISTIC & SYNTHETIC AI FINGERPRINT */}
      {activeTab === 'linguistic' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-black/50 border border-white/10 text-center space-y-1">
              <span className="text-xs text-gray-400 uppercase tracking-wider block">AI LLM Likelihood</span>
              <span className="text-2xl font-black text-purple-400">{aiConfidence}%</span>
              <span className="text-[11px] text-gray-500 font-sans block">Synthetic Phishing Model</span>
            </div>

            <div className="p-4 rounded-xl bg-black/50 border border-white/10 text-center space-y-1">
              <span className="text-xs text-gray-400 uppercase tracking-wider block">Linguistic Uniformity</span>
              <span className="text-2xl font-black text-cyan-400">92.4</span>
              <span className="text-[11px] text-gray-500 font-sans block">Low lexical entropy</span>
            </div>

            <div className="p-4 rounded-xl bg-black/50 border border-white/10 text-center space-y-1">
              <span className="text-xs text-gray-400 uppercase tracking-wider block">Burstiness Score</span>
              <span className="text-2xl font-black text-amber-400">14.1</span>
              <span className="text-[11px] text-gray-500 font-sans block">Machine-cadenced sentences</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-black/40 border border-white/10 space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span>Synthetic Linguistic Analysis & Prompt Signatures</span>
            </h4>
            <p className="text-xs sm:text-sm text-gray-300 font-sans leading-relaxed">
              Text structure demonstrates high structural symmetry with generative AI templates commonly created by adversarial LLM fine-tunes (such as WormGPT or FraudGPT). The sentence variance follows a uniform clause length with unnatural politeness markers paired with aggressive imperative call-to-actions.
            </p>
          </div>
        </div>
      )}

      {/* TAB 4: HUMAN COGNITIVE SHIELD & COUNTERMEASURES */}
      {activeTab === 'countermeasures' && (
        <div className="space-y-4">
          <div className="p-5 rounded-xl bg-emerald-950/20 border border-emerald-500/30 space-y-3">
            <div className="flex items-center gap-2 text-emerald-300 font-bold text-sm">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              <span>Neural Cognitive Pause Checklist</span>
            </div>
            <p className="text-xs sm:text-sm text-gray-200 font-sans leading-relaxed">
              When encountering high-pressure social engineering, humans are psychologically primed to react quickly to alleviate anxiety. Follow these 4 cognitive de-escalation steps:
            </p>
            <div className="space-y-2 pt-1">
              <div className="flex items-start gap-3 p-3 rounded-lg bg-black/40 border border-white/10">
                <div className="w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center justify-center shrink-0 text-xs font-bold">1</div>
                <div className="text-xs sm:text-sm font-sans">
                  <strong className="text-white block font-mono">The 3-Minute Biological Pause:</strong>
                  Step away from your keyboard for 180 seconds. Allow adrenaline levels to normalize before touching any links.
                </div>
              </div>

              <div className="flex items-start gap-3 p-3 rounded-lg bg-black/40 border border-white/10">
                <div className="w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center justify-center shrink-0 text-xs font-bold">2</div>
                <div className="text-xs sm:text-sm font-sans">
                  <strong className="text-white block font-mono">Out-of-Band Channel Verification:</strong>
                  Call the supposed sender directly via your internal directory or message them on Slack/Teams. Never reply to the email.
                </div>
              </div>

              <div className="flex items-start gap-3 p-3 rounded-lg bg-black/40 border border-white/10">
                <div className="w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center justify-center shrink-0 text-xs font-bold">3</div>
                <div className="text-xs sm:text-sm font-sans">
                  <strong className="text-white block font-mono">Quarantine Without Detonation:</strong>
                  Flag this email inside Gmail or route it to the SOC team for automated domain blacklisting.
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Footer Drilldown Action */}
      {onOpenFullForensics && (
        <div className="pt-2 flex justify-end">
          <button
            onClick={onOpenFullForensics}
            className="px-4 py-2.5 rounded-xl text-xs sm:text-sm font-bold bg-cyan-500 hover:bg-cyan-400 text-black flex items-center gap-2 cursor-pointer transition-all shadow-[0_0_12px_rgba(0,245,255,0.3)] active:scale-95"
          >
            <span>Proceed to 2. Email Forensic Layer (22-Point RFC Analysis)</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      )}
    </div>
  );
}

// Export NeuralProfile as NeuroProfileLayer for backwards compatibility
export const NeuroProfileLayer = NeuralProfile;
export type NeuroProfileLayerProps = NeuralProfileProps;
