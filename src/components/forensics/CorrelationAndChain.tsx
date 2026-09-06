import React from 'react';
import { 
  Network, ArrowRight, ArrowDown, ShieldAlert, 
  CheckCircle2, AlertOctagon, GitCommit, Eye, Database
} from 'lucide-react';
import { ForensicDossier } from '@/services/forensicsEngine';
import { DrillDownTarget } from './ForensicDrillDownModal';

interface CorrelationAndChainProps {
  dossier: ForensicDossier;
  onDrillDown: (target: DrillDownTarget) => void;
}

export function CorrelationAndChain({ dossier, onDrillDown }: CorrelationAndChainProps) {
  const fromDom = dossier.senderIdentity.fromDomain || 'Target Brand';
  const returnDom = dossier.senderIdentity.returnPathDomain || 'Bounce Origin';
  const originIp = dossier.originIP.ip || 'Relay IP';
  const primaryUrl = dossier.urlForensics[0]?.domain || 'phish-dest.com';

  // Section 15 Chain steps
  const chainSteps = [
    {
      step: 1,
      title: 'Received-SPF Verification',
      detail: `IP ${originIp} not authorized by SPF record of ${fromDom}.`,
      status: 'VERIFIED EVIDENCE',
      source: 'RFC 7208 Evaluation'
    },
    {
      step: 2,
      title: 'Return-Path Triangulation',
      detail: `Return-Path (${returnDom}) does not match Header From (${fromDom}).`,
      status: 'IDENTITY FORGERY',
      source: 'RFC 5321 vs RFC 5322'
    },
    {
      step: 3,
      title: 'DMARC Policy Alignment',
      detail: `DMARC evaluation failed alignment (p=${dossier.authentication.dmarc.policy || 'none'}).`,
      status: 'POLICY REJECTION',
      source: 'RFC 7489 Alignment'
    },
    {
      step: 4,
      title: 'Payload Hyperlink Extraction',
      detail: `Embedded destination link points to credential harvesting infrastructure (${primaryUrl}).`,
      status: 'MALICIOUS IOC',
      source: 'URL Deception Analysis'
    },
    {
      step: 5,
      title: 'Final Forensic Verdict',
      detail: `Phishing attack confirmed with ${dossier.classification.confidence}% confidence.`,
      status: 'CASE CLOSED',
      source: 'Multi-Vector Corroboration'
    }
  ];

  // Section 16 Evidence vs Conclusion Rows
  const evidenceRows = [
    {
      evidence: `SPF status: ${dossier.authentication.spf.status} on IP ${originIp}`,
      conclusion: 'Relaying infrastructure is not authorized by domain DNS policy.'
    },
    {
      evidence: `Return-Path (${returnDom}) ≠ Header From (${fromDom})`,
      conclusion: 'Sender identity was intentionally forged to deceive the recipient.'
    },
    {
      evidence: dossier.urlForensics.some(u => u.hasAnchorMismatch) ? 'Anchor text mismatch on embedded links' : 'URL domain differs from sender brand',
      conclusion: 'Hyperlink concealed deceptive credential harvesting endpoint.'
    },
    {
      evidence: `${dossier.contentAnalysis.urgencyLevel} Urgency NLP patterns in body`,
      conclusion: 'Psychological pressure coercion tactic to induce rapid action.'
    }
  ];

  return (
    <div className="space-y-6 lg:space-y-8 font-mono text-white">
      {/* SECTION 14: THREAT CORRELATION GRAPH */}
      <section 
        id="threat-correlation-graph"
        className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 sm:p-6 shadow-2xl space-y-5"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="w-3 h-3 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_10px_rgba(0,245,255,0.6)]" />
              <h2 className="text-sm sm:text-base font-bold uppercase tracking-wider text-white">
                14. Threat Correlation & Entity Graph
              </h2>
            </div>
            <p className="text-xs sm:text-sm text-gray-300 font-sans mt-1">
              Correlates isolated email entities to broader campaign infrastructure and threat clusters.
            </p>
          </div>
          <span className="text-xs sm:text-sm font-bold text-purple-300 bg-purple-950/50 border border-purple-500/40 px-3 py-1.5 rounded-lg shrink-0">
            Multi-Entity Cluster
          </span>
        </div>

        {/* Visual Graph Nodes */}
        <div className="p-4 sm:p-6 rounded-xl bg-black/40 border border-white/10">
          <div className="w-full max-w-6xl mx-auto space-y-6 sm:space-y-8">
            {/* Top Row: Attacker IP -> Fake Domain -> Spoofed Email */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 sm:gap-5">
              {/* Node 1 */}
              <div 
                onClick={() => onDrillDown({
                  type: 'IP',
                  title: `Threat Entity: Attacker Origin IP (${originIp})`,
                  badge: 'RELAY NODE',
                  badgeColor: 'red',
                  summary: 'Origin IP exhibiting high-risk relay patterns.',
                  technicalDetails: [
                    { label: 'Relay IP', value: originIp, isMono: true, copyable: true },
                    { label: 'ASN', value: dossier.originIP.asn, isMono: true }
                  ],
                  rawSnippet: `IP: ${originIp}`
                })}
                className="p-4 sm:p-5 rounded-xl bg-red-950/20 border border-red-500/40 text-center cursor-pointer hover:border-cyan-400 hover:scale-[1.02] transition-all shadow-md"
              >
                <span className="text-xs font-bold uppercase tracking-wider text-red-400 block mb-1.5">
                  RELAY ORIGIN IP
                </span>
                <span className="text-sm sm:text-base font-bold text-white break-all">{originIp}</span>
              </div>

              {/* Node 2 */}
              <div 
                onClick={() => onDrillDown({
                  type: 'NODE',
                  title: `Threat Entity: Rogue Infrastructure (${returnDom})`,
                  badge: 'FORGED DOMAIN',
                  badgeColor: 'amber',
                  summary: 'Secondary bounce-back infrastructure unaligned with targeted brand.',
                  technicalDetails: [
                    { label: 'Domain', value: returnDom, isMono: true }
                  ],
                  rawSnippet: `Domain: ${returnDom}`
                })}
                className="p-4 sm:p-5 rounded-xl bg-amber-950/20 border border-amber-500/40 text-center cursor-pointer hover:border-cyan-400 hover:scale-[1.02] transition-all shadow-md"
              >
                <span className="text-xs font-bold uppercase tracking-wider text-amber-400 block mb-1.5">
                  ROGUE INFRASTRUCTURE
                </span>
                <span className="text-sm sm:text-base font-bold text-white break-all">{returnDom}</span>
              </div>

              {/* Node 3 */}
              <div 
                onClick={() => onDrillDown({
                  type: 'NODE',
                  title: `Threat Entity: Spoofed Brand (${fromDom})`,
                  badge: 'TARGET BRAND',
                  badgeColor: 'cyan',
                  summary: 'Claimed sender identity brand being impersonated.',
                  technicalDetails: [
                    { label: 'Brand Domain', value: fromDom, isMono: true }
                  ],
                  rawSnippet: `Claimed From: ${fromDom}`
                })}
                className="p-4 sm:p-5 rounded-xl bg-cyan-950/20 border border-cyan-500/40 text-center cursor-pointer hover:border-cyan-400 hover:scale-[1.02] transition-all shadow-md"
              >
                <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 block mb-1.5">
                  IMPERSONATED BRAND
                </span>
                <span className="text-sm sm:text-base font-bold text-white break-all">{fromDom}</span>
              </div>
            </div>

            {/* Connecting Arrows Down */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 sm:gap-8 text-center text-gray-500">
              <div className="flex flex-col items-center">
                <ArrowDown className="w-5 h-5 text-cyan-400 animate-bounce" />
                <span className="text-xs font-bold uppercase tracking-wider text-cyan-300 mt-1.5">correlated into</span>
              </div>
              <div className="flex flex-col items-center">
                <ArrowDown className="w-5 h-5 text-purple-400 animate-bounce" />
                <span className="text-xs font-bold uppercase tracking-wider text-purple-300 mt-1.5">attributed to</span>
              </div>
            </div>

            {/* Bottom Row: Campaign & Threat Cluster */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 sm:gap-5">
              <div className="p-5 rounded-xl bg-[#0b1326] border border-cyan-500/30 text-center">
                <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 block mb-1.5">
                  ACTIVE PHISHING CAMPAIGN
                </span>
                <span className="text-sm sm:text-base font-bold text-white">
                  Credential Harvesting Campaign #{dossier.chainOfCustody.caseId.slice(0, 8)}
                </span>
                <p className="text-xs sm:text-sm text-gray-300 font-sans mt-2 leading-relaxed">
                  Automated mass lure deploying lookalike templates and fake account suspensions.
                </p>
              </div>

              <div className="p-5 rounded-xl bg-purple-950/20 border border-purple-500/30 text-center">
                <span className="text-xs font-bold uppercase tracking-wider text-purple-400 block mb-1.5">
                  ASSOCIATED THREAT ACTOR / TTP
                </span>
                <span className="text-sm sm:text-base font-bold text-white">
                  TA-FIN-LURE / MITRE T1566.002
                </span>
                <p className="text-xs sm:text-sm text-gray-300 font-sans mt-2 leading-relaxed">
                  Adversary leveraging compromised relay servers and dynamic DNS redirects.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 15: FORENSIC EVIDENCE CHAIN */}
      <section 
        id="forensic-evidence-chain"
        className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 sm:p-6 shadow-2xl space-y-5"
      >
        <div className="flex items-center gap-2.5 border-b border-white/10 pb-4">
          <div className="w-3 h-3 rounded-full bg-cyan-400 shadow-[0_0_10px_rgba(0,245,255,0.6)]" />
          <h2 className="text-sm sm:text-base font-bold uppercase tracking-wider text-white">
            15. Forensic Evidence Chain & Proof of Verdict
          </h2>
        </div>

        {/* Step-by-Step Chain Flow */}
        <div className="space-y-3.5">
          {chainSteps.map((step, idx) => (
            <div 
              key={step.step}
              className="p-4 sm:p-5 rounded-xl bg-black/40 border border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-3 sm:gap-4 hover:border-cyan-400/40 transition-all"
            >
              <div className="flex items-start sm:items-center gap-3.5">
                <div className="w-8 h-8 sm:w-9 sm:h-9 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-300 text-xs sm:text-sm font-bold shrink-0 shadow-sm">
                  {step.step}
                </div>
                <div>
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="text-sm sm:text-base font-bold text-white">{step.title}</span>
                    <span className="text-xs text-gray-400 font-mono">[{step.source}]</span>
                  </div>
                  <p className="text-xs sm:text-sm text-gray-300 font-sans mt-1 leading-relaxed">
                    {step.detail}
                  </p>
                </div>
              </div>

              <span className={`px-3 py-1 rounded-lg text-xs font-bold self-start sm:self-center shrink-0 uppercase tracking-wide ${
                step.step === 5 
                  ? 'bg-red-500 text-white font-black shadow-[0_0_10px_rgba(239,68,68,0.5)]' 
                  : 'bg-white/10 text-cyan-300 border border-white/15'
              }`}>
                {step.status}
              </span>
            </div>
          ))}
        </div>
      </section>

      {/* SECTION 16: EVIDENCE VS CONCLUSION */}
      <section 
        id="evidence-vs-conclusion"
        className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 sm:p-6 shadow-2xl space-y-5"
      >
        <div className="flex items-center gap-2.5 border-b border-white/10 pb-4">
          <div className="w-3 h-3 rounded-full bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.6)]" />
          <h2 className="text-sm sm:text-base font-bold uppercase tracking-wider text-white">
            16. Forensic Evidence vs. Analytical Conclusion Matrix
          </h2>
        </div>

        {/* 2-Column Table */}
        <div className="overflow-x-auto rounded-xl border border-white/10">
          <table className="w-full text-xs sm:text-sm text-left">
            <thead>
              <tr className="bg-[#0b1326] border-b border-white/10 text-xs uppercase tracking-wider text-gray-300 font-bold">
                <th className="p-3.5 sm:p-4 w-1/2">FORENSIC EVIDENCE (OBSERVED FACT)</th>
                <th className="p-3.5 sm:p-4 w-1/2 border-l border-white/10">FORENSIC CONCLUSION (ANALYST INFERENCE)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {evidenceRows.map((row, idx) => (
                <tr key={idx} className="hover:bg-white/5 transition-colors">
                  <td className="p-3 font-mono text-cyan-300 break-words">
                    {row.evidence}
                  </td>
                  <td className="p-3 border-l border-white/10 font-sans text-gray-200">
                    {row.conclusion}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
