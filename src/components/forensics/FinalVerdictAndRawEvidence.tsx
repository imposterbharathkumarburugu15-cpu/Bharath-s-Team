import React, { useState, useMemo } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertOctagon, CheckCircle2, 
  Copy, Check, Download, Search, ChevronDown, ChevronUp, 
  Terminal, Ban, Trash2, Key, Globe, Eye
} from 'lucide-react';
import { ForensicDossier } from '@/services/forensicsEngine';
import { DrillDownTarget } from './ForensicDrillDownModal';

interface FinalVerdictAndRawEvidenceProps {
  dossier: ForensicDossier;
  onDrillDown: (target: DrillDownTarget) => void;
  onBlockIp?: (ip: string) => void;
  onBlockDomain?: (domain: string) => void;
  onPurgeEmail?: () => void;
  onExportEml?: () => void;
}

export function FinalVerdictAndRawEvidence({
  dossier,
  onDrillDown,
  onBlockIp,
  onBlockDomain,
  onPurgeEmail,
  onExportEml
}: FinalVerdictAndRawEvidenceProps) {
  const [isRawExpanded, setIsRawExpanded] = useState(false);
  const [headerSearchQuery, setHeaderSearchQuery] = useState('');
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [actionDone, setActionDone] = useState<string | null>(null);

  const verdict = dossier.classification.verdict;
  const isMalicious = verdict === 'MALICIOUS' || verdict === 'CRITICAL' || verdict === 'HIGH RISK';
  const isSuspicious = verdict === 'SUSPICIOUS';
  const confidence = `${dossier.classification.confidence}%`;
  const score = dossier.scoreBreakdown.totalRiskScore;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const handleAction = (label: string, callback?: () => void) => {
    if (callback) callback();
    setActionDone(label);
    setTimeout(() => setActionDone(null), 3000);
  };

  // Construct raw headers string from dossier
  const rawHeadersText = useMemo(() => {
    if (dossier.rawHeaders && Object.keys(dossier.rawHeaders).length > 0) {
      return Object.entries(dossier.rawHeaders)
        .map(([k, v]) => Array.isArray(v) ? v.map(item => `${k}: ${item}`).join('\n') : `${k}: ${v}`)
        .join('\n');
    }
    return Object.entries(dossier.headerFields)
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n');
  }, [dossier]);

  const filteredHeaderLines = useMemo(() => {
    if (!headerSearchQuery.trim()) return rawHeadersText.split('\n');
    return rawHeadersText.split('\n').filter(line => 
      line.toLowerCase().includes(headerSearchQuery.toLowerCase())
    );
  }, [rawHeadersText, headerSearchQuery]);

  return (
    <div className="space-y-6 font-mono text-white">
      {/* SECTION 17: FINAL FORENSIC VERDICT */}
      <section 
        id="final-forensic-verdict"
        className={`rounded-2xl p-6 shadow-2xl border ${
          isMalicious 
            ? 'bg-[#0f070a] border-red-500 shadow-[0_0_30px_rgba(239,68,68,0.25)]' 
            : isSuspicious
              ? 'bg-[#0f0d07] border-amber-500 shadow-[0_0_30px_rgba(245,158,11,0.2)]'
              : 'bg-[#070f0c] border-emerald-500 shadow-[0_0_30px_rgba(16,185,129,0.2)]'
        }`}
      >
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-white/10">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="text-[10px] uppercase font-bold tracking-widest text-gray-400">
                17. INCIDENT RESOLUTION
              </span>
            </div>

            <div className="flex items-center gap-3 flex-wrap">
              <div className={`p-2.5 rounded-xl ${isMalicious ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400'}`}>
                <ShieldAlert className="w-8 h-8" />
              </div>
              <div>
                <h2 className="text-xl sm:text-2xl font-black tracking-wider text-white">
                  FINAL VERDICT: {verdict} ({dossier.classification.threatType})
                </h2>
                <p className="text-xs text-gray-300 font-sans mt-0.5">
                  Multi-protocol cryptographic failure, envelope spoofing, and malicious link indicators.
                </p>
              </div>
            </div>
          </div>

          {/* Scores Badges */}
          <div className="flex items-center gap-4">
            <div className="p-3 px-5 rounded-xl bg-black/60 border border-white/10 text-center">
              <span className="text-[10px] text-gray-400 uppercase tracking-wider block">THREAT SCORE</span>
              <strong className={`text-2xl font-black ${isMalicious ? 'text-red-400' : 'text-amber-400'}`}>
                {score}/100
              </strong>
            </div>
            <div className="p-3 px-5 rounded-xl bg-black/60 border border-white/10 text-center">
              <span className="text-[10px] text-gray-400 uppercase tracking-wider block">CONFIDENCE</span>
              <strong className="text-2xl font-black text-cyan-400">
                {confidence}
              </strong>
            </div>
          </div>
        </div>

        {/* MITRE ATT&CK MAPPINGS */}
        <div className="py-5 border-b border-white/10 space-y-3">
          <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider block">
            MITRE ATT&CK FORENSIC TECHNIQUE MAPPINGS
          </span>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3 rounded-xl bg-black/40 border border-white/10">
              <div className="text-[10px] text-red-400 font-bold">T1566.002</div>
              <div className="text-xs font-bold text-white">Spearphishing Link</div>
              <p className="text-[10px] text-gray-400 font-sans mt-0.5">Anchor mismatch & credential endpoint.</p>
            </div>

            <div className="p-3 rounded-xl bg-black/40 border border-white/10">
              <div className="text-[10px] text-amber-400 font-bold">T1566.001</div>
              <div className="text-xs font-bold text-white">Spearphishing Attachment</div>
              <p className="text-[10px] text-gray-400 font-sans mt-0.5">MIME payload structure inspection.</p>
            </div>

            <div className="p-3 rounded-xl bg-black/40 border border-white/10">
              <div className="text-[10px] text-purple-400 font-bold">T1584.004</div>
              <div className="text-xs font-bold text-white">Domain Compromise / Spoof</div>
              <p className="text-[10px] text-gray-400 font-sans mt-0.5">SPF/DKIM/DMARC failure & sender mismatch.</p>
            </div>
          </div>
        </div>

        {/* IMMEDIATE ANALYST ACTIONS (ONE-CLICK RESPONSE) */}
        <div className="pt-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-gray-400 font-bold uppercase tracking-wider">
              IMMEDIATE ANALYST CONTAINMENT ACTIONS
            </span>
            {actionDone && (
              <span className="text-xs text-emerald-400 font-bold flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Action Executed: {actionDone}</span>
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <button
              onClick={() => handleAction(`Block IP ${dossier.originIP.ip}`, () => onBlockIp?.(dossier.originIP.ip))}
              className="p-3 rounded-xl bg-red-500/15 hover:bg-red-500/25 border border-red-500/40 text-red-300 flex items-center justify-center gap-2 text-xs font-bold transition-all cursor-pointer"
            >
              <Ban className="w-4 h-4" />
              <span>Block IP {dossier.originIP.ip}</span>
            </button>

            <button
              onClick={() => handleAction(`Sinkhole Domain ${dossier.senderIdentity.returnPathDomain || dossier.senderIdentity.fromDomain}`, () => onBlockDomain?.(dossier.senderIdentity.returnPathDomain || dossier.senderIdentity.fromDomain))}
              className="p-3 rounded-xl bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/40 text-amber-300 flex items-center justify-center gap-2 text-xs font-bold transition-all cursor-pointer"
            >
              <Globe className="w-4 h-4" />
              <span>Sinkhole Sender Domain</span>
            </button>

            <button
              onClick={() => handleAction('Tenant Email Purge', onPurgeEmail)}
              className="p-3 rounded-xl bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/40 text-purple-300 flex items-center justify-center gap-2 text-xs font-bold transition-all cursor-pointer"
            >
              <Trash2 className="w-4 h-4" />
              <span>Purge Message Across Tenant</span>
            </button>

            <button
              onClick={() => handleAction('User Password Reset Initiated')}
              className="p-3 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/40 text-cyan-300 flex items-center justify-center gap-2 text-xs font-bold transition-all cursor-pointer"
            >
              <Key className="w-4 h-4" />
              <span>Reset User Credentials</span>
            </button>
          </div>
        </div>
      </section>

      {/* SECTION 19: RAW RFC 5322 EVIDENCE */}
      <section 
        id="raw-rfc-evidence-section"
        className="bg-[#080d1a] border border-white/10 rounded-2xl p-5 shadow-2xl space-y-4"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-3">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h2 className="text-xs font-bold uppercase tracking-widest text-white">
              19. Raw RFC 5322 Header & Message Stream Evidence
            </h2>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onExportEml}
              className="px-2.5 py-1.5 rounded-lg text-xs bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 flex items-center gap-1.5 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Download .EML</span>
            </button>

            <button
              onClick={() => handleCopy(rawHeadersText)}
              className="px-2.5 py-1.5 rounded-lg text-xs bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 flex items-center gap-1.5 cursor-pointer"
            >
              {copiedRaw ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedRaw ? 'Copied' : 'Copy Headers'}</span>
            </button>

            <button
              onClick={() => setIsRawExpanded(!isRawExpanded)}
              className="px-2.5 py-1.5 rounded-lg text-xs bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 flex items-center gap-1 cursor-pointer"
            >
              <span>{isRawExpanded ? 'Collapse' : 'Expand Raw'}</span>
              {isRawExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>

        {isRawExpanded && (
          <div className="space-y-3">
            {/* Header Search Filter */}
            <div className="relative">
              <Search className="w-4 h-4 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={headerSearchQuery}
                onChange={(e) => setHeaderSearchQuery(e.target.value)}
                placeholder="Search raw headers (e.g. Received:, Authentication-Results:, DKIM-Signature:)..."
                className="w-full bg-black/60 border border-white/10 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-400 font-mono"
              />
            </div>

            {/* Monospace Raw Terminal View with Header Highlights */}
            <div className="p-4 rounded-xl bg-black/80 border border-white/10 max-h-96 overflow-y-auto font-mono text-[11px] leading-relaxed select-text">
              {filteredHeaderLines.map((line, idx) => {
                const isSuspiciousHeader = /^(Received:|Authentication-Results:|Return-Path:|DKIM-Signature:|From:|Message-ID:)/i.test(line);
                const isFail = /fail|softfail|mismatch|none/i.test(line);

                return (
                  <div 
                    key={idx} 
                    className={`py-0.5 break-all ${
                      isSuspiciousHeader 
                        ? (isFail ? 'text-red-400 font-bold bg-red-950/20 px-1 rounded' : 'text-cyan-300 font-semibold') 
                        : 'text-gray-400'
                    }`}
                  >
                    {line}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
