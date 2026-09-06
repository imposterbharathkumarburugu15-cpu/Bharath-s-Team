import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, Copy, Check, Download, 
  Share2, FileText, Hash, Calendar, Mail, AlertOctagon, Terminal, Printer, Award,
  Activity, Flame, Gauge, Zap, Radio, CheckCircle2, Shield
} from 'lucide-react';
import { ForensicDossier } from '@/services/forensicsEngine';

interface ForensicCaseHeaderProps {
  dossier: ForensicDossier;
  onOpenSocReport?: () => void;
  onExportJson?: () => void;
  onExportStix?: () => void;
  onPrintPdf?: () => void;
  onToggleChainOfCustody?: () => void;
  isCustodyOpen?: boolean;
}

export function ForensicCaseHeader({
  dossier,
  onOpenSocReport,
  onExportJson,
  onExportStix,
  onPrintPdf,
  onToggleChainOfCustody,
  isCustodyOpen
}: ForensicCaseHeaderProps) {
  const [copiedHash, setCopiedHash] = useState(false);
  const [copiedCaseId, setCopiedCaseId] = useState(false);

  const copyHash = () => {
    navigator.clipboard.writeText(dossier.chainOfCustody.sha256EvidenceHash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const copyCaseId = () => {
    navigator.clipboard.writeText(dossier.chainOfCustody.caseId);
    setCopiedCaseId(true);
    setTimeout(() => setCopiedCaseId(false), 2000);
  };

  const threatScore = dossier.scoreBreakdown.totalRiskScore;
  const confidenceScore = dossier.scoreBreakdown.confidenceScore;

  // Determine Severity
  const severity = threatScore >= 75 ? 'CRITICAL' :
    threatScore >= 50 ? 'HIGH' :
    threatScore >= 25 ? 'MEDIUM' : 'LOW';

  const verdictText = threatScore >= 60 
    ? 'MALICIOUS / PHISHING' 
    : threatScore >= 35 
      ? 'SUSPICIOUS / UNVERIFIED' 
      : 'BENIGN / VERIFIED';

  const severityColorClass = {
    CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
    HIGH: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    MEDIUM: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
    LOW: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30'
  }[severity];

  const scoreBarWidth = `${Math.min(100, Math.max(0, threatScore))}%`;
  const confidenceBarWidth = `${Math.min(100, Math.max(0, confidenceScore))}%`;

  const authPts = (dossier.scoreBreakdown.authenticationScore || 0) + (dossier.scoreBreakdown.senderIdentityScore || 0);
  const urlPts = dossier.scoreBreakdown.urlAnalysisScore || 0;
  const socialPts = (dossier.scoreBreakdown.socialEngineeringScore || dossier.scoreBreakdown.contentNlpScore || 0);
  const confidenceTier = confidenceScore >= 80 ? 'EXHAUSTIVE' : confidenceScore >= 50 ? 'CORROBORATED' : 'PARTIAL';

  return (
    <div 
      id="forensic-case-header"
      className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-4 sm:p-5 shadow-2xl relative overflow-hidden font-mono text-white"
    >
      {/* Top accent glowing bar */}
      <div 
        className={`absolute top-0 left-0 right-0 h-1.5 ${
          severity === 'CRITICAL' ? 'bg-red-500 shadow-[0_0_15px_#ef4444]' :
          severity === 'HIGH' ? 'bg-amber-500 shadow-[0_0_15px_#f59e0b]' :
          severity === 'MEDIUM' ? 'bg-yellow-400 shadow-[0_0_15px_#facc15]' :
          'bg-emerald-500 shadow-[0_0_15px_#10b981]'
        }`} 
      />

      {/* Metadata Badges Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-white/10">
        <div className="flex items-center gap-2.5 flex-wrap">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs sm:text-sm">
            <Terminal className="w-4 h-4" />
            <span className="text-xs uppercase tracking-wider text-gray-400">CASE ID:</span>
            <span className="font-bold text-cyan-300">{dossier.chainOfCustody.caseId || 'CASE-2026-617311'}</span>
            <button 
              onClick={copyCaseId} 
              className="ml-1.5 hover:text-white transition-colors cursor-pointer"
              title="Copy Case ID"
            >
              {copiedCaseId ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>

          <div className="px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-xs sm:text-sm text-gray-300">
            <span className="text-xs uppercase tracking-wider text-gray-400 mr-1.5">TYPE:</span>
            <strong className="text-white">Email Forensics</strong>
          </div>

          <div className={`px-3 py-1.5 rounded-lg border text-xs sm:text-sm font-bold uppercase tracking-wider flex items-center gap-1.5 ${severityColorClass}`}>
            <AlertOctagon className="w-4 h-4" />
            <span>SEVERITY: {severity}</span>
          </div>

          <div className="px-3 py-1.5 rounded-lg bg-purple-500/15 border border-purple-500/35 text-purple-200 text-xs sm:text-sm font-bold uppercase">
            VERDICT: {verdictText}
          </div>
        </div>

        {/* Action Buttons: Includes Print to PDF, Custody Seal toggle, SOC Report, JSON, STIX */}
        <div className="flex items-center gap-2 flex-wrap">
          {onPrintPdf && (
            <button
              id="print-to-pdf-btn"
              onClick={onPrintPdf}
              className="px-3.5 py-1.5 rounded-lg text-xs sm:text-sm font-bold bg-cyan-500 hover:bg-cyan-400 text-black flex items-center gap-1.5 transition-all cursor-pointer shadow-[0_0_15px_rgba(0,245,255,0.3)] active:scale-95 shrink-0"
              title="Export complete forensic investigation report to PDF with dark aesthetic and chain-of-custody seal"
            >
              <Printer className="w-4 h-4" />
              <span>Print to PDF</span>
            </button>
          )}

          {onToggleChainOfCustody && (
            <button
              onClick={onToggleChainOfCustody}
              className={`px-3 py-1.5 rounded-lg text-xs sm:text-sm border flex items-center gap-1.5 transition-all cursor-pointer shrink-0 ${
                isCustodyOpen 
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 shadow-[0_0_10px_rgba(0,255,102,0.2)]'
                  : 'bg-white/5 hover:bg-white/10 text-gray-200 border-white/10'
              }`}
              title="Inspect or toggle official tamper-evident Chain of Custody Seal"
            >
              <Award className="w-4 h-4 text-emerald-400" />
              <span className="hidden sm:inline">Custody Seal</span>
            </button>
          )}

          {onOpenSocReport && (
            <button
              id="export-soc-report-btn"
              onClick={onOpenSocReport}
              className="px-3 py-1.5 rounded-lg text-xs sm:text-sm bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/40 flex items-center gap-1.5 transition-all cursor-pointer shadow-[0_0_10px_rgba(0,245,255,0.15)] shrink-0"
            >
              <FileText className="w-4 h-4" />
              <span>SOC Report</span>
            </button>
          )}

          {onExportJson && (
            <button
              id="export-json-btn"
              onClick={onExportJson}
              className="px-3 py-1.5 rounded-lg text-xs sm:text-sm bg-white/5 hover:bg-white/15 text-gray-200 border border-white/10 flex items-center gap-1.5 transition-all cursor-pointer shrink-0"
            >
              <Download className="w-4 h-4 text-cyan-400" />
              <span className="hidden sm:inline">JSON</span>
            </button>
          )}

          {onExportStix && (
            <button
              id="export-stix-btn"
              onClick={onExportStix}
              className="px-3 py-1.5 rounded-lg text-xs sm:text-sm bg-purple-500/15 hover:bg-purple-500/25 text-purple-200 border border-purple-500/30 flex items-center gap-1.5 transition-all cursor-pointer shrink-0"
            >
              <Share2 className="w-4 h-4" />
              <span className="hidden sm:inline">STIX 2.1</span>
            </button>
          )}
        </div>
      </div>

      {/* Main Forensic Header Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 pt-4 items-start">
        {/* Left 7 columns: Subject, From, Timestamp, Hash */}
        <div className="lg:col-span-7 space-y-3.5">
          <div>
            <span className="text-xs text-gray-400 uppercase tracking-wider block font-bold mb-1">
              SUBJECT UNDER INVESTIGATION
            </span>
            <h1 className="text-lg sm:text-xl lg:text-2xl font-bold text-white tracking-tight break-all">
              {dossier.headerFields.subject || '[No Subject Detected in RFC 5322 Headers]'}
            </h1>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs sm:text-sm">
            <div className="p-3 rounded-xl bg-black/40 border border-white/10">
              <div className="flex items-center gap-1.5 text-gray-400 text-xs uppercase tracking-wider mb-1">
                <Mail className="w-3.5 h-3.5 text-cyan-400" />
                <span>CLAIMED SENDER (FROM)</span>
              </div>
              <div className="font-bold text-white break-all text-sm">
                {dossier.senderIdentity.fromAddress || dossier.headerFields.from}
              </div>
            </div>

            <div className="p-3 rounded-xl bg-black/40 border border-white/10">
              <div className="flex items-center gap-1.5 text-gray-400 text-xs uppercase tracking-wider mb-1">
                <Calendar className="w-3.5 h-3.5 text-cyan-400" />
                <span>TIMESTAMP (UTC)</span>
              </div>
              <div className="text-gray-200 font-mono text-xs sm:text-sm truncate">
                {dossier.headerFields.date || dossier.chainOfCustody.ingestionTimestamp || 'TIMESTAMP UNAVAILABLE'}
              </div>
            </div>
          </div>

          {/* Full SHA-256 Hash with Copy */}
          <div className="p-3 rounded-xl bg-black/50 border border-cyan-500/20 flex items-center justify-between gap-2">
            <div className="flex items-center gap-2.5 overflow-hidden">
              <Hash className="w-4 h-4 text-cyan-400 shrink-0" />
              <div className="overflow-hidden">
                <span className="text-xs uppercase tracking-wider text-gray-400 block">SHA-256 EVIDENCE HASH</span>
                <span className="text-xs sm:text-sm text-cyan-300 font-mono select-all truncate block">
                  {dossier.chainOfCustody.sha256EvidenceHash}
                </span>
              </div>
            </div>
            <button
              id="copy-sha256-btn"
              onClick={copyHash}
              className="px-2.5 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-semibold flex items-center gap-1 shrink-0 transition-colors cursor-pointer"
            >
              {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedHash ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        </div>

        {/* Right 5 columns: High-Impact Cyber Telemetry HUD for Threat Score & Evidence Confidence */}
        <div className="lg:col-span-5 bg-[#060a14] border border-white/15 rounded-2xl p-4 sm:p-5 space-y-4 relative overflow-hidden shadow-[0_0_30px_rgba(0,0,0,0.7)] backdrop-blur-md">
          {/* Futuristic corner brackets */}
          <div className="absolute top-0 left-0 w-2.5 h-2.5 border-t-2 border-l-2 border-cyan-400/70 pointer-events-none" />
          <div className="absolute top-0 right-0 w-2.5 h-2.5 border-t-2 border-r-2 border-cyan-400/70 pointer-events-none" />
          <div className="absolute bottom-0 left-0 w-2.5 h-2.5 border-b-2 border-l-2 border-cyan-400/70 pointer-events-none" />
          <div className="absolute bottom-0 right-0 w-2.5 h-2.5 border-b-2 border-r-2 border-cyan-400/70 pointer-events-none" />

          {/* Dynamic ambient radial glow */}
          <div 
            className="absolute -top-14 -right-14 w-48 h-48 rounded-full pointer-events-none blur-3xl opacity-20"
            style={{
              backgroundColor: threatScore >= 75 ? '#ef4444' : threatScore >= 50 ? '#f59e0b' : '#10b981'
            }}
          />

          {/* Telemetry Card Sub-header */}
          <div className="flex items-center justify-between pb-2.5 border-b border-white/10 relative z-10">
            <div className="flex items-center gap-2">
              <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
              <span className="text-[11px] font-bold text-gray-200 uppercase tracking-widest">
                SOC THREAT & EVIDENCE TELEMETRY
              </span>
            </div>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${
              threatScore >= 75 ? 'bg-red-500/15 text-red-300 border-red-500/40 shadow-[0_0_8px_rgba(239,68,68,0.3)]' :
              threatScore >= 50 ? 'bg-amber-500/15 text-amber-300 border-amber-500/40' :
              'bg-emerald-500/15 text-emerald-300 border-emerald-500/40'
            }`}>
              {severity} SEVERITY
            </span>
          </div>

          {/* 1. Threat Score High-Impact Gauge */}
          <div className="space-y-2 relative z-10">
            <div className="flex items-end justify-between">
              <div>
                <div className="flex items-center gap-1.5">
                  <Flame className={`w-3.5 h-3.5 ${
                    threatScore >= 75 ? 'text-red-400 animate-pulse' :
                    threatScore >= 50 ? 'text-amber-400' : 'text-emerald-400'
                  }`} />
                  <span className="text-[10px] text-gray-300 uppercase tracking-widest font-bold">
                    THREAT SCORE
                  </span>
                </div>
                <span className="text-[10px] text-gray-500 block mt-0.5">
                  RFC heuristics + behavioral vectors
                </span>
              </div>
              <div className="text-right">
                <span className={`text-2xl sm:text-3xl font-black font-mono tracking-tight ${
                  threatScore >= 75 ? 'text-red-400 drop-shadow-[0_0_12px_rgba(239,68,68,0.6)]' :
                  threatScore >= 50 ? 'text-amber-400 drop-shadow-[0_0_12px_rgba(245,158,11,0.6)]' :
                  threatScore >= 25 ? 'text-yellow-400' : 'text-emerald-400 drop-shadow-[0_0_12px_rgba(16,185,129,0.6)]'
                }`}>
                  {threatScore}
                </span>
                <span className="text-xs text-gray-500 font-mono ml-1">/100</span>
              </div>
            </div>

            {/* Precision Segmented Gauge Track */}
            <div className="relative h-4 w-full bg-black/80 rounded-lg overflow-hidden p-0.5 border border-white/15 shadow-inner">
              {/* Graduation markers at 25%, 50%, 75% */}
              <div className="absolute inset-0 flex justify-between px-[25%] pointer-events-none z-10">
                <div className="w-[1px] h-full bg-white/20" />
                <div className="w-[1px] h-full bg-white/20" />
              </div>

              <div 
                className={`h-full rounded-md transition-all duration-700 relative overflow-hidden ${
                  threatScore >= 75 ? 'bg-gradient-to-r from-red-600 via-rose-500 to-red-400 shadow-[0_0_15px_#ef4444]' :
                  threatScore >= 50 ? 'bg-gradient-to-r from-amber-600 via-orange-500 to-amber-400 shadow-[0_0_12px_#f59e0b]' :
                  threatScore >= 25 ? 'bg-gradient-to-r from-yellow-600 to-yellow-400' :
                  'bg-gradient-to-r from-emerald-600 via-teal-500 to-emerald-400 shadow-[0_0_12px_#10b981]'
                }`}
                style={{ width: scoreBarWidth }}
              >
                {/* Glowing leading cursor head */}
                <div className="absolute right-0 top-0 bottom-0 w-1.5 bg-white shadow-[0_0_10px_#ffffff]" />
              </div>
            </div>

            {/* Threshold scale indicators */}
            <div className="flex justify-between text-[9px] font-mono tracking-wider">
              <span className={`flex items-center gap-1 ${threatScore < 35 ? 'text-emerald-400 font-bold' : 'text-gray-500'}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${threatScore < 35 ? 'bg-emerald-400 shadow-[0_0_6px_#10b981]' : 'bg-gray-600'}`} />
                0 BENIGN
              </span>
              <span className={`flex items-center gap-1 ${threatScore >= 35 && threatScore < 75 ? 'text-amber-400 font-bold' : 'text-gray-500'}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${threatScore >= 35 && threatScore < 75 ? 'bg-amber-400 shadow-[0_0_6px_#f59e0b]' : 'bg-gray-600'}`} />
                50 SUSPICIOUS
              </span>
              <span className={`flex items-center gap-1 ${threatScore >= 75 ? 'text-red-400 font-bold' : 'text-gray-500'}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${threatScore >= 75 ? 'bg-red-400 animate-pulse shadow-[0_0_8px_#ef4444]' : 'bg-gray-600'}`} />
                100 CRITICAL
              </span>
            </div>

            {/* Sub-vector breakdown metrics */}
            <div className="grid grid-cols-3 gap-1.5 pt-1 text-[9px] font-mono text-gray-300">
              <div className="bg-white/5 border border-white/10 rounded-md px-2 py-1 flex items-center justify-between">
                <span className="text-gray-400">AUTH/ID:</span>
                <span className="font-bold text-cyan-300">{authPts}p</span>
              </div>
              <div className="bg-white/5 border border-white/10 rounded-md px-2 py-1 flex items-center justify-between">
                <span className="text-gray-400">PAYLOAD:</span>
                <span className="font-bold text-amber-300">{urlPts}p</span>
              </div>
              <div className="bg-white/5 border border-white/10 rounded-md px-2 py-1 flex items-center justify-between">
                <span className="text-gray-400">SOCIAL:</span>
                <span className="font-bold text-purple-300">{socialPts}p</span>
              </div>
            </div>
          </div>

          {/* 2. Evidence Confidence High-Fidelity Meter */}
          <div className="space-y-2 pt-3 border-t border-white/10 relative z-10">
            <div className="flex items-end justify-between">
              <div>
                <div className="flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="text-[10px] text-gray-300 uppercase tracking-widest font-bold">
                    EVIDENCE CONFIDENCE
                  </span>
                </div>
                <span className="text-[10px] text-gray-500 block mt-0.5">
                  Multi-point corroborated fidelity
                </span>
              </div>
              <div className="text-right flex items-baseline gap-1.5">
                <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-bold tracking-wider">
                  {confidenceTier}
                </span>
                <span className="text-xl sm:text-2xl font-black font-mono text-cyan-300 drop-shadow-[0_0_12px_rgba(0,245,255,0.5)]">
                  {confidenceScore}%
                </span>
              </div>
            </div>

            {/* Laser Confidence Rail with Calibration Ticks */}
            <div className="relative h-3.5 w-full bg-black/80 rounded-lg overflow-hidden p-0.5 border border-cyan-500/30 shadow-inner">
              <div className="absolute inset-0 flex justify-between px-[33%] pointer-events-none z-10">
                <div className="w-[1px] h-full bg-cyan-400/20" />
                <div className="w-[1px] h-full bg-cyan-400/20" />
              </div>

              <div 
                className="h-full rounded-md bg-gradient-to-r from-cyan-600 via-cyan-400 to-teal-300 transition-all duration-700 shadow-[0_0_15px_rgba(0,245,255,0.5)] relative overflow-hidden"
                style={{ width: confidenceBarWidth }}
              >
                {/* Laser Tip */}
                <div className="absolute right-0 top-0 bottom-0 w-1.5 bg-white shadow-[0_0_8px_#ffffff]" />
              </div>
            </div>

            {/* Calibration labels with active states */}
            <div className="flex justify-between text-[9px] font-mono">
              <span className={confidenceScore < 40 ? 'text-amber-400 font-bold' : 'text-gray-500'}>UNVERIFIED</span>
              <span className={confidenceScore >= 40 && confidenceScore < 80 ? 'text-cyan-400 font-bold' : 'text-gray-500'}>PARTIAL</span>
              <span className={confidenceScore >= 80 ? 'text-emerald-400 font-bold' : 'text-gray-500'}>100% EXHAUSTIVE</span>
            </div>

            {/* Multi-source corroboration badges */}
            <div className="flex items-center gap-1.5 flex-wrap pt-0.5">
              <span className="text-[9px] text-gray-400 uppercase tracking-wider">SEALS:</span>
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 flex items-center gap-1 font-mono">
                <CheckCircle2 className="w-2.5 h-2.5 text-cyan-400" /> RFC 5322
              </span>
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 flex items-center gap-1 font-mono">
                <CheckCircle2 className="w-2.5 h-2.5 text-cyan-400" /> SPF/DKIM
              </span>
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/30 text-purple-300 flex items-center gap-1 font-mono">
                <CheckCircle2 className="w-2.5 h-2.5 text-purple-400" /> NEURAL NLP
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
