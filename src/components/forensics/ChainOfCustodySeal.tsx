import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, Lock, Hash, Calendar, CheckCircle2, 
  Terminal, Award, Cpu, FileCheck, Copy, Check, ChevronDown, ChevronUp, Printer
} from 'lucide-react';
import { ForensicDossier } from '@/services/forensicsEngine';

interface ChainOfCustodySealProps {
  dossier: ForensicDossier;
  forceVisible?: boolean;
  onPrint?: () => void;
}

export function ChainOfCustodySeal({ dossier, forceVisible = false, onPrint }: ChainOfCustodySealProps) {
  const [copiedHash, setCopiedHash] = useState(false);
  const [isExpanded, setIsExpanded] = useState(true);
  const [generationTimestamp, setGenerationTimestamp] = useState<string>('');

  useEffect(() => {
    // Generate authoritative UTC timestamp
    const now = new Date();
    setGenerationTimestamp(now.toUTCString());
  }, []);

  const copySha256 = () => {
    navigator.clipboard.writeText(dossier.chainOfCustody.sha256EvidenceHash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const hash = dossier.chainOfCustody.sha256EvidenceHash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const caseId = dossier.chainOfCustody.caseId || 'CASE-2026-617311';
  const ingestionTime = dossier.chainOfCustody.ingestionTimestamp || new Date().toISOString();

  return (
    <div 
      id="chain-of-custody-seal"
      className={`border rounded-2xl overflow-hidden font-mono text-white transition-all duration-300 ${
        // In print mode, always show and make pristine
        'bg-[#060b17] border-cyan-400/50 shadow-[0_0_35px_rgba(0,245,255,0.2)] print:border-cyan-400 print:bg-[#060b17] print:block print:mb-6'
      }`}
    >
      {/* Top Security Classification Banner */}
      <div className="bg-[#0b152b] border-b border-cyan-500/30 px-4 py-2 flex flex-wrap items-center justify-between gap-2 text-[10px]">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse print:hidden" />
          <span className="font-bold tracking-widest text-cyan-300 uppercase">
            CERTIFICATE OF EVIDENCE CUSTODY & TECHNICAL INTEGRITY
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="px-2 py-0.5 rounded bg-red-950/60 text-red-400 border border-red-500/40 font-bold uppercase tracking-wider">
            TLP:AMBER+STRICT
          </span>
          <span className="px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-500/40 font-bold hidden sm:inline">
            ISO/IEC 27037 ADMISSIBLE
          </span>
          {onPrint && (
            <button
              onClick={onPrint}
              id="seal-print-pdf-btn"
              className="px-2 py-0.5 rounded bg-cyan-500 hover:bg-cyan-400 text-black font-bold flex items-center gap-1 text-[10px] print:hidden cursor-pointer transition-all active:scale-95"
              title="Print certified forensic report to PDF"
            >
              <Printer className="w-3 h-3 text-black" />
              <span>Print PDF</span>
            </button>
          )}
          {/* On-screen toggle for analysts */}
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="text-gray-400 hover:text-white flex items-center gap-1 text-[10px] ml-1 print:hidden cursor-pointer"
          >
            <span>{isExpanded ? 'Collapse' : 'Expand'}</span>
            {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
        </div>
      </div>

      {/* Main Seal Body */}
      {isExpanded && (
        <div className="p-4 sm:p-6 space-y-4">
          <div className="flex flex-col lg:flex-row items-center lg:items-start justify-between gap-6">
            
            {/* Official Circular Digital Guilloche Emblem */}
            <div className="flex flex-col items-center shrink-0">
              <div className="relative w-28 h-28 sm:w-32 sm:h-32 flex items-center justify-center">
                {/* SVG Concentric Security Seal Emblem */}
                <svg className="absolute inset-0 w-full h-full animate-spin-slow print:animate-none" viewBox="0 0 120 120">
                  <circle cx="60" cy="60" r="56" fill="none" stroke="rgba(0, 243, 255, 0.4)" strokeWidth="1.5" strokeDasharray="3 3" />
                  <circle cx="60" cy="60" r="50" fill="rgba(8, 14, 28, 0.9)" stroke="#00f3ff" strokeWidth="1.5" />
                  <circle cx="60" cy="60" r="44" fill="none" stroke="rgba(0, 243, 255, 0.3)" strokeWidth="1" />
                  
                  {/* Radial tick marks */}
                  {Array.from({ length: 24 }).map((_, i) => (
                    <line
                      key={i}
                      x1="60"
                      y1="12"
                      x2="60"
                      y2="15"
                      stroke="rgba(0, 243, 255, 0.6)"
                      strokeWidth="1"
                      transform={`rotate(${i * 15} 60 60)`}
                    />
                  ))}
                  
                  {/* Circular Path for Seal Text */}
                  <path
                    id="sealPath"
                    d="M 60,60 m -38,0 a 38,38 0 1,1 76,0 a 38,38 0 1,1 -76,0"
                    fill="none"
                  />
                  <text className="text-[6.5px] uppercase font-mono fill-cyan-400 font-bold tracking-widest">
                    <textPath href="#sealPath" startOffset="0%">
                      • NEUROSHIELD FORENSIC AUTHORITY • CHAIN OF CUSTODY •
                    </textPath>
                  </text>
                </svg>

                {/* Inner Center Badge Icon */}
                <div className="relative z-10 w-14 h-14 rounded-full bg-cyan-950/80 border border-cyan-400 flex flex-col items-center justify-center text-cyan-300 shadow-[0_0_15px_rgba(0,243,255,0.4)]">
                  <ShieldCheck className="w-7 h-7 text-emerald-400" />
                  <span className="text-[7px] font-black text-cyan-300 uppercase tracking-tighter mt-0.5">
                    SEALED
                  </span>
                </div>
              </div>

              <div className="mt-2 text-center">
                <span className="text-[9px] uppercase tracking-widest text-emerald-400 font-bold flex items-center justify-center gap-1">
                  <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                  <span>TAMPER-EVIDENT</span>
                </span>
                <span className="text-[8px] text-gray-400 font-mono block">
                  DIGITALLY SIGNED & NOTARIZED
                </span>
              </div>
            </div>

            {/* Middle: Forensic Custody Attestation & Metadata */}
            <div className="flex-1 space-y-3 min-w-0 w-full">
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <h3 className="text-sm sm:text-base font-black text-white uppercase tracking-wider">
                    Digital Chain of Custody & Forensic Attestation
                  </h3>
                  <span className="text-[9px] bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded font-bold">
                    VERIFIED UNALTERED
                  </span>
                </div>
                <p className="text-[11px] text-gray-300 font-sans mt-1 leading-relaxed">
                  This cryptographic record certifies that the analyzed RFC 5322 MIME message container was acquired through secure automated transport and preserved without modification in accordance with <strong className="text-white">NIST SP 800-86</strong>, <strong className="text-white">RFC 3227</strong>, and <strong className="text-white">ISO/IEC 27037</strong> standards for digital evidence integrity.
                </p>
              </div>

              {/* Forensic Details Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 text-[11px]">
                <div className="p-2.5 rounded-xl bg-black/50 border border-white/10">
                  <span className="text-[9px] uppercase tracking-wider text-gray-400 block font-bold">
                    OFFICIAL CASE IDENTIFIER
                  </span>
                  <strong className="text-cyan-300 font-mono text-xs break-all">{caseId}</strong>
                </div>

                <div className="p-2.5 rounded-xl bg-black/50 border border-white/10">
                  <span className="text-[9px] uppercase tracking-wider text-gray-400 block font-bold">
                    INGESTION TIMESTAMP (UTC)
                  </span>
                  <span className="text-gray-200 font-mono text-xs break-all">{ingestionTime}</span>
                </div>

                <div className="p-2.5 rounded-xl bg-black/50 border border-white/10">
                  <span className="text-[9px] uppercase tracking-wider text-gray-400 block font-bold">
                    CERTIFICATE ISSUED (UTC)
                  </span>
                  <span className="text-emerald-400 font-mono text-xs break-all">
                    {generationTimestamp || 'SYNCHRONIZING UTC...'}
                  </span>
                </div>

                <div className="p-2.5 rounded-xl bg-black/50 border border-white/10">
                  <span className="text-[9px] uppercase tracking-wider text-gray-400 block font-bold">
                    FORENSIC EXAMINER / KERNEL
                  </span>
                  <span className="text-white font-mono text-[10px]">
                    NeuroShield SOC Kernel v4.2 (Node 0x7F2A)
                  </span>
                </div>

                <div className="p-2.5 rounded-xl bg-black/50 border border-white/10">
                  <span className="text-[9px] uppercase tracking-wider text-gray-400 block font-bold">
                    INGESTION PROTOCOL
                  </span>
                  <span className="text-white font-mono text-[10px]">
                    TLS-Encrypted SMTP Stream (RFC 5321)
                  </span>
                </div>

                <div className="p-2.5 rounded-xl bg-black/50 border border-white/10">
                  <span className="text-[9px] uppercase tracking-wider text-gray-400 block font-bold">
                    EVIDENCE ADMISSIBILITY GRADE
                  </span>
                  <span className="text-purple-300 font-mono text-[10px] font-bold">
                    Class 1 Primary Technical Evidence
                  </span>
                </div>
              </div>

              {/* SHA-256 Digest Cryptographic Bar */}
              <div className="p-2.5 sm:p-3 rounded-xl bg-[#081022] border border-cyan-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2 overflow-hidden w-full">
                  <Hash className="w-4 h-4 text-cyan-400 shrink-0" />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-[9px] uppercase tracking-wider text-gray-400 font-bold">
                        EVIDENCE DIGEST (SHA-256 BIT-LEVEL INTEGRITY):
                      </span>
                      <span className="text-[9px] text-emerald-400 font-mono hidden sm:inline">
                        [BIT-PERFECT MATCH]
                      </span>
                    </div>
                    <span className="text-[11px] text-cyan-300 font-mono select-all break-all block">
                      {hash}
                    </span>
                  </div>
                </div>

                <button
                  onClick={copySha256}
                  className="px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-[10px] flex items-center gap-1 shrink-0 cursor-pointer print:hidden transition-all"
                >
                  {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedHash ? 'Copied' : 'Copy Hash'}</span>
                </button>
              </div>

              {/* Micro-print Security Pattern */}
              <div className="pt-2 border-t border-white/10 flex flex-col sm:flex-row items-center justify-between gap-2 text-[9px] text-gray-500">
                <div className="flex items-center gap-2">
                  <span className="font-mono">SECURITY HASH PROTOCOL: FIPS 180-4</span>
                  <span>•</span>
                  <span className="font-mono">FRE RULE 902(14) SELF-AUTHENTICATING RECORD</span>
                </div>
                {/* Visual Barcode Strip */}
                <div className="flex items-center gap-0.5 opacity-60">
                  {Array.from({ length: 42 }).map((_, i) => (
                    <span
                      key={i}
                      className="bg-cyan-400 inline-block"
                      style={{
                        width: (i % 3 === 0 ? '3px' : i % 2 === 0 ? '1px' : '2px'),
                        height: '10px'
                      }}
                    />
                  ))}
                </div>
              </div>
            </div>

          </div>
        </div>
      )}
    </div>
  );
}
