import React from 'react';
import { 
  ShieldCheck, ShieldAlert, ArrowDown, CheckCircle2, 
  XCircle, AlertTriangle, HelpCircle, Eye, FileText
} from 'lucide-react';
import { ForensicDossier } from '@/services/forensicsEngine';
import { DrillDownTarget } from './ForensicDrillDownModal';

interface AuthMatrixAndFlowProps {
  dossier: ForensicDossier;
  onDrillDown: (target: DrillDownTarget) => void;
}

export function AuthMatrixAndFlow({ dossier, onDrillDown }: AuthMatrixAndFlowProps) {
  const { spf, dkim, dmarc } = dossier.authentication;

  const isSpfPass = spf.status === 'PASS';
  const isDkimPass = dkim.status === 'PASS';
  const isDmarcPass = dmarc.status === 'PASS';

  const spfImpact = isSpfPass ? 0 : 90;
  const dkimImpact = isDkimPass ? 0 : 95;
  const dmarcImpact = isDmarcPass ? 0 : 95;

  return (
    <div className="space-y-6 font-mono text-white">
      {/* SECTION 7: SPF / DKIM / DMARC VISUAL MATRIX */}
      <section 
        id="authentication-visual-matrix"
        className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 shadow-2xl space-y-4"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/10 pb-3">
          <div>
            <div className="flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
              <h2 className="text-xs font-bold uppercase tracking-widest text-white">
                7. SPF / DKIM / DMARC Forensic Authentication Matrix
              </h2>
            </div>
            <p className="text-[11px] text-gray-400 font-sans mt-0.5">
              Multi-protocol cryptographic verification and domain alignment evaluation.
            </p>
          </div>
          <span className="text-[10px] text-gray-500 font-sans">
            RFC 7208 / RFC 6376 / RFC 7489
          </span>
        </div>

        {/* Matrix Table */}
        <div className="overflow-x-auto rounded-xl border border-white/10">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="bg-[#0b1326] border-b border-white/10 text-[11px] uppercase tracking-wider text-gray-400">
                <th className="p-3">Attribute</th>
                <th className="p-3 text-center border-l border-white/10">SPF</th>
                <th className="p-3 text-center border-l border-white/10">DKIM</th>
                <th className="p-3 text-center border-l border-white/10">DMARC</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {/* Row 1: Result */}
              <tr className="bg-black/20">
                <td className="p-3 text-gray-400 font-bold">Result</td>
                <td className="p-3 text-center border-l border-white/10">
                  <span className={`px-2.5 py-1 rounded text-xs font-bold ${
                    isSpfPass ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'
                  }`}>
                    {spf.status}
                  </span>
                </td>
                <td className="p-3 text-center border-l border-white/10">
                  <span className={`px-2.5 py-1 rounded text-xs font-bold ${
                    isDkimPass ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'
                  }`}>
                    {dkim.status}
                  </span>
                </td>
                <td className="p-3 text-center border-l border-white/10">
                  <span className={`px-2.5 py-1 rounded text-xs font-bold ${
                    isDmarcPass ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'
                  }`}>
                    {dmarc.status}
                  </span>
                </td>
              </tr>

              {/* Row 2: Evaluated Domain */}
              <tr className="bg-black/10">
                <td className="p-3 text-gray-400">Evaluated Domain</td>
                <td className="p-3 text-center border-l border-white/10 font-bold text-white break-all">
                  {spf.envelopeSenderDomain || dossier.senderIdentity.fromDomain || 'N/A'}
                </td>
                <td className="p-3 text-center border-l border-white/10 font-bold text-white break-all">
                  {dkim.signingDomain || 'NONE'}
                </td>
                <td className="p-3 text-center border-l border-white/10 font-bold text-white break-all">
                  {dmarc.headerFromDomain || dossier.senderIdentity.fromDomain || 'N/A'}
                </td>
              </tr>

              {/* Row 3: Alignment */}
              <tr className="bg-black/20">
                <td className="p-3 text-gray-400">Alignment</td>
                <td className="p-3 text-center border-l border-white/10 text-gray-300">
                  {isSpfPass ? 'PASS' : 'FAIL'}
                </td>
                <td className="p-3 text-center border-l border-white/10 text-gray-300">
                  {dkim.signingDomain ? (isDkimPass ? 'ALIGNED' : 'MISMATCH') : 'N/A'}
                </td>
                <td className="p-3 text-center border-l border-white/10 font-bold">
                  <span className={dmarc.alignmentStatus === 'ALIGNED' ? 'text-emerald-400' : 'text-red-400'}>
                    {dmarc.alignmentStatus}
                  </span>
                </td>
              </tr>

              {/* Row 4: Evidence Vector */}
              <tr className="bg-black/10">
                <td className="p-3 text-gray-400">Evidence Vector</td>
                <td className="p-3 text-center border-l border-white/10 text-cyan-300">
                  Source IP ({dossier.originIP.ip})
                </td>
                <td className="p-3 text-center border-l border-white/10 text-cyan-300">
                  Cryptographic Signature
                </td>
                <td className="p-3 text-center border-l border-white/10 text-cyan-300">
                  RFC 5322 Header From
                </td>
              </tr>

              {/* Row 5: Threat Impact */}
              <tr className="bg-black/20 font-bold">
                <td className="p-3 text-gray-400">Impact Score</td>
                <td className="p-3 text-center border-l border-white/10">
                  <span className={isSpfPass ? 'text-emerald-400' : 'text-red-400'}>{spfImpact}/100</span>
                </td>
                <td className="p-3 text-center border-l border-white/10">
                  <span className={isDkimPass ? 'text-emerald-400' : 'text-red-400'}>{dkimImpact}/100</span>
                </td>
                <td className="p-3 text-center border-l border-white/10">
                  <span className={isDmarcPass ? 'text-emerald-400' : 'text-red-400'}>{dmarcImpact}/100</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Visual Bar Meters */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
          {/* SPF Meter */}
          <div 
            onClick={() => onDrillDown({
              type: 'SPF',
              title: 'SPF Authentication Evaluation',
              badge: spf.status,
              badgeColor: isSpfPass ? 'emerald' : 'red',
              summary: spf.explanation || 'Sender Policy Framework record verification.',
              technicalDetails: [
                { label: 'Evaluation Result', value: spf.status, isMono: true },
                { label: 'Relaying Origin IP', value: dossier.originIP.ip, isMono: true, copyable: true },
                { label: 'Envelope Domain', value: spf.envelopeSenderDomain || 'N/A', isMono: true }
              ],
              rawSnippet: spf.evidence,
              rfcStandard: 'RFC 7208'
            })}
            className="p-3 rounded-xl bg-black/40 border border-white/10 hover:border-cyan-400 transition-all cursor-pointer"
          >
            <div className="flex items-center justify-between text-xs mb-1">
              <span className="text-gray-400 font-bold">SPF</span>
              <span className={`font-bold ${isSpfPass ? 'text-emerald-400' : 'text-red-400'}`}>
                {spf.status}
              </span>
            </div>
            <div className="h-2 w-full bg-white/5 rounded-full overflow-hidden">
              <div 
                className={`h-full rounded-full ${isSpfPass ? 'bg-emerald-500' : 'bg-red-500 shadow-[0_0_8px_#ef4444]'}`} 
                style={{ width: '100%' }} 
              />
            </div>
            <span className="text-[9px] text-gray-500 block mt-1">Click to view SPF record</span>
          </div>

          {/* DKIM Meter */}
          <div 
            onClick={() => onDrillDown({
              type: 'DKIM',
              title: 'DKIM Verification Details',
              badge: dkim.status,
              badgeColor: isDkimPass ? 'emerald' : 'red',
              summary: dkim.explanation || 'DomainKeys Identified Mail cryptographic signature status.',
              technicalDetails: [
                { label: 'Evaluation Result', value: dkim.status, isMono: true },
                { label: 'Signing Domain', value: dkim.signingDomain || 'NONE', isMono: true },
                { label: 'Selector', value: dkim.selector || 'NONE', isMono: true }
              ],
              rawSnippet: dossier.headerFields.dkimSignature || 'No DKIM header found',
              rfcStandard: 'RFC 6376'
            })}
            className="p-3 rounded-xl bg-black/40 border border-white/10 hover:border-cyan-400 transition-all cursor-pointer"
          >
            <div className="flex items-center justify-between text-xs mb-1">
              <span className="text-gray-400 font-bold">DKIM</span>
              <span className={`font-bold ${isDkimPass ? 'text-emerald-400' : 'text-red-400'}`}>
                {dkim.status}
              </span>
            </div>
            <div className="h-2 w-full bg-white/5 rounded-full overflow-hidden">
              <div 
                className={`h-full rounded-full ${isDkimPass ? 'bg-emerald-500' : 'bg-red-500 shadow-[0_0_8px_#ef4444]'}`} 
                style={{ width: '100%' }} 
              />
            </div>
            <span className="text-[9px] text-gray-500 block mt-1">Click to view DKIM signature</span>
          </div>

          {/* DMARC Meter */}
          <div 
            onClick={() => onDrillDown({
              type: 'DMARC',
              title: 'DMARC Policy Evaluation',
              badge: dmarc.status,
              badgeColor: isDmarcPass ? 'emerald' : 'red',
              summary: dmarc.explanation || 'Domain-based Message Authentication alignment.',
              technicalDetails: [
                { label: 'Status', value: dmarc.status, isMono: true },
                { label: 'Alignment', value: dmarc.alignmentStatus, isMono: true },
                { label: 'Policy Action', value: dmarc.policy || 'none', isMono: true }
              ],
              rawSnippet: dmarc.evidence,
              rfcStandard: 'RFC 7489'
            })}
            className="p-3 rounded-xl bg-black/40 border border-white/10 hover:border-cyan-400 transition-all cursor-pointer"
          >
            <div className="flex items-center justify-between text-xs mb-1">
              <span className="text-gray-400 font-bold">DMARC</span>
              <span className={`font-bold ${isDmarcPass ? 'text-emerald-400' : 'text-red-400'}`}>
                {dmarc.status}
              </span>
            </div>
            <div className="h-2 w-full bg-white/5 rounded-full overflow-hidden">
              <div 
                className={`h-full rounded-full ${isDmarcPass ? 'bg-emerald-500' : 'bg-red-500 shadow-[0_0_8px_#ef4444]'}`} 
                style={{ width: '100%' }} 
              />
            </div>
            <span className="text-[9px] text-gray-500 block mt-1">Click to view DMARC policy</span>
          </div>
        </div>

        {/* 1-2 line "Why this matters" explanation */}
        <div className="p-3 rounded-xl bg-cyan-950/20 border border-cyan-500/20 text-xs text-gray-300 font-sans leading-relaxed">
          <strong className="text-cyan-400 font-mono">Why this matters:</strong>{' '}
          {(!isSpfPass || !isDmarcPass) 
            ? 'When both SPF and DMARC fail, external senders are relaying unauthorized mail using a forged sender domain. High-assurance mail filters should quarantine or reject this transmission.'
            : 'Authentication mechanisms passed, indicating the sender server is cryptographically authorized by the domain owner.'}
        </div>
      </section>

      {/* SECTION 8: AUTHENTICATION FLOW DIAGRAM */}
      <section 
        id="authentication-flow-diagram"
        className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 shadow-2xl space-y-4"
      >
        <div className="flex items-center gap-2 border-b border-white/10 pb-3">
          <div className="w-2.5 h-2.5 rounded-full bg-purple-400" />
          <h2 className="text-xs font-bold uppercase tracking-widest text-white">
            8. Authentication Pipeline & Policy Flow
          </h2>
        </div>

        {/* 3-Column Parallel Pipeline Diagram */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Pipeline 1: SPF */}
          <div className="p-4 rounded-xl bg-[#0a0f1c] border border-white/10 flex flex-col items-center text-center space-y-2">
            <span className="text-[10px] uppercase text-cyan-400 font-bold tracking-wider">
              1. RELAY ORIGIN
            </span>
            <div className="p-2 px-3 rounded bg-black/60 border border-white/10 text-xs text-white font-mono break-all w-full">
              Sending IP: {dossier.originIP.ip}
            </div>
            <ArrowDown className="w-4 h-4 text-gray-500" />
            <span className="text-[10px] text-gray-400 uppercase">SPF TXT Lookup</span>
            <div className="p-2 px-3 rounded bg-black/60 border border-white/10 text-xs text-gray-300 font-mono w-full">
              {spf.envelopeSenderDomain || 'Domain TXT'}
            </div>
            <ArrowDown className="w-4 h-4 text-gray-500" />
            <div className={`p-2 px-4 rounded-lg font-bold text-xs uppercase w-full flex items-center justify-center gap-2 ${
              isSpfPass ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' : 'bg-red-500/20 text-red-400 border border-red-500/40'
            }`}>
              {isSpfPass ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
              <span>{isSpfPass ? 'SPF PASS ✓' : 'SPF FAIL ❌'}</span>
            </div>
          </div>

          {/* Pipeline 2: DKIM */}
          <div className="p-4 rounded-xl bg-[#0a0f1c] border border-white/10 flex flex-col items-center text-center space-y-2">
            <span className="text-[10px] uppercase text-cyan-400 font-bold tracking-wider">
              2. MESSAGE HASH
            </span>
            <div className="p-2 px-3 rounded bg-black/60 border border-white/10 text-xs text-white font-mono break-all w-full">
              Signature: {dkim.signingDomain || 'NONE'}
            </div>
            <ArrowDown className="w-4 h-4 text-gray-500" />
            <span className="text-[10px] text-gray-400 uppercase">Public Key Decrypt</span>
            <div className="p-2 px-3 rounded bg-black/60 border border-white/10 text-xs text-gray-300 font-mono w-full">
              {dkim.selector ? `Selector: ${dkim.selector}` : 'No Public Key Stored'}
            </div>
            <ArrowDown className="w-4 h-4 text-gray-500" />
            <div className={`p-2 px-4 rounded-lg font-bold text-xs uppercase w-full flex items-center justify-center gap-2 ${
              isDkimPass ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' : 'bg-red-500/20 text-red-400 border border-red-500/40'
            }`}>
              {isDkimPass ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
              <span>{isDkimPass ? 'DKIM PASS ✓' : 'DKIM FAIL ❌'}</span>
            </div>
          </div>

          {/* Pipeline 3: DMARC */}
          <div className="p-4 rounded-xl bg-[#0a0f1c] border border-white/10 flex flex-col items-center text-center space-y-2">
            <span className="text-[10px] uppercase text-cyan-400 font-bold tracking-wider">
              3. VISIBLE SENDER
            </span>
            <div className="p-2 px-3 rounded bg-black/60 border border-white/10 text-xs text-white font-mono break-all w-full">
              Header From: {dossier.senderIdentity.fromDomain}
            </div>
            <ArrowDown className="w-4 h-4 text-gray-500" />
            <span className="text-[10px] text-gray-400 uppercase">Alignment Verification</span>
            <div className="p-2 px-3 rounded bg-black/60 border border-white/10 text-xs text-gray-300 font-mono w-full">
              SPF Align + DKIM Align
            </div>
            <ArrowDown className="w-4 h-4 text-gray-500" />
            <div className={`p-2 px-4 rounded-lg font-bold text-xs uppercase w-full flex items-center justify-center gap-2 ${
              isDmarcPass ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' : 'bg-red-500/20 text-red-400 border border-red-500/40'
            }`}>
              {isDmarcPass ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
              <span>{isDmarcPass ? 'DMARC PASS ✓' : 'DMARC ALIGN FAIL ❌'}</span>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
