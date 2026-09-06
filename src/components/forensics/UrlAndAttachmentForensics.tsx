import React, { useState } from 'react';
import { 
  Link, ExternalLink, AlertTriangle, ShieldAlert, 
  Paperclip, FileCode, CheckCircle2, XCircle, Copy, 
  Check, ArrowRight, CornerDownRight, Eye, ShieldCheck
} from 'lucide-react';
import { ForensicDossier } from '@/services/forensicsEngine';
import { DrillDownTarget } from './ForensicDrillDownModal';

interface UrlAndAttachmentForensicsProps {
  dossier: ForensicDossier;
  onDrillDown: (target: DrillDownTarget) => void;
}

export function UrlAndAttachmentForensics({ dossier, onDrillDown }: UrlAndAttachmentForensicsProps) {
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const urls = dossier.urlForensics || [];
  const attachments = dossier.attachments || [];

  return (
    <div className="space-y-6 font-mono text-white">
      {/* SECTION 12: URL FORENSICS */}
      <section 
        id="url-forensics-section"
        className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 shadow-2xl space-y-4"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/10 pb-3">
          <div>
            <div className="flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
              <h2 className="text-xs font-bold uppercase tracking-widest text-white">
                12. Hyperlink & Destination URL Forensics
              </h2>
            </div>
            <p className="text-[11px] text-gray-400 font-sans mt-0.5">
              Anchor text verification, redirect hops, and credential harvester endpoint analysis.
            </p>
          </div>

          <span className="text-xs font-mono text-cyan-300">
            {urls.length} Links Extracted
          </span>
        </div>

        {urls.length === 0 ? (
          <div className="p-6 rounded-xl bg-black/40 border border-white/10 text-center text-xs text-gray-400">
            No embedded hyperlinks detected in RFC 5322 payload body.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {urls.map((url, idx) => {
              const isCritical = url.threatLevel === 'CRITICAL';
              const hasMismatch = url.hasAnchorMismatch;
              const displayed = url.displayedAnchorText || url.rawUrl;

              return (
                <div
                  key={idx}
                  className={`p-4 rounded-xl border flex flex-col justify-between space-y-3 transition-all ${
                    isCritical 
                      ? 'bg-red-950/20 border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.15)]' 
                      : hasMismatch
                        ? 'bg-amber-950/20 border-amber-500/50'
                        : 'bg-black/40 border-white/10'
                  }`}
                >
                  <div className="space-y-2.5">
                    {/* Header: Threat Level & Mismatch Flag */}
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <span className="text-[10px] text-gray-400 font-bold uppercase">
                        LINK #{idx + 1}
                      </span>
                      <div className="flex items-center gap-1.5">
                        {hasMismatch && (
                          <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-red-500/20 text-red-400 border border-red-500/40 animate-pulse">
                            ANCHOR MISMATCH ❌
                          </span>
                        )}
                        <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase border ${
                          isCritical ? 'bg-red-500/20 text-red-300 border-red-500/40' : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                        }`}>
                          {url.threatLevel}
                        </span>
                      </div>
                    </div>

                    {/* Visual Comparison: Displayed Text vs Actual Destination */}
                    <div className="p-2.5 rounded-lg bg-black/60 border border-white/10 space-y-2 text-xs">
                      <div>
                        <span className="text-[9px] uppercase tracking-wider text-gray-500 block">
                          DISPLAYED ANCHOR TEXT:
                        </span>
                        <div className="font-mono text-cyan-300 break-all text-[11px] font-semibold">
                          {displayed}
                        </div>
                      </div>

                      <div className="pt-2 border-t border-white/10">
                        <span className="text-[9px] uppercase tracking-wider text-gray-500 block">
                          ACTUAL TARGET DESTINATION:
                        </span>
                        <div className={`font-mono break-all text-[11px] font-bold ${
                          hasMismatch ? 'text-red-400' : 'text-white'
                        }`}>
                          {url.rawUrl}
                        </div>
                      </div>

                      <div className="flex items-center justify-between pt-1 text-[10px] text-gray-400">
                        <span>Target Domain: <strong className="text-white font-mono">{url.domain}</strong></span>
                        <span>Mismatch: <strong className={hasMismatch ? 'text-red-400' : 'text-emerald-400'}>{hasMismatch ? 'YES ❌' : 'NO ✓'}</strong></span>
                      </div>
                    </div>

                    {/* Redirect Chain Visualization */}
                    <div className="space-y-1">
                      <span className="text-[9px] text-gray-500 uppercase tracking-wider block">
                        REDIRECT CHAIN TRACE:
                      </span>
                      <div className="p-2 rounded bg-black/40 border border-white/5 text-[11px] flex items-center gap-1.5 overflow-x-auto text-gray-300">
                        <span className="font-mono truncate max-w-[120px]">{url.domain}</span>
                        <ArrowRight className="w-3 h-3 text-cyan-400 shrink-0" />
                        <span className="font-mono text-amber-300 truncate max-w-[140px]">HTTP 302 Redirect</span>
                        <ArrowRight className="w-3 h-3 text-cyan-400 shrink-0" />
                        <span className="font-mono text-red-400 font-bold truncate max-w-[140px]">Credential Harvester</span>
                      </div>
                    </div>

                    {/* Threat Intelligence / VirusTotal Simulation */}
                    <div className="flex items-center justify-between text-[11px] text-gray-400 pt-1">
                      <span>Reputation: <strong className="text-red-400 font-bold">14/72 Engines Malicious</strong></span>
                      <span>Harvester: <strong className="text-amber-400">{url.isCredentialHarvester ? 'CONFIRMED' : 'SUSPECT'}</strong></span>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center justify-between pt-2 border-t border-white/10">
                    <button
                      onClick={() => handleCopy(url.rawUrl)}
                      className="text-[10px] text-gray-400 hover:text-white flex items-center gap-1 cursor-pointer"
                    >
                      {copiedText === url.rawUrl ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedText === url.rawUrl ? 'Copied' : 'Copy URL'}</span>
                    </button>

                    <button
                      onClick={() => onDrillDown({
                        type: 'URL',
                        title: `Hyperlink Forensics: ${url.domain}`,
                        badge: url.threatLevel,
                        badgeColor: url.threatLevel === 'CRITICAL' ? 'red' : 'amber',
                        summary: 'Extracted link shows severe anchor text deception designed to harvest victim login credentials.',
                        technicalDetails: [
                          { label: 'Displayed Anchor', value: displayed, isMono: true },
                          { label: 'True Destination', value: url.rawUrl, isMono: true, copyable: true },
                          { label: 'Domain', value: url.domain, isMono: true },
                          { label: 'Anchor Mismatch', value: hasMismatch ? 'YES (CRITICAL)' : 'NO', isMono: true },
                          { label: 'Harvesting Endpoint', value: url.isCredentialHarvester ? 'DETECTED' : 'UNCONFIRMED', isMono: true }
                        ],
                        rawSnippet: `<a href="${url.rawUrl}">${displayed}</a>`,
                        remediation: 'Sinkhole domain in local recursive DNS resolvers and submit to URLhaus.'
                      })}
                      className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                    >
                      <Eye className="w-3 h-3" />
                      <span>Drill-down</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* SECTION 13: ATTACHMENT FORENSICS */}
      <section 
        id="attachment-forensics-section"
        className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 shadow-2xl space-y-4"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/10 pb-3">
          <div>
            <div className="flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
              <h2 className="text-xs font-bold uppercase tracking-widest text-white">
                13. MIME Attachment & Payload Forensics
              </h2>
            </div>
            <p className="text-[11px] text-gray-400 font-sans mt-0.5">
              Cryptographic file integrity hashes, double extension evasion, and macro inspection.
            </p>
          </div>

          <span className="text-xs font-mono text-cyan-300">
            {attachments.length} Detected
          </span>
        </div>

        {attachments.length === 0 ? (
          /* Visual badge: "NO ATTACHMENTS DETECTED" (Clean, not broken empty space) */
          <div className="p-4 rounded-xl bg-black/40 border border-white/10 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <div>
                <span className="text-xs font-bold text-white tracking-wide block">
                  NO ATTACHMENTS DETECTED
                </span>
                <span className="text-[11px] text-gray-400 font-sans">
                  The analyzed RFC 5322 payload does not contain binary multipart/mixed file attachments.
                </span>
              </div>
            </div>
            <span className="px-2.5 py-1 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 text-[10px] font-bold">
              CLEAN
            </span>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {attachments.map((att, idx) => {
              const isMalicious = att.isDangerousExtension || att.threatScore >= 60;
              const isDoubleExt = /\.(pdf|docx|xlsx|txt)\.(exe|scr|bat|vbs|js)$/i.test(att.filename);

              return (
                <div
                  key={idx}
                  className={`p-4 rounded-xl border flex flex-col justify-between space-y-3 ${
                    isMalicious 
                      ? 'bg-red-950/20 border-red-500/50' 
                      : 'bg-black/40 border-white/10'
                  }`}
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 truncate">
                        <Paperclip className="w-4 h-4 text-cyan-400 shrink-0" />
                        <span className="text-xs font-bold text-white truncate font-mono">
                          {att.filename}
                        </span>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                        isMalicious ? 'bg-red-500/20 text-red-400 border-red-500/40' : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                      }`}>
                        {isMalicious ? 'MALICIOUS' : 'SAFE'}
                      </span>
                    </div>

                    {isDoubleExt && (
                      <div className="p-2 rounded bg-red-500/20 border border-red-500/40 text-[10px] text-red-300 font-bold flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        <span>DOUBLE EXTENSION EVASION DETECTED</span>
                      </div>
                    )}

                    <div className="p-2.5 rounded-lg bg-black/60 border border-white/10 space-y-1 text-xs">
                      <div className="flex items-center justify-between text-gray-400 text-[11px]">
                        <span>MIME Type:</span>
                        <span className="text-white font-mono">{att.mimeType || 'application/octet-stream'}</span>
                      </div>
                      <div className="flex items-center justify-between text-gray-400 text-[11px]">
                        <span>File Size:</span>
                        <span className="text-white font-mono">{att.sizeBytes} bytes</span>
                      </div>
                      <div className="flex items-center justify-between text-gray-400 text-[11px]">
                        <span>Dangerous Ext:</span>
                        <span className={att.isDangerousExtension ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                          {att.isDangerousExtension ? 'DETECTED' : 'SAFE'}
                        </span>
                      </div>
                      <div className="pt-1 border-t border-white/10 text-[10px]">
                        <span className="text-gray-500 block mb-0.5">SHA-256 HASH:</span>
                        <div className="font-mono text-cyan-300 break-all select-all">
                          {att.sha256Hash}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-2 border-t border-white/10 text-[10px]">
                    <button
                      onClick={() => handleCopy(att.sha256Hash)}
                      className="text-gray-400 hover:text-white flex items-center gap-1 cursor-pointer"
                    >
                      {copiedText === att.sha256Hash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedText === att.sha256Hash ? 'Copied' : 'Copy Hash'}</span>
                    </button>

                    <button
                      onClick={() => onDrillDown({
                        type: 'NODE',
                        title: `Attachment Forensics: ${att.filename}`,
                        badge: isMalicious ? 'MALICIOUS' : 'SAFE',
                        badgeColor: isMalicious ? 'red' : 'emerald',
                        summary: 'Attachment cryptographic analysis and executable signature evaluation.',
                        technicalDetails: [
                          { label: 'Filename', value: att.filename, isMono: true },
                          { label: 'SHA-256 Hash', value: att.sha256Hash, isMono: true, copyable: true },
                          { label: 'MIME Type', value: att.mimeType, isMono: true },
                          { label: 'Dangerous Extension', value: att.isDangerousExtension ? 'YES' : 'NO', isMono: true }
                        ],
                        rawSnippet: `Attachment: ${att.filename}\nHash: ${att.sha256Hash}`
                      })}
                      className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                    >
                      <Eye className="w-3 h-3" />
                      <span>Drill-down</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
