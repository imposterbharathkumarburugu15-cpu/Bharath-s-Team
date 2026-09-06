import React from 'react';
import { 
  Mail, ArrowDown, ArrowRight, XCircle, CheckCircle2, 
  AlertTriangle, ShieldAlert, Sparkles, User, CornerDownRight, Eye
} from 'lucide-react';
import { ForensicDossier } from '@/services/forensicsEngine';
import { DrillDownTarget } from './ForensicDrillDownModal';

interface SenderIdentityGraphProps {
  dossier: ForensicDossier;
  onDrillDown: (target: DrillDownTarget) => void;
}

export function SenderIdentityGraph({ dossier, onDrillDown }: SenderIdentityGraphProps) {
  const fromDom = dossier.senderIdentity.fromDomain?.toLowerCase() || 'unknown';
  const returnDom = dossier.senderIdentity.returnPathDomain?.toLowerCase() || 'unknown';
  const replyDom = dossier.senderIdentity.replyToDomain?.toLowerCase() || fromDom;
  const dkimDom = dossier.authentication.dkim.signingDomain?.toLowerCase() || 'NONE';

  const isReturnPathMismatch = fromDom !== returnDom && returnDom !== 'unknown';
  const isReplyToMismatch = replyDom !== fromDom && replyDom !== 'unknown';
  const isDkimMismatch = dkimDom === 'NONE' || (dkimDom !== fromDom && !fromDom.endsWith(dkimDom) && !dkimDom.endsWith(fromDom));

  // Compute Identity Consistency Score (0 - 100)
  let consistencyScore = 100;
  if (isReturnPathMismatch) consistencyScore -= 40;
  if (isReplyToMismatch) consistencyScore -= 25;
  if (isDkimMismatch) consistencyScore -= 25;
  if (dossier.senderIdentity.inconsistencies.length > 0) consistencyScore -= (dossier.senderIdentity.inconsistencies.length * 5);
  consistencyScore = Math.max(10, Math.min(100, consistencyScore));

  const consistencyBarWidth = `${consistencyScore}%`;

  return (
    <section 
      id="sender-identity-graph"
      className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 shadow-2xl font-mono text-white space-y-4"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-purple-400" />
            <h2 className="text-xs font-bold uppercase tracking-widest text-white">
              4. Sender Identity Graph & Consistency Matrix
            </h2>
          </div>
          <p className="text-[11px] text-gray-400 font-sans mt-0.5">
            Triangulates claimed identity against envelope bounce-back (Return-Path), Reply-To, and cryptographic DKIM signing domains.
          </p>
        </div>

        {/* Identity Consistency Score Bar */}
        <div className="bg-black/50 border border-white/10 rounded-xl p-2.5 px-4 min-w-[240px]">
          <div className="flex items-center justify-between text-[10px] uppercase tracking-wider mb-1">
            <span className="text-gray-400 font-bold">IDENTITY CONSISTENCY</span>
            <strong className={`font-mono text-xs ${
              consistencyScore <= 40 ? 'text-red-400' :
              consistencyScore <= 70 ? 'text-amber-400' : 'text-emerald-400'
            }`}>
              {consistencyScore}%
            </strong>
          </div>
          <div className="h-2 w-full bg-white/5 rounded-full overflow-hidden">
            <div 
              className={`h-full rounded-full transition-all duration-700 ${
                consistencyScore <= 40 ? 'bg-red-500 shadow-[0_0_10px_#ef4444]' :
                consistencyScore <= 70 ? 'bg-amber-500' : 'bg-emerald-500'
              }`}
              style={{ width: consistencyBarWidth }}
            />
          </div>
          <span className="text-[9px] text-gray-500 block mt-0.5 text-right font-sans">
            {consistencyScore <= 40 ? 'High Impersonation Risk' : consistencyScore <= 70 ? 'Suspicious Discrepancies' : 'Fully Aligned'}
          </span>
        </div>
      </div>

      {/* Visual Identity Relationship Graph */}
      <div className="bg-[#05080f] border border-white/10 rounded-xl p-5 relative overflow-hidden">
        <div className="max-w-3xl mx-auto space-y-6">
          {/* Top Node: Header From (Claimed Identity) */}
          <div className="flex flex-col items-center">
            <div className="p-3 px-6 rounded-xl bg-[#0b1326] border border-cyan-400/50 shadow-[0_0_20px_rgba(0,245,255,0.2)] text-center max-w-md w-full">
              <span className="text-[9px] text-cyan-400 font-bold uppercase tracking-widest block mb-0.5">
                RFC 5322 HEADER FROM (CLAIMED IDENTITY)
              </span>
              <div className="text-sm font-bold text-white break-all">
                {dossier.senderIdentity.fromAddress || fromDom}
              </div>
              <div className="text-[10px] text-gray-400 mt-0.5">
                Claimed Domain: <strong className="text-cyan-300 font-mono">{fromDom}</strong>
              </div>
            </div>

            {/* Connecting Arrow */}
            <div className="flex flex-col items-center my-2 text-cyan-400 text-xs">
              <span className="text-[9px] uppercase tracking-widest text-gray-500 mb-0.5">claims identity for</span>
              <ArrowDown className="w-4 h-4 animate-bounce" />
            </div>

            {/* Center Node: EMAIL OBJECT */}
            <div className="p-2.5 px-8 rounded-xl bg-black/80 border-2 border-white/20 text-center shadow-lg">
              <span className="text-xs font-bold text-white tracking-widest uppercase">
                [ EMAIL CONTAINER ]
              </span>
            </div>

            {/* Branching Lines Down */}
            <div className="w-full flex items-center justify-center my-3">
              <div className="w-3/4 h-px bg-white/20 relative">
                <div className="absolute left-0 top-0 w-2 h-2 rounded-full bg-cyan-400 -translate-y-1/2" />
                <div className="absolute left-1/2 top-0 w-2 h-2 rounded-full bg-white -translate-y-1/2 -translate-x-1/2" />
                <div className="absolute right-0 top-0 w-2 h-2 rounded-full bg-cyan-400 -translate-y-1/2" />
              </div>
            </div>
          </div>

          {/* Bottom 3 Satellite Nodes: Return-Path, Reply-To, DKIM Domain */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* 1. Return-Path Node */}
            <div 
              onClick={() => onDrillDown({
                type: 'RETURN_PATH',
                title: 'Return-Path Domain Evaluation',
                badge: isReturnPathMismatch ? 'MISMATCH ❌' : 'MATCH ✓',
                badgeColor: isReturnPathMismatch ? 'red' : 'emerald',
                summary: 'The Return-Path is where bounced emails return. Attackers frequently forge From: but configure their own server for Return-Path.',
                technicalDetails: [
                  { label: 'Header From Domain', value: fromDom, isMono: true },
                  { label: 'Return-Path Domain', value: returnDom, isMono: true },
                  { label: 'Full Return-Path', value: dossier.senderIdentity.returnPathAddress, isMono: true, copyable: true }
                ],
                rawSnippet: `Return-Path: <${dossier.senderIdentity.returnPathAddress}>\nFrom: <${dossier.senderIdentity.fromAddress}>`
              })}
              className={`p-3.5 rounded-xl border ${
                isReturnPathMismatch 
                  ? 'bg-red-950/20 border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.2)]' 
                  : 'bg-emerald-950/20 border-emerald-500/40'
              } cursor-pointer hover:border-cyan-400 transition-all text-left flex flex-col justify-between`}
            >
              <div>
                <div className="flex items-center justify-between gap-1 mb-1">
                  <span className="text-[9px] uppercase text-gray-400 font-bold">RETURN-PATH (BOUNCE)</span>
                  {isReturnPathMismatch ? (
                    <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-red-500/20 text-red-400 border border-red-500/40">
                      MISMATCH ❌
                    </span>
                  ) : (
                    <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                      ALIGNED ✓
                    </span>
                  )}
                </div>
                <div className="text-xs font-bold text-white break-all mb-1">
                  {returnDom}
                </div>
                <p className="text-[10px] text-gray-400 font-sans leading-tight">
                  {isReturnPathMismatch 
                    ? `Envelope origin differs from user-facing From: domain (${fromDom}).` 
                    : 'Envelope domain correctly matches visible sender domain.'}
                </p>
              </div>
              <div className="mt-2 text-[9px] text-cyan-400 flex items-center gap-1">
                <Eye className="w-3 h-3" />
                <span>Drill down</span>
              </div>
            </div>

            {/* 2. Reply-To Node */}
            <div 
              onClick={() => onDrillDown({
                type: 'NODE',
                title: 'Reply-To Address Verification',
                badge: isReplyToMismatch ? 'EXFILTRATION RISK' : 'MATCH',
                badgeColor: isReplyToMismatch ? 'amber' : 'emerald',
                summary: 'Reply-To specifies where email client replies will go. Divergence indicates a redirection attack.',
                technicalDetails: [
                  { label: 'Header From Address', value: dossier.senderIdentity.fromAddress, isMono: true },
                  { label: 'Reply-To Address', value: dossier.senderIdentity.replyToAddress || 'Same as From', isMono: true, copyable: true },
                  { label: 'Reply-To Domain', value: replyDom, isMono: true }
                ],
                rawSnippet: `Reply-To: ${dossier.senderIdentity.replyToAddress || 'None'}`
              })}
              className={`p-3.5 rounded-xl border ${
                isReplyToMismatch 
                  ? 'bg-amber-950/20 border-amber-500/50' 
                  : 'bg-emerald-950/20 border-emerald-500/40'
              } cursor-pointer hover:border-cyan-400 transition-all text-left flex flex-col justify-between`}
            >
              <div>
                <div className="flex items-center justify-between gap-1 mb-1">
                  <span className="text-[9px] uppercase text-gray-400 font-bold">REPLY-TO ROUTING</span>
                  {isReplyToMismatch ? (
                    <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40">
                      REROUTED ⚠️
                    </span>
                  ) : (
                    <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                      ALIGNED ✓
                    </span>
                  )}
                </div>
                <div className="text-xs font-bold text-white break-all mb-1">
                  {replyDom}
                </div>
                <p className="text-[10px] text-gray-400 font-sans leading-tight">
                  {isReplyToMismatch 
                    ? `Replies sent to ${replyDom} instead of claimed ${fromDom}.` 
                    : 'Replies route back to the verified sending address.'}
                </p>
              </div>
              <div className="mt-2 text-[9px] text-cyan-400 flex items-center gap-1">
                <Eye className="w-3 h-3" />
                <span>Drill down</span>
              </div>
            </div>

            {/* 3. DKIM Signing Domain Node */}
            <div 
              onClick={() => onDrillDown({
                type: 'DKIM',
                title: 'DKIM Cryptographic Domain Inspection',
                badge: dkimDom === 'NONE' ? 'NO SIGNATURE' : isDkimMismatch ? 'DOMAIN MISMATCH' : 'VALID',
                badgeColor: isDkimMismatch ? 'red' : 'emerald',
                summary: 'Cryptographic digital signature verified domain (d= tag in DKIM-Signature).',
                technicalDetails: [
                  { label: 'Header From Domain', value: fromDom, isMono: true },
                  { label: 'DKIM Signing Domain', value: dkimDom, isMono: true },
                  { label: 'DKIM Status', value: dossier.authentication.dkim.status, isMono: true }
                ],
                rawSnippet: dossier.headerFields.dkimSignature || 'dkim=none'
              })}
              className={`p-3.5 rounded-xl border ${
                isDkimMismatch 
                  ? 'bg-red-950/20 border-red-500/50' 
                  : 'bg-emerald-950/20 border-emerald-500/40'
              } cursor-pointer hover:border-cyan-400 transition-all text-left flex flex-col justify-between`}
            >
              <div>
                <div className="flex items-center justify-between gap-1 mb-1">
                  <span className="text-[9px] uppercase text-gray-400 font-bold">DKIM SIGNING REALM</span>
                  {isDkimMismatch ? (
                    <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-red-500/20 text-red-400 border border-red-500/40">
                      {dkimDom === 'NONE' ? 'NONE ❌' : 'MISMATCH ❌'}
                    </span>
                  ) : (
                    <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                      ALIGNED ✓
                    </span>
                  )}
                </div>
                <div className="text-xs font-bold text-white break-all mb-1">
                  {dkimDom}
                </div>
                <p className="text-[10px] text-gray-400 font-sans leading-tight">
                  {dkimDom === 'NONE' 
                    ? 'No cryptographic signature provided to vouch for sender domain.' 
                    : isDkimMismatch 
                      ? `Cryptographic signature domain (${dkimDom}) does not match Header From (${fromDom}).` 
                      : 'Cryptographic signature domain perfectly matches Header From.'}
                </p>
              </div>
              <div className="mt-2 text-[9px] text-cyan-400 flex items-center gap-1">
                <Eye className="w-3 h-3" />
                <span>Drill down</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
