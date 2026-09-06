import React, { useState } from 'react';
import { 
  Server, ArrowDown, ArrowRight, ShieldAlert, Globe, 
  Lock, Unlock, Clock, AlertTriangle, CheckCircle2, Eye, Info
} from 'lucide-react';
import { ForensicDossier, HeaderHop } from '@/services/forensicsEngine';
import { DrillDownTarget } from './ForensicDrillDownModal';

interface SmtpRouteGraphProps {
  dossier: ForensicDossier;
  onDrillDown: (target: DrillDownTarget) => void;
}

export function SmtpRouteGraph({ dossier, onDrillDown }: SmtpRouteGraphProps) {
  const [selectedHopIdx, setSelectedHopIdx] = useState<number | null>(0);
  const hops = dossier.relayReconstruction.chronologicalHops || [];

  return (
    <section 
      id="smtp-hop-route-graph"
      className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 shadow-2xl font-mono text-white space-y-4"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/10 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
            <h2 className="text-xs font-bold uppercase tracking-widest text-white">
              5. SMTP Transmission Route & Relay Graph
            </h2>
          </div>
          <p className="text-[11px] text-gray-400 font-sans mt-0.5">
            Chronological multi-hop SMTP relay tracking from origin MTA to recipient mailbox.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-gray-400 text-[10px]">TOTAL TRANSIT:</span>
          <strong className="text-cyan-300 font-mono">
            {dossier.relayReconstruction.totalTransitTimeSeconds}s
          </strong>
          <span className="text-gray-600">|</span>
          <span className="text-gray-400 text-[10px]">HOPS:</span>
          <strong className="text-white font-mono">{hops.length}</strong>
        </div>
      </div>

      {/* MANDATORY Infrastructure Attribution Disclaimer */}
      <div className="p-2.5 px-3.5 rounded-xl bg-cyan-950/30 border border-cyan-500/30 flex items-start gap-2.5 text-[11px] text-cyan-200">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-white font-bold">Forensic Attribution Notice:</strong>{' '}
          <span className="text-cyan-100 font-sans">
            "Approximate infrastructure location — does not identify the human sender." IP geolocation and autonomous system data reflect intermediate mail server infrastructure, hosting centers, or VPN/proxy nodes, not the physical location of the threat actor.
          </span>
        </div>
      </div>

      {/* Forensic Route Graph (Vertical flow for pristine mobile & desktop clarity) */}
      <div className="space-y-3 py-2">
        {/* Step 0: Sender Origin */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-300 text-xs shrink-0 shadow-[0_0_10px_rgba(0,245,255,0.2)]">
            <Server className="w-4 h-4" />
          </div>
          <div className="p-2 px-3 rounded-lg bg-black/40 border border-white/10 text-xs text-gray-300 font-sans flex-1">
            <span className="text-[9px] uppercase tracking-wider text-cyan-400 block font-mono font-bold">
              ORIGINATING SENDER INFRASTRUCTURE
            </span>
            <span>Client MUA or Automated Mail Generator sending on behalf of {dossier.senderIdentity.fromDomain || 'sender'}</span>
          </div>
        </div>

        {/* Direction arrow down */}
        <div className="ml-4 pl-px border-l-2 border-dashed border-cyan-500/30 h-6 flex items-center">
          <ArrowDown className="w-3.5 h-3.5 text-cyan-400 ml-[-7px]" />
        </div>

        {/* Hops Flow */}
        {hops.map((hop, index) => {
          const isOriginHop = index === 0;
          const isFinalHop = index === hops.length - 1;
          const isSuspicious = hop.isAnomalous || (isOriginHop && dossier.scoreBreakdown.totalRiskScore >= 50);
          const hasTls = hop.rawHeader?.toLowerCase().includes('tls') || hop.protocol?.toLowerCase().includes('tls');

          return (
            <React.Fragment key={hop.hopNumber || index}>
              <div 
                onClick={() => {
                  setSelectedHopIdx(index);
                  onDrillDown({
                    type: 'IP',
                    title: `Relay Hop #${hop.hopNumber}: ${hop.sourceIP || 'Server'}`,
                    badge: isSuspicious ? 'SUSPICIOUS HOP' : 'LEGITIMATE RELAY',
                    badgeColor: isSuspicious ? 'red' : 'emerald',
                    summary: `SMTP relay trace connecting ${hop.sourceHostname || 'Source'} to ${hop.destinationHostname || 'Destination'}.`,
                    technicalDetails: [
                      { label: 'Relay IP', value: hop.sourceIP || 'N/A', isMono: true, copyable: true },
                      { label: 'Source Hostname', value: hop.sourceHostname || 'N/A', isMono: true },
                      { label: 'Destination MX', value: hop.destinationHostname || 'N/A', isMono: true },
                      { label: 'Protocol', value: hop.protocol || 'ESMTP', isMono: true },
                      { label: 'TLS Encrypted', value: hasTls ? 'YES (TLS 1.2/1.3)' : 'NO / PLAIN SMTP', isMono: true },
                      { label: 'Timestamp (UTC)', value: hop.timestamp || 'TIMESTAMP UNAVAILABLE', isMono: true }
                    ],
                    rawSnippet: hop.rawHeader,
                    rfcStandard: 'RFC 5321 Section 4.4'
                  });
                }}
                className={`p-4 rounded-xl border transition-all duration-200 cursor-pointer ${
                  isSuspicious 
                    ? 'bg-red-950/20 border-red-500/40 hover:border-red-400 shadow-[0_0_15px_rgba(239,68,68,0.15)]' 
                    : 'bg-[#0a0f1c] border-white/10 hover:border-cyan-400/50'
                }`}
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                  {/* Left: Hop Number + Hostname + IP */}
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-white/10 text-white font-mono">
                        HOP #{hop.hopNumber}
                      </span>
                      {isOriginHop && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                          EARLIEST PUBLIC ORIGIN
                        </span>
                      )}
                      {isFinalHop && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                          INBOUND GATEWAY (MX)
                        </span>
                      )}
                      {isSuspicious && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                          ANOMALOUS RELAY
                        </span>
                      )}
                    </div>

                    <div className="text-sm font-bold text-white break-all flex items-center gap-2">
                      <span>{hop.sourceIP || 'Unknown IP'}</span>
                      {hop.sourceHostname && hop.sourceHostname !== hop.sourceIP && (
                        <span className="text-xs text-gray-400 font-normal">({hop.sourceHostname})</span>
                      )}
                    </div>

                    <div className="text-xs text-gray-400 flex items-center gap-3 flex-wrap">
                      <span>Destination: <strong className="text-cyan-300 font-mono">{hop.destinationHostname || 'Recipient Mailbox'}</strong></span>
                      <span>Protocol: <strong className="text-gray-300 font-mono">{hop.protocol || 'ESMTP'}</strong></span>
                    </div>
                  </div>

                  {/* Right: Geo, ASN, TLS & Timestamp */}
                  <div className="flex flex-wrap lg:flex-col lg:items-end gap-2 text-xs">
                    <div className="flex items-center gap-2 text-gray-300">
                      <Globe className="w-3.5 h-3.5 text-cyan-400" />
                      <span>
                        {hop.city ? `${hop.city}, ` : ''}{hop.country || dossier.originIP.country || 'Unknown Geo'}
                      </span>
                      {dossier.originIP.asn && isOriginHop && (
                        <span className="px-1.5 py-0.5 rounded bg-white/5 text-[10px] font-mono text-purple-300 border border-white/10">
                          {dossier.originIP.asn}
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      <div className={`flex items-center gap-1 text-[11px] px-2 py-0.5 rounded border ${
                        hasTls ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                      }`}>
                        {hasTls ? <Lock className="w-3 h-3" /> : <Unlock className="w-3 h-3" />}
                        <span>{hasTls ? 'TLS Encrypted' : 'Plaintext / Untagged'}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-1.5 text-[10px] text-gray-500 font-mono">
                      <Clock className="w-3 h-3" />
                      <span>{hop.timestamp || 'TIMESTAMP UNAVAILABLE'}</span>
                    </div>
                  </div>
                </div>

                {hop.anomalyReason && (
                  <div className="mt-2.5 p-2 rounded bg-amber-500/10 border border-amber-500/30 text-[11px] text-amber-300 flex items-center gap-2">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                    <span>{hop.anomalyReason}</span>
                  </div>
                )}
              </div>

              {/* Connecting arrow down to next hop */}
              <div className="ml-4 pl-px border-l-2 border-dashed border-cyan-500/30 h-6 flex items-center">
                <ArrowDown className="w-3.5 h-3.5 text-cyan-400 ml-[-7px]" />
              </div>
            </React.Fragment>
          );
        })}

        {/* Step Final: Destination Mailbox */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 text-xs shrink-0 shadow-[0_0_10px_rgba(16,185,129,0.2)]">
            <CheckCircle2 className="w-4 h-4" />
          </div>
          <div className="p-2 px-3 rounded-lg bg-black/40 border border-white/10 text-xs text-gray-300 font-sans flex-1">
            <span className="text-[9px] uppercase tracking-wider text-emerald-400 block font-mono font-bold">
              FINAL RECIPIENT MAILBOX
            </span>
            <span>Target: <strong className="text-white font-mono">{dossier.headerFields.to || 'Target Inbox'}</strong></span>
          </div>
        </div>
      </div>
    </section>
  );
}
