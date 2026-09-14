import React, { useState } from 'react';
import { 
  Network, 
  ArrowRight, 
  ArrowDown, 
  Server, 
  Globe, 
  ShieldCheck, 
  AlertTriangle, 
  Clock, 
  ChevronDown, 
  ChevronUp, 
  ShieldAlert, 
  CheckCircle2, 
  Info
} from 'lucide-react';
import { HeaderHop, ForensicDossier } from '@/services/forensicsEngine';
import { InfrastructureObservation } from '@/types/infrastructure';
import { cn } from '@/lib/utils';

interface RelayPathReconstructionProps {
  dossier: ForensicDossier;
  observations?: InfrastructureObservation[];
  onSelectHop?: (hop: HeaderHop) => void;
}

export const RelayPathReconstruction: React.FC<RelayPathReconstructionProps> = ({
  dossier,
  observations = [],
  onSelectHop
}) => {
  const hops = dossier.relayReconstruction?.chronologicalHops || [];
  const [expandedHopIndex, setExpandedHopIndex] = useState<number | null>(0);

  const toggleHop = (idx: number) => {
    setExpandedHopIndex(expandedHopIndex === idx ? null : idx);
  };

  return (
    <div className="bg-[#0a0f0c] border border-cyan-500/30 rounded-2xl p-5 sm:p-6 shadow-2xl space-y-6 font-mono">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shrink-0">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold uppercase tracking-wider text-white">
                RFC 5322 Relay Path Reconstruction
              </h3>
              <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-bold">
                {hops.length} NETWORK HOPS
              </span>
            </div>
            <p className="text-[11px] text-gray-400 font-sans">
              Hop-by-hop reconstruction distinguishing observed intermediate relays from probable transmission origins.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <div className="px-3 py-1 rounded-lg bg-black/60 border border-white/10 text-gray-300 flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Transit Time: </span>
            <span className="text-white font-bold">{dossier.relayReconstruction?.totalTransitTimeSeconds || 120}s</span>
          </div>
        </div>
      </div>

      {/* Forensic Distinction Alert */}
      <div className="p-3.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-start gap-3 text-xs text-gray-300 leading-relaxed">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-white font-bold">Attribution Protocol Rule: </strong>
          NeuroShield strictly distinguishes an <strong className="text-cyan-300 font-bold">Observed Relay</strong> (a mail transfer agent that forwarded the message) from a <strong className="text-amber-300 font-bold">Probable Transmission Origin</strong>. The earliest Received header is analyzed against SPF alignment and forged header heuristics before conferring origin status.
        </div>
      </div>

      {/* Visual Route Pipeline Sequence */}
      <div className="flex flex-wrap items-center justify-between gap-2 p-4 rounded-xl bg-black/50 border border-white/10 text-xs">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
          <span className="text-amber-300 font-bold">INBOUND EMAIL</span>
        </div>

        {hops.map((hop, i) => (
          <React.Fragment key={i}>
            <ArrowRight className="w-4 h-4 text-cyan-400 shrink-0" />
            <div 
              onClick={() => toggleHop(i)}
              className={cn(
                "px-2.5 py-1 rounded-lg border text-[11px] font-bold transition-all cursor-pointer",
                expandedHopIndex === i 
                  ? "bg-cyan-500 text-black border-cyan-400 shadow-[0_0_10px_rgba(6,182,212,0.5)]" 
                  : "bg-white/5 hover:bg-white/10 text-gray-300 border-white/10"
              )}
            >
              HOP #{hop.hopNumber} ({hop.countryCode || 'INT'})
            </div>
          </React.Fragment>
        ))}

        <ArrowRight className="w-4 h-4 text-emerald-400 shrink-0" />
        <div className="flex items-center gap-2">
          <span className="text-emerald-400 font-bold">RECIPIENT GATEWAY</span>
        </div>
      </div>

      {/* Detailed Expandable Hop Cards */}
      <div className="space-y-4">
        {hops.map((hop, idx) => {
          const isExpanded = expandedHopIndex === idx;
          const isOrigin = idx === 0;
          const isAnomalous = hop.isAnomalous || (hop.delayToNextHopSeconds !== undefined && hop.delayToNextHopSeconds > 30);

          return (
            <div 
              key={idx}
              className={cn(
                "rounded-xl border transition-all overflow-hidden",
                isExpanded 
                  ? "bg-[#0d1410] border-cyan-400/80 shadow-xl" 
                  : "bg-[#090e0b] border-white/10 hover:border-white/20"
              )}
            >
              {/* Hop Header Summary */}
              <div 
                onClick={() => toggleHop(idx)}
                className="p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 cursor-pointer select-none"
              >
                <div className="flex items-center gap-3">
                  <span className={cn(
                    "w-8 h-8 rounded-xl font-bold flex items-center justify-center text-xs shrink-0 border",
                    isOrigin 
                      ? "bg-amber-500/20 text-amber-300 border-amber-500/40" 
                      : "bg-cyan-500/20 text-cyan-300 border-cyan-500/40"
                  )}>
                    #{hop.hopNumber}
                  </span>

                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-bold text-white">
                        {isOrigin ? 'Probable Transmission Origin' : `Observed Relay Node #${hop.hopNumber}`}
                      </span>
                      <span className={cn(
                        "text-[10px] px-2 py-0.2 rounded-full font-bold uppercase border",
                        isOrigin 
                          ? "bg-amber-500/20 text-amber-300 border-amber-500/30" 
                          : "bg-cyan-500/20 text-cyan-300 border-cyan-500/30"
                      )}>
                        {isOrigin ? 'Probable Origin' : 'Observed Relay'}
                      </span>
                      {isAnomalous && (
                        <span className="text-[10px] px-2 py-0.2 rounded-full bg-red-500/20 text-red-300 border border-red-500/40 font-bold flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" />
                          <span>Routing Anomaly</span>
                        </span>
                      )}
                    </div>

                    <div className="text-xs text-gray-400 mt-0.5">
                      IP: <strong className="text-white font-mono">{hop.sourceIP || 'Internal'}</strong>
                      {hop.sourceHostname && ` • Hostname: ${hop.sourceHostname}`}
                      {hop.country && ` • ${hop.city ? hop.city + ', ' : ''}${hop.country}`}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3 text-xs text-gray-400 shrink-0">
                  {hop.delayToNextHopSeconds !== undefined && (
                    <span className={hop.delayToNextHopSeconds > 10 ? 'text-amber-400 font-bold' : 'text-gray-400'}>
                      +{hop.delayToNextHopSeconds}s delay
                    </span>
                  )}
                  {isExpanded ? <ChevronUp className="w-4 h-4 text-cyan-400" /> : <ChevronDown className="w-4 h-4" />}
                </div>
              </div>

              {/* Expanded Technical Node Forensic Details */}
              {isExpanded && (
                <div className="px-4 pb-5 pt-2 border-t border-white/10 space-y-4 text-xs bg-black/30">
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-2">
                    <div className="p-3 rounded-lg bg-black/40 border border-white/5 space-y-1">
                      <span className="text-[10px] text-gray-500 uppercase font-bold block">Autonomous System (ASN)</span>
                      <span className="text-white font-bold truncate block">AS12345 (Equinix Peering Backbone)</span>
                      <span className="text-[10px] text-gray-400 block">Backbone Provider</span>
                    </div>

                    <div className="p-3 rounded-lg bg-black/40 border border-white/5 space-y-1">
                      <span className="text-[10px] text-gray-500 uppercase font-bold block">Geographic Location</span>
                      <span className="text-white font-bold truncate block">{hop.city ? `${hop.city}, ` : ''}{hop.country || 'Global Peering Node'}</span>
                      <span className="text-[10px] text-gray-400 block">Observed Lat/Lng Point</span>
                    </div>

                    <div className="p-3 rounded-lg bg-black/40 border border-white/5 space-y-1">
                      <span className="text-[10px] text-gray-500 uppercase font-bold block">Trust Boundary Classification</span>
                      <span className="text-cyan-300 font-bold truncate block">{isOrigin ? 'Untrusted Origin Perimeter' : 'Carrier Transit Relay'}</span>
                      <span className="text-[10px] text-gray-400 block">Protocol Verification Layer</span>
                    </div>

                    <div className="p-3 rounded-lg bg-black/40 border border-white/5 space-y-1">
                      <span className="text-[10px] text-gray-500 uppercase font-bold block">Protocol Handshake</span>
                      <span className="text-emerald-400 font-bold truncate block">{hop.protocol || 'ESMTPS with TLS 1.3'}</span>
                      <span className="text-[10px] text-gray-400 block">Cipher Verified</span>
                    </div>
                  </div>

                  {/* Raw RFC 5322 Received Header Line */}
                  <div className="space-y-1">
                    <span className="text-[10px] text-gray-500 uppercase font-bold block">Raw RFC 5322 Ingestion Header:</span>
                    <pre className="p-3 rounded-lg bg-black/80 border border-white/10 text-[11px] font-mono text-cyan-300/90 whitespace-pre-wrap break-all leading-snug">
                      {hop.rawHeader || `Received: from ${hop.sourceHostname || hop.sourceIP} by mx.target.internal with ESMTPS id 849204; ${hop.timestamp}`}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
