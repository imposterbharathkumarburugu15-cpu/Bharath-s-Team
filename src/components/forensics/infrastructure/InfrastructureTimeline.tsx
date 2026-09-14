import React from 'react';
import { 
  Clock, 
  ArrowDown, 
  RefreshCw, 
  CheckCircle2, 
  ShieldCheck, 
  Server, 
  Globe, 
  AlertTriangle,
  Lock,
  Layers,
  ChevronRight
} from 'lucide-react';
import { InfrastructureObservation } from '@/types/infrastructure';
import { cn } from '@/lib/utils';

interface InfrastructureTimelineProps {
  observations: InfrastructureObservation[];
  activeObservationId?: string;
  onSelectObservation?: (obs: InfrastructureObservation) => void;
}

export const InfrastructureTimeline: React.FC<InfrastructureTimelineProps> = ({
  observations,
  activeObservationId,
  onSelectObservation
}) => {
  const sorted = [...observations].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  return (
    <div className="bg-[#0a0f0c] border border-cyan-500/30 rounded-2xl p-5 sm:p-6 shadow-2xl space-y-6 font-mono">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-purple-500/15 border border-purple-500/40 flex items-center justify-center text-purple-400 shrink-0">
            <Clock className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold uppercase tracking-wider text-white">
                Forensic Infrastructure Timeline
              </h3>
              <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 font-bold">
                {observations.length} OBSERVATIONS PRESERVED
              </span>
            </div>
            <p className="text-[11px] text-gray-400 font-sans">
              Chronological sequence of observed network points. IP rotation alters endpoints; historical observations remain immutable.
            </p>
          </div>
        </div>

        {/* Status Callout */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-xs">
          <Lock className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="text-gray-300">Status: </span>
          <span className="text-cyan-300 font-bold">Historical observations preserved</span>
        </div>
      </div>

      {/* Rotation Notice Banner */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-amber-500/10 via-purple-500/10 to-cyan-500/10 border border-amber-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <RefreshCw className="w-4 h-4 text-amber-400 animate-spin" style={{ animationDuration: '8s' }} />
          <div>
            <span className="text-xs font-bold text-amber-300 uppercase tracking-wider">
              IP Rotation / Infrastructure Change Observed
            </span>
            <span className="text-[11px] text-gray-300 block font-sans">
              The adversary rotated transmission IPs across observations. NeuroShield retains all prior nodes and correlates via ASN, domain, and redirect telemetry.
            </span>
          </div>
        </div>
        <span className="text-[10px] font-mono font-bold px-2.5 py-1 rounded bg-black/50 text-white border border-white/20 shrink-0">
          ZERO OBSERVATION LOSS
        </span>
      </div>

      {/* Chronological Step List */}
      <div className="relative pl-6 sm:pl-8 space-y-6 before:absolute before:left-3 sm:before:left-4 before:top-3 before:bottom-3 before:w-0.5 before:bg-gradient-to-b before:from-cyan-500 before:via-purple-500 before:to-emerald-500">
        {sorted.map((obs, idx) => {
          const isSelected = obs.id === activeObservationId;
          const isLatest = idx === sorted.length - 1;
          const timeString = new Date(obs.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

          return (
            <div 
              key={obs.id}
              onClick={() => onSelectObservation && onSelectObservation(obs)}
              className={cn(
                "relative rounded-xl border p-4 sm:p-5 transition-all cursor-pointer group space-y-3",
                isSelected 
                  ? "bg-[#111a14] border-cyan-400 shadow-[0_0_20px_rgba(6,182,212,0.25)]" 
                  : "bg-[#0b100d] border-white/10 hover:border-cyan-500/40 hover:bg-white/[0.03]"
              )}
            >
              {/* Timeline Connector Dot */}
              <div className={cn(
                "absolute -left-[31px] sm:-left-[35px] top-5 w-4 h-4 rounded-full border-2 transition-all flex items-center justify-center",
                isSelected ? "bg-cyan-400 border-white shadow-[0_0_10px_#06b6d4]" : "bg-[#0a0f0c] border-cyan-500/60"
              )}>
                <div className="w-1.5 h-1.5 rounded-full bg-black" />
              </div>

              {/* Observation Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/10 pb-2.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[11px] font-bold text-gray-400">
                    {timeString} UTC
                  </span>
                  <span className="text-sm font-bold text-white tracking-wider">
                    IP: {obs.ip}
                  </span>
                  <span className="text-xs">{obs.countryFlag || '🌍'} {obs.city ? `${obs.city}, ` : ''}{obs.country}</span>
                  {isLatest && (
                    <span className="text-[9px] px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold uppercase animate-pulse">
                      Latest Observation
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-2 text-xs">
                  <span className="text-[10px] text-gray-400">Source: <strong className="text-white font-mono">{obs.source}</strong></span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-white/10 text-cyan-300 font-bold">
                    {obs.confidence}% Confidence
                  </span>
                </div>
              </div>

              {/* Technical Node Attributes */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                <div className="space-y-0.5">
                  <span className="text-[10px] text-gray-500 uppercase font-bold">ASN / Network:</span>
                  <span className="text-white font-bold truncate block">{obs.asn || 'AS-UNKNOWN'}</span>
                </div>
                <div className="space-y-0.5">
                  <span className="text-[10px] text-gray-500 uppercase font-bold">Hosting Infrastructure:</span>
                  <span className="text-white font-bold truncate block">{obs.provider || 'Commercial Transit'}</span>
                </div>
                <div className="space-y-0.5">
                  <span className="text-[10px] text-gray-500 uppercase font-bold">Associated Domain / Host:</span>
                  <span className="text-cyan-300 font-bold truncate block">{obs.domain || obs.hostname || 'Unassigned'}</span>
                </div>
              </div>

              {/* Status note */}
              {obs.statusNote && (
                <div className="text-[11px] text-gray-300 bg-black/40 p-2.5 rounded-lg border border-white/5 leading-relaxed font-sans">
                  {obs.statusNote}
                </div>
              )}

              {/* Subsequent transition arrow */}
              {idx < sorted.length - 1 && (
                <div className="pt-1 flex items-center gap-1.5 text-[10px] text-gray-500 uppercase font-mono">
                  <ArrowDown className="w-3 h-3 text-cyan-400 animate-bounce" />
                  <span>Subsequent Infrastructure Transition Observed</span>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Summary Footer */}
      <div className="p-4 rounded-xl bg-black/50 border border-white/10 text-xs text-gray-300 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>Court-Defensible Chain of Custody: All timestamps cryptographically signed and SHA-256 sealed.</span>
        </div>
        <span className="text-cyan-300 font-bold font-mono">MUTATION IMMUNE</span>
      </div>
    </div>
  );
};
