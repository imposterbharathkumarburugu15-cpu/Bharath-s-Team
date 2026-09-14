import React, { useState } from 'react';
import { 
  Globe, 
  MapPin, 
  Server, 
  ShieldAlert, 
  Info, 
  Layers, 
  Maximize2, 
  Minimize2, 
  CheckCircle2, 
  Radio, 
  Network,
  Clock,
  ArrowRight
} from 'lucide-react';
import { InfrastructureObservation } from '@/types/infrastructure';
import { cn } from '@/lib/utils';

interface ObservedInfrastructureMapProps {
  observations: InfrastructureObservation[];
  activeObservationId?: string;
  onSelectObservation?: (obs: InfrastructureObservation) => void;
  isCompact?: boolean;
}

export const ObservedInfrastructureMap: React.FC<ObservedInfrastructureMapProps> = ({
  observations,
  activeObservationId,
  onSelectObservation,
  isCompact = false
}) => {
  const [selectedObsId, setSelectedObsId] = useState<string>(
    activeObservationId || observations[observations.length - 1]?.id || ''
  );
  const [isExpanded, setIsExpanded] = useState<boolean>(false);
  const [filterTrust, setFilterTrust] = useState<string>('all');

  const selectedObs = observations.find(o => o.id === selectedObsId) || observations[0];

  const filteredObservations = observations.filter(o => {
    if (filterTrust === 'all') return true;
    return o.trustBoundary === filterTrust;
  });

  // Calculate coordinates on 2D equirectangular projection (1000x500 SVG coordinate space)
  const getCoordinates = (lat?: number, lng?: number) => {
    const latitude = lat ?? 20;
    const longitude = lng ?? 0;
    const x = ((longitude + 180) / 360) * 1000;
    const y = ((90 - latitude) / 180) * 500;
    return { x, y };
  };

  return (
    <div className={cn(
      "bg-[#0a0f0c] border border-cyan-500/30 rounded-2xl p-5 sm:p-6 shadow-2xl space-y-4 font-mono relative overflow-hidden transition-all duration-300",
      isExpanded ? "fixed inset-4 z-[9999] overflow-y-auto bg-[#0a0f0c]/98 backdrop-blur-2xl" : ""
    )}>
      {/* Top Banner: Court-Defensible Attribution Standard Notice */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shrink-0">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold uppercase tracking-wider text-white">
                Observed Infrastructure Map
              </h3>
              <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-bold">
                SIH26106 TELEMETRY
              </span>
            </div>
            <p className="text-[11px] text-gray-400 font-sans">
              Geographic telemetry of confirmed mail relays, DNS resolutions, and transit points.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Exact Non-Attribution Badge */}
          <div className="px-3 py-1 rounded-lg bg-black/60 border border-white/15 text-[11px] text-gray-300 flex items-center gap-1.5" title="Court-defensible observation standard">
            <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span className="text-cyan-300 font-bold">Observed infrastructure</span>
            <span className="text-gray-500">— not physical attribution</span>
          </div>

          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white border border-white/10 transition-colors cursor-pointer"
            title={isExpanded ? "Collapse View" : "Fullscreen View"}
          >
            {isExpanded ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Filter and Mode Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-1 bg-black/40 p-1 rounded-xl border border-white/10">
          <span className="text-[10px] text-gray-500 uppercase px-2 font-bold">Boundary:</span>
          {['all', 'origin', 'transit', 'external'].map(b => (
            <button
              key={b}
              onClick={() => setFilterTrust(b)}
              className={cn(
                "px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase transition-all cursor-pointer",
                filterTrust === b ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40" : "text-gray-400 hover:text-white"
              )}
            >
              {b}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-3 text-[11px] text-gray-400">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_rgba(6,182,212,0.8)]" />
            <span>Active Point</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-400/80" />
            <span>Historical Preserved</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400/80" />
            <span>Payload URL Target</span>
          </div>
        </div>
      </div>

      {/* World Map SVG Projection (Clean Cybersecurity Aesthetic) */}
      <div className="relative w-full h-[320px] sm:h-[400px] rounded-xl bg-[#070b09] border border-white/10 overflow-hidden shadow-inner">
        {/* Subtle coordinate grid lines */}
        <svg className="absolute inset-0 w-full h-full opacity-20 pointer-events-none" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <pattern id="infraGrid" width="50" height="50" patternUnits="userSpaceOnUse">
              <path d="M 50 0 L 0 0 0 50" fill="none" stroke="rgba(6,182,212,0.4)" strokeWidth="0.5" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#infraGrid)" />
        </svg>

        {/* Global World Continents Map Outline SVG */}
        <svg viewBox="0 0 1000 500" className="w-full h-full object-contain">
          {/* Continents Silhouettes */}
          <g fill="rgba(255,255,255,0.04)" stroke="rgba(6,182,212,0.2)" strokeWidth="1">
            {/* North America */}
            <path d="M 120 70 Q 220 50 320 80 Q 300 160 260 210 Q 180 230 140 180 Z" />
            {/* South America */}
            <path d="M 270 230 Q 350 250 340 370 Q 290 450 260 410 Q 230 330 270 230 Z" />
            {/* Europe */}
            <path d="M 460 70 Q 550 60 560 140 Q 500 170 460 140 Q 440 100 460 70 Z" />
            {/* Africa */}
            <path d="M 460 170 Q 580 180 570 320 Q 510 390 480 340 Q 440 240 460 170 Z" />
            {/* Asia */}
            <path d="M 580 60 Q 820 50 880 160 Q 780 260 690 220 Q 610 170 580 60 Z" />
            {/* Australia */}
            <path d="M 740 300 Q 860 300 840 400 Q 760 410 740 300 Z" />
          </g>

          {/* Investigation Vectors / Correlation Lines between observed infrastructure */}
          {filteredObservations.map((obs, idx) => {
            if (idx === 0) return null;
            const prev = filteredObservations[idx - 1];
            const p1 = getCoordinates(prev.latitude, prev.longitude);
            const p2 = getCoordinates(obs.latitude, obs.longitude);
            return (
              <g key={`line-${obs.id}`}>
                <line
                  x1={p1.x}
                  y1={p1.y}
                  x2={p2.x}
                  y2={p2.y}
                  stroke="rgba(6,182,212,0.4)"
                  strokeWidth="1.5"
                  strokeDasharray="4 4"
                />
                <circle cx={(p1.x + p2.x) / 2} cy={(p1.y + p2.y) / 2} r="2" fill="rgba(6,182,212,0.6)" />
              </g>
            );
          })}

          {/* Observed Infrastructure Node Markers */}
          {filteredObservations.map((obs, idx) => {
            const { x, y } = getCoordinates(obs.latitude, obs.longitude);
            const isSelected = obs.id === selectedObsId;
            const isOrigin = obs.trustBoundary === 'origin';
            const isUrl = obs.source === 'url-resolution';

            const markerColor = isOrigin ? '#06b6d4' : isUrl ? '#f59e0b' : '#a855f7';

            return (
              <g 
                key={obs.id} 
                className="cursor-pointer group"
                onClick={() => {
                  setSelectedObsId(obs.id);
                  if (onSelectObservation) onSelectObservation(obs);
                }}
              >
                {/* Ping ring for selected or active */}
                {isSelected && (
                  <circle cx={x} cy={y} r="16" fill="none" stroke={markerColor} strokeWidth="1.5" opacity="0.6">
                    <animate attributeName="r" values="8;20" dur="2s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.8;0" dur="2s" repeatCount="indefinite" />
                  </circle>
                )}

                {/* Node Target Circle */}
                <circle
                  cx={x}
                  cy={y}
                  r={isSelected ? "7" : "5"}
                  fill={markerColor}
                  stroke="#0a0f0c"
                  strokeWidth="2"
                  className="transition-all duration-200 group-hover:scale-125"
                />

                {/* Text Label */}
                <text
                  x={x + 10}
                  y={y + 4}
                  fill="#ffffff"
                  fontSize="11"
                  fontFamily="monospace"
                  fontWeight="bold"
                  className="drop-shadow-[0_2px_4px_rgba(0,0,0,0.9)]"
                >
                  {obs.city || obs.country} ({obs.ip})
                </text>
              </g>
            );
          })}
        </svg>

        {/* Tactical Coordinates Overlay */}
        <div className="absolute bottom-3 left-3 bg-black/80 px-3 py-1.5 rounded-lg border border-white/10 text-[10px] text-gray-400 font-mono">
          <span>PROJECTION: CYBER EQUIRECTANGULAR • POINTS: {filteredObservations.length} OBSERVED NODES</span>
        </div>
      </div>

      {/* Selected Infrastructure Node Inspector Detail Card */}
      {selectedObs && (
        <div className="bg-[#0e1611] border border-cyan-500/30 rounded-xl p-4 sm:p-5 shadow-xl space-y-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-white/10 pb-3">
            <div className="flex items-center gap-3">
              <span className="text-2xl">{selectedObs.countryFlag || '🌍'}</span>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-base font-bold text-white tracking-wider">
                    {selectedObs.ip}
                  </span>
                  <span className={cn(
                    "text-[10px] px-2 py-0.5 rounded-full font-bold uppercase border",
                    selectedObs.trustBoundary === 'origin' ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40" :
                    selectedObs.trustBoundary === 'external' ? "bg-amber-500/20 text-amber-300 border-amber-500/40" :
                    "bg-purple-500/20 text-purple-300 border-purple-500/40"
                  )}>
                    {selectedObs.trustBoundary}
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-white/10 text-gray-300">
                    Confidence: {selectedObs.confidence}%
                  </span>
                </div>
                <div className="text-xs text-gray-400 mt-0.5">
                  Location: <span className="text-white font-semibold">{selectedObs.city ? `${selectedObs.city}, ` : ''}{selectedObs.country}</span>
                  {selectedObs.latitude && ` (Lat: ${selectedObs.latitude.toFixed(4)}, Lng: ${selectedObs.longitude?.toFixed(4)})`}
                </div>
              </div>
            </div>

            <div className="text-[11px] text-gray-400 font-mono text-left sm:text-right">
              <div>Observed: <span className="text-cyan-300 font-bold">{new Date(selectedObs.timestamp).toLocaleTimeString()} UTC</span></div>
              <div>Source: <span className="text-white font-bold">{selectedObs.source}</span></div>
            </div>
          </div>

          {/* Attributes Matrix */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div className="p-2.5 rounded-lg bg-black/40 border border-white/5 space-y-1">
              <span className="text-[10px] text-gray-500 uppercase font-bold block">Autonomous System (ASN)</span>
              <span className="text-white font-bold truncate block">{selectedObs.asn || 'AS-UNKNOWN'}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-black/40 border border-white/5 space-y-1">
              <span className="text-[10px] text-gray-500 uppercase font-bold block">Hosting Provider / ISP</span>
              <span className="text-white font-bold truncate block">{selectedObs.provider || selectedObs.organization || 'Commercial Hosting'}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-black/40 border border-white/5 space-y-1">
              <span className="text-[10px] text-gray-500 uppercase font-bold block">Associated Domain / Host</span>
              <span className="text-cyan-300 font-bold truncate block">{selectedObs.domain || selectedObs.hostname || 'Unassigned'}</span>
            </div>
          </div>

          {/* Observation Note */}
          {selectedObs.statusNote && (
            <div className="text-xs text-gray-300 bg-white/[0.03] p-3 rounded-lg border border-white/5 leading-relaxed">
              <span className="text-[#8aaf98] font-bold">FORENSIC TELEMETRY: </span>
              {selectedObs.statusNote}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
