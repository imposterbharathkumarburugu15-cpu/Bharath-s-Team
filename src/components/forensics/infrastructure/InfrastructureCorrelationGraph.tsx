import React, { useState } from 'react';
import { 
  GitBranch, 
  Mail, 
  Globe, 
  Link, 
  Server, 
  ShieldAlert, 
  Network, 
  Layers, 
  CheckCircle2, 
  Info, 
  ExternalLink,
  Zap,
  Activity,
  ArrowRight
} from 'lucide-react';
import { InfrastructureCorrelation, CorrelatedIncidentSummary } from '@/types/infrastructure';
import { cn } from '@/lib/utils';

interface InfrastructureCorrelationGraphProps {
  correlation: InfrastructureCorrelation;
  onSelectIncident?: (incidentId: string) => void;
}

export const InfrastructureCorrelationGraph: React.FC<InfrastructureCorrelationGraphProps> = ({
  correlation,
  onSelectIncident
}) => {
  const [activeNode, setActiveNode] = useState<string>('campaign');

  return (
    <div className="bg-[#0a0f0c] border border-cyan-500/30 rounded-2xl p-5 sm:p-6 shadow-2xl space-y-6 font-mono">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-purple-500/15 border border-purple-500/40 flex items-center justify-center text-purple-400 shrink-0">
            <GitBranch className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold uppercase tracking-wider text-white">
                Multi-Signal Infrastructure Correlation Graph
              </h3>
              <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 font-bold">
                CAMPAIGN CONFIDENCE: {correlation.campaignConfidenceScore}%
              </span>
            </div>
            <p className="text-[11px] text-gray-400 font-sans">
              Graph topology binding incidents by observable domain, ASN, URL hashes, and transit infrastructure.
            </p>
          </div>
        </div>

        {/* Objective Attribution Standard */}
        <div className="px-3 py-1.5 rounded-lg bg-black/60 border border-white/15 text-xs text-gray-300 flex items-center gap-2">
          <Info className="w-3.5 h-3.5 text-purple-400 shrink-0" />
          <span>Shared observable indicators — <strong className="text-white">not personal hacker identity</strong></span>
        </div>
      </div>

      {/* Campaign Cluster Summary Pill */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-purple-500/10 via-[#0d1612] to-cyan-500/10 border border-purple-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-[10px] uppercase font-bold tracking-widest text-purple-400 font-mono">
              ACTIVE CORRELATION CLUSTER
            </span>
            <span className="text-[9px] px-2 py-0.2 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40 font-bold">
              {correlation.campaignId || 'CAMP-2026-TITAN-04'}
            </span>
          </div>
          <h4 className="text-sm font-bold text-white tracking-wide">
            {correlation.campaignName || 'Operation ShadowRelay (BEC & Credential Harvest Cluster)'}
          </h4>
          <p className="text-[11px] text-gray-300 font-sans">
            These incidents share identical Autonomous System routing, common lookalike domains, and matching reverse proxy endpoints.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <div className="text-right">
            <div className="text-[10px] text-gray-400 uppercase font-bold">Correlation Strength</div>
            <div className="text-lg font-bold text-cyan-300">{correlation.campaignConfidenceScore}% (HIGH)</div>
          </div>
        </div>
      </div>

      {/* Interactive Evidence Topology Diagram */}
      <div className="p-6 rounded-xl bg-black/50 border border-white/10 space-y-6">
        <div className="text-[11px] text-gray-400 uppercase font-bold tracking-wider text-center">
          RELATIONSHIP TOPOLOGY (HOW NEUROSHIELD CORRELATES WHEN IP CHANGES)
        </div>

        {/* Tree Topology Structure */}
        <div className="flex flex-col items-center space-y-4 text-xs">
          {/* Level 1: Inbound Email */}
          <div className="px-5 py-2.5 rounded-xl bg-cyan-500/15 border-2 border-cyan-400 text-white font-bold flex items-center gap-2 shadow-[0_0_15px_rgba(6,182,212,0.3)]">
            <Mail className="w-4 h-4 text-cyan-400" />
            <span>PRIMARY INCIDENT (#{correlation.primaryIncidentId.slice(0, 12)})</span>
          </div>

          <div className="w-0.5 h-6 bg-cyan-500/50" />

          {/* Level 2: Shared Domain & URL */}
          <div className="flex flex-wrap items-center justify-center gap-4">
            <div className="px-4 py-2 rounded-lg bg-white/5 border border-cyan-500/30 text-cyan-300 font-bold flex items-center gap-2">
              <Globe className="w-3.5 h-3.5" />
              <span>Domain: {correlation.activeDomain}</span>
            </div>
            <div className="px-4 py-2 rounded-lg bg-white/5 border border-purple-500/30 text-purple-300 font-bold flex items-center gap-2">
              <Link className="w-3.5 h-3.5" />
              <span>Reverse Tunnel Endpoint</span>
            </div>
          </div>

          <div className="w-0.5 h-6 bg-purple-500/50" />

          {/* Level 3: Backbone ASN & Provider */}
          <div className="px-5 py-2 rounded-xl bg-purple-500/20 border border-purple-400 text-white font-bold flex items-center gap-2">
            <Server className="w-4 h-4 text-purple-400" />
            <span>Autonomous System: {correlation.activeAsn}</span>
          </div>

          <div className="w-0.5 h-6 bg-purple-500/50" />

          {/* Level 4: Branching to Correlated Incidents */}
          <div className="text-[10px] text-gray-400 uppercase tracking-widest font-bold">
            BRANCHING TO CORRELATED INCIDENTS (SHARED TELEMETRY)
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 w-full pt-2">
            {correlation.correlatedIncidents.map((inc, i) => (
              <div 
                key={inc.incidentId}
                onClick={() => onSelectIncident && onSelectIncident(inc.incidentId)}
                className="p-4 rounded-xl bg-[#0e1612] border border-white/15 hover:border-cyan-400 transition-all cursor-pointer space-y-2 group"
              >
                <div className="flex items-center justify-between border-b border-white/10 pb-2">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-cyan-400" />
                    <span className="font-bold text-white group-hover:text-cyan-300 transition-colors">
                      {inc.incidentId}
                    </span>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold">
                    {inc.relationshipType}
                  </span>
                </div>

                <div className="text-xs text-gray-300 truncate">
                  Subject: <span className="text-white font-semibold">{inc.subject}</span>
                </div>

                <div className="text-[11px] text-gray-400 flex items-center justify-between">
                  <span>Observed IP: <strong className="text-cyan-300 font-mono">{inc.observedIp}</strong></span>
                  <span>Confidence: <strong className="text-white">{inc.confidenceScore}%</strong></span>
                </div>

                <div className="flex flex-wrap gap-1 pt-1">
                  {inc.sharedIndicators.map((sh, idx) => (
                    <span key={idx} className="text-[9px] px-1.5 py-0.5 rounded bg-black/60 text-gray-300 border border-white/5">
                      ✓ {sh}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <div className="w-0.5 h-6 bg-emerald-500/50" />

          {/* Level 5: Campaign Assessment */}
          <div className="px-6 py-2.5 rounded-xl bg-emerald-500/15 border-2 border-emerald-400 text-white font-bold flex items-center gap-2 shadow-[0_0_15px_rgba(16,185,129,0.3)]">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>UNIFIED CAMPAIGN DEFENSE (RISK SCORE MAINTAINED ACROSS IP ROTATIONS)</span>
          </div>
        </div>
      </div>

      {/* Continuity Evidence List */}
      <div className="p-4 rounded-xl bg-white/[0.02] border border-white/10 space-y-2 text-xs">
        <span className="text-[10px] text-gray-500 uppercase font-bold block">
          DOCUMENTED CORRELATION EVIDENCE:
        </span>
        <div className="space-y-1.5">
          {correlation.continuityEvidence.map((ev, i) => (
            <div key={i} className="flex items-start gap-2 text-gray-300">
              <span className="text-cyan-400 font-bold font-mono">[{i + 1}]</span>
              <span>{ev}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
