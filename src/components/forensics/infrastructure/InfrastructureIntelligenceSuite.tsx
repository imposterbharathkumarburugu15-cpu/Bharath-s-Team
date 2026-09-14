import React, { useState, useEffect } from 'react';
import { 
  Globe, 
  Clock, 
  Network, 
  GitBranch, 
  Sparkles, 
  Download, 
  Copy, 
  Check, 
  Shield, 
  Info, 
  Layers, 
  Terminal,
  Activity,
  CheckCircle2,
  Lock,
  ArrowRight
} from 'lucide-react';
import { ForensicDossier, extractInfrastructureObservationsFromDossier, buildInfrastructureCorrelation, generateForensicCaseReport } from '@/services/forensicsEngine';
import { InfrastructureObservation, InfrastructureCorrelation, ForensicCaseReport } from '@/types/infrastructure';
import { ObservedInfrastructureMap } from './ObservedInfrastructureMap';
import { InfrastructureTimeline } from './InfrastructureTimeline';
import { RelayPathReconstruction } from './RelayPathReconstruction';
import { InfrastructureCorrelationGraph } from './InfrastructureCorrelationGraph';
import { RotatingInfrastructureDemo } from './RotatingInfrastructureDemo';
import { cn } from '@/lib/utils';

export type InfrastructureSubView = 'map' | 'timeline' | 'relay' | 'correlation' | 'demo';

interface InfrastructureIntelligenceSuiteProps {
  dossier: ForensicDossier;
  initialSubView?: InfrastructureSubView;
}

export const InfrastructureIntelligenceSuite: React.FC<InfrastructureIntelligenceSuiteProps> = ({
  dossier,
  initialSubView = 'map'
}) => {
  const [activeSubView, setActiveSubView] = useState<InfrastructureSubView>(initialSubView);
  const [copiedCaseReport, setCopiedCaseReport] = useState<boolean>(false);

  // Synchronized historical observations across all views
  const [observations, setObservations] = useState<InfrastructureObservation[]>(() => {
    return extractInfrastructureObservationsFromDossier(dossier);
  });

  const [activeObservationId, setActiveObservationId] = useState<string>(
    observations[observations.length - 1]?.id || ''
  );

  // Recalculated multi-signal correlation
  const [correlation, setCorrelation] = useState<InfrastructureCorrelation>(() => {
    return buildInfrastructureCorrelation(dossier, observations);
  });

  // Re-sync when dossier changes
  useEffect(() => {
    const extracted = extractInfrastructureObservationsFromDossier(dossier);
    setObservations(extracted);
    setActiveObservationId(extracted[extracted.length - 1]?.id || '');
    setCorrelation(buildInfrastructureCorrelation(dossier, extracted));
  }, [dossier]);

  // Handle simulation step injection from RotatingInfrastructureDemo
  const handleSimulateStep = (step: number, newObs: InfrastructureObservation) => {
    setObservations(prev => {
      // Check if already present to avoid duplication
      const existingIdx = prev.findIndex(o => o.ip === newObs.ip);
      if (existingIdx !== -1) {
        return prev.map((o, idx) => ({
          ...o,
          isCurrentActive: idx === existingIdx
        }));
      }
      // Add new observation while marking all prior as historical
      const updated = prev.map(o => ({ ...o, isCurrentActive: false }));
      updated.push(newObs);
      return updated;
    });

    setActiveObservationId(newObs.id);
    setCorrelation(prev => ({
      ...prev,
      activeIp: newObs.ip,
      activeAsn: newObs.asn || prev.activeAsn,
      activeProvider: newObs.provider || prev.activeProvider,
      totalHistoricalObservations: observations.length + 1,
      campaignConfidenceScore: Math.min(prev.campaignConfidenceScore + 4, 98)
    }));
  };

  // Generate complete court-defensible Case Report
  const caseReport: ForensicCaseReport = generateForensicCaseReport(dossier, observations, correlation);

  const handleExportCaseReport = () => {
    const blob = new Blob([JSON.stringify(caseReport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `investigation-ready-forensic-case-${caseReport.caseId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyCaseReport = () => {
    navigator.clipboard.writeText(JSON.stringify(caseReport, null, 2));
    setCopiedCaseReport(true);
    setTimeout(() => setCopiedCaseReport(false), 2000);
  };

  const navTabs: { id: InfrastructureSubView; label: string; icon: any; count?: number }[] = [
    { id: 'map', label: 'Observed Infrastructure Map', icon: Globe, count: observations.length },
    { id: 'timeline', label: 'Infrastructure Timeline', icon: Clock, count: observations.length },
    { id: 'relay', label: 'Relay Path Reconstruction', icon: Network, count: dossier.relayReconstruction?.chronologicalHops?.length || 3 },
    { id: 'correlation', label: 'Infrastructure Correlation Graph', icon: GitBranch, count: correlation.correlatedIncidents.length },
    { id: 'demo', label: 'Rotating Infrastructure Demo', icon: Sparkles },
  ];

  return (
    <div id="infrastructure-intelligence-suite" className="space-y-6 font-mono text-white">
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* MASTER SUITE BANNER (EXACT USER SPECIFICATION)                             */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      <div className="bg-[#0b120e] border-2 border-cyan-500/40 rounded-2xl p-5 sm:p-6 shadow-2xl relative overflow-hidden backdrop-blur-xl">
        <div className="absolute top-0 right-0 w-96 h-36 bg-gradient-to-l from-cyan-500/10 via-purple-500/10 to-transparent pointer-events-none" />

        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 relative z-10 border-b border-white/10 pb-4">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-cyan-400" />
                SIH26106 FLAGSHIP SUITE
              </span>
              <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 text-[10px] font-bold">
                HISTORICAL INFRASTRUCTURE TELEMETRY
              </span>
            </div>

            <h2 className="text-xl sm:text-2xl font-black text-white tracking-wide flex items-center gap-2.5 pt-1">
              <span>INFRASTRUCTURE INTELLIGENCE</span>
            </h2>

            <p className="text-xs text-gray-300 font-sans max-w-3xl leading-relaxed">
              "Historical and correlated observations from email transmission and associated infrastructure."
            </p>
          </div>

          {/* Quick Case Export Action Buttons */}
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={handleCopyCaseReport}
              className="px-3 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs text-cyan-300 font-bold flex items-center gap-1.5 transition-all cursor-pointer"
              title="Copy Investigation-ready forensic case JSON"
            >
              {copiedCaseReport ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedCaseReport ? 'Copied Case' : 'Copy Case JSON'}</span>
            </button>

            <button
              onClick={handleExportCaseReport}
              className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-black font-bold text-xs flex items-center gap-2 transition-all cursor-pointer shadow-[0_0_15px_rgba(6,182,212,0.35)]"
              title="Download full court-defensible investigation report"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Forensic Case Report</span>
            </button>
          </div>
        </div>

        {/* 4 CONNECTED VIEWS NAVIGATION TABS (+ DEMO) */}
        <div className="flex flex-wrap items-center gap-2 pt-4 relative z-10">
          {navTabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeSubView === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveSubView(tab.id)}
                className={cn(
                  "px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer border",
                  isActive
                    ? "bg-cyan-500 text-black border-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.4)]"
                    : "bg-white/[0.04] hover:bg-white/10 text-gray-300 border-white/10 hover:border-white/20"
                )}
              >
                <Icon className={cn("w-4 h-4", isActive ? "text-black" : "text-cyan-400")} />
                <span>{tab.label}</span>
                {tab.count !== undefined && (
                  <span className={cn(
                    "text-[10px] px-1.5 py-0.2 rounded font-mono font-bold",
                    isActive ? "bg-black/20 text-black" : "bg-white/10 text-cyan-300"
                  )}>
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* CONNECTED SUB-VIEW 1: OBSERVED INFRASTRUCTURE MAP                          */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {activeSubView === 'map' && (
        <ObservedInfrastructureMap
          observations={observations}
          activeObservationId={activeObservationId}
          onSelectObservation={(obs) => setActiveObservationId(obs.id)}
        />
      )}

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* CONNECTED SUB-VIEW 2: INFRASTRUCTURE TIMELINE                              */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {activeSubView === 'timeline' && (
        <InfrastructureTimeline
          observations={observations}
          activeObservationId={activeObservationId}
          onSelectObservation={(obs) => setActiveObservationId(obs.id)}
        />
      )}

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* CONNECTED SUB-VIEW 3: RELAY PATH RECONSTRUCTION                            */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {activeSubView === 'relay' && (
        <RelayPathReconstruction
          dossier={dossier}
          observations={observations}
        />
      )}

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* CONNECTED SUB-VIEW 4: INFRASTRUCTURE CORRELATION GRAPH                     */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {activeSubView === 'correlation' && (
        <InfrastructureCorrelationGraph
          correlation={correlation}
        />
      )}

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* CONTROLLED DEMO: ROTATING INFRASTRUCTURE CONTINUITY TEST                   */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {activeSubView === 'demo' && (
        <RotatingInfrastructureDemo
          onSimulateStep={handleSimulateStep}
        />
      )}
    </div>
  );
};
