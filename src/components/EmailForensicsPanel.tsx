import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import Markdown from 'react-markdown';
import { 
  FileText, Download, Share2, Globe, Terminal, 
  X, Check, Copy, ArrowUpRight, Compass, ShieldAlert, Sparkles, Printer,
  Brain, ChevronDown, ChevronUp, Network
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { ForensicDossier } from '@/services/forensicsEngine';
import { DomainAuthLookup } from '@/components/DomainAuthLookup';
import { Forensic3DGeoMap } from '@/components/Forensic3DGeoMap';

// Sub-components for the 22-point Forensic Investigation Report
import { ForensicCaseHeader } from './forensics/ForensicCaseHeader';
import { PlainEnglishThreatExplainer } from './forensics/PlainEnglishThreatExplainer';
import { NeuralProfile } from './forensics/NeuralProfile';
import { ForensicDrillDownModal, DrillDownTarget } from './forensics/ForensicDrillDownModal';
import { ForensicExecutiveSummary } from './forensics/ForensicExecutiveSummary';
import { EmailAnatomyDiagram } from './forensics/EmailAnatomyDiagram';
import { SenderIdentityGraph } from './forensics/SenderIdentityGraph';
import { SmtpRouteGraph } from './forensics/SmtpRouteGraph';
import { EmailTimelineView } from './forensics/EmailTimelineView';
import { AuthMatrixAndFlow } from './forensics/AuthMatrixAndFlow';
import { IocSectionAndTable } from './forensics/IocSectionAndTable';
import { SocialEngineeringAndNlp } from './forensics/SocialEngineeringAndNlp';
import { UrlAndAttachmentForensics } from './forensics/UrlAndAttachmentForensics';
import { CorrelationAndChain } from './forensics/CorrelationAndChain';
import { FinalVerdictAndRawEvidence } from './forensics/FinalVerdictAndRawEvidence';
import { SihForensicSuite } from './forensics/SihForensicSuite';
import { AdaptiveFeedbackSection } from '@/components/AdaptiveFeedbackSection';

export type ForensicPillarId = 'summary' | 'protocol' | 'neural' | 'iocs' | 'dossier';

export interface EmailForensicsPanelProps {
  dossier: ForensicDossier;
  compact?: boolean;
  hideNeuralProfile?: boolean;
  activePillar?: ForensicPillarId;
  onPillarChange?: (pillar: ForensicPillarId) => void;
  hideHeader?: boolean;
  hidePillarNav?: boolean;
}

export function EmailForensicsPanel({ 
  dossier, 
  compact = false, 
  hideNeuralProfile = false,
  activePillar: controlledPillar,
  onPillarChange,
  hideHeader = false,
  hidePillarNav = false
}: EmailForensicsPanelProps) {
  // Audience View Mode: 'unified' (default), 'plain-english' (for regular users), 'technical' (deep SOC)
  const [viewMode, setViewMode] = useState<'unified' | 'plain-english' | 'technical'>('unified');

  // Internal tab state if not controlled
  const [internalPillar, setInternalPillar] = useState<ForensicPillarId>('summary');
  const activePillar = controlledPillar ?? internalPillar;

  const handlePillarSelect = (pillar: ForensicPillarId) => {
    if (onPillarChange) {
      onPillarChange(pillar);
    } else {
      setInternalPillar(pillar);
    }
  };

  // Modal & Drill-down states
  const [drillDownTarget, setDrillDownTarget] = useState<DrillDownTarget | null>(null);
  const [showDnsLookup, setShowDnsLookup] = useState<boolean>(false);
  const [showSocPreview, setShowSocPreview] = useState<boolean>(false);
  const [copiedSocReport, setCopiedSocReport] = useState<boolean>(false);
  const [showGeoRadar, setShowGeoRadar] = useState<boolean>(false);
  const [copiedPlaybookKey, setCopiedPlaybookKey] = useState<string | null>(null);

  const targetDomain = dossier.senderIdentity.fromDomain || dossier.authentication.dmarc.headerFromDomain || 'domain.com';

  const handlePrintPdf = () => {
    window.print();
  };

  // Export handlers
  const copySocReport = () => {
    if (dossier.socReportMarkdown) {
      navigator.clipboard.writeText(dossier.socReportMarkdown);
      setCopiedSocReport(true);
      setTimeout(() => setCopiedSocReport(false), 2000);
    }
  };

  const downloadJsonDossier = () => {
    const blob = new Blob([JSON.stringify(dossier, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forensic-dossier-${dossier.chainOfCustody.caseId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadMarkdownReport = () => {
    const blob = new Blob([dossier.socReportMarkdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SOC-Forensic-Report-${dossier.chainOfCustody.caseId}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportSTIX21 = () => {
    const stixBundle = {
      type: 'bundle',
      id: `bundle--${Math.random().toString(36).substring(2, 15)}`,
      objects: [
        {
          type: 'report',
          id: `report--${dossier.chainOfCustody.caseId}`,
          name: `Forensic Report: ${dossier.headerFields.subject}`,
          published: dossier.chainOfCustody.ingestionTimestamp,
          labels: ['phishing', 'email-threat', dossier.scoreBreakdown.riskCategory.toLowerCase()]
        },
        ...dossier.iocs.ipAddresses.map(i => ({
          type: 'indicator',
          name: `Malicious IP: ${i.ip}`,
          pattern: `[ipv4-addr:value = '${i.ip}']`,
          labels: [i.role]
        })),
        ...dossier.iocs.domains.map(d => ({
          type: 'indicator',
          name: `Deceptive Domain: ${d.domain}`,
          pattern: `[domain-name:value = '${d.domain}']`,
          labels: [d.role]
        }))
      ]
    };
    const blob = new Blob([JSON.stringify(stixBundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `STIX-2.1-Bundle-${dossier.chainOfCustody.caseId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportIocsCsv = () => {
    const rows = [
      ['Type', 'Indicator', 'Role', 'Threat Level'],
      ...dossier.iocs.ipAddresses.map(i => ['IPv4/IPv6', i.ip, i.role, 'SUSPICIOUS']),
      ...dossier.iocs.domains.map(d => ['Domain', d.domain, d.role, d.isLookalike ? 'CRITICAL_LOOKALIKE' : 'SUSPICIOUS']),
      ...dossier.iocs.urls.map(u => ['URL', u.url, 'Payload Endpoint', u.threat || 'HIGH_RISK']),
      ...dossier.iocs.emailAddresses.map(e => ['Email', e.email, e.role, 'INVESTIGATION']),
      ...dossier.iocs.fileHashes.map(h => ['SHA-256 Hash', h.sha256, h.filename, 'ATTACHMENT'])
    ];
    const csvContent = rows.map(r => r.map(c => `"${c}"`).join(',')).join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `IOC-Export-${dossier.chainOfCustody.caseId}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const pillarTabs: { id: ForensicPillarId; label: string; icon: any }[] = [
    { id: 'summary', label: 'Executive Summary', icon: Sparkles },
    { id: 'protocol', label: 'Protocol DNA & Relays', icon: Network },
    { id: 'neural', label: 'Neural & Cognitive', icon: Brain },
    { id: 'iocs', label: 'Threat IOCs & SIH', icon: ShieldAlert },
    { id: 'dossier', label: 'Dossier & Playbooks', icon: FileText },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-6 text-white font-mono"
    >
      {/* 1. FORENSIC CASE HEADER (only when not embedded in a unified container) */}
      {!hideHeader && (
        <ForensicCaseHeader
          dossier={dossier}
          onOpenSocReport={() => setShowSocPreview(true)}
          onExportJson={downloadJsonDossier}
          onExportStix={exportSTIX21}
          onPrintPdf={handlePrintPdf}
        />
      )}

      {/* 2. PILLAR NAVIGATION BAR (rendered when not driven externally) */}
      {!hidePillarNav && (
        <div className="bg-[#0f1612]/90 border border-cyan-500/30 p-2 rounded-2xl backdrop-blur-xl shadow-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center gap-1.5 flex-wrap">
            {pillarTabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activePillar === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => handlePillarSelect(tab.id)}
                  className={cn(
                    "px-3.5 py-2 rounded-xl text-xs font-mono font-bold tracking-wider transition-all flex items-center gap-2 cursor-pointer shadow-sm",
                    isActive
                      ? "bg-cyan-500 text-black shadow-[0_0_15px_rgba(105,230,165,0.4)]"
                      : "bg-white/5 hover:bg-white/10 text-gray-300 hover:text-white border border-white/5"
                  )}
                >
                  <Icon className={cn("w-3.5 h-3.5", isActive ? "text-black" : "text-cyan-400")} />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>

          <div className="flex items-center gap-2 shrink-0 self-end sm:self-auto">
            <button
              onClick={() => setShowGeoRadar(!showGeoRadar)}
              className={cn(
                "px-3 py-1.5 rounded-xl text-xs font-mono font-bold flex items-center gap-1.5 transition-all cursor-pointer",
                showGeoRadar
                  ? "bg-cyan-500 text-black shadow-[0_0_12px_rgba(105,230,165,0.4)]"
                  : "bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10"
              )}
            >
              <Globe className="w-3.5 h-3.5 text-cyan-400" />
              <span>3D Radar</span>
            </button>

            <button
              onClick={() => setShowDnsLookup(true)}
              className="px-3 py-1.5 rounded-xl text-xs font-mono font-bold bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 flex items-center gap-1.5 cursor-pointer"
            >
              <Compass className="w-3.5 h-3.5 text-cyan-400" />
              <span>Live DNS</span>
            </button>

            <button
              onClick={handlePrintPdf}
              className="px-3 py-1.5 rounded-xl text-xs font-mono font-bold bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 flex items-center gap-1.5 cursor-pointer"
              title="Print report to PDF"
            >
              <Printer className="w-3.5 h-3.5 text-cyan-400" />
              <span>PDF</span>
            </button>
          </div>
        </div>
      )}

      {/* OPTIONAL EXPANDABLE 3D ORIGIN RADAR */}
      {showGeoRadar && (
        <div className="bg-[#0e1410] border border-cyan-500/30 rounded-2xl p-5 shadow-2xl space-y-3">
          <div className="flex items-center justify-between border-b border-white/10 pb-2">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                Origin Infrastructure 3D Telemetry
              </h3>
            </div>
            <button
              onClick={() => setShowGeoRadar(false)}
              className="text-xs text-gray-400 hover:text-white"
            >
              Close
            </button>
          </div>
          <Forensic3DGeoMap originIP={dossier.originIP} />
        </div>
      )}

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* PILLAR 1: EXECUTIVE SUMMARY & ANATOMY                                      */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {activePillar === 'summary' && (
        <div className="space-y-6">
          {/* Plain-English Threat Explainer */}
          {(viewMode === 'plain-english' || viewMode === 'unified') && (
            <PlainEnglishThreatExplainer 
              dossier={dossier}
              onSwitchToTechnicalView={() => setViewMode('technical')}
            />
          )}

          {/* Executive Forensic Summary */}
          <ForensicExecutiveSummary
            dossier={dossier}
            onDrillDown={(target) => setDrillDownTarget(target)}
          />

          {/* Email Forensic Anatomy Visualization */}
          {viewMode !== 'plain-english' && (
            <EmailAnatomyDiagram
              dossier={dossier}
              onDrillDown={(target) => setDrillDownTarget(target)}
            />
          )}

          {/* Final Forensic Verdict & Containment Action */}
          <FinalVerdictAndRawEvidence
            dossier={dossier}
            onDrillDown={(target) => setDrillDownTarget(target)}
            onBlockIp={(ip) => console.log(`Containing IP: ${ip}`)}
            onBlockDomain={(domain) => console.log(`Sinkholing domain: ${domain}`)}
            onPurgeEmail={() => console.log('Initiating mailbox purge across tenant')}
            onExportEml={() => {
              const rawContent = dossier.rawHeaders && Object.keys(dossier.rawHeaders).length > 0
                ? Object.entries(dossier.rawHeaders).map(([k, v]) => Array.isArray(v) ? v.map(i => `${k}: ${i}`).join('\n') : `${k}: ${v}`).join('\n')
                : Object.entries(dossier.headerFields).map(([k, v]) => `${k}: ${v}`).join('\n');
              const blob = new Blob([rawContent], { type: 'message/rfc822' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `evidence-${dossier.chainOfCustody.caseId}.eml`;
              a.click();
              URL.revokeObjectURL(url);
            }}
          />
        </div>
      )}

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* PILLAR 2: PROTOCOL DNA & RELAYS                                            */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {activePillar === 'protocol' && (
        <div className="space-y-6">
          {/* SPF / DKIM / DMARC Visual Matrix & Flow */}
          <AuthMatrixAndFlow
            dossier={dossier}
            onDrillDown={(target) => setDrillDownTarget(target)}
          />

          {/* Sender Identity Alignment Graph */}
          <SenderIdentityGraph
            dossier={dossier}
            onDrillDown={(target) => setDrillDownTarget(target)}
          />

          {/* SMTP Hop & Route Graph */}
          <SmtpRouteGraph
            dossier={dossier}
            onDrillDown={(target) => setDrillDownTarget(target)}
          />

          {/* Email Chronological Route Timeline */}
          <EmailTimelineView
            dossier={dossier}
          />
        </div>
      )}

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* PILLAR 3: NEURAL PROFILE & COGNITIVE NLP                                   */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {activePillar === 'neural' && (
        <div className="space-y-6">
          {/* Neural Profile */}
          {!hideNeuralProfile && (
            <NeuralProfile
              dossier={dossier}
              onOpenFullForensics={() => handlePillarSelect('summary')}
            />
          )}

          {/* Social Engineering & Cognitive Manipulation */}
          <SocialEngineeringAndNlp
            dossier={dossier}
            onDrillDown={(target) => setDrillDownTarget(target)}
          />
        </div>
      )}

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* PILLAR 4: THREAT IOCS & SIH 5-PILLAR SUITE                                */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {activePillar === 'iocs' && (
        <div className="space-y-6">
          {/* IOC Intelligence Section & Table */}
          <IocSectionAndTable
            dossier={dossier}
            onDrillDown={(target) => setDrillDownTarget(target)}
            onExportCsv={exportIocsCsv}
            onExportStix={exportSTIX21}
          />

          {/* URL & Attachment Forensics */}
          <UrlAndAttachmentForensics
            dossier={dossier}
            onDrillDown={(target) => setDrillDownTarget(target)}
          />

          {/* Threat Correlation Graph & Chain of Evidence */}
          <CorrelationAndChain
            dossier={dossier}
            onDrillDown={(target) => setDrillDownTarget(target)}
          />

          {/* SIH26106 5-Pillar Forensic Suite Upgrades */}
          <SihForensicSuite 
            dossier={dossier} 
            onDrillDown={(target) => setDrillDownTarget(target)} 
          />
        </div>
      )}

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* PILLAR 5: INCIDENT DOSSIER & PLAYBOOKS                                     */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {activePillar === 'dossier' && (
        <div className="space-y-6">
          {/* Automated SOC Mitigation Playbooks */}
          {dossier.socPlaybooks && dossier.socPlaybooks.length > 0 && (
            <section 
              id="soc-playbooks-section"
              className="bg-[#0e1410] border border-cyan-500/30 rounded-2xl p-5 sm:p-6 shadow-2xl space-y-4"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/10 pb-3">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  <h2 className="text-xs font-bold uppercase tracking-widest text-white">
                    Automated SOC Mitigation Playbooks & Containment Scripts
                  </h2>
                </div>
                <span className="text-[10px] text-gray-500 font-sans">
                  Ready-to-execute defensive policies
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {dossier.socPlaybooks.map((pb, idx) => (
                  <div 
                    key={idx} 
                    className="bg-black/40 border border-white/10 rounded-xl p-4 space-y-3 flex flex-col justify-between hover:border-cyan-500/40 transition-all shadow-inner"
                  >
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-white">{pb.title}</span>
                        <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-white/5 text-gray-400 border border-white/10 uppercase">
                          {pb.category}
                        </span>
                      </div>
                      <p className="text-[11px] text-gray-300 font-sans leading-relaxed">
                        {pb.description}
                      </p>
                    </div>

                    <div className="space-y-2 pt-2 border-t border-white/5">
                      <div className="bg-[#080c09] p-2.5 rounded-lg text-[10px] font-mono text-cyan-300 break-all select-all border border-white/5">
                        {pb.commandOrRule}
                      </div>
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(pb.commandOrRule);
                          setCopiedPlaybookKey(`pb-${idx}`);
                          setTimeout(() => setCopiedPlaybookKey(null), 2000);
                        }}
                        className="w-full py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-gray-300 text-[11px] font-mono flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                      >
                        {copiedPlaybookKey === `pb-${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedPlaybookKey === `pb-${idx}` ? 'Copied Rule' : 'Copy Playbook Script'}</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Full Markdown SOC Report View */}
          <div className="bg-[#0e1410] border border-cyan-500/30 rounded-2xl p-5 sm:p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                  Official SOC Forensic Dossier — Case #{dossier.chainOfCustody.caseId}
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={copySocReport}
                  className="px-3 py-1.5 rounded-lg bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 text-xs font-mono font-bold flex items-center gap-1.5 cursor-pointer hover:bg-cyan-500/25 transition-colors"
                >
                  {copiedSocReport ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedSocReport ? 'Copied' : 'Copy Markdown'}</span>
                </button>
                <button
                  onClick={downloadMarkdownReport}
                  className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-gray-200 border border-white/10 text-xs font-mono flex items-center gap-1.5 cursor-pointer transition-colors"
                >
                  <Download className="w-3 h-3 text-cyan-400" />
                  <span>Download .md</span>
                </button>
                <button
                  onClick={handlePrintPdf}
                  className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-gray-200 border border-white/10 text-xs font-mono flex items-center gap-1.5 cursor-pointer transition-colors"
                >
                  <Printer className="w-3 h-3 text-cyan-400" />
                  <span>Print PDF</span>
                </button>
              </div>
            </div>

            <div className="p-4 bg-black/40 rounded-xl border border-white/5 text-xs text-gray-300 leading-relaxed max-h-[500px] overflow-y-auto custom-scrollbar font-mono">
              <div className="markdown-body prose prose-invert max-w-none text-xs">
                <Markdown>{dossier.socReportMarkdown}</Markdown>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 18. ANALYST DRILL-DOWN MODAL */}
      <ForensicDrillDownModal
        target={drillDownTarget}
        onClose={() => setDrillDownTarget(null)}
      />

      {/* LIVE DNS LOOKUP MODAL */}
      <AnimatePresence>
        {showDnsLookup && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-[#0f1712] border border-cyan-500/40 rounded-2xl w-full max-w-4xl max-h-[85vh] overflow-hidden flex flex-col shadow-2xl font-mono"
            >
              <div className="p-4 border-b border-white/10 flex justify-between items-center bg-[#080c09]">
                <div className="flex items-center gap-2">
                  <Compass className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                    Live DNS & Domain Authentication Inspector
                  </h3>
                </div>
                <button
                  onClick={() => setShowDnsLookup(false)}
                  className="p-1 rounded text-gray-400 hover:text-white cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="p-4 overflow-y-auto max-h-[calc(85vh-60px)]">
                <DomainAuthLookup initialDomain={targetDomain} />
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* FULL SOC INCIDENT REPORT MARKDOWN PREVIEW MODAL */}
      <AnimatePresence>
        {showSocPreview && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-[#0f1712] border border-cyan-500/40 rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col overflow-hidden shadow-2xl font-mono"
            >
              <div className="p-4 border-b border-white/10 flex justify-between items-center bg-[#080c09]">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                    Official Forensic Incident Dossier — Case #{dossier.chainOfCustody.caseId}
                  </h3>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={copySocReport}
                    className="px-3 py-1 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 text-xs font-mono font-bold flex items-center gap-1 cursor-pointer"
                  >
                    {copiedSocReport ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedSocReport ? 'Copied' : 'Copy Markdown'}</span>
                  </button>
                  <button
                    onClick={downloadMarkdownReport}
                    className="px-3 py-1 rounded bg-white/5 text-gray-300 border border-white/10 text-xs font-mono flex items-center gap-1 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Download .md</span>
                  </button>
                  <button
                    onClick={() => setShowSocPreview(false)}
                    className="p-1 rounded text-gray-400 hover:text-white cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              <div className="p-6 overflow-y-auto space-y-4 text-xs font-mono text-gray-300 leading-relaxed">
                <div className="markdown-body">
                  <Markdown>{dossier.socReportMarkdown}</Markdown>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
