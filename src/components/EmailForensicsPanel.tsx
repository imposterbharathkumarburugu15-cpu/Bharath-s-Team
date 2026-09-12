import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import Markdown from 'react-markdown';
import { 
  FileText, Download, Share2, Globe, Terminal, 
  X, Check, Copy, ArrowUpRight, Compass, ShieldAlert, Sparkles, Printer,
  Brain, ChevronDown, ChevronUp
} from 'lucide-react';
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
import { AdaptiveFeedbackSection } from '@/components/AdaptiveFeedbackSection';

interface EmailForensicsPanelProps {
  dossier: ForensicDossier;
  compact?: boolean;
}

export function EmailForensicsPanel({ dossier, compact = false }: EmailForensicsPanelProps) {
  // Audience View Mode: 'unified' (default), 'plain-english' (for regular users), 'technical' (deep SOC)
  const [viewMode, setViewMode] = useState<'unified' | 'plain-english' | 'technical'>('unified');

  // Modal & Drill-down states
  const [drillDownTarget, setDrillDownTarget] = useState<DrillDownTarget | null>(null);
  const [showDnsLookup, setShowDnsLookup] = useState<boolean>(false);
  const [showSocPreview, setShowSocPreview] = useState<boolean>(false);
  const [copiedSocReport, setCopiedSocReport] = useState<boolean>(false);
  const [showGeoRadar, setShowGeoRadar] = useState<boolean>(false);
  const [copiedPlaybookKey, setCopiedPlaybookKey] = useState<string | null>(null);
  const [showNeuralProfile, setShowNeuralProfile] = useState<boolean>(true);

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

  const scrollToSection = (sectionId: string) => {
    if (sectionId === 'neural-profile') {
      setShowNeuralProfile(true);
    }
    const el = document.getElementById(sectionId);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const navSections = [
    { id: 'neural-profile', label: '1. Neural Profile' },
    { id: 'plain-english-explainer', label: '2. Plain-English' },
    { id: 'executive-forensic-summary', label: '3. Summary' },
    { id: 'email-forensic-anatomy-visualization', label: '4. Anatomy' },
    { id: 'sender-identity-graph', label: '5. Identity' },
    { id: 'smtp-hop-route-graph', label: '6. Route' },
    { id: 'email-timeline-section', label: '7. Timeline' },
    { id: 'authentication-visual-matrix', label: '8-9. Auth' },
    { id: 'ioc-intelligence-section', label: '10-11. IOCs' },
    { id: 'social-engineering-analysis', label: '12. Social Eng' },
    { id: 'url-forensics-section', label: '13-14. URLs/Files' },
    { id: 'threat-correlation-graph', label: '15-17. Evidence' },
    { id: 'final-forensic-verdict', label: '18. Verdict' },
    { id: 'raw-rfc-evidence-section', label: '19. Raw RFC' }
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-6 text-white font-mono"
    >
      {/* 1. FORENSIC CASE HEADER */}
      <ForensicCaseHeader
        dossier={dossier}
        onOpenSocReport={() => setShowSocPreview(true)}
        onExportJson={downloadJsonDossier}
        onExportStix={exportSTIX21}
        onPrintPdf={handlePrintPdf}
      />

      {/* AUDIENCE PRESENTATION MODE SWITCHER (Plain-English User View vs SOC Analyst View) */}
      <div className="bg-[#0b1329] border border-cyan-500/40 rounded-xl p-3 sm:p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-lg print:hidden">
        <div className="flex items-center gap-2.5">
          <Sparkles className="w-5 h-5 text-cyan-400 animate-pulse shrink-0" />
          <div>
            <span className="text-xs sm:text-sm font-bold uppercase tracking-wider text-white block">
              Forensics Presentation Mode
            </span>
            <span className="text-[11px] text-gray-400 font-sans block">
              Switch between plain-English guidance for non-technical users and 22-point RFC telemetry for SOC analysts.
            </span>
          </div>
        </div>

        <div className="flex items-center gap-1.5 bg-black/60 p-1 rounded-xl border border-white/10 w-full sm:w-auto overflow-x-auto shrink-0">
          <button
            onClick={() => setViewMode('plain-english')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
              viewMode === 'plain-english'
                ? 'bg-cyan-500 text-black shadow-[0_0_12px_rgba(0,245,255,0.4)]'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <span>👤 Plain-English (User View)</span>
          </button>

          <button
            onClick={() => setViewMode('unified')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
              viewMode === 'unified'
                ? 'bg-cyan-500 text-black shadow-[0_0_12px_rgba(0,245,255,0.4)]'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <span>⚡ Unified (Dual View)</span>
          </button>

          <button
            onClick={() => setViewMode('technical')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
              viewMode === 'technical'
                ? 'bg-cyan-500 text-black shadow-[0_0_12px_rgba(0,245,255,0.4)]'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <span>🔬 SOC Deep-Dive</span>
          </button>
        </div>
      </div>

      {/* QUICK JUMP SECTION NAV BAR (Sticky on Desktop for Rapid SOC Navigation, hidden in print) */}
      <nav 
        id="forensic-report-navigation"
        aria-label="Forensic Report Sections"
        className="sticky top-2 z-20 bg-[#080d1a]/95 border border-cyan-500/30 rounded-xl p-2.5 sm:p-3 shadow-2xl backdrop-blur-md flex items-center justify-between gap-3 overflow-x-auto text-xs sm:text-sm print:hidden"
      >
        <div className="flex items-center gap-2 overflow-x-auto scrollbar-none py-0.5">
          <span className="text-xs text-cyan-400 font-bold uppercase tracking-wider px-2 shrink-0">
            JUMP TO:
          </span>
          {navSections.map(s => (
            <button
              key={s.id}
              onClick={() => scrollToSection(s.id)}
              className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-cyan-500/25 hover:text-cyan-300 text-gray-200 transition-all whitespace-nowrap cursor-pointer text-xs sm:text-sm font-semibold"
            >
              {s.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 shrink-0 pl-3 border-l border-white/10">
          <button
            onClick={handlePrintPdf}
            id="nav-print-pdf-btn"
            className="px-3.5 py-1.5 rounded-lg text-xs sm:text-sm font-bold bg-cyan-500 hover:bg-cyan-400 text-black flex items-center gap-1.5 cursor-pointer transition-all shadow-[0_0_12px_rgba(0,245,255,0.4)] active:scale-95"
            title="Print report to PDF"
          >
            <Printer className="w-4 h-4 text-black" />
            <span className="hidden sm:inline">Print PDF</span>
          </button>

          <button
            onClick={() => setShowGeoRadar(!showGeoRadar)}
            className={`px-3.5 py-1.5 rounded-lg text-xs sm:text-sm font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
              showGeoRadar 
                ? 'bg-cyan-500 text-black shadow-[0_0_12px_rgba(0,245,255,0.4)]' 
                : 'bg-white/10 hover:bg-white/20 text-gray-200 border border-white/10'
            }`}
          >
            <Globe className="w-4 h-4 text-cyan-400" />
            <span className="hidden sm:inline">3D Radar</span>
          </button>

          <button
            onClick={() => setShowDnsLookup(true)}
            className="px-3.5 py-1.5 rounded-lg text-xs sm:text-sm font-bold bg-white/10 hover:bg-white/20 text-gray-200 border border-white/10 flex items-center gap-1.5 cursor-pointer"
          >
            <Compass className="w-4 h-4 text-cyan-400" />
            <span className="hidden sm:inline">Live DNS</span>
          </button>

          <button
            onClick={() => {
              const next = !showNeuralProfile;
              setShowNeuralProfile(next);
              if (next) {
                setTimeout(() => scrollToSection('neural-profile'), 80);
              }
            }}
            className={`px-3.5 py-1.5 rounded-lg text-xs sm:text-sm font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
              showNeuralProfile 
                ? 'bg-purple-500 text-white shadow-[0_0_12px_rgba(168,85,247,0.5)] border border-purple-400' 
                : 'bg-white/10 hover:bg-white/20 text-purple-300 border border-purple-500/30'
            }`}
            title="Inspect Neural Profile & Cognitive Threat Telemetry"
          >
            <Brain className="w-4 h-4 text-purple-400" />
            <span className="hidden sm:inline">Neural Profile</span>
          </button>
        </div>
      </nav>

      {/* OPTIONAL EXPANDABLE 3D ORIGIN RADAR */}
      {showGeoRadar && (
        <div className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 shadow-2xl space-y-3">
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

      {/* 1. NEURAL PROFILE SEPARATE BUTTON & EXPANDABLE CARD (SHOWN FIRST) */}
      <div id="neural-profile" className="bg-[#0a0f1c] border border-purple-500/30 rounded-2xl p-4 sm:p-5 shadow-xl transition-all">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-purple-500/20 border border-purple-500/40 flex items-center justify-center shrink-0 shadow-[0_0_12px_rgba(168,85,247,0.25)]">
              <Brain className="w-5 h-5 text-purple-300 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                  1. Neural Profile & Behavioral Sender Analysis
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 font-bold">
                  Layer 2 Engine
                </span>
              </div>
              <p className="text-[11px] text-gray-300 font-sans mt-0.5">
                Cognitive urgency scoring, Amygdala hijack detection, and executive impersonation mimicry.
              </p>
            </div>
          </div>

          <button
            onClick={() => setShowNeuralProfile(!showNeuralProfile)}
            className={`px-4 py-2.5 rounded-xl text-xs font-mono font-bold flex items-center justify-center gap-2 transition-all cursor-pointer whitespace-nowrap shadow-md active:scale-95 w-full sm:w-auto ${
              showNeuralProfile
                ? 'bg-purple-500 text-white shadow-[0_0_15px_rgba(168,85,247,0.4)]'
                : 'bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 border border-purple-500/40'
            }`}
          >
            <Brain className="w-4 h-4" />
            <span>{showNeuralProfile ? 'Hide Neural Profile' : 'Inspect Neural Profile'}</span>
            {showNeuralProfile ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>

        {showNeuralProfile && (
          <div className="pt-4 mt-4 border-t border-purple-500/20">
            <NeuralProfile
              dossier={dossier}
              onOpenFullForensics={() => scrollToSection('executive-forensic-summary')}
            />
          </div>
        )}
      </div>

      {/* 2. PLAIN-ENGLISH USER EXPLAINER (Rendered in Plain-English and Unified views) */}
      {(viewMode === 'plain-english' || viewMode === 'unified') && (
        <PlainEnglishThreatExplainer 
          dossier={dossier}
          onSwitchToTechnicalView={() => setViewMode('technical')}
        />
      )}

      {/* 3. EXECUTIVE FORENSIC SUMMARY */}
      <ForensicExecutiveSummary
        dossier={dossier}
        onDrillDown={(target) => setDrillDownTarget(target)}
      />

      {/* HUMAN-IN-THE-LOOP ADAPTIVE FEEDBACK LEARNING SECTION */}
      <div id="hitl-feedback-section" className="print:hidden">
        <AdaptiveFeedbackSection
          targetId={`case-${dossier.chainOfCustody.caseId}`}
          modelPrediction={`${dossier.scoreBreakdown.riskCategory}: ${dossier.headerFields.subject || 'Analyzed Email'}`}
          riskScore={dossier.scoreBreakdown.totalRiskScore}
          predictedAttackType="EMAIL"
          extractedFeatures={{
            signals: dossier.allThreatSignals?.map(s => s.name || s.id) || [],
            sender: dossier.headerFields.from,
            subject: dossier.headerFields.subject,
            detectedLinks: dossier.urlForensics?.map(u => u.rawUrl) || dossier.iocs?.urls?.map(u => u.url) || [],
            source: dossier.senderIdentity.fromDomain,
            target: dossier.headerFields.to
          }}
        />
      </div>

      {/* 4. EMAIL FORENSIC ANATOMY VISUALIZATION */}
      {(viewMode !== 'plain-english') && (
        <EmailAnatomyDiagram
          dossier={dossier}
          onDrillDown={(target) => setDrillDownTarget(target)}
        />
      )}

      {/* 5. SENDER IDENTITY GRAPH */}
      {(viewMode !== 'plain-english') && (
        <SenderIdentityGraph
          dossier={dossier}
          onDrillDown={(target) => setDrillDownTarget(target)}
        />
      )}

      {/* 6. SMTP HOP / ROUTE GRAPH */}
      {(viewMode !== 'plain-english') && (
        <SmtpRouteGraph
          dossier={dossier}
          onDrillDown={(target) => setDrillDownTarget(target)}
        />
      )}

      {/* 7. EMAIL TIMELINE */}
      {(viewMode !== 'plain-english') && (
        <EmailTimelineView
          dossier={dossier}
        />
      )}

      {/* 8 & 9. SPF / DKIM / DMARC VISUAL MATRIX & AUTHENTICATION FLOW DIAGRAM */}
      {(viewMode !== 'plain-english') && (
        <AuthMatrixAndFlow
          dossier={dossier}
          onDrillDown={(target) => setDrillDownTarget(target)}
        />
      )}

      {/* 10 & 11. IOC INTELLIGENCE SECTION & IOC TABLE */}
      {(viewMode !== 'plain-english') && (
        <IocSectionAndTable
          dossier={dossier}
          onDrillDown={(target) => setDrillDownTarget(target)}
          onExportCsv={exportIocsCsv}
          onExportStix={exportSTIX21}
        />
      )}

      {/* 12. SOCIAL ENGINEERING ANALYSIS */}
      {(viewMode !== 'plain-english') && (
        <SocialEngineeringAndNlp
          dossier={dossier}
          onDrillDown={(target) => setDrillDownTarget(target)}
        />
      )}

      {/* 13 & 14. URL FORENSICS & ATTACHMENT FORENSICS */}
      {(viewMode !== 'plain-english') && (
        <UrlAndAttachmentForensics
          dossier={dossier}
          onDrillDown={(target) => setDrillDownTarget(target)}
        />
      )}

      {/* 15, 16, 17. THREAT CORRELATION GRAPH, FORENSIC EVIDENCE CHAIN, EVIDENCE VS CONCLUSION */}
      {(viewMode !== 'plain-english') && (
        <CorrelationAndChain
          dossier={dossier}
          onDrillDown={(target) => setDrillDownTarget(target)}
        />
      )}

      {/* 17 & 19. FINAL FORENSIC VERDICT & RAW RFC 5322 EVIDENCE */}
      <FinalVerdictAndRawEvidence
        dossier={dossier}
        onDrillDown={(target) => setDrillDownTarget(target)}
        onBlockIp={(ip) => {
          // Trigger local containment notice
          console.log(`Containing IP: ${ip}`);
        }}
        onBlockDomain={(domain) => {
          console.log(`Sinkholing domain: ${domain}`);
        }}
        onPurgeEmail={() => {
          console.log('Initiating mailbox purge across tenant');
        }}
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

      {/* SOC INCIDENT MITIGATION PLAYBOOKS */}
      {dossier.socPlaybooks && dossier.socPlaybooks.length > 0 && (
        <section 
          id="soc-playbooks-section"
          className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 shadow-2xl space-y-4"
        >
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <h2 className="text-xs font-bold uppercase tracking-widest text-white">
                Automated SOC Mitigation Playbooks & Containment Scripts
              </h2>
            </div>
            <span className="text-[10px] text-gray-500">
              Ready-to-execute defensive policies
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {dossier.socPlaybooks.map((pb, idx) => (
              <div 
                key={idx} 
                className="bg-black/40 border border-white/10 rounded-xl p-4 space-y-3 flex flex-col justify-between hover:border-cyan-500/40 transition-all"
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
                  <div className="bg-[#05080f] p-2.5 rounded-lg text-[10px] font-mono text-cyan-300 break-all select-all border border-white/5">
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
              className="bg-[#0a0f1c] border border-cyan-500/40 rounded-2xl w-full max-w-4xl max-h-[85vh] overflow-hidden flex flex-col shadow-2xl font-mono"
            >
              <div className="p-4 border-b border-white/10 flex justify-between items-center bg-[#05080f]">
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
              className="bg-[#0a0f1c] border border-cyan-500/40 rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col overflow-hidden shadow-2xl font-mono"
            >
              <div className="p-4 border-b border-white/10 flex justify-between items-center bg-[#05080f]">
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
