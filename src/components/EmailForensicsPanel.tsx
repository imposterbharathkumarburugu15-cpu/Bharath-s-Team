import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import Markdown from 'react-markdown';
import { 
  FileText, Download, Globe, Terminal, 
  X, Check, Copy, Compass, ShieldAlert, Sparkles, Printer,
  Brain, Network, MapPin, Server, Activity, ArrowUpRight,
  Shield, CheckCircle2, AlertTriangle, Radio
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { ForensicDossier } from '@/services/forensicsEngine';
import { DomainAuthLookup } from '@/components/DomainAuthLookup';
import { Forensic3DGeoMap } from '@/components/Forensic3DGeoMap';

// Sub-components for the Forensic Investigation Suite
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

export type ForensicPillarId = 'geo-intel' | 'protocol' | 'summary' | 'iocs' | 'playbooks' | 'neural';

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
  // Audience View Mode: 'unified' (default), 'plain-english', 'technical'
  const [viewMode, setViewMode] = useState<'unified' | 'plain-english' | 'technical'>('unified');

  // Internal tab state if not controlled - default to 'geo-intel' to highlight IP Geolocation
  const [internalPillar, setInternalPillar] = useState<ForensicPillarId>('geo-intel');
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
  const [copiedPlaybookKey, setCopiedPlaybookKey] = useState<string | null>(null);
  const [copiedIp, setCopiedIp] = useState<boolean>(false);

  const targetDomain = dossier.senderIdentity.fromDomain || dossier.authentication.dmarc.headerFromDomain || 'domain.com';
  const originIP = dossier.originIP;

  const handlePrintPdf = () => {
    window.print();
  };

  const copyOriginIp = () => {
    if (originIP?.ip) {
      navigator.clipboard.writeText(originIP.ip);
      setCopiedIp(true);
      setTimeout(() => setCopiedIp(false), 2000);
    }
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

  const pillarTabs: { id: ForensicPillarId; label: string; icon: any; badge?: string }[] = [
    { id: 'geo-intel', label: 'IP Geolocation & Radar', icon: Globe, badge: originIP?.country || 'Origin' },
    { id: 'protocol', label: 'Protocol DNA & Relays', icon: Network },
    { id: 'summary', label: 'Summary & Anatomy', icon: Sparkles },
    { id: 'iocs', label: 'Threat IOCs & URLs', icon: ShieldAlert },
    { id: 'playbooks', label: 'Verdict & Playbooks', icon: FileText },
    ...(!hideNeuralProfile ? [{ id: 'neural' as ForensicPillarId, label: 'Neural Profile', icon: Brain }] : []),
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-6 text-white font-mono"
    >
      {/* 1. FORENSIC CASE HEADER (if not suppressed by parent) */}
      {!hideHeader && (
        <ForensicCaseHeader
          dossier={dossier}
          onOpenSocReport={() => setShowSocPreview(true)}
          onExportJson={downloadJsonDossier}
          onExportStix={exportSTIX21}
          onPrintPdf={handlePrintPdf}
        />
      )}

      {/* 2. PROMINENT IP GEOLOCATION & INFRASTRUCTURE HERO STRIP (ALWAYS VISIBLE AT TOP OF FORENSICS) */}
      <div className="bg-[#0c130f] border border-cyan-500/30 rounded-2xl p-4 sm:p-5 shadow-2xl relative overflow-hidden backdrop-blur-xl">
        <div className="absolute top-0 right-0 w-80 h-28 bg-gradient-to-l from-cyan-500/10 to-transparent pointer-events-none" />
        
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 relative z-10">
          {/* Origin IP & Country Identity */}
          <div className="flex items-start sm:items-center gap-3.5">
            <div className="w-12 h-12 rounded-xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center shrink-0 shadow-[0_0_15px_rgba(6,182,212,0.25)]">
              <Globe className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[11px] text-gray-400 uppercase tracking-widest font-bold">
                  Origin Infrastructure Telemetry
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold">
                  {originIP.countryFlag || '🌍'} {originIP.country || 'Unknown'} {originIP.city ? `• ${originIP.city}` : ''}
                </span>
                <span className={cn(
                  "text-[10px] px-2 py-0.5 rounded-full border font-bold uppercase",
                  originIP.threatReputation === 'SUSPICIOUS' || originIP.threatReputation === 'MALICIOUS'
                    ? "bg-red-500/20 text-red-300 border-red-500/40"
                    : "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                )}>
                  {originIP.vpnTorIndicator || originIP.threatReputation || 'STANDARD RELAY'}
                </span>
              </div>

              <div className="flex items-center gap-2 mt-1">
                <span className="text-base sm:text-lg font-bold text-white tracking-wider font-mono">
                  {originIP.ip || '0.0.0.0'}
                </span>
                <button
                  onClick={copyOriginIp}
                  className="p-1 text-gray-400 hover:text-cyan-300 rounded hover:bg-white/5 transition-colors cursor-pointer"
                  title="Copy Origin IP"
                >
                  {copiedIp ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
                {originIP.asn && (
                  <span className="text-xs text-gray-400 font-mono">
                    [{originIP.asn} • {originIP.isp || originIP.organization || 'ISP'}]
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Quick Origin Action Buttons */}
          <div className="flex items-center gap-2 w-full lg:w-auto overflow-x-auto justify-start lg:justify-end shrink-0">
            <button
              onClick={() => handlePillarSelect('geo-intel')}
              className={cn(
                "px-3.5 py-2 rounded-xl text-xs font-bold font-mono transition-all flex items-center gap-1.5 cursor-pointer whitespace-nowrap shadow-md",
                activePillar === 'geo-intel'
                  ? "bg-cyan-500 text-black shadow-[0_0_15px_rgba(6,182,212,0.4)]"
                  : "bg-white/5 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30"
              )}
            >
              <Radio className="w-3.5 h-3.5" />
              <span>Interactive 3D Radar</span>
            </button>

            <button
              onClick={() => setShowDnsLookup(true)}
              className="px-3.5 py-2 rounded-xl text-xs font-bold font-mono bg-white/5 hover:bg-white/10 text-gray-200 border border-white/10 flex items-center gap-1.5 cursor-pointer transition-colors whitespace-nowrap"
            >
              <Compass className="w-3.5 h-3.5 text-cyan-400" />
              <span>Live DNS & WHOIS</span>
            </button>

            <button
              onClick={handlePrintPdf}
              className="px-3.5 py-2 rounded-xl text-xs font-bold font-mono bg-white/5 hover:bg-white/10 text-gray-200 border border-white/10 flex items-center gap-1.5 cursor-pointer transition-colors whitespace-nowrap"
              title="Print PDF dossier"
            >
              <Printer className="w-3.5 h-3.5 text-cyan-400" />
              <span>Print PDF</span>
            </button>
          </div>
        </div>
      </div>

      {/* 3. FORENSIC PILLAR NAVIGATION BAR (TAB SWITCHER) */}
      {!hidePillarNav && (
        <div className="bg-[#0b110e] border border-cyan-500/30 rounded-2xl p-2 shadow-xl flex items-center justify-between gap-2 overflow-x-auto print:hidden">
          <div className="flex items-center gap-1.5 w-full overflow-x-auto scrollbar-none">
            {pillarTabs.map(p => {
              const Icon = p.icon;
              const isActive = activePillar === p.id;
              return (
                <button
                  key={p.id}
                  onClick={() => handlePillarSelect(p.id)}
                  className={cn(
                    "px-4 py-2.5 rounded-xl text-xs font-mono font-bold tracking-wider transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap shrink-0",
                    isActive
                      ? "bg-cyan-500 text-black shadow-[0_0_15px_rgba(6,182,212,0.35)]"
                      : "text-gray-400 hover:text-white hover:bg-white/5 border border-transparent hover:border-white/10"
                  )}
                >
                  <Icon className={cn("w-4 h-4", isActive ? "text-black" : "text-cyan-400")} />
                  <span>{p.label}</span>
                  {p.badge && (
                    <span className={cn(
                      "text-[9px] px-1.5 py-0.2 rounded font-mono font-bold uppercase",
                      isActive ? "bg-black/20 text-black" : "bg-white/10 text-cyan-300"
                    )}>
                      {p.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Presentation Mode Picker */}
          <div className="hidden xl:flex items-center gap-1 bg-black/50 p-1 rounded-xl border border-white/10 shrink-0">
            <button
              onClick={() => setViewMode('unified')}
              className={cn(
                "px-2.5 py-1 rounded-lg text-[10px] font-bold transition-all",
                viewMode === 'unified' ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40" : "text-gray-400 hover:text-white"
              )}
            >
              Unified
            </button>
            <button
              onClick={() => setViewMode('technical')}
              className={cn(
                "px-2.5 py-1 rounded-lg text-[10px] font-bold transition-all",
                viewMode === 'technical' ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40" : "text-gray-400 hover:text-white"
              )}
            >
              SOC Deep
            </button>
          </div>
        </div>
      )}

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* PILLAR 1: IP GEOLOCATION & ORIGIN INFRASTRUCTURE RADAR                     */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {activePillar === 'geo-intel' && (
        <div className="space-y-6">
          {/* Interactive 3D Tactical Radar Map */}
          <div className="bg-[#0e1410] border border-cyan-500/30 rounded-2xl p-5 sm:p-6 shadow-2xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-3">
              <div className="flex items-center gap-2.5">
                <Globe className="w-5 h-5 text-cyan-400" />
                <div>
                  <h3 className="text-sm font-bold uppercase tracking-wider text-white">
                    3D Origin Geolocation & Relay Radar
                  </h3>
                  <p className="text-[11px] text-gray-400 font-sans">
                    Real-time spherical projection of mail relay origin and physical hosting infrastructure
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono px-2 py-1 rounded bg-black/50 text-cyan-300 border border-cyan-500/20">
                  Lat: {originIP.latitude?.toFixed(4) || 'N/A'} • Lng: {originIP.longitude?.toFixed(4) || 'N/A'}
                </span>
              </div>
            </div>

            {/* 3D Globe Component */}
            <div className="rounded-xl overflow-hidden border border-white/10 bg-black/40">
              <Forensic3DGeoMap originIP={dossier.originIP} hops={dossier.relayReconstruction?.chronologicalHops} />
            </div>
          </div>

          {/* Deep Origin IP Telemetry Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
            {/* IP Address & PTR */}
            <div className="bg-[#0c120e] border border-white/10 rounded-xl p-4 space-y-2">
              <div className="flex items-center gap-2 text-cyan-400 text-[11px] font-bold uppercase">
                <MapPin className="w-3.5 h-3.5" />
                <span>Origin IP & PTR</span>
              </div>
              <div className="text-sm font-bold text-white break-all">{originIP.ip}</div>
              <div className="text-[11px] text-gray-400 break-all">
                PTR: {originIP.resolvedDomain || 'None configured'}
              </div>
              <div className="text-[10px] text-gray-500">
                Type: {originIP.ipType || (originIP.isPrivate ? 'Private / RFC 1918' : 'Public IPv4')}
              </div>
            </div>

            {/* Geolocation */}
            <div className="bg-[#0c120e] border border-white/10 rounded-xl p-4 space-y-2">
              <div className="flex items-center gap-2 text-emerald-400 text-[11px] font-bold uppercase">
                <Globe className="w-3.5 h-3.5" />
                <span>Geographic Location</span>
              </div>
              <div className="text-sm font-bold text-white">
                {originIP.countryFlag || '📍'} {originIP.city ? `${originIP.city}, ` : ''}{originIP.country}
              </div>
              <div className="text-[11px] text-gray-400">
                Region: {originIP.region || 'Standard Territory'}
              </div>
              <div className="text-[10px] text-gray-500">
                Timezone: {originIP.timezone || 'UTC'}
              </div>
            </div>

            {/* ASN & Network */}
            <div className="bg-[#0c120e] border border-white/10 rounded-xl p-4 space-y-2">
              <div className="flex items-center gap-2 text-purple-400 text-[11px] font-bold uppercase">
                <Server className="w-3.5 h-3.5" />
                <span>Autonomous System</span>
              </div>
              <div className="text-sm font-bold text-white truncate" title={originIP.asn}>
                {originIP.asn || 'AS-UNKNOWN'}
              </div>
              <div className="text-[11px] text-gray-400 truncate" title={originIP.isp}>
                ISP: {originIP.isp || 'Commercial Backbone'}
              </div>
              <div className="text-[10px] text-gray-500 truncate" title={originIP.organization}>
                Org: {originIP.organization || 'Unspecified Org'}
              </div>
            </div>

            {/* Threat & Infrastructure */}
            <div className="bg-[#0c120e] border border-white/10 rounded-xl p-4 space-y-2">
              <div className="flex items-center gap-2 text-amber-400 text-[11px] font-bold uppercase">
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>Infrastructure Risk</span>
              </div>
              <div className="text-sm font-bold text-white">
                {originIP.vpnTorIndicator || 'Datacenter / VPS'}
              </div>
              <div className="text-[11px] text-gray-400">
                Reputation: <span className={originIP.threatReputation === 'CLEAN' ? 'text-emerald-400 font-bold' : 'text-red-400 font-bold'}>{originIP.threatReputation}</span>
              </div>
              <div className="text-[10px] text-gray-500">
                Source: {originIP.providerSource || 'Forensic Telemetry'}
              </div>
            </div>
          </div>

          {/* Forensic Attribution Disclaimer */}
          <div className="p-3.5 rounded-xl bg-black/40 border border-white/10 flex items-start gap-3 font-mono text-xs">
            <Shield className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <p className="text-gray-300 text-[11px] leading-relaxed">
              <strong className="text-white font-bold">Court-Defensible Attribution Note: </strong>
              {originIP.attributionDisclaimer || 'IP geolocation reflects the physical location of the transmitting mail relay or anonymizing gateway, not necessarily the physical location of the human adversary.'}
            </p>
          </div>

          {/* Relay Hop Progression Timeline */}
          {dossier.relayReconstruction?.chronologicalHops && dossier.relayReconstruction.chronologicalHops.length > 0 && (
            <div className="bg-[#0e1410] border border-white/10 rounded-2xl p-5 space-y-3">
              <div className="flex items-center justify-between border-b border-white/10 pb-2">
                <span className="text-xs font-bold uppercase tracking-wider text-white">
                  Mail Server Relay Chain ({dossier.relayReconstruction.chronologicalHops.length} Network Hops)
                </span>
                <span className="text-[10px] text-gray-400">
                  Total Latency: {dossier.relayReconstruction.totalTransitTimeSeconds || 0}s
                </span>
              </div>
              <div className="space-y-2">
                {dossier.relayReconstruction.chronologicalHops.map((hop, idx) => (
                  <div 
                    key={idx}
                    className="p-3 rounded-xl bg-black/30 border border-white/5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs"
                  >
                    <div className="flex items-center gap-3">
                      <span className="w-6 h-6 rounded-full bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 text-[10px] font-bold flex items-center justify-center shrink-0">
                        #{hop.hopNumber}
                      </span>
                      <div>
                        <span className="font-bold text-white">{hop.sourceHostname || hop.destinationHostname || 'Mail Relay'}</span>
                        <span className="text-[11px] text-gray-400 block font-mono">
                          IP: {hop.sourceIP || 'Masked / Internal'} {hop.city ? `• ${hop.city}, ${hop.country}` : ''}
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 text-[11px] text-gray-400 font-mono">
                      {hop.delayToNextHopSeconds !== undefined && (
                        <span className={hop.delayToNextHopSeconds > 10 ? 'text-amber-400 font-bold' : 'text-gray-400'}>
                          +{hop.delayToNextHopSeconds}s transit
                        </span>
                      )}
                      <span className={hop.isAnomalous ? 'text-amber-400 font-bold' : 'text-emerald-400'}>
                        {hop.isAnomalous ? (hop.anomalyReason || 'Route Delay') : (hop.protocol || 'Standard SMTP')}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
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
      {/* PILLAR 3: SUMMARY & EMAIL ANATOMY                                          */}
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
        </div>
      )}

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* PILLAR 4: THREAT IOCS & URL/ATTACHMENT FORENSICS                           */}
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
      {/* PILLAR 5: VERDICT & SOC MITIGATION PLAYBOOKS                               */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {activePillar === 'playbooks' && (
        <div className="space-y-6">
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

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* PILLAR 6: NEURAL PROFILE (ONLY IF ENABLED)                                 */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {activePillar === 'neural' && !hideNeuralProfile && (
        <div className="space-y-6">
          <NeuralProfile
            dossier={dossier}
            onOpenFullForensics={() => handlePillarSelect('summary')}
          />
          <SocialEngineeringAndNlp
            dossier={dossier}
            onDrillDown={(target) => setDrillDownTarget(target)}
          />
        </div>
      )}

      {/* 18. ANALYST DRILL-DOWN MODAL */}
      <AnimatePresence>
        {drillDownTarget && (
          <ForensicDrillDownModal
            target={drillDownTarget}
            onClose={() => setDrillDownTarget(null)}
          />
        )}
      </AnimatePresence>

      {/* 19. LIVE DNS & WHOIS LOOKUP MODAL */}
      <AnimatePresence>
        {showDnsLookup && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-3xl bg-[#0b100d] border border-cyan-500/30 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
            >
              <div className="p-4 border-b border-white/10 flex items-center justify-between bg-black/40">
                <div className="flex items-center gap-2">
                  <Compass className="w-5 h-5 text-cyan-400" />
                  <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                    Live Autonomous DNS & WHOIS Resolver
                  </h3>
                </div>
                <button
                  onClick={() => setShowDnsLookup(false)}
                  className="p-1.5 text-gray-400 hover:text-white rounded-lg hover:bg-white/10 cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="p-6 overflow-y-auto custom-scrollbar">
                <DomainAuthLookup initialDomain={targetDomain} />
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* 20. FULL SOC DOSSIER MODAL */}
      <AnimatePresence>
        {showSocPreview && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-4xl max-h-[85vh] bg-[#0b100d] border border-cyan-500/30 rounded-2xl shadow-2xl flex flex-col overflow-hidden"
            >
              <div className="p-4 border-b border-white/10 flex items-center justify-between bg-black/40">
                <div className="flex items-center gap-2">
                  <FileText className="w-5 h-5 text-cyan-400" />
                  <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                    Full SOC Incident Investigation Dossier
                  </h3>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={copySocReport}
                    className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-mono text-cyan-300 hover:text-white flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    {copiedSocReport ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedSocReport ? 'Copied' : 'Copy'}</span>
                  </button>
                  <button
                    onClick={downloadMarkdownReport}
                    className="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-xs font-mono text-white flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Download .md</span>
                  </button>
                  <button
                    onClick={() => setShowSocPreview(false)}
                    className="p-1.5 text-gray-400 hover:text-white rounded-lg hover:bg-white/10 cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>
              <div className="flex-1 p-6 overflow-y-auto custom-scrollbar font-mono text-xs text-gray-200 bg-black/30">
                <div className="markdown-body prose prose-invert max-w-none prose-pre:bg-black/60 prose-pre:border prose-pre:border-white/10">
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
