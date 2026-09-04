import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import Markdown from 'react-markdown';
import { 
  Mail, Shield, ShieldCheck, ShieldAlert, AlertTriangle, FileText, 
  Terminal, ArrowRight, Copy, Check, Download, ExternalLink, Network, 
  Globe, Server, Clock, Lock, AlertCircle, Sparkles, Layers, Hash, X,
  Activity, Cpu, Eye, Share2, CornerDownRight, Database, ChevronRight,
  Radio, Key, AlertOctagon, HelpCircle, CheckCircle2, XCircle, Printer
} from 'lucide-react';
import { ForensicDossier, DeconstructedURL, ForensicFinding } from '@/services/forensicsEngine';
import { DomainAuthLookup } from '@/components/DomainAuthLookup';
import { Forensic3DGeoMap } from '@/components/Forensic3DGeoMap';

interface EmailForensicsPanelProps {
  dossier: ForensicDossier;
  compact?: boolean;
}

type SubTab = 
  | 'overview' 
  | 'headers' 
  | 'authentication' 
  | 'identity' 
  | 'urls' 
  | 'iocs' 
  | 'geolocation' 
  | 'ml_model' 
  | 'nlp_ai' 
  | 'attack_graph' 
  | 'timeline' 
  | 'soc_playbooks';

export function EmailForensicsPanel({ dossier, compact = false }: EmailForensicsPanelProps) {
  const [activeTab, setActiveTab] = useState<SubTab>('overview');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [showDnsLookup, setShowDnsLookup] = useState<boolean>(false);
  const [showSocPreview, setShowSocPreview] = useState<boolean>(false);
  const [copiedSocReport, setCopiedSocReport] = useState<boolean>(false);
  const [selectedGraphNode, setSelectedGraphNode] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<ForensicFinding | null>(null);
  const [iocFilter, setIocFilter] = useState<'ALL' | 'IP' | 'DOMAIN' | 'URL' | 'EMAIL' | 'HASH'>('ALL');
  const [threatMatrixFilter, setThreatMatrixFilter] = useState<'DETECTED' | 'ALL' | 'UNKNOWN' | 'NOT_DETECTED'>('DETECTED');

  const targetDomain = dossier.senderIdentity.fromDomain || dossier.authentication.dmarc.headerFromDomain || 'google.com';

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

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
    a.download = `neuroshield-forensics-${dossier.chainOfCustody.caseId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadMarkdownReport = () => {
    const blob = new Blob([dossier.socReportMarkdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SOC-Report-${dossier.chainOfCustody.caseId}.md`;
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
      ...dossier.iocs.urls.map(u => ['URL', u, 'Payload Endpoint', 'HIGH_RISK']),
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

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-6 text-white font-mono"
    >
      {/* Top Threat Dossier Banner */}
      <div className="bg-[#0a0f1c]/90 border border-white/10 rounded-2xl p-5 shadow-2xl relative overflow-hidden backdrop-blur-md">
        <div className={`absolute top-0 left-0 h-1.5 w-full ${
          dossier.scoreBreakdown.riskCategory === 'CRITICAL' ? 'bg-red-500 shadow-[0_0_15px_#ef4444]' :
          dossier.scoreBreakdown.riskCategory === 'HIGH_RISK' || dossier.scoreBreakdown.riskCategory === 'HIGH' ? 'bg-amber-500 shadow-[0_0_15px_#f59e0b]' :
          dossier.scoreBreakdown.riskCategory === 'SUSPICIOUS' || dossier.scoreBreakdown.riskCategory === 'MEDIUM' ? 'bg-yellow-400 shadow-[0_0_15px_#facc15]' :
          dossier.scoreBreakdown.riskCategory === 'GUARDED' ? 'bg-blue-400 shadow-[0_0_15px_#60a5fa]' :
          'bg-emerald-500 shadow-[0_0_15px_#10b981]'
        }`} />

        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-5">
          <div className="space-y-2">
            <div className="flex items-center gap-3 flex-wrap">
              <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold tracking-widest uppercase border ${
                dossier.scoreBreakdown.verdict === 'CRITICAL' ? 'bg-red-500/15 text-red-400 border-red-500/30 shadow-[0_0_10px_rgba(239,68,68,0.2)]' :
                dossier.scoreBreakdown.verdict === 'HIGH RISK' || dossier.scoreBreakdown.riskCategory === 'HIGH' ? 'bg-amber-500/15 text-amber-400 border-amber-500/30 shadow-[0_0_10px_rgba(245,158,11,0.2)]' :
                dossier.scoreBreakdown.verdict === 'SUSPICIOUS' ? 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30' :
                dossier.scoreBreakdown.verdict === 'GUARDED' ? 'bg-blue-500/15 text-blue-300 border-blue-500/30' :
                'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
              }`}>
                {dossier.scoreBreakdown.verdict} — {dossier.classification.threatType}
              </span>

              {/* Forensic Completeness Badge */}
              <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold tracking-wide uppercase border flex items-center gap-1.5 ${
                dossier.scoreBreakdown.forensicStatus === 'INCOMPLETE'
                  ? 'bg-amber-500/15 text-amber-300 border-amber-500/40 shadow-[0_0_10px_rgba(245,158,11,0.2)]'
                  : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
              }`}>
                {dossier.scoreBreakdown.forensicStatus === 'INCOMPLETE' ? (
                  <>
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                    <span>FORENSIC DATA INCOMPLETE</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>FORENSIC DATA VERIFIED</span>
                  </>
                )}
              </span>

              <span className="text-xs text-cyber-blue font-mono bg-cyber-blue/10 px-2.5 py-0.5 rounded border border-cyber-blue/20">
                CASE: {dossier.chainOfCustody.caseId}
              </span>
            </div>
            <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight break-all">
              {dossier.headerFields.subject || 'No Subject Specified'}
            </h2>
            <div className="flex items-center gap-4 text-xs text-gray-400 flex-wrap">
              <span>From: <strong className="text-white">{dossier.senderIdentity.fromAddress}</strong></span>
              <span>SHA-256: <strong className="text-cyber-blue font-mono">{dossier.chainOfCustody.sha256EvidenceHash.slice(0, 16)}...</strong></span>
              <span>ML Classifier: <strong className="text-purple-300 font-mono">{dossier.mlClassification.prediction} ({(dossier.mlClassification.confidenceScore * 100).toFixed(1)}%)</strong></span>
            </div>
          </div>

          <div className="flex items-center gap-6 shrink-0 flex-wrap">
            {/* Risk Score */}
            <div className="text-right">
              <span className="text-[10px] font-mono uppercase tracking-widest text-gray-400 block">THREAT RISK SCORE</span>
              <div className={`text-4xl font-black font-mono tracking-tighter ${
                dossier.scoreBreakdown.totalRiskScore >= 61 ? 'text-red-500 drop-shadow-[0_0_12px_rgba(239,68,68,0.4)]' :
                dossier.scoreBreakdown.totalRiskScore >= 41 ? 'text-amber-400 drop-shadow-[0_0_12px_rgba(245,158,11,0.4)]' :
                dossier.scoreBreakdown.totalRiskScore >= 21 ? 'text-yellow-400' : 'text-emerald-400'
              }`}>
                {dossier.scoreBreakdown.totalRiskScore}<span className="text-lg text-gray-600">/100</span>
              </div>
            </div>

            {/* Evidence Confidence */}
            <div className="text-right border-l border-white/10 pl-5">
              <span className="text-[10px] font-mono uppercase tracking-widest text-gray-400 block">EVIDENCE CONFIDENCE</span>
              <div className={`text-3xl font-black font-mono tracking-tighter ${
                dossier.scoreBreakdown.confidenceScore >= 80 ? 'text-emerald-400' :
                dossier.scoreBreakdown.confidenceScore >= 60 ? 'text-amber-400' : 'text-orange-400'
              }`}>
                {dossier.scoreBreakdown.confidenceScore}<span className="text-base text-gray-500">%</span>
              </div>
              <span className="text-[10px] text-gray-500 font-mono block">
                {dossier.scoreBreakdown.forensicStatus}
              </span>
            </div>

            <div className="flex flex-col sm:flex-row gap-2">
              <button
                onClick={() => setShowSocPreview(true)}
                className="px-3 py-1.5 rounded-lg text-xs font-mono bg-cyber-blue/15 hover:bg-cyber-blue/25 text-cyber-blue border border-cyber-blue/40 flex items-center gap-1.5 transition-colors cursor-pointer shadow-[0_0_15px_rgba(0,245,255,0.15)]"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>SOC Report</span>
              </button>
              <button
                onClick={downloadJsonDossier}
                className="px-3 py-1.5 rounded-lg text-xs font-mono bg-white/5 hover:bg-white/10 text-white border border-white/10 flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Download className="w-3.5 h-3.5 text-cyber-blue" />
                <span>JSON</span>
              </button>
              <button
                onClick={exportSTIX21}
                className="px-3 py-1.5 rounded-lg text-xs font-mono bg-purple-500/15 hover:bg-purple-500/25 text-purple-300 border border-purple-500/30 flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Share2 className="w-3.5 h-3.5" />
                <span>STIX 2.1</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Forensic Incompleteness Warning Banner if incomplete */}
      {dossier.scoreBreakdown.forensicStatus === 'INCOMPLETE' && (
        <div className="bg-amber-950/30 border border-amber-500/40 rounded-2xl p-4 flex items-start gap-3.5 text-amber-200 text-xs font-mono shadow-[0_0_15px_rgba(245,158,11,0.1)]">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <strong className="text-white font-bold tracking-wide">FORENSIC DATA INCOMPLETE — UNKNOWN ≠ SAFE POLICY ACTIVE</strong>
              <span className="bg-amber-500/20 text-amber-300 border border-amber-500/30 px-2 py-0.2 rounded text-[10px]">
                Confidence: {dossier.scoreBreakdown.confidenceScore}%
              </span>
            </div>
            <p className="text-gray-300 leading-relaxed">
              Certain external signals (such as domain registration age, URL reputation intelligence, or complete RFC authentication headers) are unavailable or unverified. In compliance with strict zero-trust threat scoring, <strong className="text-amber-300">missing intelligence does NOT make an email appear safe</strong> and does not artificially lower behavioral threat scores.
            </p>
          </div>
        </div>
      )}

      {/* Primary Investigation Navigation Tabs */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-2 border-b border-white/10 text-xs font-mono scrollbar-thin">
        {[
          { id: 'overview', label: '1. Executive Radar', icon: Activity },
          { id: 'headers', label: '2. RFC & Relay Hops', icon: Clock },
          { id: 'authentication', label: '3. SPF/DKIM/DMARC', icon: Shield },
          { id: 'identity', label: '4. Sender Identity', icon: Mail },
          { id: 'urls', label: '5. URL Forensics', icon: ExternalLink },
          { id: 'iocs', label: '6. Extracted IOCs', icon: Hash },
          { id: 'geolocation', label: '7. 3D Origin Radar', icon: Globe },
          { id: 'ml_model', label: '8. ML (XGBoost)', icon: Cpu },
          { id: 'nlp_ai', label: '9. NLP & AI Phish', icon: Sparkles },
          { id: 'attack_graph', label: '10. Attack Graph', icon: Network },
          { id: 'timeline', label: '11. Chronology', icon: Layers },
          { id: 'soc_playbooks', label: '12. SOC Playbooks', icon: Terminal }
        ].map(tab => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as SubTab)}
              className={`px-3.5 py-2 rounded-xl flex items-center gap-2 whitespace-nowrap transition-all cursor-pointer font-bold ${
                isActive
                  ? 'bg-cyber-blue text-black shadow-[0_0_20px_rgba(0,245,255,0.4)]'
                  : 'bg-white/5 text-gray-300 hover:bg-white/10 hover:text-white border border-white/5'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-black' : 'text-cyber-blue'}`} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab 1: Executive Dashboard & Score Radar */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Explainable Weighted Risk Score Breakdown */}
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex justify-between items-center flex-wrap gap-2">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-cyber-blue" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  WEIGHTED THREAT SCORE ENGINE (0–100)
                </h3>
              </div>
              <div className="flex items-center gap-3 text-xs font-mono">
                <span className="text-gray-400">Confidence: <strong className="text-cyber-blue">{dossier.scoreBreakdown.confidenceScore}%</strong></span>
                <span className="text-gray-500">|</span>
                <span className="text-gray-400">Status: <strong className={dossier.scoreBreakdown.forensicStatus === 'INCOMPLETE' ? 'text-amber-400' : 'text-emerald-400'}>{dossier.scoreBreakdown.forensicStatus}</strong></span>
              </div>
            </div>

            {/* 8 Explicit Threat Signal Categories */}
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-4 gap-3">
              {/* Category 1: Sender Identity */}
              <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-1.5">
                <div className="flex justify-between items-center">
                  <span className="text-[10px] text-gray-400 uppercase font-bold">1. SENDER IDENTITY</span>
                  <span className="text-[10px] text-gray-500 font-mono">Max 15</span>
                </div>
                <div className="text-lg font-bold text-white font-mono">
                  {dossier.scoreBreakdown.senderIdentityScore}<span className="text-xs text-gray-600">/15</span>
                </div>
                <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                  <div className="bg-amber-500 h-full" style={{ width: `${(dossier.scoreBreakdown.senderIdentityScore / 15) * 100}%` }} />
                </div>
              </div>

              {/* Category 2: Authentication */}
              <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-1.5">
                <div className="flex justify-between items-center">
                  <span className="text-[10px] text-gray-400 uppercase font-bold">2. AUTHENTICATION</span>
                  <span className="text-[10px] text-gray-500 font-mono">Max 15</span>
                </div>
                <div className="text-lg font-bold text-white font-mono">
                  {dossier.scoreBreakdown.authenticationScore}<span className="text-xs text-gray-600">/15</span>
                </div>
                <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                  <div className="bg-red-500 h-full" style={{ width: `${(dossier.scoreBreakdown.authenticationScore / 15) * 100}%` }} />
                </div>
              </div>

              {/* Category 3: URL Forensics */}
              <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-1.5">
                <div className="flex justify-between items-center">
                  <span className="text-[10px] text-gray-400 uppercase font-bold">3. URL FORENSICS</span>
                  <span className="text-[10px] text-gray-500 font-mono">Max 20</span>
                </div>
                <div className="text-lg font-bold text-white font-mono">
                  {dossier.scoreBreakdown.urlAnalysisScore}<span className="text-xs text-gray-600">/20</span>
                </div>
                <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                  <div className="bg-purple-500 h-full" style={{ width: `${(dossier.scoreBreakdown.urlAnalysisScore / 20) * 100}%` }} />
                </div>
              </div>

              {/* Category 4: Social Engineering */}
              <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-1.5">
                <div className="flex justify-between items-center">
                  <span className="text-[10px] text-gray-400 uppercase font-bold">4. SOCIAL ENG. & NLP</span>
                  <span className="text-[10px] text-gray-500 font-mono">Max 15</span>
                </div>
                <div className="text-lg font-bold text-white font-mono">
                  {dossier.scoreBreakdown.socialEngineeringScore}<span className="text-xs text-gray-600">/15</span>
                </div>
                <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                  <div className="bg-blue-500 h-full" style={{ width: `${(dossier.scoreBreakdown.socialEngineeringScore / 15) * 100}%` }} />
                </div>
              </div>

              {/* Category 5: Privacy & Sensitive Data */}
              <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-1.5">
                <div className="flex justify-between items-center">
                  <span className="text-[10px] text-gray-400 uppercase font-bold">5. SENSITIVE DATA</span>
                  <span className="text-[10px] text-gray-500 font-mono">Max 10</span>
                </div>
                <div className="text-lg font-bold text-white font-mono">
                  {dossier.scoreBreakdown.privacyScore}<span className="text-xs text-gray-600">/10</span>
                </div>
                <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                  <div className="bg-pink-500 h-full" style={{ width: `${(dossier.scoreBreakdown.privacyScore / 10) * 100}%` }} />
                </div>
              </div>

              {/* Category 6: AI / Prompt Injection */}
              <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-1.5">
                <div className="flex justify-between items-center">
                  <span className="text-[10px] text-gray-400 uppercase font-bold">6. AI PROMPT INJECTION</span>
                  <span className="text-[10px] text-gray-500 font-mono">Max 10</span>
                </div>
                <div className="text-lg font-bold text-white font-mono">
                  {dossier.scoreBreakdown.promptInjectionScore}<span className="text-xs text-gray-600">/10</span>
                </div>
                <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                  <div className="bg-red-400 h-full" style={{ width: `${(dossier.scoreBreakdown.promptInjectionScore / 10) * 100}%` }} />
                </div>
              </div>

              {/* Category 7: Attachment Risk */}
              <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-1.5">
                <div className="flex justify-between items-center">
                  <span className="text-[10px] text-gray-400 uppercase font-bold">7. ATTACHMENTS</span>
                  <span className="text-[10px] text-gray-500 font-mono">Max 10</span>
                </div>
                <div className="text-lg font-bold text-white font-mono">
                  {dossier.scoreBreakdown.attachmentsScore}<span className="text-xs text-gray-600">/10</span>
                </div>
                <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                  <div className="bg-indigo-500 h-full" style={{ width: `${(dossier.scoreBreakdown.attachmentsScore / 10) * 100}%` }} />
                </div>
              </div>

              {/* Category 8: Infrastructure */}
              <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-1.5">
                <div className="flex justify-between items-center">
                  <span className="text-[10px] text-gray-400 uppercase font-bold">8. INFRASTRUCTURE</span>
                  <span className="text-[10px] text-gray-500 font-mono">Max 5</span>
                </div>
                <div className="text-lg font-bold text-white font-mono">
                  {dossier.scoreBreakdown.infrastructureScore}<span className="text-xs text-gray-600">/5</span>
                </div>
                <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                  <div className="bg-teal-500 h-full" style={{ width: `${(dossier.scoreBreakdown.infrastructureScore / 5) * 100}%` }} />
                </div>
              </div>
            </div>
          </div>

          {/* Clean, Easy-to-Understand Threat Signal Matrix */}
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-5 shadow-xl space-y-4 font-sans">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-white/10">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-cyber-blue/10 border border-cyber-blue/20 text-cyber-blue">
                  <ShieldAlert className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white tracking-wide">
                    Threat & Security Signals
                  </h3>
                  <p className="text-xs text-gray-400">
                    Comprehensive heuristic evaluation of sender, routing, authentication, and links.
                  </p>
                </div>
              </div>

              {/* Interactive Filter Pills */}
              <div className="flex items-center gap-1.5 flex-wrap">
                <button
                  onClick={() => setThreatMatrixFilter('DETECTED')}
                  className={`px-3 py-1 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all border ${
                    threatMatrixFilter === 'DETECTED'
                      ? 'bg-red-500/20 text-red-400 border-red-500/50 shadow-sm'
                      : 'bg-white/5 text-gray-400 border-white/10 hover:text-white'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full bg-red-400 animate-pulse" />
                  <span>Threats Found ({dossier.allThreatSignals?.filter(s => s.status === 'DETECTED').length || 0})</span>
                </button>

                <button
                  onClick={() => setThreatMatrixFilter('UNKNOWN')}
                  className={`px-3 py-1 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all border ${
                    threatMatrixFilter === 'UNKNOWN'
                      ? 'bg-amber-500/20 text-amber-300 border-amber-500/50 shadow-sm'
                      : 'bg-white/5 text-gray-400 border-white/10 hover:text-white'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full bg-amber-400" />
                  <span>Incomplete Data ({dossier.allThreatSignals?.filter(s => s.status === 'UNKNOWN').length || 0})</span>
                </button>

                <button
                  onClick={() => setThreatMatrixFilter('NOT_DETECTED')}
                  className={`px-3 py-1 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all border ${
                    threatMatrixFilter === 'NOT_DETECTED'
                      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50 shadow-sm'
                      : 'bg-white/5 text-gray-400 border-white/10 hover:text-white'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  <span>Clean ({dossier.allThreatSignals?.filter(s => s.status === 'NOT_DETECTED').length || 0})</span>
                </button>

                <button
                  onClick={() => setThreatMatrixFilter('ALL')}
                  className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-all border ${
                    threatMatrixFilter === 'ALL'
                      ? 'bg-cyber-blue/20 text-cyber-blue border-cyber-blue/50'
                      : 'bg-white/5 text-gray-400 border-white/10 hover:text-white'
                  }`}
                >
                  All ({dossier.allThreatSignals?.length || 0})
                </button>
              </div>
            </div>

            {/* Signal Items List */}
            <div className="space-y-2.5">
              {(() => {
                const visibleSignals = (dossier.allThreatSignals || []).filter(s => 
                  threatMatrixFilter === 'ALL' ? true : s.status === threatMatrixFilter
                );

                if (visibleSignals.length === 0) {
                  return (
                    <div className="py-8 text-center bg-white/[0.02] border border-dashed border-white/10 rounded-xl">
                      <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                      <p className="text-sm font-medium text-gray-300">No signals found in this category.</p>
                      <p className="text-xs text-gray-500 mt-0.5">Switch filter to view other security telemetry.</p>
                    </div>
                  );
                }

                return visibleSignals.map((signal) => (
                  <div
                    key={signal.id}
                    className={`p-3.5 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs transition-all ${
                      signal.status === 'DETECTED' 
                        ? 'bg-red-500/10 border-red-500/30 shadow-sm' 
                        : signal.status === 'UNKNOWN' 
                        ? 'bg-amber-500/5 border-amber-500/20' 
                        : 'bg-white/[0.02] border-white/5'
                    }`}
                  >
                    <div className="space-y-1 flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          signal.status === 'DETECTED' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                          signal.status === 'UNKNOWN' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                          'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        }`}>
                          {signal.status === 'DETECTED' ? 'THREAT DETECTED' :
                           signal.status === 'UNKNOWN' ? 'DATA MISSING' : 'CLEAN / NEGATIVE'}
                        </span>
                        <span className="text-gray-500 text-[10px] font-mono">[{signal.categoryLabel}]</span>
                        <h4 className="text-white font-semibold text-xs truncate">{signal.name}</h4>
                      </div>
                      <p className="text-xs text-gray-300 font-sans leading-relaxed">{signal.evidence}</p>
                    </div>

                    <div className="flex items-center sm:flex-col sm:items-end justify-between gap-2 shrink-0 border-t sm:border-t-0 border-white/5 pt-2 sm:pt-0">
                      <span className="text-[10px] font-mono text-gray-400 bg-black/40 px-2 py-0.5 rounded border border-white/5">
                        Field: {signal.sourceField}
                      </span>
                      <span className={`text-[11px] font-bold font-mono ${
                        signal.status === 'DETECTED' ? 'text-red-400' :
                        signal.status === 'UNKNOWN' ? 'text-amber-400/80' : 'text-emerald-400/80'
                      }`}>
                        {signal.status === 'DETECTED' ? `Impact: ${signal.severity}/100` :
                         signal.status === 'UNKNOWN' ? `Confidence: ${signal.confidence}%` :
                         'Negative'}
                      </span>
                    </div>
                  </div>
                ));
              })()}
            </div>
          </div>

          {/* Quick Protocol Authentication Matrix */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className={`p-4 rounded-xl border flex flex-col justify-between ${
              dossier.authentication.spf.status === 'PASS' ? 'bg-emerald-500/10 border-emerald-500/30' :
              dossier.authentication.spf.status === 'FAIL' ? 'bg-red-500/10 border-red-500/30' :
              'bg-amber-500/10 border-amber-500/30'
            }`}>
              <div className="space-y-1">
                <div className="flex justify-between items-center">
                  <span className="text-xs font-bold text-gray-400">SPF PROTOCOL</span>
                  <span className={`px-2 py-0.5 text-xs font-bold rounded ${
                    dossier.authentication.spf.status === 'PASS' ? 'bg-emerald-500/20 text-emerald-400' :
                    dossier.authentication.spf.status === 'FAIL' ? 'bg-red-500/20 text-red-400' :
                    'bg-amber-500/20 text-amber-300'
                  }`}>
                    {dossier.authentication.spf.status}
                  </span>
                </div>
                <p className="text-xs text-gray-300 line-clamp-2">{dossier.authentication.spf.evidence}</p>
              </div>
              <span className="text-[10px] text-gray-500 block pt-2">Sender: {dossier.senderIdentity.fromDomain}</span>
            </div>

            <div className={`p-4 rounded-xl border flex flex-col justify-between ${
              dossier.authentication.dkim.status === 'PASS' ? 'bg-emerald-500/10 border-emerald-500/30' :
              dossier.authentication.dkim.status === 'FAIL' ? 'bg-red-500/10 border-red-500/30' :
              'bg-gray-500/10 border-white/10'
            }`}>
              <div className="space-y-1">
                <div className="flex justify-between items-center">
                  <span className="text-xs font-bold text-gray-400">DKIM SIGNATURE</span>
                  <span className={`px-2 py-0.5 text-xs font-bold rounded ${
                    dossier.authentication.dkim.status === 'PASS' ? 'bg-emerald-500/20 text-emerald-400' :
                    dossier.authentication.dkim.status === 'FAIL' ? 'bg-red-500/20 text-red-400' :
                    'bg-gray-500/20 text-gray-400'
                  }`}>
                    {dossier.authentication.dkim.status}
                  </span>
                </div>
                <p className="text-xs text-gray-300 line-clamp-2">{dossier.authentication.dkim.evidence}</p>
              </div>
              <span className="text-[10px] text-gray-500 block pt-2">Signing Domain: {dossier.authentication.dkim.signingDomain || 'None'}</span>
            </div>

            <div className={`p-4 rounded-xl border flex flex-col justify-between ${
              dossier.authentication.dmarc.status === 'PASS' ? 'bg-emerald-500/10 border-emerald-500/30' :
              dossier.authentication.dmarc.status === 'FAIL' ? 'bg-red-500/10 border-red-500/30' :
              'bg-amber-500/10 border-amber-500/30'
            }`}>
              <div className="space-y-1">
                <div className="flex justify-between items-center">
                  <span className="text-xs font-bold text-gray-400">DMARC POLICY</span>
                  <span className={`px-2 py-0.5 text-xs font-bold rounded ${
                    dossier.authentication.dmarc.status === 'PASS' ? 'bg-emerald-500/20 text-emerald-400' :
                    dossier.authentication.dmarc.status === 'FAIL' ? 'bg-red-500/20 text-red-400' :
                    'bg-amber-500/20 text-amber-300'
                  }`}>
                    {dossier.authentication.dmarc.status}
                  </span>
                </div>
                <p className="text-xs text-gray-300 line-clamp-2">{dossier.authentication.dmarc.evidence}</p>
              </div>
              <span className="text-[10px] text-gray-500 block pt-2">Alignment: {dossier.authentication.dmarc.alignmentStatus}</span>
            </div>
          </div>

          {/* Forensic Findings Matrix */}
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex justify-between items-center">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyber-blue" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  KEY FORENSIC FINDINGS ({dossier.findings.length} DETECTIONS)
                </h3>
              </div>
              <span className="text-xs text-gray-400">Evidence-Backed Assertions</span>
            </div>

            <div className="space-y-3">
              {dossier.findings.map((finding, idx) => (
                <div
                  key={finding.id || idx}
                  onClick={() => setSelectedFinding(finding)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer ${
                    finding.severity === 'CRITICAL' ? 'bg-red-500/5 hover:bg-red-500/10 border-red-500/30' :
                    finding.severity === 'HIGH' ? 'bg-amber-500/5 hover:bg-amber-500/10 border-amber-500/30' :
                    finding.severity === 'MEDIUM' ? 'bg-yellow-500/5 hover:bg-yellow-500/10 border-yellow-500/30' :
                    'bg-blue-500/5 hover:bg-blue-500/10 border-blue-500/30'
                  }`}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-2.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          finding.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                          finding.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' :
                          'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40'
                        }`}>
                          {finding.severity}
                        </span>
                        <h4 className="text-sm font-bold text-white">{finding.title}</h4>
                      </div>
                      <p className="text-xs text-gray-300 font-mono">{finding.evidence}</p>
                      <p className="text-[11px] text-gray-400 italic">Why it matters: {finding.whyItMatters}</p>
                    </div>
                    <ChevronRight className="w-4 h-4 text-gray-500 shrink-0 mt-1" />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Quick Chain of Custody & Origin Radar Preview */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Origin IP Radar */}
            <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4 text-cyber-blue" />
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                    EARLIEST RELIABLE PUBLIC IP & ASN
                  </h3>
                </div>
                <span className="text-[10px] text-cyber-blue font-mono bg-cyber-blue/10 px-2 py-0.5 rounded border border-cyber-blue/20">
                  OBSERVED SENDING INFRASTRUCTURE
                </span>
              </div>

              <div className="bg-[#05080f] p-4 rounded-xl border border-white/5 space-y-3 text-xs font-mono">
                <div className="flex justify-between items-center border-b border-white/5 pb-2">
                  <span className="text-gray-500">PUBLIC IP:</span>
                  <span className="text-cyber-blue font-bold text-sm">{dossier.originIP.ip}</span>
                </div>
                <div className="flex justify-between items-center border-b border-white/5 pb-2">
                  <span className="text-gray-500">LOCATION:</span>
                  <span className="text-white">{dossier.originIP.city}, {dossier.originIP.region}, {dossier.originIP.country}</span>
                </div>
                <div className="flex justify-between items-center border-b border-white/5 pb-2">
                  <span className="text-gray-500">ISP / ASN:</span>
                  <span className="text-white">{dossier.originIP.isp} ({dossier.originIP.asn})</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-500">VPN / TOR RISK:</span>
                  <span className={`font-bold ${
                    dossier.originIP.vpnTorIndicator.includes('TOR') || dossier.originIP.vpnTorIndicator.includes('BULLETPROOF')
                      ? 'text-red-400' : 'text-emerald-400'
                  }`}>
                    {dossier.originIP.vpnTorIndicator}
                  </span>
                </div>
              </div>

              <p className="text-[11px] text-gray-400 italic">
                Forensic Caveat: {dossier.originIP.attributionDisclaimer}
              </p>
            </div>

            {/* Chain of Custody */}
            <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Lock className="w-4 h-4 text-cyber-blue" />
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                    CHAIN OF CUSTODY & EVIDENCE INTEGRITY
                  </h3>
                </div>
                <span className="text-[10px] text-emerald-400 font-mono bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                  {dossier.chainOfCustody.cryptographicIntegrityStatus}
                </span>
              </div>

              <div className="bg-[#05080f] p-4 rounded-xl border border-white/5 space-y-2.5 text-xs font-mono">
                <div className="flex justify-between items-center">
                  <span className="text-gray-500">CASE ID:</span>
                  <span className="text-white font-bold">{dossier.chainOfCustody.caseId}</span>
                </div>
                <div>
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-gray-500">SHA-256 DIGITAL FINGERPRINT:</span>
                    <button
                      onClick={() => copyToClipboard(dossier.chainOfCustody.sha256EvidenceHash, 'sha256-hash')}
                      className="text-[10px] text-cyber-blue hover:text-white flex items-center gap-1 transition-colors"
                      title="Copy SHA-256 Hash"
                    >
                      {copiedKey === 'sha256-hash' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedKey === 'sha256-hash' ? 'Copied' : 'Copy Hash'}</span>
                    </button>
                  </div>
                  <div className="p-2 rounded bg-black/60 border border-white/10 text-cyber-blue text-[11px] font-mono break-all selection:bg-cyber-blue selection:text-black">
                    {dossier.chainOfCustody.sha256EvidenceHash}
                  </div>
                </div>
                <div className="flex justify-between items-center pt-1 border-t border-white/5">
                  <span className="text-gray-500">EVIDENCE SIZE:</span>
                  <span className="text-white">{dossier.chainOfCustody.fileSizeBytes} bytes</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-500">INGESTION TIME:</span>
                  <span className="text-white">{dossier.chainOfCustody.ingestionTimestamp}</span>
                </div>
              </div>

              <div className="flex gap-2">
                <button
                  onClick={downloadJsonDossier}
                  className="w-full py-2 rounded-lg bg-cyber-blue/10 hover:bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-all"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Export Evidence Package</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: RFC 5322 & Hop-by-Hop Relay Reconstruction */}
      {activeTab === 'headers' && (
        <div className="space-y-6">
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex justify-between items-center">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyber-blue" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  CHRONOLOGICAL SMTP RELAY RECONSTRUCTION ({dossier.relayReconstruction.hopCount} HOPS)
                </h3>
              </div>
              <span className="text-xs font-mono text-gray-400">
                Total Transit Delay: ~{dossier.relayReconstruction.totalTransitTimeSeconds}s
              </span>
            </div>

            <div className="relative pl-6 space-y-6 border-l-2 border-white/10 my-2">
              {dossier.relayReconstruction.chronologicalHops.map((hop, idx) => (
                <div key={idx} className="relative group">
                  <div className="absolute -left-[31px] top-1 w-4 h-4 rounded-full bg-[#0a0f1c] border-2 border-cyber-blue flex items-center justify-center">
                    <div className="w-1.5 h-1.5 rounded-full bg-cyber-blue" />
                  </div>

                  <div className="bg-[#05080f] border border-white/5 rounded-xl p-4 space-y-2.5">
                    <div className="flex justify-between items-center">
                      <span className="text-xs font-mono font-bold text-cyber-blue">
                        HOP #{hop.hopNumber}: {hop.sourceHostname}
                      </span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                        hop.ipType.includes('Public') ? 'bg-cyber-blue/10 text-cyber-blue border-cyber-blue/30' :
                        'bg-amber-500/10 text-amber-300 border-amber-500/30'
                      }`}>
                        {hop.ipType}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono text-gray-300">
                      <div>Source IP: <span className="text-white font-bold">{hop.sourceIP}</span></div>
                      <div>Destination: <span className="text-gray-400">{hop.destinationHostname}</span></div>
                      <div>Protocol: <span className="text-gray-400">{hop.protocol}</span></div>
                    </div>

                    <div className="flex justify-between items-center text-[10px] font-mono text-gray-500 pt-2 border-t border-white/5">
                      <span>Timestamp: {hop.timestamp || 'N/A'}</span>
                      {hop.delayToNextHopSeconds !== undefined && (
                        <span className="text-cyber-blue font-bold">Transit Delay: +{hop.delayToNextHopSeconds}s</span>
                      )}
                    </div>

                    {hop.isAnomalous && (
                      <div className="bg-red-500/10 border border-red-500/20 p-2 rounded text-[11px] text-red-300 flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                        <span>Anomaly: {hop.anomalyReason}</span>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Full Extracted RFC Header Fields Table */}
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              PARSED RFC 5322 HEADER FIELDS
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
              <div className="bg-[#05080f] p-3 rounded-lg border border-white/5">
                <span className="text-gray-500 block text-[10px]">FROM:</span>
                <span className="text-white break-all">{dossier.headerFields.from}</span>
              </div>
              <div className="bg-[#05080f] p-3 rounded-lg border border-white/5">
                <span className="text-gray-500 block text-[10px]">TO:</span>
                <span className="text-white break-all">{dossier.headerFields.to}</span>
              </div>
              <div className="bg-[#05080f] p-3 rounded-lg border border-white/5">
                <span className="text-gray-500 block text-[10px]">REPLY-TO:</span>
                <span className="text-white break-all">{dossier.headerFields.replyTo || 'None specified'}</span>
              </div>
              <div className="bg-[#05080f] p-3 rounded-lg border border-white/5">
                <span className="text-gray-500 block text-[10px]">RETURN-PATH:</span>
                <span className="text-white break-all">{dossier.headerFields.returnPath || 'None specified'}</span>
              </div>
              <div className="bg-[#05080f] p-3 rounded-lg border border-white/5">
                <span className="text-gray-500 block text-[10px]">MESSAGE-ID:</span>
                <span className="text-white break-all">{dossier.headerFields.messageId || 'None specified'}</span>
              </div>
              <div className="bg-[#05080f] p-3 rounded-lg border border-white/5 md:col-span-2">
                <div className="flex justify-between items-center mb-1">
                  <span className="text-gray-500 block text-[10px] uppercase font-bold flex items-center gap-1.5 text-cyber-blue">
                    <Lock className="w-3 h-3" />
                    IMMUTABLE PAYLOAD SHA-256 FINGERPRINT (LEGAL CHAIN-OF-CUSTODY):
                  </span>
                  <button
                    onClick={() => copyToClipboard(dossier.chainOfCustody.sha256EvidenceHash, 'rfc-sha256')}
                    className="text-[10px] text-cyber-blue hover:text-white flex items-center gap-1 transition-colors"
                  >
                    {copiedKey === 'rfc-sha256' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === 'rfc-sha256' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <div className="p-2 rounded bg-black/60 border border-cyber-blue/20 text-cyber-blue text-xs font-mono break-all selection:bg-cyber-blue selection:text-black">
                  {dossier.chainOfCustody.sha256EvidenceHash}
                </div>
              </div>
              <div className="bg-[#05080f] p-3 rounded-lg border border-white/5">
                <span className="text-gray-500 block text-[10px]">CONTENT-TYPE:</span>
                <span className="text-white break-all">{dossier.headerFields.contentType}</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: SPF / DKIM / DMARC Authentication Engine */}
      {activeTab === 'authentication' && (
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 bg-[#0a0f1c] border border-white/10 p-4 rounded-2xl">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                DOMAIN AUTHENTICATION PROTOCOLS
              </h3>
              <p className="text-xs text-gray-400">Sender Domain: <strong className="text-cyber-blue">{targetDomain}</strong></p>
            </div>
            <button
              onClick={() => setShowDnsLookup(!showDnsLookup)}
              className="px-3.5 py-1.5 rounded-lg bg-cyber-blue/10 hover:bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 text-xs font-mono font-bold flex items-center gap-1.5 transition-all"
            >
              <Globe className="w-3.5 h-3.5" />
              <span>{showDnsLookup ? 'Hide DNS Lookup' : 'Query Live Domain DNS'}</span>
            </button>
          </div>

          {showDnsLookup && (
            <div className="bg-[#05080f] border border-cyber-blue/30 rounded-2xl p-5 shadow-2xl">
              <DomainAuthLookup initialDomain={targetDomain} />
            </div>
          )}

          {/* Deep SPF Card */}
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-xs font-bold text-cyber-blue uppercase font-mono">1. SPF (SENDER POLICY FRAMEWORK)</span>
              <span className={`px-2.5 py-0.5 rounded text-xs font-bold ${
                dossier.authentication.spf.status === 'PASS' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' :
                dossier.authentication.spf.status === 'FAIL' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                'bg-amber-500/20 text-amber-300 border border-amber-500/40'
              }`}>
                {dossier.authentication.spf.status}
              </span>
            </div>
            <p className="text-xs text-gray-300">{dossier.authentication.spf.evidence}</p>
            <div className="bg-[#05080f] p-3 rounded-lg border border-white/5 text-xs text-gray-400 space-y-1">
              <div>Envelope Sender Domain: <span className="text-white font-mono">{dossier.authentication.spf.envelopeSenderDomain}</span></div>
              <div>Authorized Sending IP: <span className="text-cyber-blue font-mono">{dossier.authentication.spf.sendingIP}</span></div>
              <div className="text-[11px] italic text-gray-500 pt-1">{dossier.authentication.spf.explanation}</div>
            </div>
          </div>

          {/* Deep DKIM Card */}
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-xs font-bold text-cyber-blue uppercase font-mono">2. DKIM (DOMAINKEYS IDENTIFIED MAIL)</span>
              <span className={`px-2.5 py-0.5 rounded text-xs font-bold ${
                dossier.authentication.dkim.status === 'PASS' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' :
                dossier.authentication.dkim.status === 'FAIL' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                'bg-gray-500/20 text-gray-300 border border-white/10'
              }`}>
                {dossier.authentication.dkim.status}
              </span>
            </div>
            <p className="text-xs text-gray-300">{dossier.authentication.dkim.evidence}</p>
            <div className="bg-[#05080f] p-3 rounded-lg border border-white/5 text-xs text-gray-400 space-y-1">
              <div>Signing Domain (d=): <span className="text-white font-mono">{dossier.authentication.dkim.signingDomain || 'None'}</span></div>
              <div>Selector (s=): <span className="text-white font-mono">{dossier.authentication.dkim.selector || 'None'}</span></div>
              <div className="text-[11px] italic text-gray-500 pt-1">{dossier.authentication.dkim.explanation}</div>
            </div>
          </div>

          {/* Deep DMARC Card */}
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-xs font-bold text-cyber-blue uppercase font-mono">3. DMARC (DOMAIN-BASED MESSAGE AUTHENTICATION)</span>
              <span className={`px-2.5 py-0.5 rounded text-xs font-bold ${
                dossier.authentication.dmarc.status === 'PASS' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' :
                dossier.authentication.dmarc.status === 'FAIL' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                'bg-amber-500/20 text-amber-300 border border-amber-500/40'
              }`}>
                {dossier.authentication.dmarc.status}
              </span>
            </div>
            <p className="text-xs text-gray-300">{dossier.authentication.dmarc.evidence}</p>
            <div className="bg-[#05080f] p-3 rounded-lg border border-white/5 text-xs text-gray-400 space-y-1">
              <div>Header From Domain: <span className="text-white font-mono">{dossier.authentication.dmarc.headerFromDomain}</span></div>
              <div>Identifier Alignment: <span className="text-cyber-blue font-mono">{dossier.authentication.dmarc.alignmentStatus}</span></div>
              <div className="text-[11px] italic text-gray-500 pt-1">{dossier.authentication.dmarc.explanation}</div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: Sender Identity & Lookalike Forensics */}
      {activeTab === 'identity' && (
        <div className="space-y-6">
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              SENDER MULTI-WAY COMPARISON & LOOKALIKE MATRIX
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
              <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5">
                <span className="text-gray-500 text-[10px] block">HEADER FROM DOMAIN:</span>
                <span className="text-white font-bold break-all">{dossier.senderIdentity.fromDomain}</span>
              </div>
              <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5">
                <span className="text-gray-500 text-[10px] block">RETURN-PATH (ENVELOPE):</span>
                <span className="text-white font-bold break-all">{dossier.senderIdentity.returnPathDomain || 'None'}</span>
              </div>
              <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5">
                <span className="text-gray-500 text-[10px] block">REPLY-TO DOMAIN:</span>
                <span className="text-white font-bold break-all">{dossier.senderIdentity.replyToDomain || 'None'}</span>
              </div>
              <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5">
                <span className="text-gray-500 text-[10px] block">MESSAGE-ID DOMAIN:</span>
                <span className="text-white font-bold break-all">{dossier.senderIdentity.messageIdDomain || 'None'}</span>
              </div>
            </div>

            {dossier.domainAnalysis.senderDomain.isTyposquat && (
              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 space-y-2">
                <div className="flex items-center gap-2 text-red-400 font-bold text-xs">
                  <AlertOctagon className="w-4 h-4" />
                  <span>TARGETED BRAND LOOKALIKE / TYPOSQUATTING DETECTED</span>
                </div>
                <p className="text-xs text-gray-300">
                  The domain <strong className="text-white">'{dossier.domainAnalysis.senderDomain.domain}'</strong> is mimicking brand <strong className="text-cyber-blue">'{dossier.domainAnalysis.senderDomain.targetedBrand}'</strong>.
                </p>
                <div className="text-[11px] font-mono text-gray-400 space-y-1">
                  {dossier.domainAnalysis.senderDomain.reasons.map((r, i) => (
                    <div key={i}>• {r}</div>
                  ))}
                </div>
              </div>
            )}

            {dossier.senderIdentity.inconsistencies.map((inc, i) => (
              <div key={i} className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-amber-400">{inc.title}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 font-bold">{inc.severity}</span>
                </div>
                <p className="text-xs text-gray-300">{inc.description}</p>
                <p className="text-[11px] text-gray-400 italic">Significance: {inc.significance}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 5: URL Forensics & Link Mismatch Inspector */}
      {activeTab === 'urls' && (
        <div className="space-y-6">
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex justify-between items-center">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                DECONSTRUCTED URL FORENSICS & HARVESTER ENDPOINTS ({dossier.urlForensics.length})
              </h3>
              <span className="text-xs text-gray-400">Endpoint Deep Inspection</span>
            </div>

            {dossier.urlForensics.length === 0 ? (
              <div className="bg-[#05080f] p-8 rounded-xl border border-white/5 text-center text-xs text-gray-500">
                No external URLs or hyperlink endpoints detected in this message.
              </div>
            ) : (
              <div className="space-y-4">
                {dossier.urlForensics.map((url, i) => (
                  <div key={i} className={`bg-[#05080f] border ${url.isReverseTunnel ? 'border-purple-500/40 bg-purple-950/10' : 'border-white/10'} rounded-xl p-4 space-y-3`}>
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            url.threatLevel === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                            url.threatLevel === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                            'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                          }`}>
                            {url.threatLevel} THREAT
                          </span>
                          {url.isReverseTunnel && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40 animate-pulse">
                              ⚡ REVERSE TUNNEL / CLOUDFLARE EVASION
                            </span>
                          )}
                        </div>
                        <div className="text-xs font-bold text-cyber-blue break-all">{url.rawUrl}</div>
                        {url.tunnelProvider && (
                          <div className="text-[11px] text-purple-300 font-mono">
                            Tunnel Infrastructure: <span className="text-white font-semibold">{url.tunnelProvider}</span>
                          </div>
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono bg-[#0a0f1c] p-3 rounded-lg border border-white/5">
                      <div><span className="text-gray-500 block text-[10px]">DOMAIN:</span><span className="text-white">{url.domain}</span></div>
                      <div><span className="text-gray-500 block text-[10px]">SCHEME:</span><span className="text-white">{url.scheme}</span></div>
                      <div><span className="text-gray-500 block text-[10px]">IS REVERSE TUNNEL:</span><span className={url.isReverseTunnel ? 'text-purple-400 font-bold' : 'text-gray-400'}>{url.isReverseTunnel ? 'YES' : 'NO'}</span></div>
                      <div><span className="text-gray-500 block text-[10px]">IS HARVESTER:</span><span className={url.isCredentialHarvester ? 'text-red-400 font-bold' : 'text-gray-400'}>{url.isCredentialHarvester ? 'YES' : 'NO'}</span></div>
                    </div>

                    {url.evidence.length > 0 && (
                      <div className="text-[11px] text-gray-400 space-y-0.5 font-mono">
                        {url.evidence.map((ev, idx) => (
                          <div key={idx}>• {ev}</div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 6: Dedicated IOC Extractor & Export Hub */}
      {activeTab === 'iocs' && (
        <div className="space-y-6">
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  EXTRACTED INDICATORS OF COMPROMISE (IOCs)
                </h3>
                <p className="text-xs text-gray-400">Deduplicated Forensics Intelligence Artifacts</p>
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={exportIocsCsv}
                  className="px-3 py-1.5 rounded-lg bg-cyber-blue/10 hover:bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 text-xs font-mono font-bold flex items-center gap-1.5 transition-all"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Export CSV</span>
                </button>
                <button
                  onClick={exportSTIX21}
                  className="px-3 py-1.5 rounded-lg bg-purple-500/15 hover:bg-purple-500/25 text-purple-300 border border-purple-500/30 text-xs font-mono font-bold flex items-center gap-1.5 transition-all"
                >
                  <Share2 className="w-3.5 h-3.5" />
                  <span>STIX 2.1 JSON</span>
                </button>
              </div>
            </div>

            {/* Filter buttons */}
            <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
              {(['ALL', 'IP', 'DOMAIN', 'URL', 'EMAIL', 'HASH'] as const).map(f => (
                <button
                  key={f}
                  onClick={() => setIocFilter(f)}
                  className={`px-2.5 py-1 rounded-lg border font-mono ${
                    iocFilter === f
                      ? 'bg-cyber-blue/20 text-cyber-blue border-cyber-blue/40'
                      : 'bg-white/5 text-gray-400 border-white/5 hover:text-white'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>

            {/* IOC Tables */}
            <div className="space-y-4">
              {(iocFilter === 'ALL' || iocFilter === 'IP') && dossier.iocs.ipAddresses.length > 0 && (
                <div className="space-y-2">
                  <span className="text-xs font-bold text-gray-400">IPv4 / IPv6 INFRASTRUCTURE:</span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {dossier.iocs.ipAddresses.map((ip, i) => (
                      <div key={i} className="bg-[#05080f] p-3 rounded-lg border border-white/5 flex justify-between items-center text-xs font-mono">
                        <div>
                          <span className="text-white font-bold block">{ip.ip}</span>
                          <span className="text-[10px] text-gray-500">{ip.role} ({ip.type})</span>
                        </div>
                        <button
                          onClick={() => copyToClipboard(ip.ip, `ip-${i}`)}
                          className="text-gray-400 hover:text-cyber-blue"
                        >
                          {copiedKey === `ip-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {(iocFilter === 'ALL' || iocFilter === 'DOMAIN') && dossier.iocs.domains.length > 0 && (
                <div className="space-y-2">
                  <span className="text-xs font-bold text-gray-400">IDENTIFIED DOMAINS:</span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {dossier.iocs.domains.map((dom, i) => (
                      <div key={i} className="bg-[#05080f] p-3 rounded-lg border border-white/5 flex justify-between items-center text-xs font-mono">
                        <div>
                          <span className="text-white font-bold block">{dom.domain}</span>
                          <span className="text-[10px] text-gray-500">{dom.role}</span>
                        </div>
                        <button
                          onClick={() => copyToClipboard(dom.domain, `dom-${i}`)}
                          className="text-gray-400 hover:text-cyber-blue"
                        >
                          {copiedKey === `dom-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {(iocFilter === 'ALL' || iocFilter === 'URL') && dossier.iocs.urls.length > 0 && (
                <div className="space-y-2">
                  <span className="text-xs font-bold text-gray-400">PAYLOAD & HARVESTER URLs:</span>
                  <div className="space-y-2">
                    {dossier.iocs.urls.map((u, i) => (
                      <div key={i} className="bg-[#05080f] p-3 rounded-lg border border-white/5 flex justify-between items-center text-xs font-mono">
                        <span className="text-cyber-blue truncate max-w-[80%]">{u.url}</span>
                        <button
                          onClick={() => copyToClipboard(u.url, `url-${i}`)}
                          className="text-gray-400 hover:text-cyber-blue"
                        >
                          {copiedKey === `url-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab 7: 3D Geolocation & Origin Radar */}
      {activeTab === 'geolocation' && (
        <div className="space-y-6">
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex justify-between items-center">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  3D GEOSPATIAL RADAR & ORIGIN IP ATTRIBUTION
                </h3>
                <p className="text-xs text-gray-400">Earliest Reliable Public Ingress Hop</p>
              </div>
              <span className="text-xs font-mono text-cyber-blue bg-cyber-blue/10 px-2.5 py-1 rounded border border-cyber-blue/30">
                {dossier.originIP.ip}
              </span>
            </div>

            {/* 3D Map Component */}
            <Forensic3DGeoMap
              originIP={dossier.originIP}
              hops={dossier.relayReconstruction.chronologicalHops}
              isCompact={false}
            />

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 bg-[#05080f] p-4 rounded-xl border border-white/5 text-xs font-mono">
              <div><span className="text-gray-500 block text-[10px]">COUNTRY:</span><span className="text-white font-bold">{dossier.originIP.country}</span></div>
              <div><span className="text-gray-500 block text-[10px]">CITY / REGION:</span><span className="text-white font-bold">{dossier.originIP.city}, {dossier.originIP.region}</span></div>
              <div><span className="text-gray-500 block text-[10px]">ISP / ASN:</span><span className="text-white font-bold">{dossier.originIP.isp} ({dossier.originIP.asn})</span></div>
              <div><span className="text-gray-500 block text-[10px]">ANONYMIZER / TOR:</span><span className="text-red-400 font-bold">{dossier.originIP.vpnTorIndicator}</span></div>
            </div>

            <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-xl text-xs text-amber-300">
              <strong>Strict Forensic Attribution Disclaimer:</strong> {dossier.originIP.attributionDisclaimer}
            </div>
          </div>
        </div>
      )}

      {/* Tab 8: Supervised ML (XGBoost) Phishing Classifier */}
      {activeTab === 'ml_model' && (
        <div className="space-y-6">
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex justify-between items-center">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  {dossier.mlClassification.modelName}
                </h3>
                <p className="text-xs text-gray-400">Supervised Decision-Tree Ensemble Inference</p>
              </div>
              <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold uppercase border ${
                dossier.mlClassification.prediction === 'MALICIOUS_PHISHING' ? 'bg-red-500/20 text-red-400 border-red-500/40' :
                dossier.mlClassification.prediction === 'SUSPICIOUS_UNVERIFIED' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
              }`}>
                {dossier.mlClassification.prediction} ({(dossier.mlClassification.confidenceScore * 100).toFixed(1)}%)
              </span>
            </div>

            <p className="text-xs text-gray-300 bg-[#05080f] p-4 rounded-xl border border-white/5">
              {dossier.mlClassification.summary}
            </p>

            <h4 className="text-xs font-bold text-cyber-blue uppercase font-mono pt-2">
              FEATURE CONTRIBUTION WATERFALL (SHAP EXPLAINABILITY)
            </h4>

            <div className="space-y-3">
              {dossier.mlClassification.featureContributions.map((feat, idx) => (
                <div key={idx} className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-1 text-xs font-mono">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-white">{feat.feature}</span>
                    <span className={`font-bold ${feat.impact === 'RISK_INCREASING' ? 'text-red-400' : 'text-emerald-400'}`}>
                      {feat.contribution > 0 ? `+${feat.contribution.toFixed(2)}` : feat.contribution.toFixed(2)} Logit Weight
                    </span>
                  </div>
                  <div className="text-gray-400 text-[11px]">Observed Value: <span className="text-cyber-blue">{feat.value}</span></div>
                  <p className="text-gray-500 text-[11px] italic">{feat.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 9: NLP & AI Phishing Analysis */}
      {activeTab === 'nlp_ai' && (
        <div className="space-y-6">
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              LINGUISTIC SOCIAL ENGINEERING & AI-ASSISTED PHISHING DETECTOR
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
              <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5">
                <span className="text-gray-500 text-[10px] block">URGENCY LEVEL:</span>
                <span className={`font-bold text-sm ${dossier.contentAnalysis.urgencyLevel === 'HIGH' ? 'text-red-400' : 'text-gray-300'}`}>
                  {dossier.contentAnalysis.urgencyLevel}
                </span>
              </div>
              <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5">
                <span className="text-gray-500 text-[10px] block">LLM SYNTHETIC PHISHING:</span>
                <span className={`font-bold text-sm ${dossier.aiLinguisticAnalysis.isAIAssistedDetected ? 'text-purple-400' : 'text-gray-300'}`}>
                  {dossier.aiLinguisticAnalysis.isAIAssistedDetected ? 'AI-ASSISTED INDICATORS' : 'STANDARD PATTERN'}
                </span>
              </div>
              <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5">
                <span className="text-gray-500 text-[10px] block">PROMPT INJECTION:</span>
                <span className={`font-bold text-sm ${dossier.contentAnalysis.promptInjection === 'DETECTED' ? 'text-red-400' : 'text-emerald-400'}`}>
                  {dossier.contentAnalysis.promptInjection}
                </span>
              </div>
            </div>

            <div className="space-y-2">
              {dossier.contentAnalysis.signals.map((sig, idx) => (
                <div key={idx} className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 flex items-start gap-3 text-xs">
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold text-white block">{sig.category}</span>
                    <span className="text-gray-400">{sig.description}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 10: Interactive Attack Graph */}
      {activeTab === 'attack_graph' && (
        <div className="space-y-6">
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              INTERACTIVE ATTACK & INFRASTRUCTURE TOPOLOGY GRAPH
            </h3>
            <p className="text-xs text-gray-400">Click nodes to inspect forensic relationship telemetry</p>

            <div className="bg-[#05080f] p-6 rounded-2xl border border-white/5 min-h-[300px] flex flex-col justify-center items-center">
              <div className="flex flex-wrap items-center justify-center gap-3 max-w-4xl">
                {dossier.attackGraph.nodes.map((node, i) => (
                  <React.Fragment key={node.id}>
                    <button
                      onClick={() => setSelectedGraphNode(node.id)}
                      className={`p-3.5 rounded-xl border font-mono text-xs transition-all cursor-pointer text-left ${
                        selectedGraphNode === node.id
                          ? 'bg-cyber-blue text-black border-cyber-blue shadow-[0_0_15px_rgba(0,245,255,0.5)]'
                          : 'bg-[#0a0f1c] hover:bg-white/10 text-white border-white/10'
                      }`}
                    >
                      <div className="text-[9px] uppercase tracking-wider opacity-75">{node.type}</div>
                      <div className="font-bold truncate max-w-[140px]">{node.label}</div>
                    </button>
                    {i < dossier.attackGraph.nodes.length - 1 && (
                      <ArrowRight className="w-4 h-4 text-cyber-blue shrink-0" />
                    )}
                  </React.Fragment>
                ))}
              </div>

              {selectedGraphNode && (
                <div className="mt-6 p-4 bg-[#0a0f1c] border border-cyber-blue/40 rounded-xl text-xs font-mono w-full max-w-lg">
                  <span className="text-cyber-blue font-bold block mb-1">NODE FORENSIC TELEMETRY:</span>
                  <p className="text-gray-300">{dossier.attackGraph.nodes.find(n => n.id === selectedGraphNode)?.details || 'Standard infrastructure vertex.'}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab 11: Forensic Chronological Timeline */}
      {activeTab === 'timeline' && (
        <div className="space-y-6">
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              CHRONOLOGICAL FORENSIC TIMELINE
            </h3>

            <div className="relative pl-6 space-y-6 border-l-2 border-white/10 my-2">
              {dossier.timeline.map((evt, idx) => (
                <div key={idx} className="relative group">
                  <div className={`absolute -left-[31px] top-1 w-4 h-4 rounded-full bg-[#0a0f1c] border-2 flex items-center justify-center ${
                    evt.status === 'CRITICAL' ? 'border-red-500' : 'border-cyber-blue'
                  }`}>
                    <div className={`w-1.5 h-1.5 rounded-full ${evt.status === 'CRITICAL' ? 'bg-red-500' : 'bg-cyber-blue'}`} />
                  </div>

                  <div className="bg-[#05080f] p-4 rounded-xl border border-white/5 space-y-1 text-xs font-mono">
                    <div className="flex justify-between items-center">
                      <span className="font-bold text-white">{evt.title}</span>
                      <span className="text-gray-500 text-[10px]">{evt.timestamp}</span>
                    </div>
                    <p className="text-gray-300">{evt.description}</p>
                    {evt.transitDelta && (
                      <span className="text-cyber-blue text-[10px] font-bold block">{evt.transitDelta}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 12: SOC Incident Response Playbooks */}
      {activeTab === 'soc_playbooks' && (
        <div className="space-y-6">
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex justify-between items-center">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  ACTIONABLE SOC RESPONSE PLAYBOOKS
                </h3>
                <p className="text-xs text-gray-400">Incident Remediation & Firewall Drop Rules</p>
              </div>
              <button
                onClick={() => setShowSocPreview(true)}
                className="px-3 py-1.5 rounded-lg bg-cyber-blue/15 hover:bg-cyber-blue/25 text-cyber-blue border border-cyber-blue/30 text-xs font-mono font-bold flex items-center gap-1.5"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Full SOC Dossier</span>
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {dossier.socPlaybooks.map((pb, idx) => (
                <div key={idx} className="bg-[#05080f] border border-white/5 rounded-xl p-4 space-y-3 flex flex-col justify-between">
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-white">{pb.title}</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/5 text-gray-400">{pb.category}</span>
                    </div>
                    <p className="text-xs text-gray-300">{pb.description}</p>
                  </div>

                  <div className="space-y-2 pt-2 border-t border-white/5">
                    <div className="bg-[#0a0f1c] p-2 rounded text-[10px] font-mono text-cyber-blue break-all">
                      {pb.commandOrRule}
                    </div>
                    <button
                      onClick={() => copyToClipboard(pb.commandOrRule, `pb-${idx}`)}
                      className="w-full py-1 rounded bg-white/5 hover:bg-white/10 text-gray-300 text-[11px] font-mono flex items-center justify-center gap-1"
                    >
                      {copiedKey === `pb-${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>Copy Playbook Rule</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* SOC Incident Report Modal Preview */}
      <AnimatePresence>
        {showSocPreview && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-[#0a0f1c] border border-white/10 rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col overflow-hidden shadow-2xl"
            >
              <div className="p-4 border-b border-white/10 flex justify-between items-center bg-[#05080f]">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-cyber-blue" />
                  <h3 className="text-sm font-bold text-white font-mono uppercase">
                    FORENSIC INTELLIGENCE REPORT — CASE {dossier.chainOfCustody.caseId}
                  </h3>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={copySocReport}
                    className="px-3 py-1 rounded bg-cyber-blue/15 text-cyber-blue border border-cyber-blue/30 text-xs font-mono font-bold flex items-center gap-1"
                  >
                    {copiedSocReport ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedSocReport ? 'Copied' : 'Copy Markdown'}</span>
                  </button>
                  <button
                    onClick={downloadMarkdownReport}
                    className="px-3 py-1 rounded bg-white/5 text-gray-300 border border-white/10 text-xs font-mono flex items-center gap-1"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download .md</span>
                  </button>
                  <button
                    onClick={() => setShowSocPreview(false)}
                    className="p-1 rounded text-gray-400 hover:text-white"
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
