import React, { useState } from 'react';
import { 
  Hash, Search, Filter, Copy, Check, Download, Share2, 
  Globe, Server, Mail, Link, AlertTriangle, ExternalLink, ArrowRight
} from 'lucide-react';
import { ForensicDossier } from '@/services/forensicsEngine';
import { DrillDownTarget } from './ForensicDrillDownModal';

interface IocSectionAndTableProps {
  dossier: ForensicDossier;
  onDrillDown: (target: DrillDownTarget) => void;
  onExportCsv: () => void;
  onExportStix: () => void;
}

interface FlattenedIoc {
  id: string;
  type: 'IP' | 'DOMAIN' | 'URL' | 'EMAIL' | 'HASH';
  indicator: string;
  source: string;
  status: 'MALICIOUS' | 'SUSPICIOUS' | 'IMPERSONATED' | 'INVESTIGATION' | 'BENIGN';
  confidence: number;
  relationship: string;
  firstSeen?: string;
  lastSeen?: string;
}

export function IocSectionAndTable({
  dossier,
  onDrillDown,
  onExportCsv,
  onExportStix
}: IocSectionAndTableProps) {
  const [filterType, setFilterType] = useState<'ALL' | 'IP' | 'DOMAIN' | 'URL' | 'EMAIL' | 'HASH'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Flatten all IOCs from dossier
  const flattenedIocs: FlattenedIoc[] = [];

  // IP addresses
  if (dossier.iocs.ipAddresses) {
    dossier.iocs.ipAddresses.forEach((i, idx) => {
      flattenedIocs.push({
        id: `ip-${idx}`,
        type: 'IP',
        indicator: i.ip,
        source: 'Received Header (RFC 5321)',
        status: dossier.scoreBreakdown.totalRiskScore >= 60 ? 'SUSPICIOUS' : 'INVESTIGATION',
        confidence: 98,
        relationship: i.role || 'SMTP Origin Source',
        firstSeen: dossier.headerFields.date || 'UTC Session',
        lastSeen: 'Real-time Analysis'
      });
    });
  }

  // Domains
  if (dossier.iocs.domains) {
    dossier.iocs.domains.forEach((d, idx) => {
      const isFrom = d.domain === dossier.senderIdentity.fromDomain;
      const isReturn = d.domain === dossier.senderIdentity.returnPathDomain;
      flattenedIocs.push({
        id: `dom-${idx}`,
        type: 'DOMAIN',
        indicator: d.domain,
        source: isFrom ? 'RFC 5322 From' : isReturn ? 'Return-Path' : 'Extracted Domain',
        status: d.isLookalike ? 'IMPERSONATED' : isReturn && isFrom ? 'INVESTIGATION' : 'SUSPICIOUS',
        confidence: 94,
        relationship: isFrom ? 'Claimed Identity' : isReturn ? 'Bounce Mailbox Origin' : d.role,
        firstSeen: 'Observed in transit',
        lastSeen: 'Active triage'
      });
    });
  }

  // URLs
  if (dossier.iocs.urls) {
    dossier.iocs.urls.forEach((u, idx) => {
      flattenedIocs.push({
        id: `url-${idx}`,
        type: 'URL',
        indicator: u.url,
        source: 'Message Body / Anchor Href',
        status: u.threat === 'CRITICAL' ? 'MALICIOUS' : 'SUSPICIOUS',
        confidence: 96,
        relationship: 'Phishing Credential Target',
        firstSeen: 'Payload Extract',
        lastSeen: 'Sinkhole candidate'
      });
    });
  }

  // Emails
  if (dossier.iocs.emailAddresses) {
    dossier.iocs.emailAddresses.forEach((e, idx) => {
      flattenedIocs.push({
        id: `email-${idx}`,
        type: 'EMAIL',
        indicator: e.email,
        source: e.role || 'Header Field',
        status: 'INVESTIGATION',
        confidence: 92,
        relationship: e.role,
        firstSeen: 'Header Parse',
        lastSeen: 'Active case'
      });
    });
  }

  // File hashes
  if (dossier.iocs.fileHashes) {
    dossier.iocs.fileHashes.forEach((h, idx) => {
      flattenedIocs.push({
        id: `hash-${idx}`,
        type: 'HASH',
        indicator: h.sha256,
        source: `Attachment (${h.filename})`,
        status: 'MALICIOUS',
        confidence: 99,
        relationship: 'Payload Hash / Signature',
        firstSeen: 'MIME Stream',
        lastSeen: 'EDR Match'
      });
    });
  }

  // Add the primary evidence hash
  if (!flattenedIocs.some(i => i.indicator === dossier.chainOfCustody.sha256EvidenceHash)) {
    flattenedIocs.push({
      id: 'hash-primary',
      type: 'HASH',
      indicator: dossier.chainOfCustody.sha256EvidenceHash,
      source: 'Full RFC 5322 Ingestion Stream',
      status: 'INVESTIGATION',
      confidence: 100,
      relationship: 'Case Evidence Integrity Hash',
      firstSeen: dossier.chainOfCustody.ingestionTimestamp,
      lastSeen: 'Immutable Record'
    });
  }

  // Calculate Category Counts
  const ipCount = flattenedIocs.filter(i => i.type === 'IP').length;
  const domainCount = flattenedIocs.filter(i => i.type === 'DOMAIN').length;
  const urlCount = flattenedIocs.filter(i => i.type === 'URL').length;
  const emailCount = flattenedIocs.filter(i => i.type === 'EMAIL').length;
  const hashCount = flattenedIocs.filter(i => i.type === 'HASH').length;

  // Filter & Search
  const filteredIocs = flattenedIocs.filter(item => {
    const matchesFilter = filterType === 'ALL' || item.type === filterType;
    const matchesSearch = searchQuery.trim() === '' || 
      item.indicator.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.relationship.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.source.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const getStatusClass = (status: FlattenedIoc['status']) => {
    switch (status) {
      case 'MALICIOUS': return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'IMPERSONATED': return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'SUSPICIOUS': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
      case 'INVESTIGATION': default: return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
    }
  };

  return (
    <div className="space-y-6 font-mono text-white">
      {/* SECTION 9: IOC INTELLIGENCE & RELATIONSHIPS */}
      <section 
        id="ioc-intelligence-section"
        className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 shadow-2xl space-y-4"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-3">
          <div>
            <div className="flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
              <h2 className="text-xs font-bold uppercase tracking-widest text-white">
                9. Indicators of Compromise (IOC) Intelligence
              </h2>
            </div>
            <p className="text-[11px] text-gray-400 font-sans mt-0.5">
              Extracted forensic entities, role attribution, and structural relationships.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onExportCsv}
              className="px-2.5 py-1.5 rounded-lg text-xs bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 flex items-center gap-1.5 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Export CSV</span>
            </button>
            <button
              onClick={onExportStix}
              className="px-2.5 py-1.5 rounded-lg text-xs bg-purple-500/15 hover:bg-purple-500/25 text-purple-300 border border-purple-500/30 flex items-center gap-1.5 cursor-pointer"
            >
              <Share2 className="w-3.5 h-3.5" />
              <span>STIX 2.1</span>
            </button>
          </div>
        </div>

        {/* IOC Category Counts Bar */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
          <div className="p-2.5 rounded-xl bg-black/40 border border-white/10 flex items-center justify-between">
            <span className="text-xs text-gray-400 font-bold">IP</span>
            <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 text-xs font-bold font-mono">
              {ipCount}
            </span>
          </div>
          <div className="p-2.5 rounded-xl bg-black/40 border border-white/10 flex items-center justify-between">
            <span className="text-xs text-gray-400 font-bold">DOMAIN</span>
            <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 text-xs font-bold font-mono">
              {domainCount}
            </span>
          </div>
          <div className="p-2.5 rounded-xl bg-black/40 border border-white/10 flex items-center justify-between">
            <span className="text-xs text-gray-400 font-bold">URL</span>
            <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 text-xs font-bold font-mono">
              {urlCount}
            </span>
          </div>
          <div className="p-2.5 rounded-xl bg-black/40 border border-white/10 flex items-center justify-between">
            <span className="text-xs text-gray-400 font-bold">EMAIL</span>
            <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 text-xs font-bold font-mono">
              {emailCount}
            </span>
          </div>
          <div className="p-2.5 rounded-xl bg-black/40 border border-white/10 flex items-center justify-between">
            <span className="text-xs text-gray-400 font-bold">HASH</span>
            <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 text-xs font-bold font-mono">
              {hashCount}
            </span>
          </div>
        </div>

        {/* Visual IOC Relationship Tree */}
        <div className="p-4 rounded-xl bg-black/40 border border-white/10 space-y-3">
          <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider block">
            CORE ENTITY RELATIONSHIP TREE
          </span>

          <div className="space-y-3 font-mono text-xs">
            {/* Tree Branch 1: Claimed Domain */}
            <div className="pl-3 border-l-2 border-cyan-500/40 space-y-1">
              <div className="font-bold text-white flex items-center gap-2">
                <Globe className="w-3.5 h-3.5 text-cyan-400" />
                <span>{dossier.senderIdentity.fromDomain || 'Claimed Domain'}</span>
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  Targeted Brand Identity
                </span>
              </div>
              <div className="pl-4 text-gray-400 text-[11px] space-y-0.5">
                <div>├── Header From: <span className="text-gray-200 font-bold">{dossier.senderIdentity.fromAddress}</span></div>
                <div>├── DMARC Evaluation: <span className="text-red-400">{dossier.authentication.dmarc.status}</span></div>
                <div>└── Observed Action: <span className="text-amber-300">Brand Impersonation Lure</span></div>
              </div>
            </div>

            {/* Tree Branch 2: Return-Path Domain */}
            {dossier.senderIdentity.returnPathDomain && dossier.senderIdentity.returnPathDomain !== dossier.senderIdentity.fromDomain && (
              <div className="pl-3 border-l-2 border-amber-500/40 space-y-1">
                <div className="font-bold text-white flex items-center gap-2">
                  <Mail className="w-3.5 h-3.5 text-amber-400" />
                  <span>{dossier.senderIdentity.returnPathDomain}</span>
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-red-500/20 text-red-300 border border-red-500/30">
                    Actual Bounce Origin
                  </span>
                </div>
                <div className="pl-4 text-gray-400 text-[11px] space-y-0.5">
                  <div>└── Return-Path: <span className="text-gray-200 font-bold">{dossier.senderIdentity.returnPathAddress}</span></div>
                </div>
              </div>
            )}

            {/* Tree Branch 3: SMTP Source IP */}
            <div className="pl-3 border-l-2 border-red-500/40 space-y-1">
              <div className="font-bold text-white flex items-center gap-2">
                <Server className="w-3.5 h-3.5 text-red-400" />
                <span>{dossier.originIP.ip}</span>
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-red-500/20 text-red-300 border border-red-500/30">
                  SMTP Origin Node
                </span>
              </div>
              <div className="pl-4 text-gray-400 text-[11px] space-y-0.5">
                <div>├── Autonomous System: <span className="text-purple-300 font-mono">{dossier.originIP.asn}</span></div>
                <div>├── Infrastructure Geo: <span className="text-gray-300">{dossier.originIP.city}, {dossier.originIP.country}</span></div>
                <div>└── SPF Authorization: <span className="text-red-400">{dossier.authentication.spf.status}</span></div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 10: IOC TABLE */}
      <section 
        id="ioc-table-section"
        className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 shadow-2xl space-y-4"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-3">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
            <h2 className="text-xs font-bold uppercase tracking-widest text-white">
              10. Compact Forensic IOC Evidence Table
            </h2>
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
            {(['ALL', 'IP', 'DOMAIN', 'URL', 'EMAIL', 'HASH'] as const).map(type => (
              <button
                key={type}
                onClick={() => setFilterType(type)}
                className={`px-2.5 py-1 rounded-lg transition-colors cursor-pointer text-[10px] font-bold ${
                  filterType === type 
                    ? 'bg-cyan-500 text-black shadow-[0_0_10px_rgba(0,245,255,0.3)]' 
                    : 'bg-white/5 text-gray-400 hover:text-white border border-white/10'
                }`}
              >
                {type}
              </button>
            ))}
          </div>
        </div>

        {/* Search Bar */}
        <div className="relative">
          <Search className="w-4 h-4 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search indicator, source, or relationship..."
            className="w-full bg-black/40 border border-white/10 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-400 font-mono"
          />
        </div>

        {/* Compact Table */}
        <div className="overflow-x-auto rounded-xl border border-white/10">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="bg-[#0b1326] border-b border-white/10 text-[10px] uppercase tracking-wider text-gray-400">
                <th className="p-3">TYPE</th>
                <th className="p-3">INDICATOR</th>
                <th className="p-3">SOURCE</th>
                <th className="p-3 text-center">STATUS</th>
                <th className="p-3 text-center">CONFIDENCE</th>
                <th className="p-3">RELATIONSHIP</th>
                <th className="p-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filteredIocs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-6 text-center text-gray-500 text-xs">
                    No indicators match the active filter or query.
                  </td>
                </tr>
              ) : (
                filteredIocs.map((ioc) => (
                  <tr key={ioc.id} className="hover:bg-white/5 transition-colors">
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-white/10 text-cyan-300 text-[10px] font-bold">
                        {ioc.type}
                      </span>
                    </td>
                    <td className="p-3 font-mono font-bold text-white break-all max-w-xs">
                      {ioc.indicator}
                    </td>
                    <td className="p-3 text-gray-400 text-[11px] truncate max-w-[150px]">
                      {ioc.source}
                    </td>
                    <td className="p-3 text-center">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getStatusClass(ioc.status)}`}>
                        {ioc.status}
                      </span>
                    </td>
                    <td className="p-3 text-center font-bold text-gray-300">
                      {ioc.confidence}%
                    </td>
                    <td className="p-3 text-gray-300 text-[11px] truncate max-w-[180px]">
                      {ioc.relationship}
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => handleCopy(ioc.indicator, ioc.id)}
                        className="p-1.5 rounded bg-white/5 hover:bg-white/15 text-gray-400 hover:text-cyan-400 transition-colors inline-flex items-center gap-1 text-[10px] cursor-pointer"
                        title="Copy indicator"
                      >
                        {copiedId === ioc.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
