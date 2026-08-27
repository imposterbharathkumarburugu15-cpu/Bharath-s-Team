import React, { useState } from 'react';
import { motion } from 'motion/react';
import { 
  Mail, Shield, ShieldCheck, ShieldAlert, AlertTriangle, FileText, 
  Terminal, ArrowRight, Copy, Check, Download, ExternalLink, Network, 
  Globe, Server, Clock, Lock, AlertCircle, Sparkles, Layers, Hash
} from 'lucide-react';
import { ForensicDossier } from '@/services/forensicsEngine';

interface EmailForensicsPanelProps {
  dossier: ForensicDossier;
  compact?: boolean;
}

export function EmailForensicsPanel({ dossier, compact = false }: EmailForensicsPanelProps) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const downloadJsonDossier = () => {
    const blob = new Blob([JSON.stringify(dossier, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `neuroshield-forensic-dossier-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadMarkdownReport = () => {
    const blob = new Blob([dossier.socReportMarkdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SOC-Incident-Report-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-6 text-white font-mono"
    >
      {/* 1. Threat Verdict & KPI Banner */}
      <div className="bg-[#0a0f1c]/90 border border-white/10 rounded-2xl p-5 shadow-2xl relative overflow-hidden backdrop-blur-md">
        <div className={`absolute top-0 left-0 h-1.5 w-full ${
          dossier.classification.verdict === 'MALICIOUS' ? 'bg-red-500' :
          dossier.classification.verdict === 'SUSPICIOUS' ? 'bg-amber-500' : 'bg-emerald-500'
        }`} />

        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-5">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold tracking-widest uppercase border ${
                dossier.classification.verdict === 'MALICIOUS' ? 'bg-red-500/10 text-red-400 border-red-500/30' :
                dossier.classification.verdict === 'SUSPICIOUS' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
                'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
              }`}>
                {dossier.classification.verdict} — {dossier.classification.threatType}
              </span>
              <span className="text-xs text-gray-400 font-mono">Confidence: {dossier.classification.confidence}%</span>
            </div>
            <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight break-all">{dossier.headerFields.subject || 'No Subject Specified'}</h2>
            <p className="text-xs text-cyber-muted font-mono">Subtype: {dossier.classification.subtype}</p>
          </div>

          <div className="flex items-center gap-5 shrink-0">
            <div className="text-right">
              <span className="text-[10px] font-mono uppercase tracking-widest text-gray-500 block">THREAT RISK SCORE</span>
              <div className={`text-3xl sm:text-4xl font-black font-mono tracking-tighter ${
                dossier.classification.riskScore > 60 ? 'text-red-500' :
                dossier.classification.riskScore > 30 ? 'text-amber-400' : 'text-emerald-400'
              }`}>
                {dossier.classification.riskScore}<span className="text-lg text-gray-600">/100</span>
              </div>
            </div>

            <div className="flex flex-col gap-2">
              <button
                onClick={downloadJsonDossier}
                className="px-3 py-1.5 rounded-lg text-xs font-mono bg-white/5 hover:bg-white/10 text-white border border-white/10 flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Download className="w-3.5 h-3.5 text-cyber-blue" />
                <span>Export JSON</span>
              </button>
              <button
                onClick={downloadMarkdownReport}
                className="px-3 py-1.5 rounded-lg text-xs font-mono bg-cyber-blue/10 hover:bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>SOC Report (.md)</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Protocol Authentication Matrix (SPF / DKIM / DMARC) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* SPF */}
        <div className="bg-[#0a0f1c]/80 border border-white/10 rounded-2xl p-5 shadow-lg backdrop-blur-sm">
          <div className="flex justify-between items-center mb-3">
            <span className="text-xs font-mono font-bold tracking-widest uppercase text-gray-400">SPF VALIDATION</span>
            <span className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold uppercase border ${
              dossier.authentication.spf.status === 'PASS' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
              dossier.authentication.spf.status === 'FAIL' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
              'bg-gray-500/10 text-gray-400 border-gray-500/20'
            }`}>
              {dossier.authentication.spf.status}
            </span>
          </div>
          <p className="text-xs text-gray-300 leading-relaxed mb-3">{dossier.authentication.spf.evidence}</p>
          <div className="text-[10px] font-mono text-gray-500 border-t border-white/5 pt-2">
            Envelope Domain: <span className="text-gray-300">{dossier.authentication.spf.envelopeSenderDomain || 'N/A'}</span>
          </div>
        </div>

        {/* DKIM */}
        <div className="bg-[#0a0f1c]/80 border border-white/10 rounded-2xl p-5 shadow-lg backdrop-blur-sm">
          <div className="flex justify-between items-center mb-3">
            <span className="text-xs font-mono font-bold tracking-widest uppercase text-gray-400">DKIM CRYPTO SIGNATURE</span>
            <span className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold uppercase border ${
              dossier.authentication.dkim.status === 'PASS' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
              dossier.authentication.dkim.status === 'FAIL' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
              'bg-gray-500/10 text-gray-400 border-gray-500/20'
            }`}>
              {dossier.authentication.dkim.status}
            </span>
          </div>
          <p className="text-xs text-gray-300 leading-relaxed mb-3">{dossier.authentication.dkim.evidence}</p>
          <div className="text-[10px] font-mono text-gray-500 border-t border-white/5 pt-2">
            Signing Domain: <span className="text-gray-300">{dossier.authentication.dkim.signingDomain || 'None'}</span>
          </div>
        </div>

        {/* DMARC */}
        <div className="bg-[#0a0f1c]/80 border border-white/10 rounded-2xl p-5 shadow-lg backdrop-blur-sm">
          <div className="flex justify-between items-center mb-3">
            <span className="text-xs font-mono font-bold tracking-widest uppercase text-gray-400">DMARC POLICY ALIGNMENT</span>
            <span className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold uppercase border ${
              dossier.authentication.dmarc.status === 'PASS' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
              dossier.authentication.dmarc.status === 'FAIL' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
              'bg-gray-500/10 text-gray-400 border-gray-500/20'
            }`}>
              {dossier.authentication.dmarc.status}
            </span>
          </div>
          <p className="text-xs text-gray-300 leading-relaxed mb-3">{dossier.authentication.dmarc.evidence}</p>
          <div className="text-[10px] font-mono text-gray-500 border-t border-white/5 pt-2">
            Header From: <span className="text-gray-300">{dossier.authentication.dmarc.headerFromDomain || 'N/A'}</span>
          </div>
        </div>
      </div>

      {/* 3. Sender Identity & Discrepancies Matrix */}
      <div className="bg-[#0a0f1c]/90 border border-white/10 rounded-2xl p-5 sm:p-6 shadow-xl space-y-4 backdrop-blur-sm">
        <div className="flex justify-between items-center">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-cyber-blue" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              SENDER IDENTITY & HEADER DISCREPANCY AUDIT
            </h3>
          </div>
          <span className="text-xs font-mono text-gray-400">
            {dossier.senderIdentity.inconsistencies.length} Inconsistencies Detected
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 bg-[#05080f] p-4 rounded-xl border border-white/5 text-xs font-mono">
          <div>
            <span className="text-gray-500 block text-[10px]">HEADER FROM:</span>
            <span className="text-white font-medium break-all">{dossier.senderIdentity.fromAddress}</span>
          </div>
          <div>
            <span className="text-gray-500 block text-[10px]">RETURN-PATH (ENVELOPE):</span>
            <span className="text-white font-medium break-all">{dossier.senderIdentity.returnPathAddress || 'N/A'}</span>
          </div>
          <div>
            <span className="text-gray-500 block text-[10px]">REPLY-TO:</span>
            <span className="text-white font-medium break-all">{dossier.senderIdentity.replyToAddress || 'N/A'}</span>
          </div>
          <div>
            <span className="text-gray-500 block text-[10px]">MESSAGE-ID:</span>
            <span className="text-white font-medium break-all">{dossier.headerFields.messageId || 'N/A'}</span>
          </div>
        </div>

        {dossier.senderIdentity.inconsistencies.length > 0 && (
          <div className="space-y-2 pt-2">
            {dossier.senderIdentity.inconsistencies.map((inc, i) => (
              <div key={i} className="bg-red-500/5 border border-red-500/20 rounded-xl p-3 flex items-start gap-3">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <div className="space-y-1 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-red-400">{inc.title}</span>
                    <span className="text-[10px] font-mono px-2 py-0.2 bg-red-500/20 text-red-300 rounded">
                      {inc.severity}
                    </span>
                  </div>
                  <p className="text-gray-300">{inc.description}</p>
                  <p className="text-gray-400 text-[11px] italic font-mono">{inc.significance}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 4. Hop-by-Hop Relay Path & Origin IP Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Relay Path Chronology */}
        <div className="lg:col-span-2 bg-[#0a0f1c]/90 border border-white/10 rounded-2xl p-5 sm:p-6 shadow-xl space-y-4 backdrop-blur-sm">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-cyber-blue" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                RELAY PATH RECONSTRUCTION ({dossier.relayReconstruction.hopCount} HOPS)
              </h3>
            </div>
            <span className="text-xs font-mono text-gray-400">
              Transit: ~{dossier.relayReconstruction.totalTransitTimeSeconds}s
            </span>
          </div>

          <div className="relative pl-6 space-y-5 border-l-2 border-white/10 my-2 max-h-[380px] overflow-y-auto custom-scrollbar pr-2">
            {dossier.relayReconstruction.chronologicalHops.map((hop, idx) => (
              <div key={idx} className="relative group">
                <div className="absolute -left-[31px] top-0.5 w-4 h-4 rounded-full bg-[#0a0f1c] border-2 border-cyber-blue flex items-center justify-center">
                  <div className="w-1.5 h-1.5 rounded-full bg-cyber-blue" />
                </div>

                <div className="bg-[#05080f] border border-white/5 rounded-xl p-3.5 space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-xs font-mono font-bold text-cyber-blue">
                      HOP {hop.hopNumber}: {hop.sourceHostname}
                    </span>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                      hop.ipType === 'Public IPv4' ? 'bg-cyber-blue/10 text-cyber-blue border-cyber-blue/30' :
                      'bg-amber-500/10 text-amber-300 border-amber-500/30'
                    }`}>
                      {hop.ipType}
                    </span>
                  </div>

                  <div className="text-xs font-mono text-gray-300 flex flex-wrap gap-x-4 gap-y-1">
                    <div>IP: <span className="text-white font-bold">{hop.sourceIP}</span></div>
                    <div>➔ Destination: <span className="text-gray-400">{hop.destinationHostname}</span></div>
                    <div>Protocol: <span className="text-gray-400">{hop.protocol}</span></div>
                  </div>

                  <div className="flex justify-between items-center text-[10px] font-mono text-gray-500 pt-1 border-t border-white/5">
                    <span>Time: {hop.timestamp || 'N/A'}</span>
                    {hop.delayToNextHopSeconds !== undefined && (
                      <span>Transit Delay: +{hop.delayToNextHopSeconds}s</span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Origin IP & Intelligence */}
        <div className="bg-[#0a0f1c]/90 border border-white/10 rounded-2xl p-5 sm:p-6 shadow-xl flex flex-col justify-between space-y-4 backdrop-blur-sm">
          <div>
            <div className="flex items-center gap-2 mb-4">
              <Globe className="w-4 h-4 text-cyber-blue" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                ORIGIN IP & GEOLOCATION
              </h3>
            </div>

            <div className="space-y-3 bg-[#05080f] p-4 rounded-xl border border-white/5 font-mono text-xs">
              <div>
                <span className="text-[10px] text-gray-500 block">EARLIEST RELIABLE PUBLIC IP:</span>
                <span className="text-base text-cyber-blue font-bold">{dossier.originIP.ip}</span>
              </div>
              <div>
                <span className="text-[10px] text-gray-500 block">IP CLASSIFICATION:</span>
                <span className="text-white">{dossier.originIP.ipType}</span>
              </div>
              <div>
                <span className="text-[10px] text-gray-500 block">COUNTRY / LOCATION:</span>
                <span className="text-white">{dossier.originIP.country}</span>
              </div>
              <div>
                <span className="text-[10px] text-gray-500 block">CITY / REGION:</span>
                <span className="text-white">{dossier.originIP.city}, {dossier.originIP.region}</span>
              </div>
              <div>
                <span className="text-[10px] text-gray-500 block">ISP / ASN:</span>
                <span className="text-white">{dossier.originIP.isp} ({dossier.originIP.asn})</span>
              </div>
            </div>

            <p className="text-[11px] text-gray-400 italic mt-3 leading-relaxed">
              Forensic Caveat: Identifies the sending mail server gateway; does not prove physical identity of the human operator.
            </p>
          </div>

          <div className="pt-3 border-t border-white/5">
            <button
              type="button"
              onClick={() => {
                // Ensure active graph is saved in localStorage
                if (dossier.attackGraph) {
                  localStorage.setItem('neuroshield_active_attack_graph', JSON.stringify(dossier.attackGraph));
                }
                // Dispatch custom event for single page app navigation
                window.dispatchEvent(new CustomEvent('neuroshield:navigate', { detail: 'graph' }));
                window.location.hash = '#/attack-graph';
              }}
              className="w-full py-2.5 rounded-xl font-mono text-xs font-bold uppercase tracking-wider bg-cyber-blue/10 hover:bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 flex items-center justify-center gap-2 transition-all duration-200 hover:shadow-[0_0_15px_rgba(0,245,255,0.2)] cursor-pointer"
            >
              <Network className="w-3.5 h-3.5" />
              <span>Inspect in Attack Graph</span>
            </button>
          </div>
        </div>
      </div>

      {/* 5. Indicators of Compromise (IOC) Matrix */}
      <div className="bg-[#0a0f1c]/90 border border-white/10 rounded-2xl p-5 sm:p-6 shadow-xl space-y-4 backdrop-blur-sm">
        <div className="flex justify-between items-center">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyber-blue" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              EXTRACTED INDICATORS OF COMPROMISE (IOCs)
            </h3>
          </div>
          <span className="text-xs font-mono text-gray-400">Ready for SIEM/EDR Ingestion</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {/* IP Addresses */}
          <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-2">
            <span className="text-[10px] font-mono text-gray-400 font-bold uppercase block">IP ADDRESSES</span>
            <div className="space-y-1 max-h-32 overflow-y-auto pr-1 custom-scrollbar">
              {dossier.iocs.ipAddresses.map((ipObj, i) => (
                <div key={i} className="flex justify-between items-center text-xs font-mono bg-black/40 p-1.5 rounded border border-white/5">
                  <span className="text-white truncate">{ipObj.ip}</span>
                  <button
                    onClick={() => copyToClipboard(ipObj.ip, `ip-${i}`)}
                    className="text-gray-400 hover:text-white p-1 cursor-pointer"
                  >
                    {copiedKey === `ip-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Domains */}
          <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-2">
            <span className="text-[10px] font-mono text-gray-400 font-bold uppercase block">DOMAINS</span>
            <div className="space-y-1 max-h-32 overflow-y-auto pr-1 custom-scrollbar">
              {dossier.iocs.domains.map((dom, i) => (
                <div key={i} className="flex justify-between items-center text-xs font-mono bg-black/40 p-1.5 rounded border border-white/5">
                  <span className="text-white truncate" title={dom.domain}>{dom.domain}</span>
                  <button
                    onClick={() => copyToClipboard(dom.domain, `dom-${i}`)}
                    className="text-gray-400 hover:text-white p-1 cursor-pointer"
                  >
                    {copiedKey === `dom-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* URLs */}
          <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-2">
            <span className="text-[10px] font-mono text-gray-400 font-bold uppercase block">PHISHING URLS</span>
            <div className="space-y-1 max-h-32 overflow-y-auto pr-1 custom-scrollbar">
              {dossier.iocs.urls.length > 0 ? (
                dossier.iocs.urls.map((u, i) => (
                  <div key={i} className="flex justify-between items-center text-xs font-mono bg-black/40 p-1.5 rounded border border-white/5">
                    <span className="text-red-400 truncate" title={u}>{u}</span>
                    <button
                      onClick={() => copyToClipboard(u, `url-${i}`)}
                      className="text-gray-400 hover:text-white p-1 cursor-pointer"
                    >
                      {copiedKey === `url-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                ))
              ) : (
                <div className="text-xs text-gray-500 italic p-1">No embedded URLs</div>
              )}
            </div>
          </div>

          {/* Email Accounts */}
          <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-2">
            <span className="text-[10px] font-mono text-gray-400 font-bold uppercase block">IDENTIFIED EMAILS</span>
            <div className="space-y-1 max-h-32 overflow-y-auto pr-1 custom-scrollbar">
              {dossier.iocs.emailAddresses.map((em, i) => (
                <div key={i} className="flex justify-between items-center text-xs font-mono bg-black/40 p-1.5 rounded border border-white/5">
                  <span className="text-white truncate" title={em.email}>{em.email}</span>
                  <button
                    onClick={() => copyToClipboard(em.email, `em-${i}`)}
                    className="text-gray-400 hover:text-white p-1 cursor-pointer"
                  >
                    {copiedKey === `em-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 6. Top Prioritized Forensic Findings */}
      <div className="bg-[#0a0f1c]/90 border border-white/10 rounded-2xl p-5 sm:p-6 shadow-xl space-y-3 backdrop-blur-sm">
        <div className="flex items-center gap-2 mb-2">
          <ShieldCheck className="w-4 h-4 text-cyber-blue" />
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
            TOP PRIORITIZED FORENSIC FINDINGS
          </h3>
        </div>

        <div className="space-y-2">
          {dossier.topFindings.map((f, i) => (
            <div key={i} className="flex items-start gap-3 bg-[#05080f] p-3 rounded-xl border border-white/5">
              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase shrink-0 mt-0.5 ${
                f.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                f.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30'
              }`}>
                {f.severity}
              </span>
              <p className="text-xs text-gray-300 leading-relaxed font-sans">{f.finding}</p>
            </div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}
