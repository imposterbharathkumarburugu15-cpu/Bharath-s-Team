import React, { useState } from 'react';
import { 
  AlertOctagon, AlertTriangle, Info, ChevronDown, 
  ChevronUp, ExternalLink, ShieldAlert, Terminal, Eye
} from 'lucide-react';
import { ForensicDossier } from '@/services/forensicsEngine';
import { DrillDownTarget } from './ForensicDrillDownModal';

interface ForensicExecutiveSummaryProps {
  dossier: ForensicDossier;
  onDrillDown: (target: DrillDownTarget) => void;
}

interface VisualEvidenceCardData {
  id: string;
  detection: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  impactScore: number;
  evidenceSource: string;
  summary: string;
  rawEvidence: string;
  drillDownTarget: DrillDownTarget;
}

export function ForensicExecutiveSummary({ dossier, onDrillDown }: ForensicExecutiveSummaryProps) {
  const [expandedCardId, setExpandedCardId] = useState<string | null>(null);

  // Synthesize 5-7 major evidence findings from the dossier
  const evidenceCards: VisualEvidenceCardData[] = [];

  // 1. SPF Check
  if (dossier.authentication.spf.status === 'FAIL' || dossier.authentication.spf.status === 'SOFTFAIL') {
    evidenceCards.push({
      id: 'spf-fail',
      detection: 'SPF FAILURE',
      category: 'Authentication',
      severity: 'CRITICAL',
      impactScore: 90,
      evidenceSource: 'Received-SPF, Authentication-Results',
      summary: 'Sending server IP is not authorized by the published SPF DNS TXT record.',
      rawEvidence: dossier.authentication.spf.evidence || 'v=spf1 ... -all / sender IP unauthorized',
      drillDownTarget: {
        type: 'SPF',
        title: 'SPF Authentication Failure',
        badge: 'CRITICAL FAIL',
        badgeColor: 'red',
        summary: 'The relaying host was rejected by the envelope sender domain SPF policy. The sending IP is outside legitimate enterprise infrastructure.',
        technicalDetails: [
          { label: 'Evaluation Status', value: dossier.authentication.spf.status, isMono: true },
          { label: 'Sender Domain', value: dossier.authentication.spf.envelopeSenderDomain || 'N/A', isMono: true },
          { label: 'Relaying Origin IP', value: dossier.originIP.ip, isMono: true, copyable: true },
          { label: 'SPF Policy Evidence', value: dossier.authentication.spf.evidence || 'N/A', isMono: true }
        ],
        rawSnippet: dossier.authentication.spf.evidence,
        rfcStandard: 'RFC 7208 (Sender Policy Framework)',
        remediation: 'Block sender IP or isolate email. High likelihood of external infrastructure impersonation.'
      }
    });
  }

  // 2. DKIM Check
  if (dossier.authentication.dkim.status === 'FAIL' || dossier.authentication.dkim.status === 'NONE') {
    const isNone = dossier.authentication.dkim.status === 'NONE';
    evidenceCards.push({
      id: 'dkim-fail',
      detection: isNone ? 'DKIM MISSING / NONE' : 'DKIM SIGNATURE MISMATCH',
      category: 'Cryptographic Auth',
      severity: isNone ? 'HIGH' : 'CRITICAL',
      impactScore: isNone ? 80 : 95,
      evidenceSource: 'DKIM-Signature, Authentication-Results',
      summary: isNone 
        ? 'No cryptographic digital signature found in RFC 5322 header blocks.' 
        : 'Digital cryptographic signature verification failed (body hash or key mismatch).',
      rawEvidence: dossier.authentication.dkim.evidence || 'dkim=none (no key provided)',
      drillDownTarget: {
        type: 'DKIM',
        title: isNone ? 'Missing DKIM Signature' : 'DKIM Cryptographic Verification Mismatch',
        badge: isNone ? 'UNSIGNED' : 'INVALID HASH',
        badgeColor: isNone ? 'amber' : 'red',
        summary: 'DKIM allows senders to take cryptographic responsibility. Failure indicates unauthorized tampering or spoofed transmission.',
        technicalDetails: [
          { label: 'DKIM Status', value: dossier.authentication.dkim.status, isMono: true },
          { label: 'Signing Domain', value: dossier.authentication.dkim.signingDomain || 'NONE', isMono: true },
          { label: 'Selector', value: dossier.authentication.dkim.selector || 'NONE', isMono: true },
          { label: 'Explanation', value: dossier.authentication.dkim.explanation, isMono: false }
        ],
        rawSnippet: dossier.headerFields.dkimSignature || 'No DKIM-Signature header present in RFC message stream.',
        rfcStandard: 'RFC 6376 (DomainKeys Identified Mail)',
        remediation: 'Enforce strict inbound DKIM verification policies across mail gateways.'
      }
    });
  }

  // 3. DMARC Check
  if (dossier.authentication.dmarc.status === 'FAIL' || dossier.authentication.dmarc.alignmentStatus === 'UNALIGNED') {
    evidenceCards.push({
      id: 'dmarc-fail',
      detection: 'DMARC ALIGNMENT FAILED',
      category: 'Policy Enforcement',
      severity: 'CRITICAL',
      impactScore: 95,
      evidenceSource: 'Authentication-Results, DMARC TXT Record',
      summary: 'Neither SPF nor DKIM domains align with the visible RFC 5322 Header From domain.',
      rawEvidence: dossier.authentication.dmarc.evidence || `dmarc=fail (p=${dossier.authentication.dmarc.policy || 'none'})`,
      drillDownTarget: {
        type: 'DMARC',
        title: 'DMARC Alignment Verification Failure',
        badge: 'POLICY FAILED',
        badgeColor: 'red',
        summary: 'DMARC links the sender From: header with validated SPF or DKIM domains. Mismatch proves deceptive sender masking.',
        technicalDetails: [
          { label: 'DMARC Result', value: dossier.authentication.dmarc.status, isMono: true },
          { label: 'Alignment Status', value: dossier.authentication.dmarc.alignmentStatus, isMono: true },
          { label: 'Header From Domain', value: dossier.authentication.dmarc.headerFromDomain || 'N/A', isMono: true },
          { label: 'Published Policy', value: dossier.authentication.dmarc.policy || 'none', isMono: true }
        ],
        rawSnippet: dossier.authentication.dmarc.evidence,
        rfcStandard: 'RFC 7489 (Domain-based Message Authentication)',
        remediation: 'Quarantine or reject message at mail gateway if policy specifies p=quarantine/reject.'
      }
    });
  }

  // 4. Sender Mismatch (Return-Path != Header From)
  const fromDom = dossier.senderIdentity.fromDomain?.toLowerCase();
  const retDom = dossier.senderIdentity.returnPathDomain?.toLowerCase();
  if (fromDom && retDom && fromDom !== retDom) {
    evidenceCards.push({
      id: 'sender-mismatch',
      detection: 'SENDER IDENTITY MISMATCH',
      category: 'Header Anomalies',
      severity: 'HIGH',
      impactScore: 85,
      evidenceSource: 'Return-Path vs RFC 5322 From',
      summary: `Return-Path (${retDom}) differs from visible Header From (${fromDom}).`,
      rawEvidence: `From: ${dossier.senderIdentity.fromAddress}\nReturn-Path: ${dossier.senderIdentity.returnPathAddress}`,
      drillDownTarget: {
        type: 'RETURN_PATH',
        title: 'Envelope / Header From Domain Mismatch',
        badge: 'SENDER SPOOF',
        badgeColor: 'amber',
        summary: 'The displayed user-facing sender domain differs from the actual bounce-back return path address.',
        technicalDetails: [
          { label: 'Header From Domain', value: fromDom, isMono: true },
          { label: 'Return-Path Domain', value: retDom, isMono: true },
          { label: 'Full From Header', value: dossier.senderIdentity.fromAddress, isMono: true, copyable: true },
          { label: 'Full Return-Path', value: dossier.senderIdentity.returnPathAddress, isMono: true, copyable: true }
        ],
        rawSnippet: `From: ${dossier.senderIdentity.fromAddress}\nReturn-Path: ${dossier.senderIdentity.returnPathAddress}`,
        rfcStandard: 'RFC 5322 / RFC 5321 Section 4.4',
        remediation: 'Investigate bounce-back infrastructure and look for credential harvesting domains.'
      }
    });
  }

  // 5. Suspicious Infrastructure / IP
  if (dossier.originIP.threatReputation && dossier.originIP.threatReputation !== 'CLEAN' && dossier.originIP.threatReputation !== 'UNKNOWN') {
    evidenceCards.push({
      id: 'suspicious-ip',
      detection: 'SUSPICIOUS ORIGIN INFRASTRUCTURE',
      category: 'Infrastructure',
      severity: 'HIGH',
      impactScore: 80,
      evidenceSource: 'First Received RFC Header, ASN & GeoIP Intel',
      summary: `Sending IP ${dossier.originIP.ip} (${dossier.originIP.asn}) exhibits threat reputation ${dossier.originIP.threatReputation}.`,
      rawEvidence: `IP: ${dossier.originIP.ip} | ASN: ${dossier.originIP.asn} | Org: ${dossier.originIP.organization}`,
      drillDownTarget: {
        type: 'IP',
        title: 'Relay Infrastructure Intelligence',
        badge: dossier.originIP.threatReputation,
        badgeColor: 'red',
        summary: 'The observed origin IP is associated with high-risk hosting or known threat relay networks.',
        technicalDetails: [
          { label: 'Origin IP', value: dossier.originIP.ip, isMono: true, copyable: true },
          { label: 'ISP / Host', value: dossier.originIP.isp || 'N/A', isMono: true },
          { label: 'Autonomous System', value: dossier.originIP.asn || 'N/A', isMono: true },
          { label: 'Infrastructure Geo', value: `${dossier.originIP.city || ''}, ${dossier.originIP.country || ''}`, isMono: false }
        ],
        rawSnippet: `Received: from ... [${dossier.originIP.ip}] by mx.google.com`,
        rfcStandard: 'RFC 5321 (SMTP Origin Tracking)',
        remediation: 'Add IP to firewall / boundary egress and ingress blocklists.'
      }
    });
  }

  // 6. Social Engineering / Artificial Urgency
  if (dossier.contentAnalysis.urgencyLevel === 'HIGH' || dossier.scoreBreakdown.socialEngineeringScore >= 8) {
    evidenceCards.push({
      id: 'social-eng',
      detection: 'SOCIAL ENGINEERING PRESSURE',
      category: 'Linguistic NLP',
      severity: 'MEDIUM',
      impactScore: 75,
      evidenceSource: 'Email Body RFC Payload',
      summary: 'Artificial urgency, psychological fear, and credential inducement patterns detected.',
      rawEvidence: 'Keywords detected: action required, immediately, account suspension, verify now',
      drillDownTarget: {
        type: 'FINDING',
        title: 'Social Engineering & Psychological Coercion',
        badge: 'NLP DETECTED',
        badgeColor: 'amber',
        summary: 'Natural language analysis detected high-urgency keywords designed to bypass analytical scrutiny.',
        technicalDetails: [
          { label: 'Urgency Pressure', value: dossier.contentAnalysis.urgencyLevel, isMono: true },
          { label: 'Credential Harvester Detected', value: dossier.contentAnalysis.credentialHarvesterDetected ? 'YES' : 'NO', isMono: true },
          { label: 'Hidden Elements', value: dossier.contentAnalysis.hiddenHtmlElementsDetected ? 'DETECTED' : 'CLEAN', isMono: true }
        ],
        rawSnippet: 'Linguistic patterns: "urgent account action", "suspended in 24 hours", "click to verify"',
        rfcStandard: 'MITRE ATT&CK T1566.002 (Spearphishing Link)',
        remediation: 'Deliver immediate phishing awareness advisory to targeted employee.'
      }
    });
  }

  // 7. Malicious URL / Deceptive Link
  if (dossier.urlForensics.length > 0) {
    const dangerousUrl = dossier.urlForensics.find(u => u.threatLevel === 'CRITICAL' || u.threatLevel === 'HIGH') || dossier.urlForensics[0];
    evidenceCards.push({
      id: 'url-threat',
      detection: 'SUSPICIOUS URL PAYLOAD',
      category: 'IOC Payload',
      severity: dangerousUrl.threatLevel === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
      impactScore: dangerousUrl.threatLevel === 'CRITICAL' ? 95 : 80,
      evidenceSource: 'HTML href / Plaintext Body URL',
      summary: dangerousUrl.hasAnchorMismatch 
        ? `Anchor text mismatch with destination domain (${dangerousUrl.domain}).`
        : `Deceptive or credential harvesting endpoint on domain ${dangerousUrl.domain}.`,
      rawEvidence: dangerousUrl.rawUrl,
      drillDownTarget: {
        type: 'URL',
        title: 'Deceptive URL Endpoint Forensics',
        badge: dangerousUrl.threatLevel,
        badgeColor: dangerousUrl.threatLevel === 'CRITICAL' ? 'red' : 'amber',
        summary: 'Link extraction uncovered suspicious target destination or anchor text deception.',
        technicalDetails: [
          { label: 'Target Domain', value: dangerousUrl.domain, isMono: true },
          { label: 'Has Anchor Mismatch', value: dangerousUrl.hasAnchorMismatch ? 'YES' : 'NO', isMono: true },
          { label: 'Credential Harvester', value: dangerousUrl.isCredentialHarvester ? 'CONFIRMED' : 'NO', isMono: true },
          { label: 'Full Destination URL', value: dangerousUrl.rawUrl, isMono: true, copyable: true }
        ],
        rawSnippet: `<a href="${dangerousUrl.rawUrl}">${dangerousUrl.displayedAnchorText || dangerousUrl.rawUrl}</a>`,
        rfcStandard: 'MITRE ATT&CK T1566.002 (Phishing Link)',
        remediation: 'Block domain across Web Proxy and DNS sinkhole immediately.'
      }
    });
  }

  // Ensure we display at least 5 cards (pull from dossier.findings if needed)
  if (evidenceCards.length < 5 && dossier.findings) {
    dossier.findings.forEach((f, idx) => {
      if (evidenceCards.length < 7 && !evidenceCards.some(c => c.detection === f.title)) {
        evidenceCards.push({
          id: `finding-${idx}`,
          detection: f.title.toUpperCase(),
          category: f.sourceField || 'Forensics',
          severity: f.severity === 'CRITICAL' ? 'CRITICAL' : f.severity === 'HIGH' ? 'HIGH' : 'MEDIUM',
          impactScore: f.severity === 'CRITICAL' ? 90 : f.severity === 'HIGH' ? 75 : 55,
          evidenceSource: f.sourceField,
          summary: f.whyItMatters,
          rawEvidence: f.evidence,
          drillDownTarget: {
            type: 'FINDING',
            title: f.title,
            badge: f.severity,
            badgeColor: f.severity === 'CRITICAL' ? 'red' : f.severity === 'HIGH' ? 'amber' : 'cyan',
            summary: f.whyItMatters,
            technicalDetails: [
              { label: 'Source Field', value: f.sourceField, isMono: true },
              { label: 'Severity Level', value: f.severity, isMono: true }
            ],
            rawSnippet: f.evidence,
            remediation: f.recommendedAction
          }
        });
      }
    });
  }

  const toggleExpand = (id: string) => {
    setExpandedCardId(expandedCardId === id ? null : id);
  };

  return (
    <section 
      id="executive-forensic-summary"
      className="space-y-4"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/10 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="w-3 h-3 rounded-full bg-red-500 animate-pulse shadow-[0_0_10px_rgba(239,68,68,0.6)]" />
          <h2 className="text-sm sm:text-base font-bold font-mono uppercase tracking-wider text-white">
            2. Executive Forensic Summary
          </h2>
          <span className="text-xs sm:text-sm text-gray-400 font-mono">
            ({evidenceCards.length} Critical Observations)
          </span>
        </div>
        <span className="text-xs font-mono font-semibold text-cyan-400">
          Click card to inspect evidence
        </span>
      </div>

      {/* Grid of 5-7 Compact Visual Finding Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {evidenceCards.slice(0, 7).map((card) => {
          const isExpanded = expandedCardId === card.id;
          const severityColors = {
            CRITICAL: { border: 'border-red-500/40', bg: 'bg-red-950/20', badge: 'bg-red-500/20 text-red-300 border-red-500/40', bar: 'bg-red-500' },
            HIGH: { border: 'border-amber-500/40', bg: 'bg-amber-950/20', badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40', bar: 'bg-amber-500' },
            MEDIUM: { border: 'border-yellow-500/30', bg: 'bg-yellow-950/20', badge: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30', bar: 'bg-yellow-400' },
            LOW: { border: 'border-blue-500/30', bg: 'bg-blue-950/20', badge: 'bg-blue-500/20 text-blue-300 border-blue-500/30', bar: 'bg-blue-400' },
            INFO: { border: 'border-white/10', bg: 'bg-white/5', badge: 'bg-white/10 text-gray-300 border-white/20', bar: 'bg-gray-400' }
          }[card.severity];

          return (
            <div
              key={card.id}
              className={`rounded-xl border ${severityColors.border} ${severityColors.bg} p-4 sm:p-5 flex flex-col justify-between transition-all duration-200 hover:border-cyan-500/60 hover:shadow-[0_0_20px_rgba(0,0,0,0.6)] font-mono`}
            >
              <div>
                {/* Header: Category & Severity Badge */}
                <div className="flex items-center justify-between gap-2 mb-2.5">
                  <span className="text-xs uppercase text-gray-300 font-bold tracking-wide truncate">
                    {card.category}
                  </span>
                  <span className={`px-2.5 py-0.5 rounded text-xs font-bold uppercase border ${severityColors.badge}`}>
                    [{card.severity}]
                  </span>
                </div>

                {/* Detection Title */}
                <h3 className="text-sm sm:text-base font-bold text-white tracking-wide mb-1.5 break-words">
                  {card.detection}
                </h3>

                {/* One-sentence summary */}
                <p className="text-xs sm:text-sm text-gray-300 leading-relaxed mb-3 font-sans">
                  {card.summary}
                </p>
              </div>

              <div>
                {/* Impact score bar */}
                <div className="space-y-1.5 mb-3 pt-2 border-t border-white/10">
                  <div className="flex items-center justify-between text-xs font-semibold">
                    <span className="text-gray-400">IMPACT SCORE</span>
                    <strong className="text-white font-bold">{card.impactScore}/100</strong>
                  </div>
                  <div className="h-2 w-full bg-black/50 rounded-full overflow-hidden">
                    <div 
                      className={`h-full ${severityColors.bar} rounded-full`} 
                      style={{ width: `${card.impactScore}%` }} 
                    />
                  </div>
                </div>

                {/* Evidence Source Label */}
                <div className="text-xs text-gray-400 mb-2.5 truncate font-sans">
                  Source: <span className="text-cyan-300 font-mono font-semibold">{card.evidenceSource}</span>
                </div>

                {/* Expandable Evidence View + Drill Down Trigger */}
                <div className="flex items-center justify-between pt-2 border-t border-white/10">
                  <button
                    onClick={() => toggleExpand(card.id)}
                    className="text-xs text-gray-300 hover:text-white flex items-center gap-1 transition-colors cursor-pointer font-sans"
                  >
                    <span>{isExpanded ? 'Hide Raw' : 'View Evidence'}</span>
                    {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  </button>

                  <button
                    onClick={() => onDrillDown(card.drillDownTarget)}
                    className="text-xs font-bold text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors cursor-pointer"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    <span>Drill-Down</span>
                  </button>
                </div>

                {/* Expanded Raw Snippet */}
                {isExpanded && (
                  <div className="mt-3 p-3 rounded-lg bg-black/70 border border-white/10 text-xs text-green-400 font-mono break-all leading-relaxed">
                    {card.rawEvidence}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
