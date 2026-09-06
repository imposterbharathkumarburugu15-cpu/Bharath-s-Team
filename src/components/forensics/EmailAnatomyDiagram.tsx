import React, { useState } from 'react';
import { 
  Mail, ShieldCheck, ShieldAlert, AlertTriangle, HelpCircle, 
  Server, Globe, Link, Paperclip, FileText, CheckCircle2, 
  XCircle, CornerDownRight, Eye
} from 'lucide-react';
import { ForensicDossier } from '@/services/forensicsEngine';
import { DrillDownTarget } from './ForensicDrillDownModal';

interface EmailAnatomyDiagramProps {
  dossier: ForensicDossier;
  onDrillDown: (target: DrillDownTarget) => void;
}

type NodeStatus = 'PASS' | 'FAIL' | 'SUSPICIOUS' | 'UNKNOWN';

interface AnatomyNode {
  id: string;
  label: string;
  status: NodeStatus;
  value: string;
  description: string;
  drillDown: DrillDownTarget;
}

export function EmailAnatomyDiagram({ dossier, onDrillDown }: EmailAnatomyDiagramProps) {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  // Derive status for each anatomy node
  const fromStatus: NodeStatus = dossier.senderIdentity.inconsistencies.some(i => i.severity === 'CRITICAL' || i.severity === 'HIGH')
    ? 'FAIL'
    : 'PASS';

  const returnPathStatus: NodeStatus = (dossier.senderIdentity.fromDomain?.toLowerCase() !== dossier.senderIdentity.returnPathDomain?.toLowerCase())
    ? 'FAIL'
    : 'PASS';

  const spfStatus: NodeStatus = dossier.authentication.spf.status === 'PASS' 
    ? 'PASS' 
    : dossier.authentication.spf.status === 'FAIL' || dossier.authentication.spf.status === 'SOFTFAIL' 
      ? 'FAIL' 
      : 'UNKNOWN';

  const dkimStatus: NodeStatus = dossier.authentication.dkim.status === 'PASS'
    ? 'PASS'
    : dossier.authentication.dkim.status === 'FAIL' || dossier.authentication.dkim.status === 'NONE'
      ? 'FAIL'
      : 'UNKNOWN';

  const dmarcStatus: NodeStatus = dossier.authentication.dmarc.status === 'PASS'
    ? 'PASS'
    : dossier.authentication.dmarc.status === 'FAIL' || dossier.authentication.dmarc.alignmentStatus === 'UNALIGNED'
      ? 'FAIL'
      : 'UNKNOWN';

  const ipStatus: NodeStatus = dossier.originIP.threatReputation === 'MALICIOUS' || dossier.originIP.threatReputation === 'SUSPICIOUS'
    ? 'FAIL'
    : dossier.originIP.isPrivate ? 'UNKNOWN' : 'SUSPICIOUS';

  const domainStatus: NodeStatus = dossier.domainAnalysis?.senderDomain?.isTyposquat
    ? 'FAIL'
    : (dossier.domainAnalysis?.senderDomain?.isNewlyRegistered ? 'SUSPICIOUS' : 'PASS');

  const urlStatus: NodeStatus = dossier.urlForensics.some(u => u.threatLevel === 'CRITICAL')
    ? 'FAIL'
    : dossier.urlForensics.some(u => u.threatLevel === 'HIGH' || u.threatLevel === 'MEDIUM')
      ? 'SUSPICIOUS'
      : dossier.urlForensics.length === 0 ? 'PASS' : 'PASS';

  const attachmentStatus: NodeStatus = dossier.attachments && dossier.attachments.length > 0
    ? (dossier.attachments.some(a => a.isDangerousExtension || a.threatScore > 50) ? 'FAIL' : 'SUSPICIOUS')
    : 'PASS';

  const bodyStatus: NodeStatus = dossier.contentAnalysis.urgencyLevel === 'HIGH' || dossier.contentAnalysis.credentialHarvesterDetected
    ? 'FAIL'
    : 'PASS';

  const subjectStatus: NodeStatus = /urgent|verify|action|suspended|payment|invoice/i.test(dossier.headerFields.subject || '')
    ? 'SUSPICIOUS'
    : 'PASS';

  const messageIdStatus: NodeStatus = dossier.headerFields.messageId
    ? (dossier.senderIdentity.messageIdDomain && dossier.senderIdentity.fromDomain && !dossier.senderIdentity.messageIdDomain.includes(dossier.senderIdentity.fromDomain) ? 'SUSPICIOUS' : 'PASS')
    : 'UNKNOWN';

  const receivedStatus: NodeStatus = (dossier.relayReconstruction.anomalies && dossier.relayReconstruction.anomalies.length > 0)
    ? 'FAIL'
    : 'PASS';

  const nodes: AnatomyNode[] = [
    {
      id: 'FROM',
      label: 'FROM HEADER',
      status: fromStatus,
      value: dossier.senderIdentity.fromAddress || dossier.headerFields.from || 'N/A',
      description: 'Visible RFC 5322 claimed sender identity address.',
      drillDown: {
        type: 'NODE',
        title: 'RFC 5322 From: Header Inspection',
        badge: fromStatus,
        badgeColor: fromStatus === 'PASS' ? 'emerald' : 'red',
        summary: 'RFC 5322 Header From is the primary user-facing identity. In phishing, this domain is frequently spoofed or typosquatted.',
        technicalDetails: [
          { label: 'Claimed Address', value: dossier.senderIdentity.fromAddress, isMono: true, copyable: true },
          { label: 'Claimed Domain', value: dossier.senderIdentity.fromDomain, isMono: true }
        ],
        rawSnippet: `From: ${dossier.senderIdentity.fromAddress}`,
        rfcStandard: 'RFC 5322 Section 3.6.2 (Originator Fields)'
      }
    },
    {
      id: 'RETURN-PATH',
      label: 'RETURN-PATH',
      status: returnPathStatus,
      value: dossier.senderIdentity.returnPathAddress || 'N/A',
      description: 'Envelope bounce-back address (RFC 5321 MAIL FROM).',
      drillDown: {
        type: 'RETURN_PATH',
        title: 'Envelope Return-Path / MAIL FROM',
        badge: returnPathStatus,
        badgeColor: returnPathStatus === 'PASS' ? 'emerald' : 'red',
        summary: 'The Return-Path is where bounce notifications are directed. A domain mismatch with the From: header strongly indicates forged sender identity.',
        technicalDetails: [
          { label: 'Return-Path Address', value: dossier.senderIdentity.returnPathAddress, isMono: true, copyable: true },
          { label: 'Return-Path Domain', value: dossier.senderIdentity.returnPathDomain, isMono: true },
          { label: 'Aligned with From', value: returnPathStatus === 'PASS' ? 'YES' : 'MISMATCH', isMono: true }
        ],
        rawSnippet: `Return-Path: <${dossier.senderIdentity.returnPathAddress}>`,
        rfcStandard: 'RFC 5321 Section 4.4 (Trace Information)'
      }
    },
    {
      id: 'SPF',
      label: 'SPF POLICY',
      status: spfStatus,
      value: `${dossier.authentication.spf.status} (${dossier.authentication.spf.envelopeSenderDomain || 'N/A'})`,
      description: 'Domain authorization for relaying IP address.',
      drillDown: {
        type: 'SPF',
        title: 'SPF Authentication Evaluation',
        badge: spfStatus,
        badgeColor: spfStatus === 'PASS' ? 'emerald' : 'red',
        summary: dossier.authentication.spf.explanation || 'SPF checks if sending IP is authorized by the domain TXT records.',
        technicalDetails: [
          { label: 'Status', value: dossier.authentication.spf.status, isMono: true },
          { label: 'Sending IP', value: dossier.originIP.ip, isMono: true, copyable: true },
          { label: 'Domain', value: dossier.authentication.spf.envelopeSenderDomain || 'N/A', isMono: true }
        ],
        rawSnippet: dossier.authentication.spf.evidence,
        rfcStandard: 'RFC 7208'
      }
    },
    {
      id: 'DKIM',
      label: 'DKIM SIGNATURE',
      status: dkimStatus,
      value: `${dossier.authentication.dkim.status} (${dossier.authentication.dkim.signingDomain || 'NONE'})`,
      description: 'Cryptographic public-key digital message signature.',
      drillDown: {
        type: 'DKIM',
        title: 'DKIM Verification Record',
        badge: dkimStatus,
        badgeColor: dkimStatus === 'PASS' ? 'emerald' : 'red',
        summary: dossier.authentication.dkim.explanation,
        technicalDetails: [
          { label: 'Status', value: dossier.authentication.dkim.status, isMono: true },
          { label: 'Signing Domain', value: dossier.authentication.dkim.signingDomain || 'NONE', isMono: true }
        ],
        rawSnippet: dossier.headerFields.dkimSignature || 'No signature header',
        rfcStandard: 'RFC 6376'
      }
    },
    {
      id: 'DMARC',
      label: 'DMARC ALIGNMENT',
      status: dmarcStatus,
      value: `${dossier.authentication.dmarc.status} (p=${dossier.authentication.dmarc.policy || 'none'})`,
      description: 'Strict policy alignment connecting Header From to SPF/DKIM.',
      drillDown: {
        type: 'DMARC',
        title: 'DMARC Policy Alignment Check',
        badge: dmarcStatus,
        badgeColor: dmarcStatus === 'PASS' ? 'emerald' : 'red',
        summary: dossier.authentication.dmarc.explanation,
        technicalDetails: [
          { label: 'Status', value: dossier.authentication.dmarc.status, isMono: true },
          { label: 'Alignment', value: dossier.authentication.dmarc.alignmentStatus, isMono: true }
        ],
        rawSnippet: dossier.authentication.dmarc.evidence,
        rfcStandard: 'RFC 7489'
      }
    },
    {
      id: 'IP',
      label: 'RELAY ORIGIN IP',
      status: ipStatus,
      value: `${dossier.originIP.ip} (${dossier.originIP.country || 'Unknown'})`,
      description: 'First public hops infrastructure geolocation and ASN.',
      drillDown: {
        type: 'IP',
        title: 'Origin Host Infrastructure',
        badge: ipStatus,
        badgeColor: ipStatus === 'FAIL' ? 'red' : 'amber',
        summary: 'Earliest public relay IP in SMTP transmission chain.',
        technicalDetails: [
          { label: 'Origin IP', value: dossier.originIP.ip, isMono: true, copyable: true },
          { label: 'ASN', value: dossier.originIP.asn, isMono: true },
          { label: 'ISP', value: dossier.originIP.isp, isMono: true },
          { label: 'Location', value: `${dossier.originIP.city || ''} ${dossier.originIP.country || ''}`, isMono: false }
        ],
        rawSnippet: `Origin IP: ${dossier.originIP.ip} | ASN: ${dossier.originIP.asn}`,
        rfcStandard: 'RFC 5321'
      }
    },
    {
      id: 'DOMAIN',
      label: 'SENDER DOMAIN',
      status: domainStatus,
      value: dossier.senderIdentity.fromDomain || 'N/A',
      description: 'Registered domain age, registrar, and typosquatting risk.',
      drillDown: {
        type: 'NODE',
        title: 'Domain Infrastructure Intel',
        badge: domainStatus,
        badgeColor: domainStatus === 'PASS' ? 'emerald' : 'amber',
        summary: 'Domain registration intelligence and homoglyph inspection.',
        technicalDetails: [
          { label: 'Domain', value: dossier.senderIdentity.fromDomain, isMono: true },
          { label: 'Typosquat', value: dossier.domainAnalysis?.senderDomain?.isTyposquat ? 'DETECTED' : 'CLEAN', isMono: true }
        ],
        rawSnippet: `Domain: ${dossier.senderIdentity.fromDomain}`
      }
    },
    {
      id: 'URL',
      label: 'URL HYPERLINKS',
      status: urlStatus,
      value: `${dossier.urlForensics.length} Extracted Links`,
      description: 'Anchor mismatches, redirect chains, credential harvesters.',
      drillDown: {
        type: 'URL',
        title: 'Extracted Link Payload Forensics',
        badge: urlStatus,
        badgeColor: urlStatus === 'PASS' ? 'emerald' : 'red',
        summary: 'Extracted hyperlinks from message plaintext and HTML parts.',
        technicalDetails: [
          { label: 'Total Links', value: String(dossier.urlForensics.length), isMono: true },
          { label: 'High Risk Links', value: String(dossier.urlForensics.filter(u => u.threatLevel === 'CRITICAL' || u.threatLevel === 'HIGH').length), isMono: true }
        ],
        rawSnippet: dossier.urlForensics.map(u => u.rawUrl).join('\n')
      }
    },
    {
      id: 'ATTACHMENT',
      label: 'ATTACHMENTS',
      status: attachmentStatus,
      value: dossier.attachments && dossier.attachments.length > 0 ? `${dossier.attachments.length} Detected` : 'None (0)',
      description: 'MIME attachments, executable macros, and payload hashes.',
      drillDown: {
        type: 'NODE',
        title: 'Attachment Forensics',
        badge: attachmentStatus,
        badgeColor: attachmentStatus === 'PASS' ? 'emerald' : 'red',
        summary: 'Payload attachment detection and SHA-256 integrity inspection.',
        technicalDetails: [
          { label: 'Attachments Detected', value: String(dossier.attachments?.length || 0), isMono: true }
        ],
        rawSnippet: dossier.attachments?.map(a => `${a.filename} (${a.sha256Hash})`).join('\n') || 'No attachments in message'
      }
    },
    {
      id: 'BODY',
      label: 'BODY NLP / PAYLOAD',
      status: bodyStatus,
      value: `${dossier.contentAnalysis.urgencyLevel} Urgency`,
      description: 'Psychological pressure keywords, hidden HTML, evasion.',
      drillDown: {
        type: 'NODE',
        title: 'Linguistic NLP & Social Engineering',
        badge: bodyStatus,
        badgeColor: bodyStatus === 'PASS' ? 'emerald' : 'red',
        summary: 'Heuristic and natural language inspection of message body.',
        technicalDetails: [
          { label: 'Urgency Level', value: dossier.contentAnalysis.urgencyLevel, isMono: true },
          { label: 'Credential Request', value: dossier.contentAnalysis.credentialHarvesterDetected ? 'YES' : 'NO', isMono: true }
        ],
        rawSnippet: 'NLP Body Signal Analysis'
      }
    },
    {
      id: 'SUBJECT',
      label: 'SUBJECT LINE',
      status: subjectStatus,
      value: dossier.headerFields.subject || 'No Subject',
      description: 'Linguistic urgency and pretexting lures in subject.',
      drillDown: {
        type: 'NODE',
        title: 'RFC Subject Header Analysis',
        badge: subjectStatus,
        badgeColor: subjectStatus === 'PASS' ? 'emerald' : 'amber',
        summary: 'Evaluation of psychological triggers in RFC Subject header.',
        technicalDetails: [
          { label: 'Subject', value: dossier.headerFields.subject || 'N/A', isMono: true }
        ],
        rawSnippet: `Subject: ${dossier.headerFields.subject}`
      }
    },
    {
      id: 'MESSAGE-ID',
      label: 'MESSAGE-ID',
      status: messageIdStatus,
      value: dossier.headerFields.messageId ? `${dossier.headerFields.messageId.slice(0, 24)}...` : 'Missing',
      description: 'Unique message identifier and generator hostname.',
      drillDown: {
        type: 'NODE',
        title: 'Message-ID RFC Header Inspection',
        badge: messageIdStatus,
        badgeColor: messageIdStatus === 'PASS' ? 'emerald' : 'amber',
        summary: 'Message-ID provides origin MTA signature and uniqueness.',
        technicalDetails: [
          { label: 'Message-ID', value: dossier.headerFields.messageId || 'MISSING', isMono: true, copyable: true }
        ],
        rawSnippet: `Message-ID: ${dossier.headerFields.messageId}`
      }
    },
    {
      id: 'RECEIVED',
      label: 'RECEIVED TRACE',
      status: receivedStatus,
      value: `${dossier.relayReconstruction.hopCount} Hops Logged`,
      description: 'Multi-hop SMTP relay transmission route records.',
      drillDown: {
        type: 'NODE',
        title: 'Received Header Relay Reconstruction',
        badge: receivedStatus,
        badgeColor: receivedStatus === 'PASS' ? 'emerald' : 'red',
        summary: 'Reconstructed chronological hops from MTA Received: headers.',
        technicalDetails: [
          { label: 'Total Hop Count', value: String(dossier.relayReconstruction.hopCount), isMono: true },
          { label: 'Transit Anomalies', value: String(dossier.relayReconstruction.anomalies.length), isMono: true }
        ],
        rawSnippet: dossier.relayReconstruction.chronologicalHops.map(h => `Hop ${h.hopNumber}: ${h.sourceIP} -> ${h.destinationHostname}`).join('\n')
      }
    }
  ];

  const getStatusBadge = (status: NodeStatus) => {
    switch (status) {
      case 'PASS':
        return <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">PASS</span>;
      case 'FAIL':
        return <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-red-500/20 text-red-400 border border-red-500/30 animate-pulse">FAIL</span>;
      case 'SUSPICIOUS':
        return <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">SUSPICIOUS</span>;
      case 'UNKNOWN':
      default:
        return <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-gray-500/20 text-gray-400 border border-gray-500/30">UNKNOWN</span>;
    }
  };

  const getStatusBorder = (status: NodeStatus) => {
    switch (status) {
      case 'PASS': return 'border-emerald-500/40 hover:border-emerald-400';
      case 'FAIL': return 'border-red-500/50 hover:border-red-400 shadow-[0_0_12px_rgba(239,68,68,0.2)]';
      case 'SUSPICIOUS': return 'border-amber-500/40 hover:border-amber-400';
      case 'UNKNOWN': default: return 'border-white/10 hover:border-white/30';
    }
  };

  return (
    <section 
      id="email-forensic-anatomy-visualization"
      className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 shadow-2xl font-mono text-white space-y-4"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/10 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
            <h2 className="text-xs font-bold uppercase tracking-widest text-white">
              3. Email Forensic Anatomy Visualization
            </h2>
          </div>
          <p className="text-[11px] text-gray-400 font-sans mt-0.5">
            Holistic structural breakdown of RFC 5322 metadata and RFC 5321 envelope components. Click any node to drill down.
          </p>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-2 text-[10px]">
          <span className="flex items-center gap-1 text-emerald-400"><span className="w-2 h-2 rounded-full bg-emerald-500" /> PASS</span>
          <span className="flex items-center gap-1 text-amber-400"><span className="w-2 h-2 rounded-full bg-amber-500" /> SUSPICIOUS</span>
          <span className="flex items-center gap-1 text-red-400"><span className="w-2 h-2 rounded-full bg-red-500" /> FAIL</span>
          <span className="flex items-center gap-1 text-gray-400"><span className="w-2 h-2 rounded-full bg-gray-500" /> UNKNOWN</span>
        </div>
      </div>

      {/* Interactive Anatomy Tree Layout */}
      <div className="relative p-2 sm:p-4 bg-black/40 rounded-xl border border-white/5 overflow-x-auto">
        {/* Central EMAIL Hub Node */}
        <div className="flex justify-center mb-6">
          <div className="p-3 px-6 rounded-2xl bg-[#0e1626] border-2 border-cyan-400 shadow-[0_0_25px_rgba(0,245,255,0.3)] flex items-center gap-3 text-center">
            <div className="p-2 rounded-xl bg-cyan-500/20 text-cyan-300">
              <Mail className="w-6 h-6" />
            </div>
            <div className="text-left">
              <span className="text-[9px] uppercase tracking-widest text-cyan-400 font-bold block">
                ROOT INVESTIGATION OBJECT
              </span>
              <span className="text-sm font-black text-white tracking-wider">
                RFC 5322 EMAIL
              </span>
            </div>
          </div>
        </div>

        {/* 13 Connected Satellite Nodes Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
          {nodes.map((node) => (
            <div
              key={node.id}
              onClick={() => onDrillDown(node.drillDown)}
              onMouseEnter={() => setHoveredNode(node.id)}
              onMouseLeave={() => setHoveredNode(null)}
              className={`p-3 rounded-xl bg-[#0a0f1c] border ${getStatusBorder(node.status)} transition-all duration-200 cursor-pointer flex flex-col justify-between group hover:shadow-[0_0_15px_rgba(0,245,255,0.15)]`}
            >
              <div>
                <div className="flex items-center justify-between gap-1 mb-1.5">
                  <span className="text-[10px] font-bold text-gray-300 group-hover:text-cyan-300 transition-colors truncate">
                    {node.label}
                  </span>
                  {getStatusBadge(node.status)}
                </div>

                <div className="text-xs font-bold text-white truncate break-all mb-1 font-mono">
                  {node.value}
                </div>

                <p className="text-[10px] text-gray-400 font-sans leading-tight line-clamp-2">
                  {node.description}
                </p>
              </div>

              <div className="mt-2 pt-1.5 border-t border-white/5 flex items-center justify-between text-[9px] text-gray-500 group-hover:text-cyan-400">
                <span>Click to drill down</span>
                <Eye className="w-3 h-3" />
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
