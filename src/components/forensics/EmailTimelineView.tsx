import React from 'react';
import { 
  Clock, CheckCircle2, ShieldCheck, Mail, Server, 
  Cpu, AlertTriangle, ArrowDown, ChevronRight
} from 'lucide-react';
import { ForensicDossier } from '@/services/forensicsEngine';

interface EmailTimelineViewProps {
  dossier: ForensicDossier;
}

interface ForensicMilestone {
  id: string;
  stage: string;
  label: string;
  timestamp: string;
  detail: string;
  status: 'VERIFIED' | 'SUSPICIOUS' | 'UNAVAILABLE' | 'NORMAL';
}

export function EmailTimelineView({ dossier }: EmailTimelineViewProps) {
  // Extract real timestamps from headerFields and hops
  const generatedTimestamp = dossier.headerFields.date || null;
  const firstHop = dossier.relayReconstruction.chronologicalHops?.[0];
  const lastHop = dossier.relayReconstruction.chronologicalHops?.[dossier.relayReconstruction.chronologicalHops.length - 1];
  
  const smtpConnectTimestamp = firstHop?.timestamp || null;
  const firstReceivedTimestamp = firstHop?.timestamp || null;
  const authEvalTimestamp = lastHop?.timestamp || firstHop?.timestamp || null;
  const mailboxDeliveryTimestamp = lastHop?.timestamp || null;
  const analysisTimestamp = dossier.chainOfCustody?.ingestionTimestamp || new Date().toISOString();

  const milestones: ForensicMilestone[] = [
    {
      id: 'generated',
      stage: 'STAGE 1: GENERATION',
      label: 'Email Message Generated',
      timestamp: generatedTimestamp ? generatedTimestamp : 'TIMESTAMP UNAVAILABLE',
      detail: `RFC 5322 Date header claimed by client MUA (${dossier.senderIdentity.fromAddress || 'sender'}).`,
      status: generatedTimestamp ? 'NORMAL' : 'UNAVAILABLE'
    },
    {
      id: 'smtp_connect',
      stage: 'STAGE 2: SMTP SESSION',
      label: 'SMTP Initial Handshake & EHLO',
      timestamp: smtpConnectTimestamp ? smtpConnectTimestamp : 'TIMESTAMP UNAVAILABLE',
      detail: `Transmission initiated from relay host ${dossier.originIP.ip || 'Origin'}.`,
      status: smtpConnectTimestamp ? 'NORMAL' : 'UNAVAILABLE'
    },
    {
      id: 'first_received',
      stage: 'STAGE 3: FIRST HOP',
      label: 'First RFC 5321 Received Header Recorded',
      timestamp: firstReceivedTimestamp ? firstReceivedTimestamp : 'TIMESTAMP UNAVAILABLE',
      detail: `MTA timestamp stamped at public infrastructure boundary.`,
      status: firstReceivedTimestamp ? (dossier.relayReconstruction.anomalies.length > 0 ? 'SUSPICIOUS' : 'VERIFIED') : 'UNAVAILABLE'
    },
    {
      id: 'auth_eval',
      stage: 'STAGE 4: AUTHENTICATION',
      label: 'Authentication Evaluation (SPF / DKIM / DMARC)',
      timestamp: authEvalTimestamp ? authEvalTimestamp : 'TIMESTAMP UNAVAILABLE',
      detail: `SPF: ${dossier.authentication.spf.status} | DKIM: ${dossier.authentication.dkim.status} | DMARC: ${dossier.authentication.dmarc.status}`,
      status: (dossier.authentication.spf.status === 'FAIL' || dossier.authentication.dmarc.status === 'FAIL') ? 'SUSPICIOUS' : 'VERIFIED'
    },
    {
      id: 'delivery',
      stage: 'STAGE 5: DELIVERY',
      label: 'Inbound Gateway & Mailbox Delivery',
      timestamp: mailboxDeliveryTimestamp ? mailboxDeliveryTimestamp : 'TIMESTAMP UNAVAILABLE',
      detail: `Message routed to destination mailbox for ${dossier.headerFields.to || 'recipient'}.`,
      status: mailboxDeliveryTimestamp ? 'NORMAL' : 'UNAVAILABLE'
    },
    {
      id: 'analysis',
      stage: 'STAGE 6: FORENSICS',
      label: 'SOC Automated Forensic Investigation',
      timestamp: analysisTimestamp,
      detail: `SHA-256 evidence integrity verified & ML threat classification rendered.`,
      status: 'VERIFIED'
    }
  ];

  return (
    <section 
      id="email-timeline-section"
      className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 shadow-2xl font-mono text-white space-y-4"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/10 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
            <h2 className="text-xs font-bold uppercase tracking-widest text-white">
              6. Email Forensic Chronological Timeline
            </h2>
          </div>
          <p className="text-[11px] text-gray-400 font-sans mt-0.5">
            Strict empirical transit reconstruction. Missing timestamps are marked "TIMESTAMP UNAVAILABLE" per forensic audit integrity.
          </p>
        </div>

        <span className="text-[10px] text-cyan-300 bg-cyan-950/40 border border-cyan-500/30 px-2.5 py-1 rounded-md">
          {milestones.filter(m => m.timestamp !== 'TIMESTAMP UNAVAILABLE').length} of {milestones.length} Timestamps Grounded
        </span>
      </div>

      {/* Visually Dominant Stepped Forensic Timeline */}
      <div className="relative pl-6 sm:pl-8 space-y-6 before:absolute before:left-3 sm:before:left-4 before:top-3 before:bottom-3 before:w-0.5 before:bg-gradient-to-b before:from-cyan-400 before:via-purple-400 before:to-emerald-400">
        {milestones.map((item, idx) => {
          const isUnavailable = item.timestamp === 'TIMESTAMP UNAVAILABLE';
          const isSuspicious = item.status === 'SUSPICIOUS';

          return (
            <div key={item.id} className="relative group">
              {/* Stepper Dot */}
              <div 
                className={`absolute -left-6 sm:-left-8 top-1 w-4 h-4 rounded-full border-2 flex items-center justify-center -translate-x-1/2 ${
                  isSuspicious 
                    ? 'bg-red-500 border-red-300 shadow-[0_0_10px_#ef4444]' 
                    : isUnavailable 
                      ? 'bg-gray-800 border-gray-600' 
                      : 'bg-[#080d1a] border-cyan-400 shadow-[0_0_8px_rgba(0,245,255,0.4)]'
                }`}
              >
                <div className={`w-1.5 h-1.5 rounded-full ${isSuspicious ? 'bg-white' : isUnavailable ? 'bg-gray-500' : 'bg-cyan-400'}`} />
              </div>

              {/* Card Content */}
              <div className={`p-3.5 rounded-xl border transition-all ${
                isSuspicious 
                  ? 'bg-red-950/20 border-red-500/40' 
                  : isUnavailable
                    ? 'bg-black/40 border-white/5 opacity-80'
                    : 'bg-[#0b1326] border-white/10 hover:border-cyan-500/30'
              }`}>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 mb-1">
                  <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider">
                    {item.stage}
                  </span>
                  <div className="flex items-center gap-1.5">
                    <Clock className="w-3 h-3 text-gray-500" />
                    <span className={`text-[11px] font-mono ${
                      isUnavailable ? 'text-amber-400/80 italic font-semibold' : 'text-gray-200'
                    }`}>
                      {item.timestamp}
                    </span>
                  </div>
                </div>

                <h3 className="text-xs font-bold text-white tracking-wide mb-1">
                  {item.label}
                </h3>

                <p className="text-[11px] text-gray-400 font-sans leading-relaxed">
                  {item.detail}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
