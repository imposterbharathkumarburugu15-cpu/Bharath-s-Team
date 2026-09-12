import React, { useState, useMemo } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Search, 
  Filter, 
  Bot, 
  Clock, 
  User, 
  Globe, 
  Mail, 
  MessageSquare, 
  PhoneCall, 
  Network, 
  Lock, 
  ChevronRight, 
  X, 
  Copy, 
  Check, 
  Terminal, 
  Sparkles, 
  Zap, 
  Download, 
  RefreshCw,
  ExternalLink,
  Shield,
  Activity,
  CheckCircle2,
  Cpu
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useLanguage } from '@/contexts/LanguageContext';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from '@/lib/utils';

export interface AlertIncident {
  id: string;
  threat: string;
  category: 'SPEAR_PHISHING' | 'CREDENTIAL_HARVESTER' | 'BEC_FRAUD' | 'MALICIOUS_ATTACHMENT' | 'SMISHING' | 'REVERSE_TUNNEL' | 'VOICE_CLONE';
  channel: 'Email' | 'Web' | 'SMS' | 'Voice' | 'Network';
  score: number;
  source: string;
  sourceIp: string;
  user: string;
  targetDepartment: string;
  status: 'active' | 'investigating' | 'quarantined' | 'resolved';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  date: string;
  isoTimestamp: string;
  mitreTechnique: string;
  summary: string;
  iocs: {
    ip: string;
    domain: string;
    sha256?: string;
  };
  remediationSteps: string[];
}

const INITIAL_ALERTS: AlertIncident[] = [
  { 
    id: 'INC-2026-0891', 
    threat: 'Reverse Tunnel Credential Theft', 
    category: 'REVERSE_TUNNEL',
    channel: 'Web',
    score: 98, 
    source: 'https://auth-session-recovery.trycloudflare.com/sso', 
    sourceIp: '104.28.19.44 (Cloudflare Proxy)',
    user: 'cfo@company.com', 
    targetDepartment: 'Executive Leadership',
    status: 'quarantined', 
    severity: 'CRITICAL',
    date: '10 mins ago',
    isoTimestamp: new Date(Date.now() - 10 * 60000).toISOString(),
    mitreTechnique: 'T1566.002 (Phishing: Spearphishing Link)',
    summary: 'Adversary deployed Cloudflare Quick Tunnel to bypass perimeter URL firewalls and spoof Microsoft 365 Single Sign-On credentials.',
    iocs: {
      ip: '104.28.19.44',
      domain: 'auth-session-recovery.trycloudflare.com',
      sha256: '9f83a45c612e34b9d0e123456789abcdef0123456789abcdef0123456789abcdef'
    },
    remediationSteps: [
      'Isolated user browser session immediately via NeuroShield Guard extension',
      'Revoked existing Azure AD / Okta refresh tokens for cfo@company.com',
      'Pushed wildcard block for ephemeral *.trycloudflare.com endpoint'
    ]
  },
  { 
    id: 'INC-2026-0890', 
    threat: 'M365 OAuth Token Intercept', 
    category: 'CREDENTIAL_HARVESTER',
    channel: 'Email',
    score: 95, 
    source: 'http://login.microsoftonline.verification-doc.pages.dev', 
    sourceIp: '185.220.101.44 (Tor Exit Node)',
    user: 'sales-team@company.com', 
    targetDepartment: 'Commercial Sales',
    status: 'active', 
    severity: 'CRITICAL',
    date: '25 mins ago',
    isoTimestamp: new Date(Date.now() - 25 * 60000).toISOString(),
    mitreTechnique: 'T1556 (Modify Authentication Process)',
    summary: 'Lookalike Microsoft Cloudflare Worker hosting AitM (Adversary-in-the-Middle) proxy capturing session cookies and 2FA tokens in real time.',
    iocs: {
      ip: '185.220.101.44',
      domain: 'verification-doc.pages.dev'
    },
    remediationSteps: [
      'Auto-quarantine inbound lure from mailboxes',
      'Enforce FIDO2 WebAuthn requirement for high-risk accounts',
      'Submit domain takedown request to registrar'
    ]
  },
  { 
    id: 'INC-2026-0889', 
    threat: 'CEO Impersonation & Wire BEC', 
    category: 'BEC_FRAUD',
    channel: 'Email',
    score: 88, 
    source: 'ceo.corporate-exec@gmail.com', 
    sourceIp: '198.51.100.12 (Freemail MTA)',
    user: 'finance-ap@company.com', 
    targetDepartment: 'Accounts Payable',
    status: 'investigating', 
    severity: 'HIGH',
    date: '1 hr ago',
    isoTimestamp: new Date(Date.now() - 60 * 60000).toISOString(),
    mitreTechnique: 'T1656 (Impersonation)',
    summary: 'Executive display-name spoofing requesting $42,500 confidential escrow wire transfer bypassing dual authorization procedures.',
    iocs: {
      ip: '198.51.100.12',
      domain: 'gmail.com'
    },
    remediationSteps: [
      'Triggered voice verification policy with executive office',
      'Placed AP wire hold in ERP platform',
      'Flagged external sender domain baseline anomaly'
    ]
  },
  { 
    id: 'INC-2026-0888', 
    threat: 'Synthetic AI Voice Vishing', 
    category: 'VOICE_CLONE',
    channel: 'Voice',
    score: 92, 
    source: '+1 (415) 555-0199 (Spoofed Caller ID)', 
    sourceIp: '203.0.113.88 (SIP Trunk)',
    user: 'it-helpdesk@company.com', 
    targetDepartment: 'IT Security',
    status: 'quarantined', 
    severity: 'CRITICAL',
    date: '2 hrs ago',
    isoTimestamp: new Date(Date.now() - 120 * 60000).toISOString(),
    mitreTechnique: 'T1566 (Phishing: Voice Phishing)',
    summary: 'Acoustic neural clone detected with 91% synthetic score requesting urgent multi-factor authentication reset for privileged user.',
    iocs: {
      ip: '203.0.113.88',
      domain: 'sip-telecom-relay.net'
    },
    remediationSteps: [
      'In-call alert dispatched to IT analyst dashboard',
      'Denied password override request',
      'Logged acoustic deepfake fingerprint into global intelligence pool'
    ]
  },
  { 
    id: 'INC-2026-0887', 
    threat: 'Quishing QR Code Lure', 
    category: 'SPEAR_PHISHING',
    channel: 'Email',
    score: 84, 
    source: 'it-notice@authenticator-secure.net', 
    sourceIp: '194.26.29.112 (Bulletproof Hosting)',
    user: 'hr-benefits@company.com', 
    targetDepartment: 'Human Resources',
    status: 'resolved', 
    severity: 'HIGH',
    date: '4 hrs ago',
    isoTimestamp: new Date(Date.now() - 240 * 60000).toISOString(),
    mitreTechnique: 'T1204.001 (User Execution: Malicious Link)',
    summary: 'Embedded high-density QR code redirecting mobile device cameras to credential harvesting form to evade desktop email text scanners.',
    iocs: {
      ip: '194.26.29.112',
      domain: 'authenticator-secure.net'
    },
    remediationSteps: [
      'Computer vision neural OCR extracted embedded link',
      'Quarantined email across all enterprise mailboxes',
      'Updated mobile device management security policy'
    ]
  },
  { 
    id: 'INC-2026-0886', 
    threat: 'Smishing Banking OTP Bait', 
    category: 'SMISHING',
    channel: 'SMS',
    score: 76, 
    source: 'HDFC-ALERT / +1 (555) 019-2834', 
    sourceIp: '198.51.100.99 (SMS Gateway)',
    user: 'dev-lead (Mobile)', 
    targetDepartment: 'Engineering',
    status: 'resolved', 
    severity: 'MEDIUM',
    date: '8 hrs ago',
    isoTimestamp: new Date(Date.now() - 480 * 60000).toISOString(),
    mitreTechnique: 'T1598 (Phishing for Information)',
    summary: 'SMS urgent notification alleging account suspension with fraudulent PAN verification link soliciting NetBanking credentials.',
    iocs: {
      ip: '198.51.100.99',
      domain: 'hdfc-bank-verify.in'
    },
    remediationSteps: [
      'Mobile threat defense agent intercepted notification preview',
      'Blacklisted malicious URL domain',
      'Sent user educational micro-training prompt'
    ]
  }
];

export function Alerts() {
  const { t } = useLanguage();
  const [alerts, setAlerts] = useState<AlertIncident[]>(INITIAL_ALERTS);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'active' | 'investigating' | 'quarantined' | 'resolved'>('ALL');
  const [channelFilter, setChannelFilter] = useState<'ALL' | 'Email' | 'Web' | 'SMS' | 'Voice' | 'Network'>('ALL');
  
  const [selectedAlert, setSelectedAlert] = useState<AlertIncident | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [actionSuccessMessage, setActionSuccessMessage] = useState<string | null>(null);

  // Metrics computation
  const metrics = useMemo(() => {
    const total = alerts.length;
    const critical = alerts.filter(a => a.severity === 'CRITICAL' || a.score >= 90).length;
    const active = alerts.filter(a => a.status === 'active').length;
    const quarantined = alerts.filter(a => a.status === 'quarantined').length;
    return { total, critical, active, quarantined };
  }, [alerts]);

  // Filtered alerts
  const filteredAlerts = useMemo(() => {
    return alerts.filter(a => {
      const matchSearch = 
        a.id.toLowerCase().includes(searchTerm.toLowerCase()) || 
        a.source.toLowerCase().includes(searchTerm.toLowerCase()) ||
        a.threat.toLowerCase().includes(searchTerm.toLowerCase()) ||
        a.user.toLowerCase().includes(searchTerm.toLowerCase()) ||
        a.targetDepartment.toLowerCase().includes(searchTerm.toLowerCase());

      if (!matchSearch) return false;
      if (severityFilter !== 'ALL' && a.severity !== severityFilter) return false;
      if (statusFilter !== 'ALL' && a.status !== statusFilter) return false;
      if (channelFilter !== 'ALL' && a.channel !== channelFilter) return false;

      return true;
    });
  }, [alerts, searchTerm, severityFilter, statusFilter, channelFilter]);

  const handleCopyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(key);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleQuarantineAlert = (id: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: 'quarantined' } : a));
    if (selectedAlert && selectedAlert.id === id) {
      setSelectedAlert(prev => prev ? { ...prev, status: 'quarantined' } : null);
    }
    showToast(`Incident ${id} placed into automated SOC quarantine.`);
  };

  const handleResolveAlert = (id: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: 'resolved' } : a));
    if (selectedAlert && selectedAlert.id === id) {
      setSelectedAlert(prev => prev ? { ...prev, status: 'resolved' } : null);
    }
    showToast(`Incident ${id} marked as fully mitigated and resolved.`);
  };

  const handleAutoRemediateAll = () => {
    setAlerts(prev => prev.map(a => a.status === 'active' ? { ...a, status: 'quarantined' } : a));
    showToast('Autonomous SOC defense policy applied: All active threats quarantined.');
  };

  const showToast = (msg: string) => {
    setActionSuccessMessage(msg);
    setTimeout(() => setActionSuccessMessage(null), 3500);
  };

  const handleAskCopilot = (alert: AlertIncident, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    window.location.hash = 'copilot';
    window.dispatchEvent(new CustomEvent('neuroshield:navigate', { detail: 'copilot' }));
  };

  return (
    <div className="space-y-6 max-w-[1400px] mx-auto px-2 md:px-5 py-4 font-sans text-slate-100">
      {/* Toast Feedback */}
      {actionSuccessMessage && (
        <div className="fixed top-5 right-6 z-50 bg-[#091122]/95 border border-cyan-500/60 text-cyan-200 px-5 py-3.5 rounded-2xl shadow-[0_0_30px_rgba(6,182,212,0.35)] flex items-center gap-3 text-xs font-mono backdrop-blur-2xl animate-in fade-in slide-in-from-top-3">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
          <span className="font-semibold">{actionSuccessMessage}</span>
        </div>
      )}

      {/* =========================================================================
          HERO HEADER & SOC METRICS RIBBON
         ========================================================================= */}
      <div className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-[#0b1224] via-[#060a14] to-[#0d172e] border border-cyan-500/20 shadow-[0_0_50px_rgba(0,0,0,0.8)] p-6 md:p-8 backdrop-blur-2xl">
        <div className="absolute -top-24 -right-24 w-96 h-96 bg-cyan-500/10 rounded-full blur-[100px] pointer-events-none" />
        <div className="absolute -bottom-24 -left-24 w-96 h-96 bg-rose-500/10 rounded-full blur-[100px] pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6 relative z-10">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs font-semibold tracking-wider uppercase">
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Real-Time Incident Triage & Automated Quarantine</span>
            </div>
            <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight text-white font-mono flex items-center gap-3">
              <span>SECURITY INCIDENT RESPONSE CENTER</span>
            </h1>
            <p className="text-xs md:text-sm text-slate-300 max-w-2xl leading-relaxed">
              Consolidated multi-channel telemetry of intercepted phishing attacks, credential harvesting lures, and social engineering campaigns requiring SOC analyst oversight.
            </p>
          </div>

          {/* Quick Global Action */}
          <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
            <Button
              onClick={handleAutoRemediateAll}
              variant="cyber"
              size="default"
              className="gap-2"
            >
              <Zap className="w-4 h-4 text-slate-950 fill-slate-950" />
              <span>AUTO-REMEDIATE ACTIVE ({metrics.active})</span>
            </Button>
          </div>
        </div>

        {/* 4 Metrics Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-6 mt-6 border-t border-slate-800/80 font-mono">
          <div className="p-3.5 rounded-2xl bg-slate-900/60 border border-slate-800/80 flex flex-col">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider">Total Intercepts</span>
            <span className="text-2xl font-bold text-white mt-1">{metrics.total}</span>
            <span className="text-[10px] text-cyan-400 mt-0.5">Multi-channel Telemetry</span>
          </div>
          <div className="p-3.5 rounded-2xl bg-slate-900/60 border border-rose-500/30 flex flex-col">
            <span className="text-[10px] text-rose-300/80 uppercase tracking-wider">Critical Severity</span>
            <span className="text-2xl font-bold text-rose-400 mt-1">{metrics.critical}</span>
            <span className="text-[10px] text-rose-300 mt-0.5">CVSS &ge; 90 / Zero-Day</span>
          </div>
          <div className="p-3.5 rounded-2xl bg-slate-900/60 border border-amber-500/30 flex flex-col">
            <span className="text-[10px] text-amber-300/80 uppercase tracking-wider">Active Triage</span>
            <span className="text-2xl font-bold text-amber-400 mt-1">{metrics.active}</span>
            <span className="text-[10px] text-amber-300 mt-0.5">Awaiting Verification</span>
          </div>
          <div className="p-3.5 rounded-2xl bg-slate-900/60 border border-emerald-500/30 flex flex-col">
            <span className="text-[10px] text-emerald-300/80 uppercase tracking-wider">Quarantined / Safe</span>
            <span className="text-2xl font-bold text-emerald-400 mt-1">{metrics.quarantined}</span>
            <span className="text-[10px] text-emerald-300 mt-0.5">100% Contained</span>
          </div>
        </div>
      </div>

      {/* =========================================================================
          FILTER BAR & SEARCH CONTROLS
         ========================================================================= */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-[#080e1b]/90 border border-slate-800 p-4 rounded-2xl shadow-xl">
        {/* Search */}
        <div className="relative w-full lg:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Filter by ID, domain, target, technique..."
            className="w-full bg-slate-900/90 border border-slate-800 rounded-xl pl-10 pr-3 py-2 text-xs text-slate-200 outline-none focus:border-cyan-500 font-mono transition"
          />
        </div>

        {/* Severity Filters */}
        <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
          <span className="text-slate-400 text-[10px] uppercase font-bold mr-1">Severity:</span>
          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={cn(
                "px-2.5 py-1.5 rounded-lg transition-all cursor-pointer font-bold",
                severityFilter === sev
                  ? sev === 'CRITICAL' ? "bg-rose-500 text-slate-950 shadow-md shadow-rose-950/40"
                    : sev === 'HIGH' ? "bg-amber-500 text-slate-950 shadow-md shadow-amber-950/40"
                    : "bg-cyan-500 text-slate-950 shadow-md shadow-cyan-950/40"
                  : "bg-slate-900/80 text-slate-400 hover:text-slate-200 border border-slate-800"
              )}
            >
              {sev}
            </button>
          ))}
        </div>

        {/* Status Filters */}
        <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
          <span className="text-slate-400 text-[10px] uppercase font-bold mr-1">Status:</span>
          {(['ALL', 'active', 'quarantined', 'investigating', 'resolved'] as const).map(st => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={cn(
                "px-2.5 py-1.5 rounded-lg transition-all cursor-pointer font-bold capitalize",
                statusFilter === st
                  ? "bg-slate-700 text-white border border-slate-600 shadow-md"
                  : "bg-slate-900/80 text-slate-400 hover:text-slate-200 border border-slate-800"
              )}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* =========================================================================
          INCIDENTS DATA TABLE
         ========================================================================= */}
      <div className="rounded-3xl bg-[#080e1b]/95 border border-slate-800 shadow-2xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs whitespace-nowrap font-mono">
            <thead className="bg-[#050a16] border-b border-slate-800 text-slate-400 text-[11px] uppercase">
              <tr>
                <th className="px-5 py-4 font-bold">Incident ID</th>
                <th className="px-5 py-4 font-bold">Threat &amp; Channel</th>
                <th className="px-5 py-4 font-bold">Risk Score</th>
                <th className="px-5 py-4 font-bold">Source Indicator / Origin</th>
                <th className="px-5 py-4 font-bold">Targeted User</th>
                <th className="px-5 py-4 font-bold">Status</th>
                <th className="px-5 py-4 font-bold text-right">SOC Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-slate-500 font-mono">
                    <ShieldCheck className="w-8 h-8 text-emerald-400/40 mx-auto mb-2" />
                    <p className="text-sm text-slate-400 font-bold">No matching incidents found</p>
                    <p className="text-xs text-slate-500">All defense parameters within nominal threshold.</p>
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => {
                  const isCritical = alert.severity === 'CRITICAL' || alert.score >= 90;
                  const isHigh = alert.severity === 'HIGH' || alert.score >= 80;

                  return (
                    <tr
                      key={alert.id}
                      onClick={() => setSelectedAlert(alert)}
                      className={cn(
                        "hover:bg-cyan-950/20 transition-colors cursor-pointer group",
                        selectedAlert?.id === alert.id ? "bg-cyan-950/30 border-l-4 border-l-cyan-400" : ""
                      )}
                    >
                      {/* ID */}
                      <td className="px-5 py-4">
                        <div className="flex items-center gap-2">
                          <span className="text-cyan-300 font-bold group-hover:text-cyan-200">
                            {alert.id}
                          </span>
                          <span className="text-[10px] text-slate-500">({alert.date})</span>
                        </div>
                      </td>

                      {/* Threat & Channel */}
                      <td className="px-5 py-4">
                        <div className="space-y-0.5">
                          <div className="font-bold text-white flex items-center gap-1.5">
                            {alert.channel === 'Email' && <Mail className="w-3.5 h-3.5 text-emerald-400" />}
                            {alert.channel === 'Web' && <Globe className="w-3.5 h-3.5 text-cyan-400" />}
                            {alert.channel === 'SMS' && <MessageSquare className="w-3.5 h-3.5 text-amber-400" />}
                            {alert.channel === 'Voice' && <PhoneCall className="w-3.5 h-3.5 text-purple-400" />}
                            {alert.channel === 'Network' && <Network className="w-3.5 h-3.5 text-sky-400" />}
                            <span>{alert.threat}</span>
                          </div>
                          <div className="text-[10px] text-slate-400">
                            {alert.mitreTechnique}
                          </div>
                        </div>
                      </td>

                      {/* Score Gauge */}
                      <td className="px-5 py-4">
                        <div className="flex items-center gap-2.5">
                          <div className="w-16 h-2 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                            <div
                              className={cn(
                                "h-full rounded-full",
                                isCritical ? "bg-rose-500 shadow-[0_0_10px_rgba(244,63,94,0.6)]" 
                                  : isHigh ? "bg-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.6)]" 
                                  : "bg-cyan-500"
                              )}
                              style={{ width: `${alert.score}%` }}
                            />
                          </div>
                          <span className={cn(
                            "font-bold text-xs",
                            isCritical ? "text-rose-400" : isHigh ? "text-amber-400" : "text-cyan-400"
                          )}>
                            {alert.score}
                          </span>
                        </div>
                      </td>

                      {/* Source Indicator */}
                      <td className="px-5 py-4 text-slate-300 max-w-xs truncate" title={alert.source}>
                        <span className="text-slate-200 block truncate">{alert.source}</span>
                        <span className="text-[10px] text-slate-500 block truncate">{alert.sourceIp}</span>
                      </td>

                      {/* Targeted User */}
                      <td className="px-5 py-4">
                        <div className="space-y-0.5">
                          <span className="text-slate-200 font-bold block">{alert.user}</span>
                          <span className="text-[10px] text-slate-400 block">{alert.targetDepartment}</span>
                        </div>
                      </td>

                      {/* Status Badge */}
                      <td className="px-5 py-4">
                        <span className={cn(
                          "px-2.5 py-1 rounded-full text-[10px] font-extrabold uppercase border",
                          alert.status === 'quarantined' ? "bg-emerald-950/60 text-emerald-300 border-emerald-500/40"
                            : alert.status === 'active' ? "bg-rose-950/60 text-rose-300 border-rose-500/40 animate-pulse"
                            : alert.status === 'investigating' ? "bg-amber-950/60 text-amber-300 border-amber-500/40"
                            : "bg-slate-800/80 text-slate-400 border-slate-700"
                        )}>
                          {alert.status}
                        </span>
                      </td>

                      {/* Actions */}
                      <td className="px-5 py-4 text-right">
                        <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                          {alert.status === 'active' ? (
                            <Button
                              onClick={(e) => handleQuarantineAlert(alert.id, e)}
                              variant="danger"
                              size="xs"
                            >
                              Quarantine
                            </Button>
                          ) : (
                            <Button
                              onClick={() => setSelectedAlert(alert)}
                              variant="outline"
                              size="xs"
                            >
                              Details
                            </Button>
                          )}
                          <Button
                            onClick={(e) => handleAskCopilot(alert, e)}
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            title="Ask AI SOC Copilot"
                          >
                            <Bot className="w-3.5 h-3.5 text-cyan-400" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* =========================================================================
          SLIDE-OUT INCIDENT INVESTIGATION DRAWER
         ========================================================================= */}
      <AnimatePresence>
        {selectedAlert && (
          <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex justify-end">
            <motion.div
              initial={{ opacity: 0, x: 400 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 400 }}
              transition={{ duration: 0.25, ease: 'easeOut' }}
              className="w-full max-w-xl h-full bg-[#070c18] border-l border-cyan-500/30 shadow-2xl p-6 flex flex-col justify-between overflow-y-auto custom-scrollbar font-mono text-xs"
            >
              <div className="space-y-6">
                {/* Header */}
                <div className="flex items-start justify-between border-b border-slate-800 pb-4">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 text-[10px] font-bold">
                        {selectedAlert.channel.toUpperCase()} VECTOR
                      </span>
                      <span className="text-slate-400 text-[10px]">{selectedAlert.date}</span>
                    </div>
                    <h2 className="text-xl font-bold text-white">{selectedAlert.threat}</h2>
                    <span className="text-cyan-400 text-xs font-bold">{selectedAlert.id}</span>
                  </div>
                  <button
                    onClick={() => setSelectedAlert(null)}
                    className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                {/* Score & Verdict Banner */}
                <div className="p-4 rounded-2xl bg-gradient-to-r from-rose-950/40 via-[#0a1020] to-slate-900 border border-rose-500/30 flex items-center justify-between">
                  <div className="space-y-1">
                    <span className="text-[10px] text-rose-300 uppercase font-bold block">Threat Assessment</span>
                    <div className="text-base font-bold text-white flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-rose-400" />
                      <span>{selectedAlert.severity} SEVERITY</span>
                    </div>
                    <span className="text-[10px] text-slate-400 block">{selectedAlert.mitreTechnique}</span>
                  </div>
                  <div className="text-right">
                    <span className="text-3xl font-black text-rose-400">{selectedAlert.score}</span>
                    <span className="text-[10px] text-slate-400 block">/ 100 Risk</span>
                  </div>
                </div>

                {/* Summary */}
                <div className="space-y-2">
                  <span className="text-[11px] text-slate-400 uppercase font-bold flex items-center gap-1.5">
                    <Activity className="w-3.5 h-3.5 text-cyan-400" />
                    Executive Forensic Summary
                  </span>
                  <p className="text-slate-200 bg-slate-900/80 p-3.5 rounded-xl border border-slate-800/80 leading-relaxed">
                    {selectedAlert.summary}
                  </p>
                </div>

                {/* Target & Source Grid */}
                <div className="grid grid-cols-2 gap-3">
                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
                    <span className="text-[10px] text-slate-500 uppercase">Target Identity</span>
                    <span className="text-white font-bold block truncate">{selectedAlert.user}</span>
                    <span className="text-[10px] text-slate-400 block">{selectedAlert.targetDepartment}</span>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
                    <span className="text-[10px] text-slate-500 uppercase">Origin Gateway / IP</span>
                    <span className="text-cyan-300 font-bold block truncate">{selectedAlert.sourceIp}</span>
                    <span className="text-[10px] text-slate-400 block truncate">{selectedAlert.source}</span>
                  </div>
                </div>

                {/* Extracted IOCs */}
                <div className="space-y-2">
                  <span className="text-[11px] text-slate-400 uppercase font-bold flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-purple-400" />
                    Extracted Indicators of Compromise (IOCs)
                  </span>
                  <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Target Domain:</span>
                      <div className="flex items-center gap-1.5">
                        <span className="text-cyan-300 font-bold">{selectedAlert.iocs.domain}</span>
                        <button
                          onClick={() => handleCopyText(selectedAlert.iocs.domain, 'dom')}
                          className="text-slate-500 hover:text-cyan-300 cursor-pointer"
                        >
                          {copiedField === 'dom' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Origin IP:</span>
                      <div className="flex items-center gap-1.5">
                        <span className="text-amber-300 font-bold">{selectedAlert.iocs.ip}</span>
                        <button
                          onClick={() => handleCopyText(selectedAlert.iocs.ip, 'ip')}
                          className="text-slate-500 hover:text-amber-300 cursor-pointer"
                        >
                          {copiedField === 'ip' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>
                    </div>
                    {selectedAlert.iocs.sha256 && (
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">SHA-256 Hash:</span>
                        <div className="flex items-center gap-1.5">
                          <span className="text-purple-300 text-[10px] truncate max-w-[200px]">{selectedAlert.iocs.sha256}</span>
                          <button
                            onClick={() => handleCopyText(selectedAlert.iocs.sha256!, 'sha')}
                            className="text-slate-500 hover:text-purple-300 cursor-pointer"
                          >
                            {copiedField === 'sha' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Remediation Playbook */}
                <div className="space-y-2">
                  <span className="text-[11px] text-slate-400 uppercase font-bold flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                    Recommended SOC Remediation Steps
                  </span>
                  <div className="space-y-1.5">
                    {selectedAlert.remediationSteps.map((step, idx) => (
                      <div key={idx} className="flex items-start gap-2 p-2 rounded-lg bg-emerald-950/20 border border-emerald-500/20 text-slate-300">
                        <span className="w-4 h-4 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5">
                          {idx + 1}
                        </span>
                        <span className="leading-relaxed">{step}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Drawer Bottom Actions */}
              <div className="pt-6 border-t border-slate-800 flex items-center justify-between gap-3 mt-6">
                <Button
                  onClick={() => handleAskCopilot(selectedAlert)}
                  variant="outline"
                  size="default"
                  className="gap-2 flex-1"
                >
                  <Bot className="w-4 h-4 text-cyan-400" />
                  <span>Deep AI Forensic Triage</span>
                </Button>

                {selectedAlert.status !== 'resolved' ? (
                  <Button
                    onClick={() => handleResolveAlert(selectedAlert.id)}
                    variant="emerald"
                    size="default"
                    className="gap-2 flex-1"
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Resolve Incident</span>
                  </Button>
                ) : (
                  <Button
                    onClick={() => handleQuarantineAlert(selectedAlert.id)}
                    variant="danger"
                    size="default"
                    className="gap-2 flex-1"
                  >
                    <Lock className="w-4 h-4" />
                    <span>Re-Quarantine</span>
                  </Button>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}

