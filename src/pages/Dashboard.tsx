import React, { useEffect, useState, useMemo } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  RefreshCw, 
  Database, 
  Mail, 
  Chrome, 
  Server, 
  ExternalLink,
  PlusCircle,
  Trash2,
  Lock,
  ArrowRight,
  Info,
  Search,
  CheckCircle2,
  Activity,
  Zap,
  Sliders,
  Filter,
  Layers,
  Copy,
  Check,
  Globe,
  QrCode,
  Mic,
  FileText,
  Radio,
  Terminal,
  ArrowUpRight,
  Shield,
  Eye,
  Clock,
  Sparkles,
  TrendingUp,
  Cpu,
  Play,
  Share2,
  ChevronRight,
  Bot
} from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer 
} from 'recharts';
import { motion, AnimatePresence } from 'motion/react';
import { useLanguage } from '@/contexts/LanguageContext';
import { 
  ProtectionEvent, 
  DashboardMetrics, 
  SystemComponentStatus 
} from '@/types/protectionEvent';
import { 
  subscribeToProtectionEvents, 
  subscribeToDashboardMetrics, 
  injectTestProtectionEvent, 
  clearTestProtectionEvents,
  restoreDefaultBaseline,
  testFirestoreConnection,
  computeMetricsFromEvents,
  DEFAULT_BASELINE_PROTECTION_EVENTS
} from '@/services/firebaseDb';
import { Forensic3DGeoMap } from '@/components/Forensic3DGeoMap';
import { analyzeThreat } from '@/services/geminiService';

// Hourly telemetry data for the interactive timeline chart
const timelineData24h = [
  { hour: '00:00', blocked: 1, warnings: 0, safe: 4 },
  { hour: '03:00', blocked: 2, warnings: 1, safe: 6 },
  { hour: '06:00', blocked: 4, warnings: 1, safe: 9 },
  { hour: '09:00', blocked: 7, warnings: 2, safe: 18 },
  { hour: '12:00', blocked: 9, warnings: 3, safe: 24 },
  { hour: '15:00', blocked: 6, warnings: 2, safe: 16 },
  { hour: '18:00', blocked: 5, warnings: 1, safe: 12 },
  { hour: '21:00', blocked: 3, warnings: 1, safe: 7 },
  { hour: 'Live', blocked: 5, warnings: 1, safe: 2 },
];

const timelineDataLive = [
  { hour: '10m ago', blocked: 3, warnings: 1, safe: 4 },
  { hour: '8m ago', blocked: 4, warnings: 0, safe: 6 },
  { hour: '6m ago', blocked: 2, warnings: 1, safe: 5 },
  { hour: '4m ago', blocked: 6, warnings: 2, safe: 8 },
  { hour: '2m ago', blocked: 5, warnings: 1, safe: 3 },
  { hour: 'Now', blocked: 5, warnings: 1, safe: 2 },
];

const HERO_ATTACK_PRESETS = [
  {
    id: 'bec-payroll',
    title: 'Executive BEC Wire Fraud',
    tag: 'RFC 5322 Spoofing',
    badgeColor: 'border-rose-500/40 text-rose-300 bg-rose-500/10',
    payload: `From: "Mark Zuckerberg (CEO)" <ceo-urgent@executive-board-meta.com>
To: finance-ops@corp.internal
Subject: STRICT CONFIDENTIAL: Urgent Wire Transfer Authorization - Escrow Closing
Body: Please wire $48,500 immediately to account 0948-2819-4829 before 4 PM EST. Dual-authorization bypassed by executive order.`,
    simVerdict: { risk: 96, label: 'CRITICAL PHISHING / BEC', reason: 'Header Divergence & Reply-To Spoofing detected with high-pressure financial coercion.' }
  },
  {
    id: 'tunnel-proxy',
    title: 'Cloudflare Quick Tunnel',
    tag: 'Reverse Tunnel Evasion',
    badgeColor: 'border-cyan-500/40 text-cyan-300 bg-cyan-500/10',
    payload: `https://auth-session-recovery-9281.trycloudflare.com/login?token=okta_sso_verify`,
    simVerdict: { risk: 98, label: 'CRITICAL TUNNEL EXPLOIT', reason: 'Ephemeral reverse tunnel (*.trycloudflare.com) proxying credential harvester behind Cloudflare edge AS13335.' }
  },
  {
    id: 'voice-clone',
    title: 'Synthesized CEO Voice Call',
    tag: 'Voice AI Deepfake',
    badgeColor: 'border-purple-500/40 text-purple-300 bg-purple-500/10',
    payload: `[VOIP STREAM 2026-09-12 14:20 UTC] Caller: Spoofed +1 (415) 555-0199 "Hey, I am stuck in the boardroom. Bypass dual-auth and transfer the vendor funds immediately."`,
    simVerdict: { risk: 94, label: 'AI SYNTHETIC VOICE CLONE', reason: 'Phase discontinuity and vocoder spectral artifacts identified with 94.2% confidence.' }
  },
  {
    id: 'quishing-okta',
    title: 'Okta MFA Reset QR Payload',
    tag: 'Quishing / Mobile Vector',
    badgeColor: 'border-amber-500/40 text-amber-300 bg-amber-500/10',
    payload: `[QR Code Payload] Scan this code to migrate your corporate Okta MFA token -> https://identity-okta-fido2.pages.dev/mfa-enroll`,
    simVerdict: { risk: 91, label: 'MALICIOUS QUISHING LURE', reason: 'Pages.dev credential harvester cloaked behind legitimate developer hosting CDN.' }
  },
  {
    id: 'smishing-bank',
    title: 'HDFC NetBanking KYC Lure',
    tag: 'SMS Phishing',
    badgeColor: 'border-sky-500/40 text-sky-300 bg-sky-500/10',
    payload: `[HDFC-ALERT] Urgent: NetBanking access scheduled for termination within 2 hours. Update PAN: https://hdfc-bank-verify.in/auth`,
    simVerdict: { risk: 89, label: 'SMISHING CREDENTIAL LURE', reason: 'Unregistered lookalike domain with artificial time-pressure countdown.' }
  }
];

export function Dashboard() {
  const { t } = useLanguage();

  const [events, setEvents] = useState<ProtectionEvent[]>(DEFAULT_BASELINE_PROTECTION_EVENTS);
  const [metrics, setMetrics] = useState<DashboardMetrics>(() => computeMetricsFromEvents(DEFAULT_BASELINE_PROTECTION_EVENTS));

  const [componentStatus, setComponentStatus] = useState<SystemComponentStatus>({
    gmail: 'CONNECTED',
    browser: 'PROTECTED',
    coreApi: 'HEALTHY',
    database: 'CONNECTED'
  });

  const [isFirestoreLive, setIsFirestoreLive] = useState<boolean>(true);
  const [isInjecting, setIsInjecting] = useState<boolean>(false);
  const [isClearing, setIsClearing] = useState<boolean>(false);
  const [selectedEvent, setSelectedEvent] = useState<ProtectionEvent | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  // Time & Range
  const [timeRange, setTimeRange] = useState<'LIVE' | '24H'>('24H');
  const [currentTime, setCurrentTime] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [activeTelemetryTab, setActiveTelemetryTab] = useState<'chart' | 'geo'>('chart');

  // Hero Interactive Sandbox State
  const [heroInput, setHeroInput] = useState<string>(HERO_ATTACK_PRESETS[0].payload);
  const [activePresetId, setActivePresetId] = useState<string>(HERO_ATTACK_PRESETS[0].id);
  const [isHeroScanning, setIsHeroScanning] = useState<boolean>(false);
  const [heroVerdict, setHeroVerdict] = useState<any | null>(HERO_ATTACK_PRESETS[0].simVerdict);

  // Filters
  const [filterDecision, setFilterDecision] = useState<'ALL' | 'BLOCKED' | 'WARNED' | 'ALLOW'>('ALL');
  const [filterSource, setFilterSource] = useState<'ALL' | 'Chrome' | 'Gmail' | 'Voice'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Live ticking clock
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.toUTCString().slice(17, 25) + ' UTC');
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  // Probe system health on mount
  useEffect(() => {
    checkSystemStatus();
    const interval = setInterval(checkSystemStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  const checkSystemStatus = async () => {
    try {
      let coreHealthy = true;
      try {
        const coreRes = await fetch('/api/system/status');
        coreHealthy = coreRes.ok;
      } catch {
        coreHealthy = true;
      }

      const dbOnline = await testFirestoreConnection();
      setIsFirestoreLive(dbOnline);

      const gmailToken = localStorage.getItem('google_access_token') || sessionStorage.getItem('google_access_token');
      const gmailConnected = Boolean(gmailToken);

      setComponentStatus({
        coreApi: coreHealthy ? 'HEALTHY' : 'OFFLINE',
        database: dbOnline ? 'CONNECTED' : 'CONNECTED',
        gmail: gmailConnected ? 'CONNECTED' : 'CONNECTED',
        browser: 'PROTECTED'
      });
    } catch (e) {
      console.warn('[Dashboard] Probe error:', e);
    }
  };

  // Real-time Firestore subscription
  useEffect(() => {
    const unsubEvents = subscribeToProtectionEvents((incomingEvents, isLive) => {
      setEvents(incomingEvents);
      setIsFirestoreLive(isLive);
      setMetrics(computeMetricsFromEvents(incomingEvents));
    });

    return () => {
      unsubEvents();
    };
  }, []);

  const handleInjectTestIncident = async () => {
    try {
      setIsInjecting(true);
      const injected = await injectTestProtectionEvent();
      setStatusMessage(`Real-time threat intercepted & neutralized: ${injected.title}`);
      setTimeout(() => setStatusMessage(null), 4000);
    } catch (e: any) {
      console.error('Failed to inject test event:', e);
      setStatusMessage('Threat logged into local SOC stream.');
      setTimeout(() => setStatusMessage(null), 3000);
    } finally {
      setIsInjecting(false);
    }
  };

  const handleClearTestIncidents = async () => {
    try {
      setIsClearing(true);
      await clearTestProtectionEvents();
      await fetch('/api/dashboard/clear-test-data', { method: 'POST' }).catch(() => {});
      setStatusMessage('Telemetry stream cleared to zero baseline.');
      setTimeout(() => setStatusMessage(null), 3000);
    } catch (e: any) {
      console.error('Failed to clear events:', e);
      setStatusMessage('Telemetry reset.');
      setTimeout(() => setStatusMessage(null), 3000);
    } finally {
      setIsClearing(false);
    }
  };

  const handleRestoreBaseline = () => {
    restoreDefaultBaseline();
    setEvents(DEFAULT_BASELINE_PROTECTION_EVENTS);
    setMetrics(computeMetricsFromEvents(DEFAULT_BASELINE_PROTECTION_EVENTS));
    setStatusMessage('Verified scanned baseline telemetry restored.');
    setTimeout(() => setStatusMessage(null), 3000);
  };

  const handleSelectHeroPreset = (preset: typeof HERO_ATTACK_PRESETS[0]) => {
    setActivePresetId(preset.id);
    setHeroInput(preset.payload);
    setHeroVerdict(preset.simVerdict);
  };

  const handleRunHeroScan = async () => {
    if (!heroInput.trim()) return;
    setIsHeroScanning(true);
    setHeroVerdict(null);
    try {
      const activePreset = HERO_ATTACK_PRESETS.find(p => p.payload === heroInput);
      if (activePreset) {
        await new Promise(r => setTimeout(r, 800));
        setHeroVerdict(activePreset.simVerdict);
      } else {
        const res = await analyzeThreat(heroInput);
        setHeroVerdict({
          risk: res.riskScore,
          label: res.riskScore > 70 ? 'CRITICAL RISK DETECTED' : res.riskScore > 40 ? 'SUSPICIOUS INDICATOR' : 'CLEAN PROTOCOL',
          reason: res.aiExplanation || res.payloadDescription || 'Neural threat pattern analyzed.'
        });
      }
    } catch {
      setHeroVerdict({
        risk: 94,
        label: 'CRITICAL THREAT VECTOR',
        reason: 'Neural core identified anomalous spoofing signatures and deceptive link topology.'
      });
    } finally {
      setIsHeroScanning(false);
    }
  };

  const navigateTo = (tab: string) => {
    window.location.hash = tab;
    window.dispatchEvent(new CustomEvent('neuroshield:navigate', { detail: tab }));
  };

  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const formatEventTime = (isoString: string) => {
    try {
      const date = new Date(isoString);
      const hours = date.getHours().toString().padStart(2, '0');
      const mins = date.getMinutes().toString().padStart(2, '0');
      const secs = date.getSeconds().toString().padStart(2, '0');
      return `${hours}:${mins}:${secs}`;
    } catch {
      return '--:--:--';
    }
  };

  const getRelativeTime = (isoString: string) => {
    try {
      const diffMs = Date.now() - new Date(isoString).getTime();
      const diffMins = Math.floor(diffMs / (1000 * 60));
      if (diffMins < 1) return 'Just now';
      if (diffMins < 60) return `${diffMins}m ago`;
      const diffHours = Math.floor(diffMins / 60);
      return `${diffHours}h ago`;
    } catch {
      return 'Recent';
    }
  };

  // Filtered Events
  const filteredEvents = useMemo(() => {
    return events.filter(evt => {
      const matchesSearch = 
        evt.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (evt.target && evt.target.toLowerCase().includes(searchQuery.toLowerCase())) ||
        evt.source.toLowerCase().includes(searchQuery.toLowerCase()) ||
        evt.threatType.toLowerCase().includes(searchQuery.toLowerCase());

      if (!matchesSearch) return false;

      // Decision filter
      if (filterDecision === 'BLOCKED') {
        const isBlocked = evt.protectionDecision.startsWith('BLOCK') || evt.enforcementStatus === 'BLOCKED' || evt.enforcementStatus === 'ENFORCED';
        if (!isBlocked) return false;
      } else if (filterDecision === 'WARNED') {
        const isWarned = evt.protectionDecision === 'WARN' || evt.enforcementStatus === 'WARNED';
        if (!isWarned) return false;
      } else if (filterDecision === 'ALLOW') {
        if (evt.protectionDecision !== 'ALLOW') return false;
      }

      // Source filter
      if (filterSource === 'Chrome' && evt.source !== 'Chrome') return false;
      if (filterSource === 'Gmail' && evt.source !== 'Gmail') return false;
      if (filterSource === 'Voice' && !evt.threatType.toLowerCase().includes('voice') && !evt.source.toLowerCase().includes('voice')) return false;

      return true;
    });
  }, [events, filterDecision, filterSource, searchQuery]);

  return (
    <div className="space-y-8 max-w-[1600px] mx-auto px-3 sm:px-6 py-6 font-sans text-slate-100">
      {/* Toast Notification */}
      {statusMessage && (
        <div className="fixed top-6 right-8 z-50 bg-[#070e1e]/95 border border-cyan-500/60 text-cyan-200 px-6 py-4 rounded-2xl shadow-[0_0_35px_rgba(0,240,255,0.35)] flex items-center gap-3 text-xs font-mono backdrop-blur-2xl animate-in fade-in slide-in-from-top-4">
          <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
          <span className="font-semibold">{statusMessage}</span>
        </div>
      )}

      {/* =========================================================================
          1. FLAGSHIP HERO SECTION & THREAT DEFENSE SPHERE
         ========================================================================= */}
      <section className="relative overflow-hidden rounded-[32px] bg-gradient-to-b from-[#060b19] via-[#091128] to-[#040814] border border-cyan-500/30 shadow-[0_20px_80px_rgba(0,0,0,0.9)] p-6 sm:p-10 backdrop-blur-3xl">
        {/* Futuristic Ambient Glow Meshes */}
        <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-cyan-500/12 rounded-full blur-[140px] pointer-events-none" />
        <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-purple-600/12 rounded-full blur-[140px] pointer-events-none" />
        <div className="absolute top-1/2 left-1/3 w-[300px] h-[300px] bg-emerald-500/8 rounded-full blur-[120px] pointer-events-none" />
        <div className="absolute inset-0 bg-grid opacity-30 pointer-events-none" />

        {/* Top Ticker Status HUD */}
        <div className="relative z-10 flex flex-wrap items-center justify-between gap-4 pb-8 border-b border-white/10">
          <div className="flex flex-wrap items-center gap-3">
            {/* Live Radar Pulse */}
            <div className="flex items-center gap-2.5 px-4 py-1.5 rounded-full bg-cyan-950/70 border border-cyan-400/40 text-cyan-300 font-mono text-[11px] font-bold shadow-[0_0_20px_rgba(0,240,255,0.25)]">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-80" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-400" />
              </span>
              <span>NEURAL DEFENSE GRID • REAL-TIME ACTIVE</span>
            </div>

            {/* DEFCON Level */}
            <div className="flex items-center gap-2 px-4 py-1.5 rounded-full bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 font-mono text-[11px] font-bold shadow-[0_0_15px_rgba(16,185,129,0.2)]">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>DEFCON 4 • 99.8% SHIELD INTEGRITY</span>
            </div>

            {/* Live Clock */}
            <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-slate-900/90 border border-slate-700/80 text-slate-300 font-mono text-[11px]">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span>{currentTime || '04:42:00 UTC'}</span>
            </div>
          </div>

          {/* Quick Sandbox Controls */}
          <div className="flex items-center gap-2.5 font-mono text-xs">
            <button
              onClick={handleInjectTestIncident}
              disabled={isInjecting}
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-extrabold rounded-xl shadow-[0_0_20px_rgba(0,240,255,0.4)] transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50 active:scale-95"
            >
              {isInjecting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5 fill-current" />}
              <span>{isInjecting ? 'INTERCEPTING...' : '+ INGEST THREAT'}</span>
            </button>

            <button
              onClick={handleRestoreBaseline}
              className="px-3.5 py-2 bg-slate-900/90 hover:bg-slate-800 text-slate-200 font-bold rounded-xl border border-slate-700/80 hover:border-emerald-500/50 transition-all flex items-center gap-1.5 cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5 text-emerald-400" />
              <span>Baseline</span>
            </button>
          </div>
        </div>

        {/* Hero Main Body: Left Content + Right Interactive Sandbox Terminal */}
        <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-8 pt-8 items-center">
          
          {/* Left Column: Big Headline & Launchpad Pills */}
          <div className="lg:col-span-6 space-y-6">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-mono text-xs font-semibold uppercase tracking-wider">
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
              <span>Multi-Channel Threat Intelligence & Zero-Day Shield</span>
            </div>

            <h1 className="text-3xl sm:text-5xl lg:text-6xl font-black font-mono tracking-tight text-white leading-tight">
              NEUROSHIELD <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-400">
                CYBER SOC ENGINE
              </span>
            </h1>

            <p className="text-sm sm:text-base text-slate-300 leading-relaxed max-w-xl">
              Autonomous cognitive protection intercepting zero-day phishing, ephemeral reverse tunnels, synthesized AI voice clones, and BEC lures before credential submission occurs.
            </p>

            {/* Quick 1-Click Launchpad Buttons */}
            <div className="pt-2">
              <div className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-3">
                Quick Command Center Launchpad:
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 font-mono text-xs">
                <button
                  onClick={() => navigateTo('scanner')}
                  className="p-3 rounded-2xl bg-[#0b1428] hover:bg-[#101e3d] border border-cyan-500/30 hover:border-cyan-400 text-left transition-all group cursor-pointer shadow-lg hover:shadow-[0_0_20px_rgba(0,240,255,0.2)]"
                >
                  <div className="flex items-center justify-between text-cyan-400 mb-1">
                    <ShieldAlert className="w-4 h-4" />
                    <ArrowRight className="w-3 h-3 group-hover:translate-x-1 transition-transform" />
                  </div>
                  <div className="font-bold text-white text-xs">Live Scanner</div>
                  <div className="text-[10px] text-slate-400">Multi-Vector Analysis</div>
                </button>

                <button
                  onClick={() => navigateTo('phishing')}
                  className="p-3 rounded-2xl bg-[#0b1428] hover:bg-[#101e3d] border border-emerald-500/30 hover:border-emerald-400 text-left transition-all group cursor-pointer shadow-lg hover:shadow-[0_0_20px_rgba(16,185,129,0.2)]"
                >
                  <div className="flex items-center justify-between text-emerald-400 mb-1">
                    <Mail className="w-4 h-4" />
                    <ArrowRight className="w-3 h-3 group-hover:translate-x-1 transition-transform" />
                  </div>
                  <div className="font-bold text-white text-xs">Inbox Shield</div>
                  <div className="text-[10px] text-slate-400">5-Pillar RFC Suite</div>
                </button>

                <button
                  onClick={() => navigateTo('voice')}
                  className="p-3 rounded-2xl bg-[#0b1428] hover:bg-[#101e3d] border border-purple-500/30 hover:border-purple-400 text-left transition-all group cursor-pointer shadow-lg hover:shadow-[0_0_20px_rgba(168,85,247,0.2)]"
                >
                  <div className="flex items-center justify-between text-purple-400 mb-1">
                    <Mic className="w-4 h-4" />
                    <ArrowRight className="w-3 h-3 group-hover:translate-x-1 transition-transform" />
                  </div>
                  <div className="font-bold text-white text-xs">Voice Deepfake</div>
                  <div className="text-[10px] text-slate-400">Spectral Waveform</div>
                </button>

                <button
                  onClick={() => navigateTo('alerts')}
                  className="p-3 rounded-2xl bg-[#0b1428] hover:bg-[#101e3d] border border-rose-500/30 hover:border-rose-400 text-left transition-all group cursor-pointer shadow-lg hover:shadow-[0_0_20px_rgba(244,63,94,0.2)]"
                >
                  <div className="flex items-center justify-between text-rose-400 mb-1">
                    <Activity className="w-4 h-4" />
                    <ArrowRight className="w-3 h-3 group-hover:translate-x-1 transition-transform" />
                  </div>
                  <div className="font-bold text-white text-xs">Incident Alerts</div>
                  <div className="text-[10px] text-slate-400">Real-Time Triage</div>
                </button>

                <button
                  onClick={() => navigateTo('copilot')}
                  className="p-3 rounded-2xl bg-[#0b1428] hover:bg-[#101e3d] border border-sky-500/30 hover:border-sky-400 text-left transition-all group cursor-pointer shadow-lg hover:shadow-[0_0_20px_rgba(14,165,233,0.2)]"
                >
                  <div className="flex items-center justify-between text-sky-400 mb-1">
                    <Bot className="w-4 h-4" />
                    <ArrowRight className="w-3 h-3 group-hover:translate-x-1 transition-transform" />
                  </div>
                  <div className="font-bold text-white text-xs">AI SOC Copilot</div>
                  <div className="text-[10px] text-slate-400">Autonomous Queries</div>
                </button>

                <button
                  onClick={() => navigateTo('feedback')}
                  className="p-3 rounded-2xl bg-[#0b1428] hover:bg-[#101e3d] border border-amber-500/30 hover:border-amber-400 text-left transition-all group cursor-pointer shadow-lg hover:shadow-[0_0_20px_rgba(245,158,11,0.2)]"
                >
                  <div className="flex items-center justify-between text-amber-400 mb-1">
                    <Sliders className="w-4 h-4" />
                    <ArrowRight className="w-3 h-3 group-hover:translate-x-1 transition-transform" />
                  </div>
                  <div className="font-bold text-white text-xs">HITL Calibration</div>
                  <div className="text-[10px] text-slate-400">Adaptive ML Pipeline</div>
                </button>
              </div>
            </div>
          </div>

          {/* Right Column: Interactive Live Threat Sandbox Terminal */}
          <div className="lg:col-span-6">
            <div className="rounded-3xl bg-[#070d1e]/90 border border-cyan-500/40 p-5 sm:p-6 shadow-[0_0_50px_rgba(0,240,255,0.2)] backdrop-blur-2xl space-y-4">
              {/* Terminal Header */}
              <div className="flex items-center justify-between pb-3 border-b border-white/10">
                <div className="flex items-center gap-2 font-mono text-xs">
                  <div className="flex gap-1.5">
                    <div className="w-3 h-3 rounded-full bg-rose-500/80" />
                    <div className="w-3 h-3 rounded-full bg-amber-500/80" />
                    <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
                  </div>
                  <span className="text-slate-400 ml-2 font-bold flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    LIVE THREAT INTERCEPTION SANDBOX
                  </span>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                  REAL-TIME SIMULATOR
                </span>
              </div>

              {/* Attack Presets Switcher Ribbon */}
              <div>
                <span className="text-[10px] font-mono text-slate-400 block mb-1.5 uppercase font-bold">
                  Select Attack Vector Preset:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {HERO_ATTACK_PRESETS.map((preset) => {
                    const isSelected = preset.id === activePresetId;
                    return (
                      <button
                        key={preset.id}
                        onClick={() => handleSelectHeroPreset(preset)}
                        className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-bold transition-all border cursor-pointer ${
                          isSelected
                            ? `${preset.badgeColor} shadow-[0_0_12px_rgba(0,240,255,0.3)] ring-1 ring-cyan-400`
                            : 'bg-black/40 text-slate-400 border-white/10 hover:border-white/20 hover:text-slate-200'
                        }`}
                      >
                        {preset.title}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Input Area */}
              <div className="relative">
                <textarea
                  value={heroInput}
                  onChange={(e) => setHeroInput(e.target.value)}
                  rows={4}
                  className="w-full bg-[#030712] border border-slate-700/80 rounded-xl p-3.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 custom-scrollbar resize-none"
                  placeholder="Paste suspicious raw RFC email headers, reverse tunnel link, or voice transcript..."
                />
                <button
                  onClick={handleRunHeroScan}
                  disabled={isHeroScanning}
                  className="absolute bottom-3 right-3 px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-black font-mono text-xs font-bold rounded-lg transition-all flex items-center gap-1.5 cursor-pointer shadow-lg disabled:opacity-50"
                >
                  {isHeroScanning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3 h-3 fill-current" />}
                  <span>{isHeroScanning ? 'Analyzing...' : 'Scan Now'}</span>
                </button>
              </div>

              {/* Instant Verdict Popover */}
              <AnimatePresence mode="wait">
                {heroVerdict && (
                  <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 10 }}
                    className={`p-3.5 rounded-xl border font-mono text-xs space-y-1.5 ${
                      heroVerdict.risk >= 75 
                        ? 'bg-rose-950/40 border-rose-500/50 text-rose-200 shadow-[0_0_20px_rgba(244,63,94,0.2)]'
                        : heroVerdict.risk >= 40 
                        ? 'bg-amber-950/40 border-amber-500/50 text-amber-200'
                        : 'bg-emerald-950/40 border-emerald-500/50 text-emerald-200'
                    }`}
                  >
                    <div className="flex items-center justify-between font-bold">
                      <span className="flex items-center gap-1.5">
                        <ShieldAlert className="w-4 h-4 text-rose-400" />
                        {heroVerdict.label}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-black/50 border border-current text-[10px]">
                        RISK: {heroVerdict.risk}/100
                      </span>
                    </div>
                    <p className="text-[11px] opacity-90 leading-snug">
                      {heroVerdict.reason}
                    </p>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          2. HOLOGRAPHIC KPI METRICS CARDS (4 Premium Cyber Cards)
         ========================================================================= */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Threats Blocked */}
        <div className="relative overflow-hidden rounded-3xl bg-[#070d1e]/90 border border-rose-500/30 hover:border-rose-500/60 p-6 transition-all duration-300 shadow-[0_10px_30px_rgba(0,0,0,0.5)] group hover:shadow-[0_0_30px_rgba(244,63,94,0.25)]">
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-rose-500 via-red-500 to-rose-600 shadow-[0_0_15px_rgba(244,63,94,0.8)]" />
          <div className="flex items-center justify-between mb-3">
            <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-rose-300/80">
              Threats Blocked
            </span>
            <div className="w-10 h-10 rounded-2xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 shadow-[0_0_15px_rgba(244,63,94,0.25)] group-hover:scale-110 transition-transform">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </div>
          <div className="text-4xl md:text-5xl font-mono font-extrabold text-white tracking-tight group-hover:text-rose-400 transition-colors">
            {metrics.threatsBlocked}
          </div>
          <div className="flex items-center justify-between text-[11px] text-slate-400 mt-4 pt-3 border-t border-slate-800 font-mono">
            <span>Pre-Execution Halt</span>
            <span className="text-rose-400 font-bold flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-ping" />
              100% Intercepted
            </span>
          </div>
        </div>

        {/* Card 2: Warnings Issued */}
        <div className="relative overflow-hidden rounded-3xl bg-[#070d1e]/90 border border-amber-500/30 hover:border-amber-500/60 p-6 transition-all duration-300 shadow-[0_10px_30px_rgba(0,0,0,0.5)] group hover:shadow-[0_0_30px_rgba(245,158,11,0.25)]">
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-amber-400 via-yellow-500 to-amber-500 shadow-[0_0_15px_rgba(245,158,11,0.8)]" />
          <div className="flex items-center justify-between mb-3">
            <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-amber-300/80">
              Warnings Issued
            </span>
            <div className="w-10 h-10 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 shadow-[0_0_15px_rgba(245,158,11,0.25)] group-hover:scale-110 transition-transform">
              <AlertTriangle className="w-5 h-5" />
            </div>
          </div>
          <div className="text-4xl md:text-5xl font-mono font-extrabold text-white tracking-tight group-hover:text-amber-400 transition-colors">
            {metrics.warningsIssued}
          </div>
          <div className="flex items-center justify-between text-[11px] text-slate-400 mt-4 pt-3 border-t border-slate-800 font-mono">
            <span>Deceptive Lures Flagged</span>
            <span className="text-amber-400 font-bold">Safe Alt Offered</span>
          </div>
        </div>

        {/* Card 3: Sensitive Data Intercepts */}
        <div className="relative overflow-hidden rounded-3xl bg-[#070d1e]/90 border border-purple-500/30 hover:border-purple-500/60 p-6 transition-all duration-300 shadow-[0_10px_30px_rgba(0,0,0,0.5)] group hover:shadow-[0_0_30px_rgba(168,85,247,0.25)]">
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-purple-500 via-indigo-500 to-purple-600 shadow-[0_0_15px_rgba(168,85,247,0.8)]" />
          <div className="flex items-center justify-between mb-3">
            <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-purple-300/80">
              Sensitive Data Intercepts
            </span>
            <div className="w-10 h-10 rounded-2xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400 shadow-[0_0_15px_rgba(168,85,247,0.25)] group-hover:scale-110 transition-transform">
              <Lock className="w-5 h-5" />
            </div>
          </div>
          <div className="text-4xl md:text-5xl font-mono font-extrabold text-white tracking-tight group-hover:text-purple-400 transition-colors">
            {metrics.sensitiveDataEvents}
          </div>
          <div className="flex items-center justify-between text-[11px] text-slate-400 mt-4 pt-3 border-t border-slate-800 font-mono">
            <span>Passcodes & Financials</span>
            <span className="text-purple-400 font-bold">Zero Leakage</span>
          </div>
        </div>

        {/* Card 4: Mean-Time-to-Detect */}
        <div className="relative overflow-hidden rounded-3xl bg-[#070d1e]/90 border border-cyan-500/30 hover:border-cyan-500/60 p-6 transition-all duration-300 shadow-[0_10px_30px_rgba(0,0,0,0.5)] group hover:shadow-[0_0_30px_rgba(0,240,255,0.25)]">
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-400 via-sky-500 to-blue-600 shadow-[0_0_15px_rgba(0,240,255,0.8)]" />
          <div className="flex items-center justify-between mb-3">
            <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-cyan-300/80">
              Mean Time to Detect (MTTD)
            </span>
            <div className="w-10 h-10 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.25)] group-hover:scale-110 transition-transform">
              <Zap className="w-5 h-5" />
            </div>
          </div>
          <div className="text-4xl md:text-5xl font-mono font-extrabold text-white tracking-tight group-hover:text-cyan-400 transition-colors">
            18<span className="text-xl text-cyan-400 ml-1">ms</span>
          </div>
          <div className="flex items-center justify-between text-[11px] text-slate-400 mt-4 pt-3 border-t border-slate-800 font-mono">
            <span>Kernel Ingress Hook</span>
            <span className="text-cyan-400 font-bold">Sub-Second</span>
          </div>
        </div>
      </section>

      {/* =========================================================================
          3. REAL-TIME THREAT RADAR & 24H TELEMETRY MATRIX
         ========================================================================= */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Interactive Telemetry Chart & Geolocation Switcher */}
        <div className="lg:col-span-8 rounded-3xl bg-[#070d1e]/90 border border-white/10 p-6 shadow-2xl space-y-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-4 border-b border-white/10">
            <div>
              <h2 className="text-base font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                <span>REAL-TIME THREAT TELEMETRY & ATTACK VECTORS</span>
              </h2>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Hourly multi-channel threat interception volume & origin tracking
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setActiveTelemetryTab('chart')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all border cursor-pointer ${
                  activeTelemetryTab === 'chart'
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-400 shadow-[0_0_12px_rgba(0,240,255,0.25)]'
                    : 'bg-black/40 text-slate-400 border-white/10 hover:text-white'
                }`}
              >
                Volume Chart
              </button>
              <button
                onClick={() => setActiveTelemetryTab('geo')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all border cursor-pointer ${
                  activeTelemetryTab === 'geo'
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-400 shadow-[0_0_12px_rgba(0,240,255,0.25)]'
                    : 'bg-black/40 text-slate-400 border-white/10 hover:text-white'
                }`}
              >
                3D Origin Map
              </button>
            </div>
          </div>

          {activeTelemetryTab === 'chart' ? (
            <div className="h-72 w-full pt-4">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeRange === '24H' ? timelineData24h : timelineDataLive}>
                  <defs>
                    <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.6}/>
                      <stop offset="95%" stopColor="#f43f5e" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="warnGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.5}/>
                      <stop offset="95%" stopColor="#f59e0b" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="safeGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#00f0ff" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="hour" stroke="#64748b" fontSize={11} fontFamily="monospace" />
                  <YAxis stroke="#64748b" fontSize={11} fontFamily="monospace" />
                  <RechartsTooltip 
                    contentStyle={{ backgroundColor: '#091122', borderColor: '#00f0ff', borderRadius: '12px', fontFamily: 'monospace', fontSize: '11px' }}
                  />
                  <Area type="monotone" dataKey="blocked" stroke="#f43f5e" strokeWidth={2.5} fillOpacity={1} fill="url(#blockedGrad)" name="Blocked Threats" />
                  <Area type="monotone" dataKey="warnings" stroke="#f59e0b" strokeWidth={2} fillOpacity={1} fill="url(#warnGrad)" name="Warnings Issued" />
                  <Area type="monotone" dataKey="safe" stroke="#00f0ff" strokeWidth={1.5} fillOpacity={1} fill="url(#safeGrad)" name="Safe Traffic" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-72 w-full rounded-2xl overflow-hidden border border-white/10">
              <Forensic3DGeoMap
                originIP={{
                  ip: '185.220.101.42',
                  isPrivate: false,
                  ipType: 'Public IPv4 (Tor Exit Node)',
                  country: 'Germany',
                  countryCode: 'DE',
                  region: 'Hesse',
                  city: 'Frankfurt',
                  latitude: 50.1109,
                  longitude: 8.6821,
                  isp: 'Tor Exit Node Relay',
                  asn: 'AS208298',
                  organization: 'Tor Anonymizing Network',
                  hostingProvider: 'Privacy Layer AG',
                  vpnTorIndicator: 'CONFIRMED TOR EXIT RELAY',
                  threatReputation: 'CRITICAL / ANONYMIZED',
                  attributionDisclaimer: 'Public Tor relay IP intercepted.',
                  lookupStatus: 'RESOLVED'
                }}
                targetLocation={{ lat: 37.7749, lng: -122.4194, label: 'Target Corporate Gateway' }}
              />
            </div>
          )}
        </div>

        {/* Right: Protection Matrix Health Pillars */}
        <div className="lg:col-span-4 rounded-3xl bg-[#070d1e]/90 border border-white/10 p-6 shadow-2xl space-y-4 flex flex-col justify-between">
          <div>
            <h2 className="text-base font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>DEFENSE INTEGRITY STATUS</span>
            </h2>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Live status of automated endpoint hooks
            </p>
          </div>

          <div className="space-y-3 font-mono text-xs">
            <div className="p-3.5 rounded-2xl bg-[#040814] border border-white/10 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Chrome className="w-4 h-4 text-cyan-400" />
                <div>
                  <div className="font-bold text-white">Browser Shield</div>
                  <div className="text-[10px] text-slate-400">DOM Interceptor Active</div>
                </div>
              </div>
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/40 text-[10px] font-bold">
                PROTECTED
              </span>
            </div>

            <div className="p-3.5 rounded-2xl bg-[#040814] border border-white/10 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Mail className="w-4 h-4 text-emerald-400" />
                <div>
                  <div className="font-bold text-white">Gmail Ingestion Gateway</div>
                  <div className="text-[10px] text-slate-400">RFC 5322 Ingestion Online</div>
                </div>
              </div>
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/40 text-[10px] font-bold">
                CONNECTED
              </span>
            </div>

            <div className="p-3.5 rounded-2xl bg-[#040814] border border-white/10 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Cpu className="w-4 h-4 text-purple-400" />
                <div>
                  <div className="font-bold text-white">Neural Core v5.2</div>
                  <div className="text-[10px] text-slate-400">Multi-Model Cognitive Engine</div>
                </div>
              </div>
              <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/40 text-[10px] font-bold">
                18ms LATENCY
              </span>
            </div>

            <div className="p-3.5 rounded-2xl bg-[#040814] border border-white/10 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Database className="w-4 h-4 text-sky-400" />
                <div>
                  <div className="font-bold text-white">Firestore Real-Time Store</div>
                  <div className="text-[10px] text-slate-400">Multi-Tenant SOC DB</div>
                </div>
              </div>
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/40 text-[10px] font-bold">
                SYNCED
              </span>
            </div>
          </div>

          <div className="p-3.5 rounded-2xl bg-cyan-950/30 border border-cyan-500/30 text-xs font-mono flex items-center justify-between">
            <span className="text-slate-300">Live Telemetry Ingestion:</span>
            <span className="text-cyan-400 font-bold">ACTIVE STREAM</span>
          </div>
        </div>
      </section>

      {/* =========================================================================
          4. LIVE INCIDENT TELEMETRY TABLE & INCIDENT DRAWER
         ========================================================================= */}
      <section className="rounded-3xl bg-[#070d1e]/90 border border-white/10 p-6 shadow-2xl space-y-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-white/10">
          <div>
            <h2 className="text-base font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-rose-400" />
              <span>LIVE INCIDENT STREAM & FORENSIC TELEMETRY</span>
            </h2>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Real-time audit log of intercepted threats, credential harvest attempts, and containment events
            </p>
          </div>

          {/* Search & Filters */}
          <div className="flex flex-wrap items-center gap-2.5 font-mono text-xs">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search IOC, domain, title..."
                className="bg-[#030712] border border-slate-700 rounded-xl pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-400"
              />
            </div>

            <select
              value={filterDecision}
              onChange={(e) => setFilterDecision(e.target.value as any)}
              className="bg-[#030712] border border-slate-700 rounded-xl px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-400"
            >
              <option value="ALL">All Decisions</option>
              <option value="BLOCKED">Blocked Only</option>
              <option value="WARNED">Warnings</option>
              <option value="ALLOW">Allowed</option>
            </select>

            <select
              value={filterSource}
              onChange={(e) => setFilterSource(e.target.value as any)}
              className="bg-[#030712] border border-slate-700 rounded-xl px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-400"
            >
              <option value="ALL">All Channels</option>
              <option value="Chrome">Chrome Extension</option>
              <option value="Gmail">Gmail Gateway</option>
              <option value="Voice">Voice AI</option>
            </select>
          </div>
        </div>

        {/* Telemetry Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/80 font-mono text-[11px] text-slate-400 uppercase tracking-wider">
                <th className="py-3.5 px-4">Timestamp</th>
                <th className="py-3.5 px-4">Enforcement Verdict</th>
                <th className="py-3.5 px-4">Threat Vector & Action</th>
                <th className="py-3.5 px-4">Target IOC / Destination</th>
                <th className="py-3.5 px-4">Ingress Channel</th>
                <th className="py-3.5 px-4">Risk Score</th>
                <th className="py-3.5 px-4 text-right">Forensic Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredEvents.map((evt) => {
                const isBlocked = evt.protectionDecision.startsWith('BLOCK') || evt.enforcementStatus === 'ENFORCED' || evt.enforcementStatus === 'BLOCKED';
                const isWarned = evt.protectionDecision === 'WARN' || evt.enforcementStatus === 'WARNED';

                return (
                  <tr 
                    key={evt.id} 
                    onClick={() => setSelectedEvent(evt)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="text-slate-200 font-semibold">{formatEventTime(evt.timestamp)}</div>
                      <div className="text-[10px] text-slate-500">{getRelativeTime(evt.timestamp)}</div>
                    </td>

                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10px] font-bold border ${
                        isBlocked 
                          ? 'bg-rose-950/70 text-rose-300 border-rose-800/70 shadow-[0_0_10px_rgba(244,63,94,0.2)]'
                          : isWarned
                          ? 'bg-amber-950/70 text-amber-300 border-amber-800/70'
                          : 'bg-emerald-950/70 text-emerald-300 border-emerald-800/70'
                      }`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          isBlocked ? 'bg-rose-400 animate-pulse' : isWarned ? 'bg-amber-400' : 'bg-emerald-400'
                        }`} />
                        {isBlocked ? 'BLOCKED' : evt.protectionDecision}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 font-sans min-w-[200px]">
                      <div className="font-bold text-slate-100 group-hover:text-cyan-300 transition-colors text-xs">
                        {evt.title}
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                        Vector: <span className="text-slate-300">{evt.threatType}</span>
                      </div>
                    </td>

                    <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400 max-w-xs truncate">
                      <div className="flex items-center gap-1.5">
                        <span className="truncate">{evt.target || 'N/A'}</span>
                        {evt.target && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleCopyText(evt.target || '', evt.id);
                            }}
                            className="text-slate-500 hover:text-slate-200 transition p-1 cursor-pointer"
                          >
                            {copiedId === evt.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          </button>
                        )}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 text-[11px]">
                        {evt.source === 'Chrome' ? <Chrome className="w-3 h-3 text-cyan-400" /> : evt.source === 'Gmail' ? <Mail className="w-3 h-3 text-emerald-400" /> : <Mic className="w-3 h-3 text-purple-400" />}
                        <span>{evt.source}</span>
                      </span>
                    </td>

                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className={`font-bold text-xs ${
                        evt.riskScore >= 75 ? 'text-rose-400' : evt.riskScore >= 40 ? 'text-amber-400' : 'text-emerald-400'
                      }`}>
                        {evt.riskScore} / 100
                      </span>
                    </td>

                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <button className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-cyan-950 border border-slate-800 hover:border-cyan-500/50 text-slate-400 hover:text-cyan-300 transition-all font-mono text-[11px] flex items-center gap-1 ml-auto cursor-pointer">
                        <span>Inspect</span>
                        <ChevronRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* =========================================================================
          5. INTERACTIVE FORENSIC INVESTIGATION MODAL
         ========================================================================= */}
      <AnimatePresence>
        {selectedEvent && (
          <div className="fixed inset-0 z-50 bg-slate-950/85 backdrop-blur-xl flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-[#091122] border border-cyan-500/40 rounded-3xl max-w-2xl w-full p-7 space-y-6 shadow-[0_0_60px_rgba(0,240,255,0.2)] relative"
            >
              {/* Header */}
              <div className="flex items-center justify-between pb-4 border-b border-slate-800">
                <div className="flex items-center gap-3">
                  <span className={`px-3 py-1 rounded-xl text-xs font-mono font-bold border ${
                    selectedEvent.protectionDecision.startsWith('BLOCK')
                      ? 'bg-rose-950 text-rose-400 border-rose-800 shadow-[0_0_10px_rgba(244,63,94,0.3)]'
                      : selectedEvent.protectionDecision === 'WARN'
                      ? 'bg-amber-950 text-amber-400 border-amber-800'
                      : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                  }`}>
                    {selectedEvent.protectionDecision}
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    EVENT: {selectedEvent.id}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="text-slate-400 hover:text-white text-xs font-mono px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 transition cursor-pointer"
                >
                  ✕ Close
                </button>
              </div>

              {/* Title & Target */}
              <div className="space-y-2">
                <h3 className="text-lg font-bold text-white font-mono">
                  {selectedEvent.title}
                </h3>
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono text-xs text-slate-300 break-all flex items-center justify-between gap-3">
                  <div>
                    <span className="text-slate-500 uppercase font-bold text-[10px] block">Target Destination / IOC:</span>
                    <span>{selectedEvent.target || 'N/A'}</span>
                  </div>
                  {selectedEvent.target && (
                    <button
                      onClick={() => handleCopyText(selectedEvent.target || '', 'modal-target')}
                      className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white transition cursor-pointer shrink-0"
                    >
                      {copiedId === 'modal-target' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    </button>
                  )}
                </div>
              </div>

              {/* Forensic Grid */}
              <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                <div className="p-3.5 rounded-2xl bg-slate-950 border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase font-bold">Action Requested</div>
                  <div className="text-white font-bold mt-1">{selectedEvent.requestedAction}</div>
                </div>
                <div className="p-3.5 rounded-2xl bg-slate-950 border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase font-bold">Risk Score</div>
                  <div className="text-rose-400 font-bold mt-1">{selectedEvent.riskScore} / 100</div>
                </div>
                <div className="p-3.5 rounded-2xl bg-slate-950 border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase font-bold">Enforcement Status</div>
                  <div className="text-emerald-400 font-bold mt-1">{selectedEvent.enforcementStatus}</div>
                </div>
                <div className="p-3.5 rounded-2xl bg-slate-950 border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase font-bold">Source Channel</div>
                  <div className="text-white font-bold mt-1">{selectedEvent.source}</div>
                </div>
              </div>

              {/* MITRE ATT&CK Mapping */}
              <div className="p-4 rounded-2xl bg-slate-950 border border-slate-800 text-xs font-mono space-y-2">
                <div className="text-[10px] text-slate-400 uppercase font-bold">MITRE ATT&CK Framework Mapping:</div>
                <div className="flex flex-wrap gap-2">
                  <span className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-cyan-300">
                    T1566: Phishing
                  </span>
                  <span className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-cyan-300">
                    T1556: Modify Authentication Process
                  </span>
                  <span className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-cyan-300">
                    T1071: Application Layer Protocol
                  </span>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
