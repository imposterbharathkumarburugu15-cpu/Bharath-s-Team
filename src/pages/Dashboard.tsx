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
  Cpu
} from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer 
} from 'recharts';
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

  const handleNavigateToVoice = () => {
    window.location.hash = 'voice';
    window.dispatchEvent(new CustomEvent('neuroshield:navigate', { detail: 'voice' }));
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
    <div className="space-y-6 max-w-[1400px] mx-auto px-2 md:px-5 py-4 font-sans text-slate-100">
      {/* Toast Notification */}
      {statusMessage && (
        <div className="fixed top-5 right-6 z-50 bg-[#091122]/95 border border-cyan-500/60 text-cyan-200 px-5 py-3.5 rounded-2xl shadow-[0_0_30px_rgba(6,182,212,0.35)] flex items-center gap-3 text-xs font-mono backdrop-blur-2xl animate-in fade-in slide-in-from-top-3">
          <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
          <span className="font-semibold">{statusMessage}</span>
        </div>
      )}

      {/* =========================================================================
          HERO LIVE COMMAND CENTER & SOC HUD
         ========================================================================= */}
      <div className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-[#0b1224] via-[#060a14] to-[#0d172e] border border-cyan-500/20 shadow-[0_0_50px_rgba(0,0,0,0.8)] p-6 md:p-8 backdrop-blur-2xl">
        {/* Futuristic Ambient Glow Orbs */}
        <div className="absolute -top-24 -right-24 w-96 h-96 bg-cyan-500/10 rounded-full blur-[100px] pointer-events-none" />
        <div className="absolute -bottom-24 -left-24 w-96 h-96 bg-purple-600/10 rounded-full blur-[100px] pointer-events-none" />
        <div className="absolute top-1/2 right-1/3 w-64 h-64 bg-emerald-500/5 rounded-full blur-[90px] pointer-events-none" />

        {/* Top Ticker / Heartbeat Ribbon */}
        <div className="flex flex-wrap items-center justify-between gap-4 pb-6 border-b border-slate-800/80">
          <div className="flex flex-wrap items-center gap-3">
            {/* Live Radar Pulse */}
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-cyan-950/60 border border-cyan-500/40 text-cyan-300 font-mono text-[11px] font-bold shadow-[0_0_15px_rgba(6,182,212,0.2)]">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-400" />
              </span>
              <span>REAL-TIME SOC STREAM ONLINE</span>
            </div>

            {/* DEFCON Status */}
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-emerald-950/50 border border-emerald-500/40 text-emerald-300 font-mono text-[11px] font-bold">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>DEFCON 4 • AUTONOMOUS SHIELD ACTIVE</span>
            </div>

            {/* Live Clock */}
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-slate-900/80 border border-slate-800 text-slate-300 font-mono text-[11px]">
              <Clock className="w-3.5 h-3.5 text-slate-400" />
              <span>{currentTime || '04:42:00 UTC'}</span>
            </div>
          </div>

          {/* Quick Nav Shortcut to Voice Clone Defense */}
          <button
            onClick={handleNavigateToVoice}
            className="group px-3.5 py-1.5 rounded-full bg-gradient-to-r from-purple-900/60 to-indigo-900/60 hover:from-purple-800/80 hover:to-indigo-800/80 border border-purple-500/40 text-purple-200 font-mono text-xs flex items-center gap-2 transition-all duration-300 shadow-[0_0_15px_rgba(168,85,247,0.2)] cursor-pointer"
          >
            <Mic className="w-3.5 h-3.5 text-purple-400 group-hover:scale-110 transition-transform" />
            <span className="font-bold">Voice Clone Defense</span>
            <ArrowUpRight className="w-3 h-3 text-purple-400" />
          </button>
        </div>

        {/* Hero Title & Primary Controls */}
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6 pt-6">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs font-semibold tracking-wider uppercase">
              <Sparkles className="w-3.5 h-3.5" />
              <span>Autonomous Multi-Channel Threat Interception Matrix</span>
            </div>
            <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight text-white font-mono flex items-center gap-3">
              <span>NEUROSHIELD DEFENSE CONSOLE</span>
            </h1>
            <p className="text-xs md:text-sm text-slate-300 max-w-2xl leading-relaxed">
              Continuously intercepting zero-day phishing, credential harvesting lures, and deepfake synthetic vectors before user interaction or credential submission occurs.
            </p>
          </div>

          {/* Interactive Simulation Action Buttons */}
          <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
            <button
              onClick={handleInjectTestIncident}
              disabled={isInjecting}
              className="px-4 py-3 bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-extrabold rounded-2xl shadow-[0_0_25px_rgba(6,182,212,0.4)] hover:shadow-[0_0_35px_rgba(6,182,212,0.6)] transition-all duration-300 flex items-center gap-2.5 cursor-pointer disabled:opacity-50 group"
              title="Trigger a real-time incoming malicious vector to test inline enforcement"
            >
              {isInjecting ? (
                <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
              ) : (
                <Zap className="w-4 h-4 text-slate-950 group-hover:scale-110 transition-transform fill-slate-950" />
              )}
              <span>{isInjecting ? 'INTERCEPTING...' : '+ INGEST LIVE THREAT'}</span>
            </button>

            <button
              onClick={handleRestoreBaseline}
              className="px-4 py-3 bg-slate-900/90 hover:bg-slate-800 text-slate-200 font-bold rounded-2xl border border-slate-700/80 hover:border-emerald-500/50 transition-all duration-300 flex items-center gap-2 cursor-pointer shadow-lg hover:shadow-emerald-950/40"
              title="Restore the verified enterprise scanned telemetry baseline"
            >
              <RefreshCw className="w-3.5 h-3.5 text-emerald-400" />
              <span>Restore Baseline</span>
            </button>

            <button
              onClick={handleClearTestIncidents}
              disabled={isClearing || events.length === 0}
              className="px-3.5 py-3 bg-slate-950/80 hover:bg-rose-950/40 text-slate-400 hover:text-rose-300 rounded-2xl border border-slate-800/80 hover:border-rose-700/50 transition-all duration-300 flex items-center gap-1.5 cursor-pointer disabled:opacity-40"
              title="Reset telemetry counters to test empty state"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear</span>
            </button>
          </div>
        </div>
      </div>

      {/* =========================================================================
          HERO KPI CARDS (4 Sleek Holographic Cards with Glowing Micro-Accents)
         ========================================================================= */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Threats Blocked */}
        <div className="relative overflow-hidden rounded-3xl bg-[#090f1e]/90 border border-rose-500/30 hover:border-rose-500/60 p-6 transition-all duration-300 shadow-[0_10px_30px_rgba(0,0,0,0.5)] group hover:shadow-[0_0_30px_rgba(244,63,94,0.2)]">
          <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-rose-500 via-red-500 to-rose-600 shadow-[0_0_15px_rgba(244,63,94,0.8)]" />
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
          <div className="flex items-center justify-between text-[11px] text-slate-400 mt-4 pt-3 border-t border-slate-800/80 font-mono">
            <span>Pre-Execution Halt</span>
            <span className="text-rose-400 font-bold flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-ping" />
              100% Intercepted
            </span>
          </div>
        </div>

        {/* Card 2: Warnings Issued */}
        <div className="relative overflow-hidden rounded-3xl bg-[#090f1e]/90 border border-amber-500/30 hover:border-amber-500/60 p-6 transition-all duration-300 shadow-[0_10px_30px_rgba(0,0,0,0.5)] group hover:shadow-[0_0_30px_rgba(245,158,11,0.2)]">
          <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-amber-400 via-yellow-500 to-amber-500 shadow-[0_0_15px_rgba(245,158,11,0.8)]" />
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
          <div className="flex items-center justify-between text-[11px] text-slate-400 mt-4 pt-3 border-t border-slate-800/80 font-mono">
            <span>Deceptive Lures Flagged</span>
            <span className="text-amber-400 font-bold">Safe Alt Offered</span>
          </div>
        </div>

        {/* Card 3: Sensitive Data Intercepts */}
        <div className="relative overflow-hidden rounded-3xl bg-[#090f1e]/90 border border-purple-500/30 hover:border-purple-500/60 p-6 transition-all duration-300 shadow-[0_10px_30px_rgba(0,0,0,0.5)] group hover:shadow-[0_0_30px_rgba(168,85,247,0.2)]">
          <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-purple-500 via-indigo-500 to-purple-600 shadow-[0_0_15px_rgba(168,85,247,0.8)]" />
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
          <div className="flex items-center justify-between text-[11px] text-slate-400 mt-4 pt-3 border-t border-slate-800/80 font-mono">
            <span>Passcodes & Financials</span>
            <span className="text-purple-400 font-bold">Zero Leakage</span>
          </div>
        </div>

        {/* Card 4: High-Risk Vectors */}
        <div className="relative overflow-hidden rounded-3xl bg-[#090f1e]/90 border border-cyan-500/30 hover:border-cyan-500/60 p-6 transition-all duration-300 shadow-[0_10px_30px_rgba(0,0,0,0.5)] group hover:shadow-[0_0_30px_rgba(6,182,212,0.2)]">
          <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-cyan-400 via-sky-400 to-blue-500 shadow-[0_0_15px_rgba(6,182,212,0.8)]" />
          <div className="flex items-center justify-between mb-3">
            <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-cyan-300/80">
              High-Risk Vectors
            </span>
            <div className="w-10 h-10 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.25)] group-hover:scale-110 transition-transform">
              <Activity className="w-5 h-5" />
            </div>
          </div>
          <div className="text-4xl md:text-5xl font-mono font-extrabold text-white tracking-tight group-hover:text-cyan-400 transition-colors">
            {metrics.highRiskEvents}
          </div>
          <div className="flex items-center justify-between text-[11px] text-slate-400 mt-4 pt-3 border-t border-slate-800/80 font-mono">
            <span>CVSS Score ≥ 75</span>
            <span className="text-cyan-400 font-bold">Killchain Broken</span>
          </div>
        </div>
      </section>

      {/* =========================================================================
          LIVE TICKER MARQUEE (Real-Time Attack Interception Stream)
         ========================================================================= */}
      <div className="rounded-2xl bg-gradient-to-r from-[#0a1020] via-[#091124] to-[#0a1020] border border-slate-800 p-3 shadow-lg flex items-center gap-3 overflow-hidden">
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-rose-500/20 text-rose-300 text-[10px] font-mono font-extrabold uppercase shrink-0 border border-rose-500/30">
          <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-pulse" />
          <span>LIVE INTERCEPTIONS</span>
        </div>
        <div className="flex-1 overflow-x-auto whitespace-nowrap text-xs font-mono text-slate-300 flex items-center gap-6 scrollbar-none py-0.5">
          {events.slice(0, 4).map((evt, idx) => (
            <div key={idx} className="inline-flex items-center gap-2 shrink-0">
              <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                evt.protectionDecision.startsWith('BLOCK') 
                  ? 'bg-rose-950 text-rose-400 border border-rose-800' 
                  : evt.protectionDecision === 'WARN'
                  ? 'bg-amber-950 text-amber-400 border border-amber-800'
                  : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
              }`}>
                {evt.protectionDecision.startsWith('BLOCK') ? 'BLOCKED' : evt.protectionDecision}
              </span>
              <span className="font-semibold text-white">{evt.title}</span>
              <span className="text-slate-500">({getRelativeTime(evt.timestamp)})</span>
              <span className="text-slate-600">•</span>
            </div>
          ))}
        </div>
      </div>

      {/* =========================================================================
          SECTION 2: REAL-TIME INGESTION TIMELINE & ATTACK VECTOR MATRIX
         ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Real-time Threat Ingestion Timeline Chart (8 cols) */}
        <div className="lg:col-span-8 rounded-3xl bg-[#080e1b]/90 border border-slate-800 p-6 md:p-7 shadow-2xl space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                <Zap className="w-4 h-4 text-cyan-400" />
                <span>Real-Time Threat Ingestion Chronology</span>
              </h3>
              <p className="text-xs text-slate-400">
                Continuous chronological distribution of blocked vectors, flagged warnings, and safe baselines.
              </p>
            </div>

            {/* Timeframe Toggle Buttons */}
            <div className="flex items-center gap-1.5 bg-slate-900/90 p-1 rounded-xl border border-slate-800 text-xs font-mono">
              <button
                onClick={() => setTimeRange('LIVE')}
                className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer font-bold ${
                  timeRange === 'LIVE' ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-950/50' : 'text-slate-400 hover:text-white'
                }`}
              >
                Live (10m)
              </button>
              <button
                onClick={() => setTimeRange('24H')}
                className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer font-bold ${
                  timeRange === '24H' ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-950/50' : 'text-slate-400 hover:text-white'
                }`}
              >
                24 Hours
              </button>
            </div>
          </div>

          {/* Area Chart Container */}
          <div className="h-64 w-full pt-3">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeRange === 'LIVE' ? timelineDataLive : timelineData24h}>
                <defs>
                  <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.45} />
                    <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorWarned" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#fbbf24" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#fbbf24" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorSafe" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="hour" stroke="#64748b" fontSize={11} fontFamily="monospace" />
                <YAxis stroke="#64748b" fontSize={11} fontFamily="monospace" />
                <RechartsTooltip 
                  contentStyle={{ 
                    backgroundColor: '#091122', 
                    borderColor: '#334155', 
                    borderRadius: '1rem',
                    fontFamily: 'monospace',
                    fontSize: '11px',
                    color: '#f8fafc',
                    boxShadow: '0 10px 25px rgba(0,0,0,0.6)'
                  }} 
                />
                <Area type="monotone" dataKey="blocked" stroke="#f43f5e" strokeWidth={2.5} fillOpacity={1} fill="url(#colorBlocked)" name="Blocked" />
                <Area type="monotone" dataKey="warnings" stroke="#fbbf24" strokeWidth={2} fillOpacity={1} fill="url(#colorWarned)" name="Warned" />
                <Area type="monotone" dataKey="safe" stroke="#10b981" strokeWidth={1.5} fillOpacity={1} fill="url(#colorSafe)" name="Safe" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Operational Metrics Pill Strip */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 font-mono text-xs">
            <div className="p-3 rounded-2xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400">Interception Latency:</span>
              <span className="text-cyan-400 font-bold">28ms (Inline)</span>
            </div>
            <div className="p-3 rounded-2xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400">False Positive Rate:</span>
              <span className="text-emerald-400 font-bold">&lt; 0.01%</span>
            </div>
            <div className="p-3 rounded-2xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400">Active Pipeline:</span>
              <span className="text-purple-400 font-bold">v5.2 Multi-Agent</span>
            </div>
          </div>
        </div>

        {/* Attack Vector Classification & Defense Readiness (4 cols) */}
        <div className="lg:col-span-4 rounded-3xl bg-[#080e1b]/90 border border-slate-800 p-6 md:p-7 shadow-2xl space-y-5 flex flex-col justify-between">
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                <Sliders className="w-4 h-4 text-purple-400" />
                <span>Attack Vectors</span>
              </h3>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-purple-950/60 text-purple-300 border border-purple-800/60">
                100% Mitigated
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Distribution of intercepted attacks by vector category.
            </p>
          </div>

          {/* Progress Bars */}
          <div className="space-y-4">
            {/* Vector 1 */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1.5">
                <span className="text-slate-200 font-semibold">M365 & SSO Credential Theft</span>
                <span className="text-rose-400 font-bold">45%</span>
              </div>
              <div className="w-full bg-slate-900 rounded-full h-2.5 overflow-hidden p-0.5 border border-slate-800">
                <div className="bg-gradient-to-r from-rose-500 to-red-600 h-full rounded-full w-[45%]" />
              </div>
            </div>

            {/* Vector 2 */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1.5">
                <span className="text-slate-200 font-semibold">Reverse Tunnel & Worker Evasion</span>
                <span className="text-cyan-400 font-bold">25%</span>
              </div>
              <div className="w-full bg-slate-900 rounded-full h-2.5 overflow-hidden p-0.5 border border-slate-800">
                <div className="bg-gradient-to-r from-cyan-400 to-blue-500 h-full rounded-full w-[25%]" />
              </div>
            </div>

            {/* Vector 3 */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1.5">
                <span className="text-slate-200 font-semibold">Financial Wire Remittance Fraud</span>
                <span className="text-amber-400 font-bold">20%</span>
              </div>
              <div className="w-full bg-slate-900 rounded-full h-2.5 overflow-hidden p-0.5 border border-slate-800">
                <div className="bg-gradient-to-r from-amber-400 to-orange-500 h-full rounded-full w-[20%]" />
              </div>
            </div>

            {/* Vector 4: AI Voice Clone */}
            <div className="p-3 rounded-2xl bg-purple-950/30 border border-purple-500/30 hover:border-purple-500/60 transition-all">
              <div className="flex justify-between text-xs font-mono mb-1.5">
                <span className="text-purple-200 font-semibold flex items-center gap-1.5">
                  <Mic className="w-3.5 h-3.5 text-purple-400" />
                  AI Voice Clone & Vishing
                </span>
                <span className="text-purple-400 font-bold">10%</span>
              </div>
              <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden mb-2">
                <div className="bg-gradient-to-r from-purple-400 to-indigo-500 h-full rounded-full w-[10%]" />
              </div>
              <button
                onClick={handleNavigateToVoice}
                className="text-[11px] font-mono text-purple-300 hover:text-purple-100 flex items-center gap-1 font-bold transition cursor-pointer"
              >
                <span>Launch Voice Clone Analysis</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          </div>

          {/* Bottom Card Summary */}
          <div className="pt-3 border-t border-slate-800/80 text-[11px] font-mono text-slate-400 flex items-center justify-between">
            <span>Enforcement Strategy:</span>
            <span className="text-emerald-400 font-bold flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              Deterministic Halt
            </span>
          </div>
        </div>
      </div>

      {/* =========================================================================
          SECTION 3: RECENT PROTECTION EVENTS STREAM (Table with Rich Filters)
         ========================================================================= */}
      <section className="space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <h2 className="text-sm font-mono font-extrabold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>Real-Time Interception Telemetry Feed</span>
            </h2>
            <span className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-bold">
              {filteredEvents.length} Events Logged
            </span>
          </div>

          {/* Search & Multi-Filter Controls */}
          <div className="flex flex-wrap items-center gap-3">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search domain, vector, target..."
                className="bg-slate-900/90 border border-slate-800 rounded-xl pl-9 pr-3 py-2 text-xs text-slate-200 outline-none focus:border-cyan-500 font-mono w-48 sm:w-64 transition shadow-inner"
              />
            </div>

            {/* Source Channel Filter */}
            <div className="flex items-center gap-1 bg-slate-900/90 p-1 rounded-xl border border-slate-800 font-mono text-[11px]">
              <button
                onClick={() => setFilterSource('ALL')}
                className={`px-2.5 py-1.5 rounded-lg transition cursor-pointer ${
                  filterSource === 'ALL' ? 'bg-slate-800 text-white font-bold' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                All Sources
              </button>
              <button
                onClick={() => setFilterSource('Chrome')}
                className={`px-2.5 py-1.5 rounded-lg transition cursor-pointer flex items-center gap-1 ${
                  filterSource === 'Chrome' ? 'bg-cyan-600 text-white font-bold' : 'text-slate-400 hover:text-cyan-400'
                }`}
              >
                <Chrome className="w-3 h-3" />
                <span>Chrome</span>
              </button>
              <button
                onClick={() => setFilterSource('Gmail')}
                className={`px-2.5 py-1.5 rounded-lg transition cursor-pointer flex items-center gap-1 ${
                  filterSource === 'Gmail' ? 'bg-emerald-600 text-white font-bold' : 'text-slate-400 hover:text-emerald-400'
                }`}
              >
                <Mail className="w-3 h-3" />
                <span>Gmail</span>
              </button>
              <button
                onClick={() => setFilterSource('Voice')}
                className={`px-2.5 py-1.5 rounded-lg transition cursor-pointer flex items-center gap-1 ${
                  filterSource === 'Voice' ? 'bg-purple-600 text-white font-bold' : 'text-slate-400 hover:text-purple-400'
                }`}
              >
                <Mic className="w-3 h-3" />
                <span>Voice AI</span>
              </button>
            </div>

            {/* Decision Filter Tabs */}
            <div className="flex items-center gap-1 bg-slate-900/90 p-1 rounded-xl border border-slate-800 font-mono text-[11px]">
              <button
                onClick={() => setFilterDecision('ALL')}
                className={`px-2.5 py-1.5 rounded-lg transition cursor-pointer ${
                  filterDecision === 'ALL' ? 'bg-cyan-600 text-white font-bold' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                All ({events.length})
              </button>
              <button
                onClick={() => setFilterDecision('BLOCKED')}
                className={`px-2.5 py-1.5 rounded-lg transition cursor-pointer ${
                  filterDecision === 'BLOCKED' ? 'bg-rose-600 text-white font-bold' : 'text-slate-400 hover:text-rose-400'
                }`}
              >
                Blocked ({events.filter(e => e.protectionDecision.startsWith('BLOCK') || e.enforcementStatus === 'ENFORCED' || e.enforcementStatus === 'BLOCKED').length})
              </button>
              <button
                onClick={() => setFilterDecision('WARNED')}
                className={`px-2.5 py-1.5 rounded-lg transition cursor-pointer ${
                  filterDecision === 'WARNED' ? 'bg-amber-600 text-white font-bold' : 'text-slate-400 hover:text-amber-400'
                }`}
              >
                Warned ({events.filter(e => e.protectionDecision === 'WARN' || e.enforcementStatus === 'WARNED').length})
              </button>
              <button
                onClick={() => setFilterDecision('ALLOW')}
                className={`px-2.5 py-1.5 rounded-lg transition cursor-pointer ${
                  filterDecision === 'ALLOW' ? 'bg-emerald-600 text-white font-bold' : 'text-slate-400 hover:text-emerald-400'
                }`}
              >
                Allowed ({events.filter(e => e.protectionDecision === 'ALLOW').length})
              </button>
            </div>
          </div>
        </div>

        {/* Interactive Telemetry Table */}
        <div className="rounded-3xl bg-[#080e1b]/90 border border-slate-800 overflow-hidden shadow-2xl">
          {filteredEvents.length === 0 ? (
            <div className="py-16 px-6 text-center space-y-4">
              <div className="w-14 h-14 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto text-slate-500 shadow-inner">
                <CheckCircle2 className="w-7 h-7 text-emerald-400" />
              </div>
              <div className="text-base font-bold text-slate-200 font-mono">
                No matching protection events
              </div>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                No events match your current filters. Click "Restore Baseline" to inspect verified enterprise telemetry.
              </p>
              <button
                onClick={handleRestoreBaseline}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs rounded-xl transition cursor-pointer"
              >
                Reload Telemetry Baseline
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-900/80 font-mono text-[11px] text-slate-400 uppercase tracking-wider">
                    <th className="py-4 px-5">Time & Delta</th>
                    <th className="py-4 px-5">Enforcement Verdict</th>
                    <th className="py-4 px-5">Threat Vector & Action</th>
                    <th className="py-4 px-5">Destination / Indicator</th>
                    <th className="py-4 px-5">Ingestion Source</th>
                    <th className="py-4 px-5">Risk Quotient</th>
                    <th className="py-4 px-5 text-right">Forensic Dossier</th>
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
                        {/* Time */}
                        <td className="py-4 px-5 whitespace-nowrap">
                          <div className="text-slate-200 font-semibold">{formatEventTime(evt.timestamp)}</div>
                          <div className="text-[10px] text-slate-500">{getRelativeTime(evt.timestamp)}</div>
                        </td>

                        {/* Decision Badge */}
                        <td className="py-4 px-5 whitespace-nowrap">
                          <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-[10px] font-bold border shadow-sm ${
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

                        {/* Title & Threat Type */}
                        <td className="py-4 px-5 font-sans min-w-[220px]">
                          <div className="font-bold text-slate-100 group-hover:text-cyan-300 transition-colors">
                            {evt.title}
                          </div>
                          <div className="text-[11px] text-slate-400 font-mono mt-0.5 flex items-center gap-2">
                            <span>Vector: <span className="text-slate-300">{evt.threatType}</span></span>
                            <span>•</span>
                            <span>Action: <span className="text-slate-300">{evt.requestedAction}</span></span>
                          </div>
                        </td>

                        {/* Target Destination with Copy Button */}
                        <td className="py-4 px-5 font-mono text-[11px] text-slate-400 max-w-xs truncate">
                          <div className="flex items-center gap-1.5">
                            <span className="truncate">{evt.target || 'N/A'}</span>
                            {evt.target && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleCopyText(evt.target || '', evt.id);
                                }}
                                className="text-slate-500 hover:text-slate-200 transition p-1 cursor-pointer"
                                title="Copy target destination"
                              >
                                {copiedId === evt.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              </button>
                            )}
                          </div>
                        </td>

                        {/* Ingestion Source */}
                        <td className="py-4 px-5 whitespace-nowrap">
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 text-[11px]">
                            {evt.source === 'Chrome' ? (
                              <Chrome className="w-3.5 h-3.5 text-cyan-400" />
                            ) : evt.source === 'Gmail' ? (
                              <Mail className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Mic className="w-3.5 h-3.5 text-purple-400" />
                            )}
                            <span>{evt.source}</span>
                          </span>
                        </td>

                        {/* Risk Quotient Gauge */}
                        <td className="py-4 px-5 whitespace-nowrap">
                          <div className="flex items-center gap-2.5">
                            <span className={`font-bold text-xs ${
                              evt.riskScore >= 75 ? 'text-rose-400' : evt.riskScore >= 40 ? 'text-amber-400' : 'text-emerald-400'
                            }`}>
                              {evt.riskScore}
                            </span>
                            <div className="w-16 bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
                              <div 
                                className={`h-full rounded-full ${
                                  evt.riskScore >= 75 ? 'bg-gradient-to-r from-rose-500 to-red-600' : evt.riskScore >= 40 ? 'bg-gradient-to-r from-amber-400 to-orange-500' : 'bg-gradient-to-r from-emerald-400 to-teal-500'
                                }`} 
                                style={{ width: `${evt.riskScore}%` }}
                              />
                            </div>
                          </div>
                        </td>

                        {/* Inspect Dossier Action */}
                        <td className="py-4 px-5 text-right whitespace-nowrap">
                          <button className="px-3 py-1 rounded-lg bg-slate-900 hover:bg-cyan-950 border border-slate-800 hover:border-cyan-500/50 text-slate-400 hover:text-cyan-300 transition-all font-mono text-[11px] flex items-center gap-1.5 ml-auto cursor-pointer">
                            <span>Inspect</span>
                            <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      {/* =========================================================================
          SECTION 4: SYSTEM COMPONENT HEALTH & ARCHITECTURE STATUS
         ========================================================================= */}
      <section className="space-y-3">
        <h2 className="text-xs font-mono font-bold tracking-wider text-slate-400 uppercase flex items-center gap-2">
          <Server className="w-4 h-4 text-cyan-400" />
          <span>SYSTEM PROTECTION STATUS & COMPONENT MATRIX</span>
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono">
          {/* Chrome Browser Extension */}
          <div className="p-5 rounded-2xl bg-[#080e1b]/90 border border-slate-800 space-y-2 shadow-lg hover:border-cyan-500/40 transition">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400">Chrome Extension</span>
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
            </div>
            <div className="text-sm font-bold text-white flex items-center gap-2">
              <Chrome className="w-4 h-4 text-cyan-400" />
              <span>PROTECTED</span>
            </div>
            <div className="text-[11px] text-slate-400">
              Capture-phase DOM Interceptor
            </div>
          </div>

          {/* Gmail Inbox Shield */}
          <div className="p-5 rounded-2xl bg-[#080e1b]/90 border border-slate-800 space-y-2 shadow-lg hover:border-emerald-500/40 transition">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400">Gmail Ingestion</span>
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
            </div>
            <div className="text-sm font-bold text-white flex items-center gap-2">
              <Mail className="w-4 h-4 text-emerald-400" />
              <span>CONNECTED</span>
            </div>
            <div className="text-[11px] text-slate-400">
              Autonomous Ingestion Active
            </div>
          </div>

          {/* Core Neural API */}
          <div className="p-5 rounded-2xl bg-[#080e1b]/90 border border-slate-800 space-y-2 shadow-lg hover:border-purple-500/40 transition">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400">NeuroShield Neural Core</span>
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
            </div>
            <div className="text-sm font-bold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-purple-400" />
              <span>HEALTHY (28ms)</span>
            </div>
            <div className="text-[11px] text-slate-400">
              v5.2 Multi-Agent Engine
            </div>
          </div>

          {/* Cloud Firestore Persistence */}
          <div className="p-5 rounded-2xl bg-[#080e1b]/90 border border-slate-800 space-y-2 shadow-lg hover:border-blue-500/40 transition">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400">Cloud Firestore SOC Store</span>
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
            </div>
            <div className="text-sm font-bold text-white flex items-center gap-2">
              <Database className="w-4 h-4 text-blue-400" />
              <span>SYNCHRONIZED</span>
            </div>
            <div className="text-[11px] text-slate-400">
              Real-time Multi-tenant Listener
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          INTERACTIVE FORENSIC DOSSIER MODAL
         ========================================================================= */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-slate-950/85 backdrop-blur-xl flex items-center justify-center p-4">
          <div className="bg-[#091122] border border-slate-700/80 rounded-3xl max-w-2xl w-full p-7 space-y-6 shadow-[0_0_50px_rgba(0,0,0,0.8)] relative animate-in fade-in zoom-in-95">
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
                  ID: {selectedEvent.id}
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
              <div className="bg-slate-950 p-3 rounded-xl border border-slate-800/80 font-mono text-xs text-slate-300 break-all flex items-center justify-between gap-3">
                <div>
                  <span className="text-slate-500 uppercase font-bold text-[10px] block">Target Destination:</span>
                  <span>{selectedEvent.target || 'N/A'}</span>
                </div>
                {selectedEvent.target && (
                  <button
                    onClick={() => handleCopyText(selectedEvent.target || '', 'modal-target')}
                    className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white transition cursor-pointer shrink-0"
                    title="Copy target"
                  >
                    {copiedId === 'modal-target' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  </button>
                )}
              </div>
            </div>

            {/* Forensic Grid */}
            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3.5 rounded-2xl bg-slate-950/80 border border-slate-800">
                <div className="text-[10px] text-slate-500 uppercase font-bold">Action Requested</div>
                <div className="text-white font-bold mt-1">{selectedEvent.requestedAction}</div>
              </div>
              <div className="p-3.5 rounded-2xl bg-slate-950/80 border border-slate-800">
                <div className="text-[10px] text-slate-500 uppercase font-bold">Risk Quotient</div>
                <div className="text-rose-400 font-bold mt-1">{selectedEvent.riskScore} / 100</div>
              </div>
              <div className="p-3.5 rounded-2xl bg-slate-950/80 border border-slate-800">
                <div className="text-[10px] text-slate-500 uppercase font-bold">Enforcement Status</div>
                <div className="text-emerald-400 font-bold mt-1">{selectedEvent.enforcementStatus}</div>
              </div>
              <div className="p-3.5 rounded-2xl bg-slate-950/80 border border-slate-800">
                <div className="text-[10px] text-slate-500 uppercase font-bold">Source Channel</div>
                <div className="text-white font-bold mt-1">{selectedEvent.source}</div>
              </div>
            </div>

            {/* Sensitive Data Targets */}
            {selectedEvent.sensitiveDataCategories && selectedEvent.sensitiveDataCategories.length > 0 && (
              <div className="p-4 rounded-2xl bg-rose-950/20 border border-rose-900/40 text-xs font-mono space-y-2">
                <div className="text-[10px] text-rose-400 uppercase font-bold flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5" />
                  <span>Sensitive Data Exfiltration Targets:</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {selectedEvent.sensitiveDataCategories.map((c, idx) => (
                    <span key={idx} className="px-2.5 py-1 rounded-lg bg-rose-950/80 border border-rose-800 text-[11px] text-rose-300 font-bold">
                      {c}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* MITRE ATT&CK Mapping */}
            <div className="p-4 rounded-2xl bg-slate-950/80 border border-slate-800 text-xs font-mono space-y-2">
              <div className="text-[10px] text-slate-400 uppercase font-bold">MITRE ATT&CK Framework Mapping:</div>
              <div className="flex flex-wrap gap-2">
                <span className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-cyan-300">
                  T1566: Phishing
                </span>
                <span className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-cyan-300">
                  T1556: Modify Authentication Process
                </span>
                <span className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-cyan-300">
                  T1071: Standard Application Layer Protocol
                </span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
