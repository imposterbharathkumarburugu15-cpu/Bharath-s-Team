import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  Mail, 
  ArrowRight, 
  Zap, 
  Activity, 
  Clock, 
  Sparkles, 
  Terminal, 
  Play, 
  ChevronRight, 
  Check, 
  Copy, 
  ExternalLink,
  Cpu,
  Lock,
  RefreshCw,
  Plus
} from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer 
} from 'recharts';
import { getScanHistory, ScanHistoryItem } from '@/lib/history';

interface DashboardOverviewProps {
  onNavigateToAnalyze: () => void;
  onNavigateToHistory: () => void;
}

const activityData = [
  { time: '00:00', threats: 1, safe: 12 },
  { time: '04:00', threats: 3, safe: 18 },
  { time: '08:00', threats: 8, safe: 45 },
  { time: '12:00', threats: 12, safe: 68 },
  { time: '16:00', threats: 6, safe: 52 },
  { time: '20:00', threats: 4, safe: 28 },
  { time: 'Now', threats: 5, safe: 34 }
];

export function DashboardOverview({ onNavigateToAnalyze, onNavigateToHistory }: DashboardOverviewProps) {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [quickInput, setQuickInput] = useState('');
  const [currentTime, setCurrentTime] = useState('');

  useEffect(() => {
    setHistory(getScanHistory());
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.toUTCString().slice(17, 25) + ' UTC');
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-8 font-sans text-slate-100">
      
      {/* =========================================================================
          A. DASHBOARD HERO / WELCOME SECTION
         ========================================================================= */}
      <section className="relative overflow-hidden rounded-3xl bg-gradient-to-r from-[#10151D] via-[#121924] to-[#0A0E17] border border-white/[0.08] p-6 sm:p-8 shadow-2xl backdrop-blur-2xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2">
            <div className="flex items-center gap-2.5 font-mono text-xs text-[#00F0FF]">
              <span className="w-2 h-2 rounded-full bg-[#10B981] animate-pulse" />
              <span className="font-bold">KITSIH ACTIVE DEFENSE MATRIX</span>
              <span className="text-[#8995A5]">• {currentTime || '04:42:00 UTC'}</span>
            </div>

            <h1 className="text-2xl sm:text-4xl font-extrabold text-white font-sans tracking-tight">
              Your inbox, under intelligent protection.
            </h1>

            <p className="text-xs sm:text-sm text-[#8995A5] max-w-xl font-mono">
              Continuously intercepting zero-day phishing lures, header spoofing, and reverse tunnels before user interaction.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0 font-mono text-xs">
            <button
              onClick={onNavigateToAnalyze}
              className="px-5 py-3 bg-[#00F0FF] hover:bg-[#00F0FF]/90 text-black font-extrabold rounded-xl shadow-[0_0_20px_rgba(0,240,255,0.3)] hover:shadow-[0_0_25px_rgba(0,240,255,0.5)] transition-all flex items-center gap-2 cursor-pointer active:scale-95"
            >
              <Plus className="w-4 h-4" />
              <span>Analyze New Email</span>
            </button>
          </div>
        </div>
      </section>

      {/* =========================================================================
          B. SECURITY SUMMARY CARDS (4 Sleek Metric Cards)
         ========================================================================= */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Emails Analyzed */}
        <div className="p-5 rounded-2xl bg-[#10151D] border border-white/[0.08] hover:border-white/[0.15] transition-all space-y-3">
          <div className="flex items-center justify-between text-[#8995A5] text-xs font-mono">
            <span>Total Analyzed</span>
            <Mail className="w-4 h-4 text-[#00F0FF]" />
          </div>
          <div className="text-3xl font-extrabold text-white font-mono">
            1,420
          </div>
          <div className="text-[11px] text-[#10B981] font-mono flex items-center gap-1">
            <span>+14.2% ingress volume this week</span>
          </div>
        </div>

        {/* Card 2: Threats Blocked */}
        <div className="p-5 rounded-2xl bg-[#10151D] border border-white/[0.08] hover:border-white/[0.15] transition-all space-y-3">
          <div className="flex items-center justify-between text-[#8995A5] text-xs font-mono">
            <span>Threats Blocked</span>
            <ShieldAlert className="w-4 h-4 text-[#F43F5E]" />
          </div>
          <div className="text-3xl font-extrabold text-white font-mono">
            184
          </div>
          <div className="text-[11px] text-[#F43F5E] font-mono flex items-center gap-1">
            <span>100% Pre-Execution Halt</span>
          </div>
        </div>

        {/* Card 3: Safe Verified */}
        <div className="p-5 rounded-2xl bg-[#10151D] border border-white/[0.08] hover:border-white/[0.15] transition-all space-y-3">
          <div className="flex items-center justify-between text-[#8995A5] text-xs font-mono">
            <span>Safe Emails Verified</span>
            <ShieldCheck className="w-4 h-4 text-[#10B981]" />
          </div>
          <div className="text-3xl font-extrabold text-white font-mono">
            1,236
          </div>
          <div className="text-[11px] text-[#8995A5] font-mono">
            Cryptographic SPF/DKIM Pass
          </div>
        </div>

        {/* Card 4: Mean-Time-to-Detect */}
        <div className="p-5 rounded-2xl bg-[#10151D] border border-white/[0.08] hover:border-white/[0.15] transition-all space-y-3">
          <div className="flex items-center justify-between text-[#8995A5] text-xs font-mono">
            <span>Mean Time to Detect (MTTD)</span>
            <Zap className="w-4 h-4 text-[#00F0FF]" />
          </div>
          <div className="text-3xl font-extrabold text-white font-mono">
            18<span className="text-lg text-[#00F0FF] ml-1">ms</span>
          </div>
          <div className="text-[11px] text-[#00F0FF] font-mono">
            Sub-Second Ingress Engine
          </div>
        </div>
      </section>

      {/* =========================================================================
          C. THREAT ACTIVITY VISUALIZATION & D. QUICK ANALYSIS PANEL
         ========================================================================= */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Threat Activity Chart */}
        <div className="lg:col-span-8 p-6 rounded-2xl bg-[#10151D] border border-white/[0.08] space-y-4 shadow-xl">
          <div className="flex items-center justify-between pb-3 border-b border-white/[0.08]">
            <div>
              <h2 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#00F0FF]" />
                Threat Activity & Ingress Telemetry
              </h2>
              <p className="text-xs text-[#8995A5] font-mono">
                Real-time 24-hour threat detection trends vs. clean traffic
              </p>
            </div>
            <span className="text-[10px] font-mono text-[#10B981] px-2 py-0.5 rounded bg-[#10B981]/10 border border-[#10B981]/30">
              LIVE HOURLY FEED
            </span>
          </div>

          <div className="h-64 w-full pt-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={activityData}>
                <defs>
                  <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#F43F5E" stopOpacity={0.6}/>
                    <stop offset="95%" stopColor="#F43F5E" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="safeGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00F0FF" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#00F0FF" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#161D27" />
                <XAxis dataKey="time" stroke="#64748b" fontSize={11} fontFamily="monospace" />
                <YAxis stroke="#64748b" fontSize={11} fontFamily="monospace" />
                <RechartsTooltip 
                  contentStyle={{ backgroundColor: '#10151D', borderColor: '#00F0FF', borderRadius: '12px', fontFamily: 'monospace', fontSize: '11px' }}
                />
                <Area type="monotone" dataKey="threats" stroke="#F43F5E" strokeWidth={2} fillOpacity={1} fill="url(#threatGrad)" name="Threats Intercepted" />
                <Area type="monotone" dataKey="safe" stroke="#00F0FF" strokeWidth={1.5} fillOpacity={1} fill="url(#safeGrad)" name="Safe Emails" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Quick Analysis Panel */}
        <div className="lg:col-span-4 p-6 rounded-2xl bg-[#10151D] border border-white/[0.08] space-y-4 flex flex-col justify-between shadow-xl">
          <div>
            <div className="flex items-center gap-2 text-white font-mono text-sm font-bold pb-2 border-b border-white/[0.08]">
              <Terminal className="w-4 h-4 text-[#00F0FF]" />
              <span>Quick Email Analysis</span>
            </div>
            <p className="text-xs text-[#8995A5] font-mono mt-2">
              Paste raw email headers or suspicious text to run an instant AI forensic scan:
            </p>
          </div>

          <textarea
            value={quickInput}
            onChange={(e) => setQuickInput(e.target.value)}
            rows={5}
            placeholder="From: ceo@company-internal.com&#10;Subject: Urgent wire transfer...&#10;https://suspicious-login.trycloudflare.com"
            className="w-full bg-[#080B10] border border-white/[0.1] rounded-xl p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-[#00F0FF] resize-none"
          />

          <button
            onClick={onNavigateToAnalyze}
            className="w-full py-3 bg-[#00F0FF] hover:bg-[#00F0FF]/90 text-black font-extrabold text-xs font-mono rounded-xl transition-all shadow-lg flex items-center justify-center gap-2 cursor-pointer active:scale-95"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Launch Analysis Engine</span>
          </button>
        </div>
      </section>

      {/* =========================================================================
          E. RECENT SCANS TABLE / LIST
         ========================================================================= */}
      <section className="p-6 rounded-2xl bg-[#10151D] border border-white/[0.08] space-y-4 shadow-xl">
        <div className="flex items-center justify-between pb-3 border-b border-white/[0.08]">
          <div>
            <h2 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Clock className="w-4 h-4 text-[#00F0FF]" />
              <span>Recent Email Scans & Security Logs</span>
            </h2>
            <p className="text-xs text-[#8995A5] font-mono">
              Audit ledger of recent email analysis runs
            </p>
          </div>

          <button
            onClick={onNavigateToHistory}
            className="text-xs font-mono text-[#00F0FF] hover:underline flex items-center gap-1 cursor-pointer"
          >
            <span>View All Scans</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-white/[0.08] text-[11px] text-[#8995A5] uppercase tracking-wider">
                <th className="py-3 px-3">Scan ID</th>
                <th className="py-3 px-3">Threat Name / Description</th>
                <th className="py-3 px-3">Sender</th>
                <th className="py-3 px-3">Risk Level</th>
                <th className="py-3 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {history.slice(0, 5).map((scan) => {
                const isCrit = scan.riskScore >= 75;
                const isWarn = scan.riskScore >= 40 && scan.riskScore < 75;

                return (
                  <tr key={scan.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="py-3 px-3 font-bold text-white">{scan.id}</td>
                    <td className="py-3 px-3 max-w-xs truncate text-slate-200 font-semibold">
                      {scan.threatName || scan.payloadDescription}
                    </td>
                    <td className="py-3 px-3 text-[#8995A5] max-w-xs truncate">{scan.source}</td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        isCrit 
                          ? 'bg-[#F43F5E]/15 text-[#F43F5E] border-[#F43F5E]/40' 
                          : isWarn 
                          ? 'bg-[#F59E0B]/15 text-[#F59E0B] border-[#F59E0B]/40' 
                          : 'bg-[#10B981]/15 text-[#10B981] border-[#10B981]/40'
                      }`}>
                        {isCrit ? 'CRITICAL PHISH' : isWarn ? 'SUSPICIOUS' : 'CLEAN'} ({scan.riskScore}/100)
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button 
                        onClick={onNavigateToAnalyze}
                        className="text-[#00F0FF] hover:underline font-bold text-[11px] cursor-pointer"
                      >
                        Inspect →
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

    </div>
  );
}
