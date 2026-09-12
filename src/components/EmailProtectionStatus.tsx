import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { 
  Shield, ShieldCheck, ShieldAlert, Activity, Clock, 
  AlertTriangle, CheckCircle2, Eye, Zap, RefreshCw 
} from 'lucide-react';
import { IngestionStats } from '@/services/gmailIngestionService';

interface EmailProtectionStatusProps {
  stats: IngestionStats;
  isConnected: boolean;
  isScanning: boolean;
  userEmail?: string | null;
  nextPollIn?: number; // seconds until next poll
  onRefresh?: () => void;
}

export function EmailProtectionStatus({
  stats,
  isConnected,
  isScanning,
  userEmail,
  nextPollIn,
  onRefresh
}: EmailProtectionStatusProps) {
  const [countdownSeconds, setCountdownSeconds] = useState(nextPollIn || 0);

  useEffect(() => {
    if (nextPollIn !== undefined) {
      setCountdownSeconds(nextPollIn);
    }
  }, [nextPollIn]);

  useEffect(() => {
    if (countdownSeconds <= 0 || !stats.isMonitoring) return;
    const timer = setInterval(() => {
      setCountdownSeconds(prev => Math.max(0, prev - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, [countdownSeconds, stats.isMonitoring]);

  const formatCountdown = (s: number) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return `${m}:${sec.toString().padStart(2, '0')}`;
  };

  const statusColor = !isConnected 
    ? 'from-zinc-500/20 to-zinc-600/10 border-zinc-500/30'
    : stats.highRiskCount > 0
    ? 'from-red-500/15 to-red-900/10 border-red-500/30'
    : stats.suspiciousCount > 0
    ? 'from-amber-500/15 to-amber-900/10 border-amber-500/30'
    : 'from-emerald-500/15 to-emerald-900/10 border-emerald-500/30';

  const statusIcon = !isConnected ? Shield : stats.highRiskCount > 0 ? ShieldAlert : ShieldCheck;
  const StatusIcon = statusIcon;
  const statusDotColor = !isConnected 
    ? 'bg-zinc-400'
    : isScanning 
    ? 'bg-blue-400 animate-pulse'
    : stats.isMonitoring 
    ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)]' 
    : 'bg-zinc-400';

  const statusLabel = !isConnected 
    ? 'DISCONNECTED'
    : isScanning 
    ? 'SCANNING...'
    : stats.isMonitoring 
    ? 'ACTIVE MONITORING' 
    : 'CONNECTED';

  return (
    <motion.div
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={`w-full rounded-xl border bg-gradient-to-r ${statusColor} backdrop-blur-md px-5 py-3.5`}
    >
      <div className="flex items-center justify-between flex-wrap gap-3">
        {/* Left: Status */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <StatusIcon className={`w-5 h-5 ${
              !isConnected ? 'text-zinc-400' :
              stats.highRiskCount > 0 ? 'text-red-400' : 'text-emerald-400'
            }`} />
            <div className={`absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full ${statusDotColor}`} />
          </div>
          
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-mono font-bold tracking-widest text-white/80">
                {statusLabel}
              </span>
              {isScanning && (
                <RefreshCw className="w-3 h-3 text-blue-400 animate-spin" />
              )}
            </div>
            {userEmail && (
              <span className="text-[10px] font-mono text-white/40 truncate max-w-[200px]">
                {userEmail}
              </span>
            )}
          </div>
        </div>

        {/* Center: Stats */}
        {isConnected && stats.totalScanned > 0 && (
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5">
              <Eye className="w-3.5 h-3.5 text-cyan-400/70" />
              <span className="text-xs font-mono text-white/60">
                <span className="text-cyan-300 font-bold">{stats.totalScanned}</span> scanned
              </span>
            </div>
            
            {stats.highRiskCount > 0 && (
              <div className="flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                <span className="text-xs font-mono text-red-300 font-bold">
                  {stats.highRiskCount} threats
                </span>
              </div>
            )}
            
            {stats.suspiciousCount > 0 && (
              <div className="flex items-center gap-1.5">
                <Zap className="w-3.5 h-3.5 text-amber-400/70" />
                <span className="text-xs font-mono text-amber-300">
                  {stats.suspiciousCount} suspicious
                </span>
              </div>
            )}
            
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400/70" />
              <span className="text-xs font-mono text-emerald-300">
                {stats.safeCount} safe
              </span>
            </div>
          </div>
        )}

        {/* Right: Timing + Refresh */}
        <div className="flex items-center gap-3">
          {stats.lastScanTimestamp && (
            <div className="flex items-center gap-1.5">
              <Clock className="w-3 h-3 text-white/30" />
              <span className="text-[10px] font-mono text-white/30">
                Last: {new Date(stats.lastScanTimestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </span>
            </div>
          )}

          {stats.isMonitoring && countdownSeconds > 0 && (
            <div className="flex items-center gap-1.5 bg-white/5 rounded-md px-2 py-0.5">
              <Activity className="w-3 h-3 text-cyan-400/50" />
              <span className="text-[10px] font-mono text-cyan-300/60">
                Next: {formatCountdown(countdownSeconds)}
              </span>
            </div>
          )}

          {isConnected && onRefresh && !isScanning && (
            <button
              onClick={onRefresh}
              className="p-1.5 rounded-lg hover:bg-white/10 transition-colors group"
              title="Refresh now"
            >
              <RefreshCw className="w-3.5 h-3.5 text-white/40 group-hover:text-white/70 transition-colors" />
            </button>
          )}
        </div>
      </div>
    </motion.div>
  );
}
