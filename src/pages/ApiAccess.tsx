import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { useLanguage } from '@/contexts/LanguageContext';
import { 
  Key, 
  Terminal, 
  Copy, 
  CheckCircle2, 
  Shield, 
  Zap, 
  Database,
  RefreshCw,
  Activity,
  Sparkles,
  Sliders,
  Check,
  Server,
  Lock,
  AlertTriangle,
  Cpu,
  Layers,
  ArrowUpRight,
  Clock,
  Gauge,
  Play,
  X
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { ResponsiveContainer, AreaChart, Area, XAxis, Tooltip, CartesianGrid } from 'recharts';

interface ApiKeyItem {
  id: string;
  name: string;
  key: string;
  created: string;
  lastUsed: string;
  status: 'active' | 'revoked';
  tier: 'Enterprise' | 'Pro' | 'Free';
  quotaAllocated: string;
  scopes: string[];
}

export type SubscriptionTier = 'free' | 'pro' | 'enterprise';

interface TierConfig {
  id: SubscriptionTier;
  name: string;
  badge: string;
  price: string;
  cadence: string;
  dailyQuota: number;
  burstPerSec: number;
  neuroProfileQuota: number;
  sla: string;
  description: string;
  features: string[];
}

const SUBSCRIPTION_TIERS: Record<SubscriptionTier, TierConfig> = {
  free: {
    id: 'free',
    name: 'Community Free',
    badge: 'FREE TIER',
    price: '$0',
    cadence: 'Forever Free',
    dailyQuota: 1000,
    burstPerSec: 10,
    neuroProfileQuota: 50,
    sla: 'Best-effort community',
    description: 'Basic RFC email analysis for personal research and prototype evaluations.',
    features: [
      '1,000 requests / day',
      '10 req/sec burst limit',
      'Basic SPF / DKIM verification',
      'Single user mailbox',
      'Standard community support'
    ]
  },
  pro: {
    id: 'pro',
    name: 'Professional SOC',
    badge: 'PRO TIER',
    price: '$499',
    cadence: 'per month',
    dailyQuota: 50000,
    burstPerSec: 250,
    neuroProfileQuota: 10000,
    sla: '99.9% High Availability',
    description: 'High-speed automated forensics for dedicated security teams & SOC pipelines.',
    features: [
      '50,000 requests / day',
      '250 req/sec burst rate',
      'Gmail API live inbox webhook ingestion',
      '3D Infrastructure Origin Radar',
      'STIX 2.1 & SOC markdown export',
      '8-hour priority ticket SLA'
    ]
  },
  enterprise: {
    id: 'enterprise',
    name: 'Enterprise Cyber & Neural Profile',
    badge: 'ENTERPRISE DEFENSE',
    price: '$2,499',
    cadence: 'per month / billed annually',
    dailyQuota: 1000000,
    burstPerSec: 1200,
    neuroProfileQuota: 250000,
    sla: '99.999% Guaranteed Enterprise SLA',
    description: 'Mission-critical cognitive defense with dedicated high-throughput Neural Profile inference clusters.',
    features: [
      '1,000,000 requests / day (Custom unlimited available)',
      '1,200 req/sec dedicated ingress burst',
      'Neural Profile Cognitive Vulnerability & Amygdala Hijack Engine',
      'Continuous Gmail & Google Workspace stream monitoring',
      'Custom SIEM telemetry pipelines (Splunk, Sentinel, QRadar)',
      'Dedicated Customer Security Architect & 15-min SLA'
    ]
  }
};

export function ApiAccess() {
  const { t } = useLanguage();
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [currentTier, setCurrentTier] = useState<SubscriptionTier>(() => {
    return (localStorage.getItem('neuroshield_api_tier') as SubscriptionTier) || 'enterprise';
  });
  const [showTierModal, setShowTierModal] = useState<boolean>(false);
  const [showNewKeyModal, setShowNewKeyModal] = useState<boolean>(false);

  // Live simulation & quota states
  const [requestsToday, setRequestsToday] = useState<number>(142390);
  const [neuroCallsToday, setNeuroCallsToday] = useState<number>(18420);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [simulatedResponse, setSimulatedResponse] = useState<any | null>(null);

  // New key form state
  const [newKeyName, setNewKeyName] = useState<string>('');
  const [newKeyTier, setNewKeyTier] = useState<SubscriptionTier>('enterprise');
  const [newKeyScopeNeuro, setNewKeyScopeNeuro] = useState<boolean>(true);

  // Existing keys
  const [keysList, setKeysList] = useState<ApiKeyItem[]>([
    { 
      id: '1', 
      name: 'Primary Enterprise SOC Gateway', 
      key: 'sk_live_enterprise_908f4c718a2214', 
      created: '2026-01-15', 
      lastUsed: 'Just now', 
      status: 'active',
      tier: 'Enterprise',
      quotaAllocated: '1,000,000 / day',
      scopes: ['forensics:full', 'neural-profile:write', 'gmail:stream', 'siem:export']
    },
    { 
      id: '2', 
      name: 'Gmail Continuous Monitoring Webhook', 
      key: 'sk_live_webhook_b8319f3900a21d', 
      created: '2026-02-10', 
      lastUsed: '4 mins ago', 
      status: 'active',
      tier: 'Enterprise',
      quotaAllocated: '500,000 / day',
      scopes: ['gmail:stream', 'forensics:read']
    },
    { 
      id: '3', 
      name: 'Staging Integration Tester', 
      key: 'sk_test_soc_4920fcb7188b0a', 
      created: '2026-03-22', 
      lastUsed: '2 hours ago', 
      status: 'active',
      tier: 'Pro',
      quotaAllocated: '50,000 / day',
      scopes: ['forensics:full']
    },
  ]);

  const activeConfig = SUBSCRIPTION_TIERS[currentTier];

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleSelectTier = (tier: SubscriptionTier) => {
    setCurrentTier(tier);
    localStorage.setItem('neuroshield_api_tier', tier);
    setShowTierModal(false);
  };

  const handleSimulateApiCall = () => {
    setIsSimulating(true);
    setTimeout(() => {
      setRequestsToday(prev => prev + 1);
      setNeuroCallsToday(prev => prev + 1);
      setIsSimulating(false);
      setSimulatedResponse({
        status: 200,
        latency: '18ms',
        endpoint: 'POST /v1/forensics/neural-profile',
        ratelimitLimit: activeConfig.burstPerSec,
        ratelimitRemaining: activeConfig.burstPerSec - 14,
        ratelimitResetSeconds: 42,
        neuroModel: 'NeuroShield-Cognitive-v3.4-Flash',
        threatScore: 84,
        verdict: 'SUSPICIOUS_AMYGDALA_HIJACK'
      });
    }, 450);
  };

  const handleCreateNewKey = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyName.trim()) return;

    const randomHash = Math.random().toString(36).substring(2, 12) + Math.random().toString(36).substring(2, 6);
    const newKeyItem: ApiKeyItem = {
      id: Date.now().toString(),
      name: newKeyName.trim(),
      key: `sk_live_${newKeyTier}_${randomHash}`,
      created: 'Today',
      lastUsed: 'Never',
      status: 'active',
      tier: newKeyTier === 'enterprise' ? 'Enterprise' : newKeyTier === 'pro' ? 'Pro' : 'Free',
      quotaAllocated: `${SUBSCRIPTION_TIERS[newKeyTier].dailyQuota.toLocaleString()} / day`,
      scopes: newKeyScopeNeuro 
        ? ['forensics:full', 'neural-profile:write', 'gmail:stream'] 
        : ['forensics:read']
    };

    setKeysList([newKeyItem, ...keysList]);
    setNewKeyName('');
    setShowNewKeyModal(false);
  };

  const chartData = Array.from({ length: 24 }).map((_, i) => ({
    time: `${i}:00`,
    requests: Math.floor(Math.random() * 45000) + 12000,
    neuroProfileCalls: Math.floor(Math.random() * 12000) + 2000,
    errors: Math.floor(Math.random() * 8)
  }));

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.08 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 15 },
    show: { opacity: 1, y: 0, transition: { type: "spring" as any, stiffness: 300, damping: 24 } }
  };

  const percentDailyUsed = Math.min(100, Math.round((requestsToday / activeConfig.dailyQuota) * 1000) / 10);
  const percentNeuroUsed = Math.min(100, Math.round((neuroCallsToday / activeConfig.neuroProfileQuota) * 1000) / 10);

  return (
    <motion.div 
      variants={containerVariants}
      initial="hidden"
      animate="show"
      className="h-full flex flex-col p-4 sm:p-6 lg:p-8 overflow-y-auto custom-scrollbar font-mono"
    >
      {/* HEADER WITH ENTERPRISE SUBSCRIPTION STATUS */}
      <motion.div variants={itemVariants} className="mb-6 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyber-blue/10 border border-cyber-blue/30 flex items-center justify-center">
              <Terminal className="w-5 h-5 text-cyber-blue" />
            </div>
            <div>
              <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white flex items-center gap-3">
                {t('api')} & Enterprise Quotas
              </h1>
              <p className="text-xs sm:text-sm text-cyber-muted tracking-wider mt-0.5">
                Developer Ingress • Rate Limits • Neural Profile Engine Endpoints
              </p>
            </div>
          </div>
        </div>

        {/* ACTIVE PLAN BADGE & TIER SWITCHER */}
        <div className="flex items-center gap-3 bg-[#0a0f1c] border border-white/10 rounded-xl p-2.5 shadow-lg">
          <div className="flex items-center gap-2.5 px-2">
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <div>
              <div className="text-[10px] uppercase tracking-widest text-gray-400">Current Subscription</div>
              <div className="text-xs font-bold text-white flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                <span>{activeConfig.name}</span>
              </div>
            </div>
          </div>

          <button
            onClick={() => setShowTierModal(true)}
            className="px-3 py-1.5 rounded-lg text-xs font-bold bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 flex items-center gap-1.5 transition-all cursor-pointer whitespace-nowrap active:scale-95"
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>Change Tier</span>
          </button>
        </div>
      </motion.div>

      {/* ENTERPRISE SUBSCRIPTION HERO BANNER */}
      <motion.div 
        variants={itemVariants}
        className="bg-gradient-to-r from-[#0b1428] via-[#091024] to-[#150a26] border border-cyan-500/30 rounded-2xl p-5 sm:p-6 mb-6 shadow-xl relative overflow-hidden"
      >
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-md text-[10px] font-bold tracking-widest uppercase bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                {activeConfig.badge}
              </span>
              <span className="px-2.5 py-0.5 rounded-md text-[10px] font-bold tracking-widest uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                SLA: {activeConfig.sla}
              </span>
              <span className="px-2.5 py-0.5 rounded-md text-[10px] font-bold tracking-widest uppercase bg-purple-500/20 text-purple-300 border border-purple-500/30">
                Burst: {activeConfig.burstPerSec} req/sec
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              {activeConfig.name}
            </h2>
            <p className="text-xs sm:text-sm text-gray-300 font-sans max-w-3xl leading-relaxed">
              {activeConfig.description} Includes real-time Gmail inbox telemetry integration, cognitive vulnerability heuristics, and automated STIX 2.1 threat sharing.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 shrink-0 w-full lg:w-auto">
            <button
              onClick={handleSimulateApiCall}
              disabled={isSimulating}
              className="px-4 py-2.5 rounded-xl text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-black flex items-center justify-center gap-2 transition-all cursor-pointer shadow-[0_0_15px_rgba(0,245,255,0.4)] active:scale-95 disabled:opacity-50"
            >
              <Play className={cn("w-3.5 h-3.5", isSimulating && "animate-spin")} />
              <span>{isSimulating ? 'Executing...' : 'Simulate API Call'}</span>
            </button>

            <button
              onClick={() => setShowTierModal(true)}
              className="px-4 py-2.5 rounded-xl text-xs font-bold bg-white/10 hover:bg-white/20 text-white border border-white/15 flex items-center justify-center gap-2 transition-all cursor-pointer"
            >
              <span>View Enterprise Plans</span>
              <ArrowUpRight className="w-3.5 h-3.5 text-gray-400" />
            </button>
          </div>
        </div>

        {/* LIVE SIMULATION RESULT TOAST (if executed) */}
        {simulatedResponse && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            className="mt-4 pt-4 border-t border-white/10 flex flex-wrap items-center justify-between gap-3 text-xs"
          >
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/30">
                HTTP {simulatedResponse.status} OK ({simulatedResponse.latency})
              </span>
              <span className="text-gray-300 font-mono">{simulatedResponse.endpoint}</span>
            </div>
            <div className="flex items-center gap-3 text-[11px] text-gray-400">
              <span>Limit: <strong className="text-white">{simulatedResponse.ratelimitLimit}</strong></span>
              <span>Remaining: <strong className="text-cyan-300">{simulatedResponse.ratelimitRemaining}</strong></span>
              <span>Reset in: <strong className="text-purple-300">{simulatedResponse.ratelimitResetSeconds}s</strong></span>
              <span className="text-emerald-400 font-bold">{simulatedResponse.verdict}</span>
            </div>
          </motion.div>
        )}
      </motion.div>

      {/* RATE LIMIT METERS & QUOTA GAUGES */}
      <motion.div variants={itemVariants} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {/* Metric 1: Daily Requests */}
        <div className="bg-[#0a0d1a]/60 backdrop-blur-md border border-white/10 rounded-xl p-4 sm:p-5 relative overflow-hidden group hover:border-cyan-500/30 transition-all">
          <div className="flex items-center justify-between text-xs text-cyber-muted mb-2">
            <span className="uppercase tracking-widest text-[10px]">Daily Request Limit</span>
            <Gauge className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white tracking-wider">
            {requestsToday.toLocaleString()} <span className="text-xs text-gray-400 font-normal">/ {activeConfig.dailyQuota.toLocaleString()}</span>
          </div>
          <div className="w-full bg-white/5 h-2 rounded-full mt-3 overflow-hidden">
            <div 
              className="bg-cyan-500 h-full rounded-full transition-all duration-500 shadow-[0_0_10px_rgba(0,245,255,0.5)]"
              style={{ width: `${percentDailyUsed}%` }}
            />
          </div>
          <div className="flex items-center justify-between text-[10px] text-gray-400 mt-2">
            <span>{percentDailyUsed}% Consumed</span>
            <span className="text-emerald-400 font-bold">Throttling: 0%</span>
          </div>
        </div>

        {/* Metric 2: Burst Per Second */}
        <div className="bg-[#0a0d1a]/60 backdrop-blur-md border border-white/10 rounded-xl p-4 sm:p-5 relative overflow-hidden group hover:border-cyan-500/30 transition-all">
          <div className="flex items-center justify-between text-xs text-cyber-muted mb-2">
            <span className="uppercase tracking-widest text-[10px]">Burst Concurrency</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-white tracking-wider">
            48 <span className="text-xs text-gray-400 font-normal">/ {activeConfig.burstPerSec} req/sec</span>
          </div>
          <div className="w-full bg-white/5 h-2 rounded-full mt-3 overflow-hidden">
            <div 
              className="bg-amber-400 h-full rounded-full transition-all duration-500 shadow-[0_0_10px_rgba(251,191,36,0.5)]"
              style={{ width: `${Math.min(100, Math.round((48 / activeConfig.burstPerSec) * 100))}%` }}
            />
          </div>
          <div className="flex items-center justify-between text-[10px] text-gray-400 mt-2">
            <span>Safe Operating Window</span>
            <span className="text-emerald-400 font-bold">Healthy</span>
          </div>
        </div>

        {/* Metric 3: Neural Profile Calls */}
        <div className="bg-[#0a0d1a]/60 backdrop-blur-md border border-white/10 rounded-xl p-4 sm:p-5 relative overflow-hidden group hover:border-purple-500/30 transition-all">
          <div className="flex items-center justify-between text-xs text-cyber-muted mb-2">
            <span className="uppercase tracking-widest text-[10px]">Neural Profile Inferences</span>
            <Cpu className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-white tracking-wider">
            {neuroCallsToday.toLocaleString()} <span className="text-xs text-gray-400 font-normal">/ {activeConfig.neuroProfileQuota.toLocaleString()}</span>
          </div>
          <div className="w-full bg-white/5 h-2 rounded-full mt-3 overflow-hidden">
            <div 
              className="bg-purple-500 h-full rounded-full transition-all duration-500 shadow-[0_0_10px_rgba(168,85,247,0.5)]"
              style={{ width: `${percentNeuroUsed}%` }}
            />
          </div>
          <div className="flex items-center justify-between text-[10px] text-gray-400 mt-2">
            <span>{percentNeuroUsed}% Analyzed</span>
            <span className="text-purple-400 font-bold">Cognitive AI</span>
          </div>
        </div>

        {/* Metric 4: Live Latency & Edge Health */}
        <div className="bg-[#0a0d1a]/60 backdrop-blur-md border border-white/10 rounded-xl p-4 sm:p-5 relative overflow-hidden group hover:border-emerald-500/30 transition-all">
          <div className="flex items-center justify-between text-xs text-cyber-muted mb-2">
            <span className="uppercase tracking-widest text-[10px]">Avg Ingress Latency</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-white tracking-wider">
            21ms <span className="text-xs text-emerald-400 font-normal">p99: 44ms</span>
          </div>
          <div className="w-full bg-white/5 h-2 rounded-full mt-3 overflow-hidden">
            <div className="bg-emerald-500 h-full rounded-full w-[24%]" />
          </div>
          <div className="flex items-center justify-between text-[10px] text-gray-400 mt-2">
            <span>Global Anycast CDN</span>
            <span className="text-emerald-400 font-bold">99.999% SLA</span>
          </div>
        </div>
      </motion.div>

      {/* TRAFFIC MONITORING & HEADERS SECTION */}
      <motion.div variants={itemVariants} className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        {/* Real-time Usage Chart */}
        <div className="lg:col-span-2 bg-[#0a0d1a]/60 backdrop-blur-md border border-white/10 rounded-xl p-6 hover:border-cyan-500/30 transition-all">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
            <div className="flex items-center gap-2">
              <Activity className="w-5 h-5 text-cyber-blue" />
              <h2 className="text-white font-semibold tracking-wider">{t('api_usage')} (24-Hour Telemetry)</h2>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <div className="flex items-center gap-1.5 text-cyan-400">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block" />
                <span>REST Requests</span>
              </div>
              <div className="flex items-center gap-1.5 text-purple-400">
                <span className="w-2.5 h-2.5 rounded-full bg-purple-400 inline-block" />
                <span>Neural Profile Calls</span>
              </div>
            </div>
          </div>
          
          <div className="h-[240px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 0, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorRequests" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00f5ff" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#00f5ff" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorNeuro" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#a855f7" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#a855f7" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                <XAxis dataKey="time" stroke="#4a5568" fontSize={10} tickMargin={10} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#060A13', borderColor: '#1a2235', fontSize: '12px' }}
                  itemStyle={{ color: '#00f5ff' }}
                />
                <Area type="monotone" dataKey="requests" stroke="#00f5ff" fillOpacity={1} fill="url(#colorRequests)" name="Requests" />
                <Area type="monotone" dataKey="neuroProfileCalls" stroke="#a855f7" fillOpacity={1} fill="url(#colorNeuro)" name="Neuro Inferences" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* HTTP Rate Limit Protocol Headers Inspector */}
        <div className="bg-[#0a0d1a]/60 backdrop-blur-md border border-white/10 rounded-xl p-6 flex flex-col justify-between hover:border-white/20 transition-all">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2 text-white">
                <Server className="w-5 h-5 text-cyan-400" />
                <h3 className="font-semibold text-sm tracking-wider">Rate Limit Headers</h3>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono border border-emerald-500/30">
                IETF DRAFT-7
              </span>
            </div>

            <p className="text-xs text-gray-400 font-sans mb-4">
              Inspect headers emitted on every API response to orchestrate client-side backoff and retry budgets:
            </p>

            <div className="bg-black/60 rounded-lg p-3.5 font-mono text-xs space-y-2 border border-white/5 text-gray-300">
              <div className="flex justify-between border-b border-white/5 pb-1">
                <span className="text-cyan-400">RateLimit-Limit:</span>
                <span className="text-white font-bold">{activeConfig.burstPerSec}</span>
              </div>
              <div className="flex justify-between border-b border-white/5 pb-1">
                <span className="text-cyan-400">RateLimit-Remaining:</span>
                <span className="text-emerald-400 font-bold">{activeConfig.burstPerSec - 14}</span>
              </div>
              <div className="flex justify-between border-b border-white/5 pb-1">
                <span className="text-cyan-400">RateLimit-Reset:</span>
                <span className="text-purple-400 font-bold">42s (Rolling Window)</span>
              </div>
              <div className="flex justify-between border-b border-white/5 pb-1">
                <span className="text-cyan-400">RateLimit-Policy:</span>
                <span className="text-gray-400 font-mono text-[11px]">{activeConfig.burstPerSec};w=1</span>
              </div>
              <div className="flex justify-between">
                <span className="text-cyan-400">X-Subscription-Tier:</span>
                <span className="text-white font-bold">{activeConfig.badge}</span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-4 border-t border-white/10 flex items-center justify-between text-[11px] text-gray-400">
            <span>Auto-Retry-After Header: Supported</span>
            <span className="text-cyan-400 cursor-pointer hover:underline" onClick={() => setShowTierModal(true)}>Upgrade Limits</span>
          </div>
        </div>
      </motion.div>

      {/* API KEYS TABLE & REST ENDPOINTS */}
      <motion.div variants={itemVariants} className="grid grid-cols-1 lg:grid-cols-2 gap-6 pb-6">
        {/* Active API Keys List */}
        <div className="bg-[#0a0d1a]/60 backdrop-blur-md border border-white/10 rounded-xl p-6 hover:border-white/20 transition-all">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <Key className="w-5 h-5 text-cyber-blue" />
              <h2 className="text-white font-semibold tracking-wider">{t('api_keys')}</h2>
            </div>
            <button 
              onClick={() => setShowNewKeyModal(true)}
              className="bg-cyber-blue/15 hover:bg-cyber-blue/25 text-cyber-blue border border-cyber-blue/40 px-3.5 py-1.5 rounded-lg text-xs font-bold tracking-wider transition-all flex items-center gap-2 cursor-pointer active:scale-95 shadow-[0_0_10px_rgba(0,245,255,0.2)]"
            >
              <Zap className="w-3.5 h-3.5" />
              GENERATE NEW KEY
            </button>
          </div>
          
          <div className="space-y-3">
            {keysList.map((k) => (
              <div 
                key={k.id}
                className="bg-black/40 border border-white/5 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:border-white/20 transition-all"
              >
                <div className="space-y-1.5 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm text-white font-bold">{k.name}</span>
                    <span className={cn(
                      "px-1.5 py-0.5 rounded text-[9px] uppercase tracking-wider font-bold",
                      k.status === 'active' 
                        ? "bg-cyber-green/10 text-cyber-green border border-cyber-green/30" 
                        : "bg-red-500/10 text-red-400 border border-red-500/30"
                    )}>
                      {k.status}
                    </span>
                    <span className="px-1.5 py-0.5 rounded text-[9px] uppercase tracking-wider bg-purple-500/15 text-purple-300 border border-purple-500/30">
                      {k.tier} Tier
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-3 text-xs text-cyber-muted font-mono">
                    <span className="text-cyan-300">{k.key}</span>
                    <span>Quota: {k.quotaAllocated}</span>
                    <span>Used: {k.lastUsed}</span>
                  </div>

                  {/* Scopes */}
                  <div className="flex flex-wrap items-center gap-1 pt-1">
                    {k.scopes.map(scope => (
                      <span key={scope} className="text-[10px] px-1.5 py-0.2 rounded bg-white/5 text-gray-400 font-mono">
                        {scope}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end sm:self-center">
                  <button 
                    onClick={() => handleCopy(k.key, k.id)}
                    disabled={k.status !== 'active'}
                    className={cn(
                      "p-2 rounded-lg border transition-all cursor-pointer",
                      k.status === 'active' 
                        ? "bg-white/5 hover:bg-white/10 text-cyber-blue border-white/10" 
                        : "text-cyber-muted/30 border-transparent cursor-not-allowed"
                    )}
                    title="Copy Key to Clipboard"
                  >
                    {copiedKey === k.id ? <CheckCircle2 className="w-4 h-4 text-cyber-green" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* REST Endpoints (Including Neural Profile & Gmail Sync Webhooks) */}
        <div className="bg-[#0a0d1a]/60 backdrop-blur-md border border-white/10 rounded-xl p-6 hover:border-white/20 transition-all">
          <div className="flex items-center gap-2 mb-6 text-white">
            <Database className="w-5 h-5 text-cyber-blue" />
            <h2 className="font-semibold tracking-wider">{t('rest_endpoints')} & Webhooks</h2>
          </div>
          
          <div className="space-y-4">
            {/* Endpoint 1: Neural Profile */}
            <div className="bg-black/60 rounded-xl overflow-hidden border border-purple-500/30 hover:border-purple-500/50 transition-colors">
              <div className="px-4 py-2.5 bg-purple-950/20 text-xs text-purple-300 font-mono flex justify-between items-center border-b border-purple-500/20">
                <span className="font-bold">POST /v1/forensics/neural-profile</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">Enterprise Only</span>
              </div>
              <div className="p-4 font-mono text-xs overflow-x-auto text-purple-300 leading-relaxed">
                curl -X POST https://api.neuroshield.cyber/v1/forensics/neural-profile \<br/>
                &nbsp;&nbsp;-H "Authorization: Bearer $NEUROSHIELD_KEY" \<br/>
                &nbsp;&nbsp;-H "Content-Type: application/json" \<br/>
                &nbsp;&nbsp;-d '&#123;"subject": "Urgent wire", "body": "...", "sender": "..."&#125;'
              </div>
            </div>

            {/* Endpoint 2: Full Email Forensics */}
            <div className="bg-black/60 rounded-xl overflow-hidden border border-white/10 hover:border-cyber-blue/30 transition-colors">
              <div className="px-4 py-2.5 bg-white/5 text-xs text-cyber-muted font-mono flex justify-between items-center border-b border-white/5">
                <span>POST /v1/scan/email</span>
                <span className="text-cyber-blue text-[11px]">Auth: Bearer</span>
              </div>
              <div className="p-4 font-mono text-xs overflow-x-auto text-emerald-400 leading-relaxed">
                curl -X POST https://api.neuroshield.cyber/v1/scan/email \<br/>
                &nbsp;&nbsp;-H "Authorization: Bearer $NEUROSHIELD_KEY" \<br/>
                &nbsp;&nbsp;-d '&#123;"rawHeaders": "...", "rfcBody": "..."&#125;'
              </div>
            </div>

            {/* Endpoint 3: Gmail Webhook Stream */}
            <div className="bg-black/60 rounded-xl overflow-hidden border border-white/10 hover:border-cyan-500/30 transition-colors">
              <div className="px-4 py-2.5 bg-white/5 text-xs text-cyber-muted font-mono flex justify-between items-center border-b border-white/5">
                 <span>GET /v1/gmail/stream-webhook</span>
                 <span className="text-cyan-400 text-[11px]">SSE / WebSocket</span>
              </div>
              <div className="p-4 font-mono text-[11px] text-gray-400">
                Continuous Gmail message event push listener. Automatically pushes incoming messages into the forensics analysis queue in under 35ms.
              </div>
            </div>
          </div>
        </div>
      </motion.div>

      {/* SUBSCRIPTION TIER SELECTION MODAL */}
      <AnimatePresence>
        {showTierModal && (
          <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 overflow-y-auto">
            <motion.div 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-5xl bg-[#080d1a] border border-cyan-500/40 rounded-2xl p-6 sm:p-8 shadow-2xl relative"
            >
              <button
                onClick={() => setShowTierModal(false)}
                className="absolute top-4 right-4 text-gray-400 hover:text-white p-1 rounded-lg bg-white/5 hover:bg-white/10 transition-all cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>

              <div className="text-center mb-8 space-y-2">
                <span className="px-3 py-1 rounded-full text-xs font-bold uppercase tracking-widest bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                  Enterprise Subscription Tiers
                </span>
                <h3 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
                  Choose Your Forensics API Quota Tier
                </h3>
                <p className="text-sm text-gray-400 font-sans max-w-2xl mx-auto">
                  Scale your automated email threat defense with dedicated throughput, SLA guarantees, and cognitive Neural Profile analysis.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {(Object.keys(SUBSCRIPTION_TIERS) as SubscriptionTier[]).map((tierKey) => {
                  const t = SUBSCRIPTION_TIERS[tierKey];
                  const isCurrent = currentTier === tierKey;

                  return (
                    <div
                      key={tierKey}
                      className={cn(
                        "rounded-2xl p-6 flex flex-col justify-between border transition-all relative",
                        isCurrent 
                          ? "bg-[#0c1833] border-cyan-400 shadow-[0_0_25px_rgba(0,245,255,0.2)]" 
                          : "bg-black/40 border-white/10 hover:border-white/20"
                      )}
                    >
                      {isCurrent && (
                        <span className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full text-[10px] font-bold bg-cyan-400 text-black shadow-md uppercase tracking-wider">
                          Active Subscription
                        </span>
                      )}

                      <div className="space-y-4">
                        <div>
                          <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-400 block mb-1">
                            {t.badge}
                          </span>
                          <h4 className="text-lg font-bold text-white">{t.name}</h4>
                          <p className="text-xs text-gray-400 font-sans mt-1">{t.description}</p>
                        </div>

                        <div className="pt-2 border-t border-white/10">
                          <div className="text-3xl font-bold text-white font-sans">{t.price}</div>
                          <div className="text-xs text-gray-400">{t.cadence}</div>
                        </div>

                        <div className="space-y-2 pt-2 border-t border-white/10">
                          {t.features.map((feature, idx) => (
                            <div key={idx} className="flex items-start gap-2 text-xs text-gray-300 font-sans">
                              <Check className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                              <span>{feature}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div className="pt-6">
                        <button
                          onClick={() => handleSelectTier(tierKey)}
                          disabled={isCurrent}
                          className={cn(
                            "w-full py-2.5 rounded-xl text-xs font-bold transition-all cursor-pointer",
                            isCurrent
                              ? "bg-white/10 text-gray-400 cursor-default"
                              : "bg-cyan-500 hover:bg-cyan-400 text-black shadow-[0_0_15px_rgba(0,245,255,0.4)] active:scale-95"
                          )}
                        >
                          {isCurrent ? 'Current Plan' : `Switch to ${t.name}`}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* GENERATE NEW API KEY MODAL */}
      <AnimatePresence>
        {showNewKeyModal && (
          <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-lg bg-[#080d1a] border border-cyan-500/40 rounded-2xl p-6 shadow-2xl relative"
            >
              <button
                onClick={() => setShowNewKeyModal(false)}
                className="absolute top-4 right-4 text-gray-400 hover:text-white p-1 rounded-lg bg-white/5 hover:bg-white/10 transition-all cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>

              <div className="flex items-center gap-3 mb-5">
                <div className="w-10 h-10 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center">
                  <Key className="w-5 h-5 text-cyan-400" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white">Generate Enterprise API Key</h3>
                  <p className="text-xs text-gray-400 font-sans">Set name, quotas, and service scopes</p>
                </div>
              </div>

              <form onSubmit={handleCreateNewKey} className="space-y-4">
                <div>
                  <label className="text-xs font-bold text-gray-300 block mb-1">Key Description / Service Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Gmail Threat Ingest Webhook"
                    value={newKeyName}
                    onChange={(e) => setNewKeyName(e.target.value)}
                    className="w-full bg-black/60 border border-white/15 rounded-xl px-4 py-2.5 text-xs text-white focus:outline-none focus:border-cyan-400 font-mono"
                  />
                </div>

                <div>
                  <label className="text-xs font-bold text-gray-300 block mb-1">Assigned Quota Tier</label>
                  <select
                    value={newKeyTier}
                    onChange={(e) => setNewKeyTier(e.target.value as SubscriptionTier)}
                    className="w-full bg-black/60 border border-white/15 rounded-xl px-4 py-2.5 text-xs text-white focus:outline-none focus:border-cyan-400 font-mono"
                  >
                    <option value="enterprise">Enterprise (1,000,000 req/day • 1,200 burst/sec)</option>
                    <option value="pro">Professional (50,000 req/day • 250 burst/sec)</option>
                    <option value="free">Community (1,000 req/day • 10 burst/sec)</option>
                  </select>
                </div>

                <div className="pt-2">
                  <label className="text-xs font-bold text-gray-300 block mb-2">Scope Permissions</label>
                  <div className="space-y-2">
                    <label className="flex items-center gap-2.5 text-xs text-gray-300 font-sans cursor-pointer">
                      <input
                        type="checkbox"
                        checked={newKeyScopeNeuro}
                        onChange={(e) => setNewKeyScopeNeuro(e.target.checked)}
                        className="rounded accent-cyan-400"
                      />
                      <span>Enable Neural Profile Cognitive Vulnerability API access</span>
                    </label>
                    <label className="flex items-center gap-2.5 text-xs text-gray-300 font-sans cursor-pointer">
                      <input
                        type="checkbox"
                        defaultChecked
                        className="rounded accent-cyan-400"
                      />
                      <span>Enable RFC 5322 Inbound Header Forensics Scan</span>
                    </label>
                  </div>
                </div>

                <div className="pt-4 flex items-center justify-end gap-3">
                  <button
                    type="button"
                    onClick={() => setShowNewKeyModal(false)}
                    className="px-4 py-2 rounded-xl text-xs font-bold text-gray-400 hover:text-white bg-white/5 hover:bg-white/10 transition-all cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-5 py-2 rounded-xl text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-black transition-all cursor-pointer shadow-[0_0_15px_rgba(0,245,255,0.4)] active:scale-95"
                  >
                    Create Key
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
