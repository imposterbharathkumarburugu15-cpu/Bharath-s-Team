import React, { useState } from 'react';
import { motion } from 'motion/react';
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
  Activity
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { ResponsiveContainer, AreaChart, Area, XAxis, Tooltip, CartesianGrid } from 'recharts';

export function ApiAccess() {
  const { t } = useLanguage();
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const mockKeys = [
    { id: '1', name: 'Production Gateway', key: 'sk_live_...e8f9a', created: '2026-01-15', lastUsed: '2 mins ago', status: 'active' },
    { id: '2', name: 'Staging Env', key: 'sk_test_...b3c4d', created: '2026-03-22', lastUsed: '5 hours ago', status: 'active' },
    { id: '3', name: 'Legacy Auth V1', key: 'sk_live_...9f2b1', created: '2025-11-04', lastUsed: '1 month ago', status: 'revoked' },
  ];

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const chartData = Array.from({ length: 24 }).map((_, i) => ({
    time: `${i}:00`,
    requests: Math.floor(Math.random() * 50000) + 10000,
    errors: Math.floor(Math.random() * 50)
  }));

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.1 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0, transition: { type: "spring" as any, stiffness: 300, damping: 24 } }
  };

  return (
    <motion.div 
      variants={containerVariants}
      initial="hidden"
      animate="show"
      className="h-full flex flex-col p-6 overflow-y-auto custom-scrollbar"
    >
      <motion.div variants={itemVariants} className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
          <Terminal className="w-8 h-8 text-cyber-blue" />
          {t('api')}
        </h1>
        <p className="text-sm text-cyber-muted tracking-widest mt-2 uppercase">
          Enterprise Integration Gateway • v3.1.0-stable
        </p>
      </motion.div>

      <motion.div variants={itemVariants} className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        {/* API Usage Chart */}
        <div className="lg:col-span-2 bg-[#0a0d1a]/50 backdrop-blur-md border border-white/5 rounded-xl p-6 group hover:border-cyber-blue/30 transition-colors">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <Activity className="w-5 h-5 text-cyber-blue group-hover:scale-110 transition-transform" />
              <h2 className="text-white font-semibold tracking-wider">{t('api_usage')}</h2>
            </div>
            <div className="text-xs text-cyber-green flex items-center gap-1.5 bg-cyber-green/10 border border-cyber-green/30 px-2 py-1 rounded">
              <div className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
              99.99% UPTIME
            </div>
          </div>
          
          <div className="h-[250px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 0, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorRequests" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00f5ff" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#00f5ff" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                <XAxis dataKey="time" stroke="#4a5568" fontSize={10} tickMargin={10} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#060A13', borderColor: '#1a2235', fontSize: '12px' }}
                  itemStyle={{ color: '#00f5ff' }}
                />
                <Area type="monotone" dataKey="requests" stroke="#00f5ff" fillOpacity={1} fill="url(#colorRequests)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="flex flex-col gap-6">
          <div className="bg-[#0a0d1a]/50 backdrop-blur-md border border-white/5 rounded-xl p-6 flex-1 flex flex-col justify-center relative overflow-hidden group hover:border-cyber-blue/30 transition-colors">
            <div className="absolute inset-0 bg-gradient-to-br from-cyber-blue/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="text-cyber-muted text-xs tracking-widest uppercase mb-2">Total Requests (24h)</div>
            <div className="text-4xl font-bold text-white tracking-widest text-shadow-[0_0_15px_rgba(0,245,255,0.3)] group-hover:scale-105 origin-left transition-transform">
              1.24M
            </div>
            <div className="text-cyber-green text-xs mt-2 flex items-center gap-1">
              <span>+12.5%</span> from yesterday
            </div>
          </div>
          
          <div className="bg-[#0a0d1a]/50 backdrop-blur-md border border-white/5 rounded-xl p-6 flex-1 flex flex-col justify-center relative overflow-hidden group hover:border-cyber-red/30 transition-colors">
             <div className="absolute inset-0 bg-gradient-to-br from-cyber-red/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="text-cyber-muted text-xs tracking-widest uppercase mb-2">Average Latency</div>
            <div className="text-4xl font-bold text-white tracking-widest text-shadow-[0_0_15px_rgba(255,255,255,0.1)] group-hover:scale-105 origin-left transition-transform">
              42ms
            </div>
            <div className="text-cyber-muted text-xs mt-2 flex items-center gap-1">
              Global Edge Network
            </div>
          </div>
        </div>
      </motion.div>

      <motion.div variants={itemVariants} className="grid grid-cols-1 lg:grid-cols-2 gap-6 pb-6">
        {/* API Keys Table */}
        <div className="bg-[#0a0d1a]/50 backdrop-blur-md border border-white/5 rounded-xl p-6 group hover:border-white/20 transition-colors">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <Key className="w-5 h-5 text-cyber-blue group-hover:rotate-12 transition-transform" />
              <h2 className="text-white font-semibold tracking-wider">{t('api_keys')}</h2>
            </div>
            <button className="bg-cyber-blue/10 hover:bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 px-3 py-1.5 rounded text-xs font-bold tracking-wider transition-colors flex items-center gap-2">
              <Zap className="w-3.5 h-3.5" />
              GENERATE NEW KEY
            </button>
          </div>
          
          <div className="space-y-3">
            {mockKeys.map((k, i) => (
              <motion.div 
                key={k.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.1 }}
                className="bg-black/40 border border-white/5 rounded-lg p-4 flex items-center justify-between hover:border-white/20 transition-colors"
              >
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm text-white font-medium">{k.name}</span>
                    {k.status === 'active' ? (
                      <span className="px-1.5 py-0.5 rounded text-[9px] uppercase tracking-wider bg-cyber-green/10 text-cyber-green border border-cyber-green/20">Active</span>
                    ) : (
                      <span className="px-1.5 py-0.5 rounded text-[9px] uppercase tracking-wider bg-[#ff2e5b]/10 text-[#ff2e5b] border border-[#ff2e5b]/20">Revoked</span>
                    )}
                  </div>
                  <div className="flex items-center gap-4 text-xs text-cyber-muted">
                    <span className="font-mono">{k.key}</span>
                    <span>Created: {k.created}</span>
                    <span>Last used: {k.lastUsed}</span>
                  </div>
                </div>
                <button 
                  onClick={() => handleCopy(k.key, k.id)}
                  disabled={k.status !== 'active'}
                  className={cn(
                    "p-2 rounded transition-colors group/btn",
                    k.status === 'active' ? "hover:bg-white/10 text-cyber-blue" : "text-cyber-muted/30 cursor-not-allowed"
                  )}
                >
                  {copiedKey === k.id ? <CheckCircle2 className="w-4 h-4 text-cyber-green" /> : <Copy className="w-4 h-4 group-hover/btn:scale-110 transition-transform" />}
                </button>
              </motion.div>
            ))}
          </div>
        </div>

        {/* Quick Start / Endpoints */}
        <div className="bg-[#0a0d1a]/50 backdrop-blur-md border border-white/5 rounded-xl p-6 hover:border-white/20 transition-colors">
          <div className="flex items-center gap-2 mb-6 text-white">
            <Database className="w-5 h-5 text-cyber-blue" />
            <h2 className="font-semibold tracking-wider">REST Endpoints</h2>
          </div>
          
          <div className="space-y-4">
            <div className="bg-black/60 rounded-lg overflow-hidden border border-white/5 hover:border-cyber-blue/30 transition-colors">
              <div className="px-4 py-2 bg-white/5 text-xs text-cyber-muted tracking-widest font-mono flex justify-between items-center border-b border-white/5">
                <span>POST /v1/scan</span>
                <span className="text-cyber-blue">Auth: Bearer</span>
              </div>
              <div className="p-4 font-mono text-xs overflow-x-auto text-green-400">
                curl -X POST https://api.neuroshield.cyber/v1/scan \<br/>
                &nbsp;&nbsp;-H "Authorization: Bearer $NEUROSHIELD_API_KEY" \<br/>
                &nbsp;&nbsp;-H "Content-Type: application/json" \<br/>
                &nbsp;&nbsp;-d '&#123;"payload": "URL_OR_TEXT_HERE"&#125;'
              </div>
            </div>

            <div className="bg-black/60 rounded-lg overflow-hidden border border-white/5 hover:border-cyan-500/30 transition-colors">
              <div className="px-4 py-2 bg-white/5 text-xs text-cyber-muted tracking-widest font-mono flex justify-between items-center border-b border-white/5">
                 <span>GET /v1/intel/lookup</span>
                 <span className="text-cyber-blue">Auth: Bearer</span>
              </div>
               <div className="p-4 font-mono text-[11px] text-cyber-muted hover:text-white transition-colors">
                 Query the global threat intelligence database for known malicious IoCs (IPs, domains, hashes). Rate limit: 1000/min.
               </div>
            </div>
            
            <button className="w-full py-3 bg-white/5 hover:bg-cyber-blue/10 border border-white/10 hover:border-cyber-blue/50 transition-colors rounded-lg flex items-center justify-center gap-2 text-sm text-white tracking-widest group">
               <Shield className="w-4 h-4 text-cyber-blue group-hover:scale-125 transition-transform" />
               VIEW FULL DOCUMENTATION
            </button>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}
