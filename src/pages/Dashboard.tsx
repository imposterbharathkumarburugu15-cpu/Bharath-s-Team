import React, { useEffect, useState } from 'react';
import { motion } from 'motion/react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Mail, ShieldAlert, Globe, Activity, ArrowUpRight, Mic, Waves } from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  PieChart, Pie, Cell
} from 'recharts';
import { useLanguage } from '@/contexts/LanguageContext';
import { getScanHistory, ScanHistoryItem } from '@/lib/history';

const timelineData = [
  { time: '00:00', safe: 1200, suspicious: 400, phishing: 120 },
  { time: '04:00', safe: 800, suspicious: 200, phishing: 80 },
  { time: '08:00', safe: 3400, suspicious: 800, phishing: 250 },
  { time: '12:00', safe: 4500, suspicious: 1200, phishing: 400 },
  { time: '16:00', safe: 3800, suspicious: 900, phishing: 300 },
  { time: '20:00', safe: 2100, suspicious: 500, phishing: 150 },
  { time: '24:00', safe: 1500, suspicious: 300, phishing: 90 },
];

const liveThreats: Array<{ id: string, type: string, source: string, target: string, risk: string, time: string, score?: number }> = [
  { id: 'TR-9921', type: 'Email', source: 'billing@paypaI-support.com', target: 'finance@corp.com', risk: 'high_risk', time: '2m ago' },
  { id: 'TR-9920', type: 'Chat', source: 'Telegram Bot (+44...)', target: 'Employee Support Group', risk: 'high_risk', time: '5m ago' },
  { id: 'TR-9919', type: 'URL', source: 'http://docs-update-portal-login.net', target: 'N/A', risk: 'high_risk', time: '12m ago' },
  { id: 'TR-9918', type: 'Email', source: 'hr-benefits@company-portal.net', target: 'all-staff@corp.com', risk: 'high_risk', time: '18m ago' },
  { id: 'TR-9917', type: 'Chat', source: 'WhatsApp / Unknown', target: 'exec-team', risk: 'medium_risk', time: '25m ago' },
];

export function Dashboard() {
  const { t } = useLanguage();
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);

  useEffect(() => {
    setHistory(getScanHistory());
    
    // Optional polling for new scans
    const interval = setInterval(() => {
      setHistory(getScanHistory());
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const displayedThreats = history.length > 0 ? history.slice(0, 10).map(item => {
    // Determine risk level based on score
    let riskLevel = 'low_risk';
    if (item.riskScore >= 75) riskLevel = 'high_risk';
    else if (item.riskScore >= 40) riskLevel = 'medium_risk';
    
    // Format relative time (basic)
    const diffMs = new Date().getTime() - new Date(item.timestamp).getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const timeStr = diffMins === 0 ? 'Just now' : diffMins < 60 ? `${diffMins}m ago` : `${Math.floor(diffMins/60)}h ago`;

    return {
      id: item.id,
      type: item.detectedType || 'UNKNOWN',
      source: item.source || 'N/A',
      target: item.target || 'N/A',
      risk: riskLevel,
      score: item.riskScore,
      time: timeStr
    };
  }) : liveThreats; // fallback to fake data if no history

  const riskData = [
    { name: t('low_risk'), value: 75, color: 'var(--color-cyber-green)' },
    { name: t('medium_risk'), value: 15, color: '#f59e0b' },
    { name: t('high_risk'), value: 10, color: 'var(--color-cyber-red)' },
  ];

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1
      }
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
      className="flex flex-col space-y-6"
    >
      <motion.div variants={itemVariants} className="flex justify-between items-end">
        <div>
          <h2 className="text-[18px] font-semibold text-cyber-text tracking-tight mb-1">{t('dashboard').toUpperCase()}</h2>
          <p className="text-[#8a99af] text-sm">Global threat overview and active anomaly detection.</p>
        </div>
      </motion.div>

      {/* KPI Cards */}
      <motion.div variants={itemVariants} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="relative overflow-hidden bg-cyber-panel/80 border-cyber-border/30 hover:border-cyber-blue/50 group transition-all duration-500">
          <div className="absolute inset-0 bg-gradient-to-br from-cyber-blue/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
          <div className="absolute top-0 left-0 w-2 h-full bg-cyber-blue shadow-[0_0_15px_var(--color-cyber-blue-glow)]" />
          <CardContent className="p-6 pl-8 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-sans uppercase tracking-widest text-[#5e738c] mb-2">{t('total_threats').toUpperCase()}</p>
              <h3 className="text-3xl font-mono font-bold text-white drop-shadow-[0_0_10px_rgba(255,255,255,0.3)] group-hover:text-cyber-blue transition-colors">1,482,903</h3>
              <div className="flex items-center gap-1 text-[10px] text-cyber-green mt-2 font-mono font-semibold">
                <ArrowUpRight className="w-3 h-3" />
                <span>+12% vs last 24h</span>
              </div>
            </div>
            <div className="w-12 h-12 rounded-full border border-cyber-border/30 bg-cyber-panel flex items-center justify-center relative shadow-[inset_0_0_10px_rgba(0,243,255,0.1)] group-hover:border-cyber-blue/50 transition-colors">
              <Globe className="w-5 h-5 text-cyber-blue opacity-80" />
            </div>
          </CardContent>
        </Card>

        <Card className="relative overflow-hidden bg-cyber-panel/80 border-cyber-border/30 hover:border-cyber-red/50 group transition-all duration-500">
          <div className="absolute inset-0 bg-gradient-to-br from-cyber-red/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
          <div className="absolute top-0 left-0 w-2 h-full bg-cyber-red shadow-[0_0_15px_rgba(255,42,85,0.6)]" />
          <CardContent className="p-6 pl-8 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-sans uppercase tracking-widest text-[#5e738c] mb-2">{t('blocked_attacks').toUpperCase()}</p>
              <h3 className="text-3xl font-mono font-bold text-white drop-shadow-[0_0_10px_rgba(255,255,255,0.3)] group-hover:text-cyber-red transition-colors">4,291</h3>
              <div className="flex items-center gap-1 text-[10px] text-cyber-red mt-2 font-mono font-semibold">
                <ArrowUpRight className="w-3 h-3" />
                <span>+4.3% surge detected</span>
              </div>
            </div>
            <div className="w-12 h-12 rounded-full border border-cyber-border/30 bg-cyber-panel flex items-center justify-center relative shadow-[inset_0_0_10px_rgba(255,42,85,0.1)] group-hover:border-cyber-red/50 transition-colors">
              <ShieldAlert className="w-5 h-5 text-cyber-red opacity-80" />
            </div>
          </CardContent>
        </Card>

        <Card className="relative overflow-hidden bg-cyber-panel/80 border-cyber-border/30 hover:border-[#f59e0b]/50 group transition-all duration-500">
          <div className="absolute inset-0 bg-gradient-to-br from-[#f59e0b]/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
          <div className="absolute top-0 left-0 w-2 h-full bg-[#f59e0b] shadow-[0_0_15px_rgba(245,158,11,0.6)]" />
          <CardContent className="p-6 pl-8 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-sans uppercase tracking-widest text-[#5e738c] mb-2">MALICIOUS DOMAINS</p>
              <h3 className="text-3xl font-mono font-bold text-white drop-shadow-[0_0_10px_rgba(255,255,255,0.3)] group-hover:text-[#f59e0b] transition-colors">12,804</h3>
              <div className="flex items-center gap-1 text-[10px] text-cyber-muted mt-2 font-mono">
                <Activity className="w-3 h-3 text-[#f59e0b]" />
                <span>Active intelligence feed</span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="relative overflow-hidden bg-cyber-panel/80 border-cyber-border/30 hover:border-[#a855f7]/50 group transition-all duration-500">
          <div className="absolute inset-0 bg-gradient-to-br from-[#a855f7]/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
          <div className="absolute top-0 left-0 w-2 h-full bg-[#a855f7] shadow-[0_0_15px_rgba(168,85,247,0.6)]" />
          <CardContent className="p-6 pl-8 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-sans uppercase tracking-widest text-[#5e738c] mb-2">AVG DETECTION TIME</p>
              <h3 className="text-3xl font-mono font-bold text-white drop-shadow-[0_0_10px_rgba(255,255,255,0.3)] group-hover:text-[#a855f7] transition-colors">420ms</h3>
              <div className="flex items-center gap-1 text-[10px] text-[#a855f7] mt-2 font-mono font-semibold tracking-widest">
                <span className="w-1.5 h-1.5 rounded-full bg-[#a855f7] animate-pulse" />
                AI OPTIMIZED
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      <motion.div variants={itemVariants} className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Chart */}
        <Card className="col-span-1 lg:col-span-2 relative overflow-hidden bg-cyber-panel/80 border-cyber-border/30 hover:border-cyber-blue/50 group transition-all duration-500">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-100 transition-opacity">
            <svg width="60" height="60" viewBox="0 0 100 100" className="animate-[spin_40s_linear_infinite]">
              <polygon points="50 0 100 25 100 75 50 100 0 75 0 25" fill="none" stroke="var(--color-cyber-blue)" strokeWidth="1" strokeDasharray="4 4" />
            </svg>
          </div>
          <CardHeader>
            <CardTitle className="text-sm tracking-widest text-[#5e738c] font-sans">ATTACK TIMELINE (24H)</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px] w-full transition-transform duration-500">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorPhishing" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--color-cyber-red)" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="var(--color-cyber-red)" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorSuspicious" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.6}/>
                      <stop offset="95%" stopColor="#f59e0b" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorSafe" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--color-cyber-blue)" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="var(--color-cyber-blue)" stopOpacity={0}/>
                    </linearGradient>
                    <filter id="glowChart" x="-20%" y="-20%" width="140%" height="140%">
                      <feGaussianBlur stdDeviation="4" result="blur" />
                      <feComposite in="SourceGraphic" in2="blur" operator="over" />
                    </filter>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--color-cyber-border)" vertical={false} opacity={0.2} />
                  <XAxis dataKey="time" stroke="var(--color-cyber-muted)" fontSize={12} tickLine={false} axisLine={false} />
                  <YAxis stroke="var(--color-cyber-muted)" fontSize={12} tickLine={false} axisLine={false} />
                  <RechartsTooltip 
                    contentStyle={{ backgroundColor: 'rgba(8, 14, 23, 0.95)', borderColor: 'var(--color-cyber-border)', borderRadius: '8px', boxShadow: '0 0 15px rgba(0, 243, 255, 0.3)' }}
                    itemStyle={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}
                    labelStyle={{ color: 'var(--color-cyber-muted)', marginBottom: '4px' }}
                  />
                  <Area type="monotone" dataKey="safe" stackId="1" stroke="var(--color-cyber-blue)" strokeWidth={2} fill="url(#colorSafe)" filter="url(#glowChart)" />
                  <Area type="monotone" dataKey="suspicious" stackId="1" stroke="#f59e0b" strokeWidth={2} fill="url(#colorSuspicious)" filter="url(#glowChart)" />
                  <Area type="monotone" dataKey="phishing" stackId="1" stroke="var(--color-cyber-red)" strokeWidth={2} fill="url(#colorPhishing)" filter="url(#glowChart)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Risk Donut */}
        <Card className="col-span-1 relative overflow-hidden bg-cyber-panel/80 border-cyber-border/30 hover:border-cyber-blue/50 group transition-all duration-500 flex flex-col justify-between">
          <CardHeader>
            <CardTitle className="text-sm tracking-widest text-[#5e738c] font-sans">RISK DISTRIBUTION</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col items-center justify-center flex-1">
             <div className="h-[220px] w-full relative">
              {/* Radar pulse behind chart */}
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-32 h-32 rounded-full border border-cyber-border opacity-20 animate-ping" />
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-48 h-48 rounded-full border border-cyber-border opacity-10 animate-ping" style={{ animationDelay: '0.5s' }} />
              
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={riskData}
                    cx="50%"
                    cy="50%"
                    innerRadius={70}
                    outerRadius={90}
                    paddingAngle={8}
                    dataKey="value"
                    stroke="none"
                    cornerRadius={4}
                  >
                    {riskData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} style={{ filter: `drop-shadow(0 0 8px ${entry.color}80)` }} />
                    ))}
                  </Pie>
                  <RechartsTooltip 
                    contentStyle={{ backgroundColor: 'rgba(8, 14, 23, 0.95)', borderColor: 'var(--color-cyber-border)', borderRadius: '8px', border: '1px solid', boxShadow: '0 0 15px rgba(0, 243, 255, 0.3)' }}
                    itemStyle={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center justify-center text-center">
                <span className="text-3xl font-mono font-bold text-white drop-shadow-[0_0_10px_rgba(255,255,255,0.5)]">75%</span>
                <span className="text-[9px] text-[#00ff66] tracking-widest uppercase">SAFE</span>
              </div>
             </div>
             <div className="flex space-x-4 mt-6 flex-wrap justify-center font-mono text-xs gap-y-2 w-full px-4">
                {riskData.map(d => (
                  <div key={d.name} className="flex items-center">
                    <span className="w-2 h-2 rounded-full mr-2 shadow-sm" style={{ backgroundColor: d.color, boxShadow: `0 0 5px ${d.color}` }}></span>
                    <span className="text-cyber-muted text-[10px] uppercase">{d.name}</span>
                  </div>
                ))}
             </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* New Feature Highlight: Voice & Wave */}
      <motion.div variants={itemVariants} className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card className="relative overflow-hidden bg-cyber-panel/40 border-cyber-border/30 hover:border-cyber-blue/50 transition-all duration-500 group h-40">
           <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,_var(--color-cyber-blue-glow)_0%,_transparent_70%)] opacity-5 group-hover:opacity-10 transition-opacity" />
           <div className="absolute right-0 top-0 bottom-0 w-32 opacity-10 group-hover:opacity-20 transition-opacity pointer-events-none">
             <svg viewBox="0 0 100 100" className="w-full h-full text-cyber-blue">
               <path d="M10 50 Q 25 20, 40 50 T 70 50 T 100 50" fill="none" stroke="currentColor" strokeWidth="2" className="animate-pulse" />
               <path d="M10 60 Q 25 30, 40 60 T 70 60 T 100 60" fill="none" stroke="currentColor" strokeWidth="1" opacity="0.5" />
             </svg>
           </div>
           <CardContent className="p-6 h-full flex flex-col justify-between relative z-10">
             <div>
               <div className="flex items-center gap-2 mb-2">
                 <Mic className="w-4 h-4 text-cyber-blue" />
                 <h3 className="text-sm font-bold tracking-widest text-white uppercase italic">NeuroShield <span className="text-cyber-blue">Voice</span></h3>
               </div>
               <p className="text-[10px] text-cyber-muted font-mono leading-relaxed max-w-[200px]">Real-time deepfake & scam call detection with voice print analysis.</p>
             </div>
             <div className="text-[9px] font-bold text-cyber-blue border border-cyber-blue/30 w-fit px-2 py-0.5 rounded bg-cyber-blue/5">MODULE ACTIVE</div>
           </CardContent>
        </Card>

        <Card className="relative overflow-hidden bg-cyber-panel/40 border-cyber-border/30 hover:border-cyber-green/50 transition-all duration-500 group h-40">
           <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,_rgba(0,255,102,0.1)_0%,_transparent_70%)] opacity-5 group-hover:opacity-10 transition-opacity" />
           <div className="absolute right-0 top-0 bottom-0 w-32 opacity-10 group-hover:opacity-20 transition-opacity pointer-events-none p-4">
              <svg viewBox="0 0 100 100" className="w-full h-full text-cyber-green">
                <circle cx="50" cy="50" r="40" fill="none" stroke="currentColor" strokeWidth="1" strokeDasharray="4 4" className="animate-spin-slow" />
                <circle cx="50" cy="50" r="10" fill="currentColor" className="animate-pulse" />
              </svg>
           </div>
           <CardContent className="p-6 h-full flex flex-col justify-between relative z-10">
             <div>
               <div className="flex items-center gap-2 mb-2">
                 <Waves className="w-4 h-4 text-cyber-green" />
                 <h3 className="text-sm font-bold tracking-widest text-white uppercase italic">NeuroShield <span className="text-cyber-green">Wave</span></h3>
               </div>
               <p className="text-[10px] text-cyber-muted font-mono leading-relaxed max-w-[200px]">Advanced network topology map & packet isolation system.</p>
             </div>
             <div className="text-[9px] font-bold text-cyber-green border border-cyber-green/30 w-fit px-2 py-0.5 rounded bg-cyber-green/5">THREAT GUARD ON</div>
           </CardContent>
        </Card>
      </motion.div>

      {/* Live Threat Feed */}
      <motion.div variants={itemVariants}>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm uppercase">{t('live_threat_feed')}</CardTitle>
            <div className="flex items-center text-xs font-mono text-cyber-green">
              <span className="w-2 h-2 rounded-full bg-cyber-green mr-2 animate-pulse"></span>
              SYNCING
            </div>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="text-xs font-mono text-cyber-muted border-b border-cyber-border">
                  <tr>
                    <th className="px-4 py-3 font-medium">ID</th>
                    <th className="px-4 py-3 font-medium">TYPE</th>
                    <th className="px-4 py-3 font-medium">SOURCE</th>
                    <th className="px-4 py-3 font-medium">TARGET</th>
                    <th className="px-4 py-3 font-medium">RISK</th>
                    <th className="px-4 py-3 font-medium text-right">TIME</th>
                  </tr>
                </thead>
                <tbody className="font-mono text-xs">
                  {displayedThreats.map((threat) => (
                    <tr key={threat.id} className="border-b border-cyber-border/50 hover:bg-cyber-panel/50 transition-colors">
                      <td className="px-4 py-3 text-cyber-blue font-semibold">{threat.id}</td>
                      <td className="px-4 py-3">{threat.type}</td>
                      <td className="px-4 py-3 text-cyber-text truncate max-w-[150px]" title={threat.source}>{threat.source}</td>
                      <td className="px-4 py-3 text-cyber-muted truncate max-w-[150px]" title={threat.target}>{threat.target}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 rounded text-[10px] font-bold uppercase ${
                          threat.risk === 'high_risk' ? 'bg-cyber-red/20 text-cyber-red border border-cyber-red/30' :
                          threat.risk === 'medium_risk' ? 'bg-[#f59e0b]/20 text-[#f59e0b] border border-[#f59e0b]/30' :
                          'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30'
                        }`}>
                          {t(threat.risk)} {threat.score ? `(${threat.score})` : ''}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right text-cyber-muted">{threat.time}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      </motion.div>

    </motion.div>
  );
}
