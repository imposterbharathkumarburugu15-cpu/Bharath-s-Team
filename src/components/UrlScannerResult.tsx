import React from 'react';
import { motion } from 'motion/react';
import { Globe, Shield, Activity as ActivityIcon, X } from 'lucide-react';
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, ResponsiveContainer, PolarRadiusAxis } from 'recharts';
import { ScanResult } from '@/services/geminiService';
import { cn } from '@/lib/utils';
import { useLanguage } from '@/contexts/LanguageContext';

interface UrlScannerResultProps {
  scanResult: ScanResult;
  inputText: string;
  onReset: () => void;
}

export function UrlScannerResult({ scanResult, inputText, onReset }: UrlScannerResultProps) {
  const { t } = useLanguage();
  const isHighRisk = scanResult.riskScore > 50;
  const metrics = scanResult.urlMetrics;

  const data = metrics ? [
    { subject: 'Domain Age', A: metrics.radarData.domainAge, fullMark: 100 },
    { subject: 'SSL Status', A: metrics.radarData.sslStatus, fullMark: 100 },
    { subject: 'Blacklist', A: metrics.radarData.blacklist, fullMark: 100 },
    { subject: 'Typosquatting', A: metrics.radarData.typosquatting, fullMark: 100 },
    { subject: 'Subdomains', A: metrics.radarData.subdomains, fullMark: 100 },
    { subject: 'Content Risk', A: metrics.radarData.contentRisk, fullMark: 100 },
  ] : [];

  const getHostname = (url: string) => {
    try {
      return new URL(url).hostname;
    } catch (e) {
      return url;
    }
  };

  return (
    <div className="flex-1 flex flex-col w-full h-full text-white">
      {/* Header Area */}
      <div className="mb-6 flex-shrink-0 flex items-start justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            {t('url_scanner_title')}
          </h2>
          <p className="text-sm text-cyber-muted tracking-widest mt-1">{t('url_scanner_desc')}</p>
        </div>
        <button 
          onClick={onReset}
          className="p-2 bg-[#0a0d1a]/50 text-cyber-muted hover:text-white rounded-full border border-white/5 hover:bg-white/10 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>
      </div>
      
      <div className="mb-6 flex-shrink-0">
        <div className="relative group w-full">
            <div className="absolute -inset-0.5 bg-gradient-to-r from-cyber-blue/10 via-[#7000ff]/10 to-cyber-blue/10 rounded-lg blur opacity-100 transition-all duration-500" />
            <div className="relative bg-[#0a0d1a] border border-white/5 rounded-lg flex items-center p-1.5 focus-within:border-cyber-blue/30 transition-colors">
              <div className="pl-3 pr-2 text-cyber-muted">
                <Globe className="w-5 h-5" />
              </div>
              <input 
                type="text" 
                value={inputText}
                readOnly
                className="flex-1 bg-transparent px-2 py-3 text-sm text-white font-mono outline-none"
              />
              <button 
                className="px-6 py-2.5 bg-cyber-blue/10 text-cyber-blue border border-cyber-blue/30 hover:bg-cyber-blue hover:text-black rounded transition-all font-bold tracking-wider text-xs flex items-center gap-2"
              >
                <div className="animate-pulse w-1.5 h-1.5 bg-current rounded-full" /> {t('scan_button')}
              </button>
            </div>
          </div>
        </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 flex-1 min-h-0 pb-6">
        
        {/* Column 1: Risk Meter */}
        <div className="col-span-1 bg-[#0a0d1a]/50 backdrop-blur-md rounded-xl p-6 flex flex-col relative border border-white/5 h-full">
          <motion.div 
            initial={{ opacity: 0 }} animate={{ opacity: 1 }}
            className={cn(
              "absolute inset-0 rounded-xl opacity-20 pointer-events-none transition-colors",
              isHighRisk ? "bg-cyber-red/10 border-cyber-red/50" : ""
            )}
          />
          <div className="flex-1 flex flex-col items-center justify-center">
            <div className="w-48 h-48 relative flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90 drop-shadow-[0_0_15px_rgba(0,0,0,0.5)]" viewBox="0 0 100 100">
                <circle cx="50" cy="50" r="40" stroke="rgba(255,255,255,0.05)" strokeWidth="8" fill="none" />
                <motion.circle 
                  cx="50" cy="50" r="40" 
                  stroke={isHighRisk ? "#ff2e5b" : "#00f5ff"} 
                  strokeWidth="8" 
                  fill="none" 
                  strokeDasharray="251.2"
                  initial={{ strokeDashoffset: 251.2 }}
                  animate={{ strokeDashoffset: 251.2 - (251.2 * (scanResult.riskScore / 100)) }}
                  transition={{ duration: 1.5, ease: "easeOut" }}
                  strokeLinecap="round"
                />
              </svg>
              <div className="absolute flex flex-col items-center">
                <motion.span 
                  initial={{ opacity: 0, scale: 0.5 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.5 }}
                  className="text-4xl font-bold tracking-tighter text-white"
                >
                  {scanResult.riskScore}
                </motion.span>
              </div>
            </div>
            
            <div className="text-center mt-6">
              <h3 className={cn("text-xl font-bold tracking-widest", isHighRisk ? "text-cyber-red" : "text-cyber-green")}>
                {isHighRisk ? t('high_risk') : t('low_risk')}
              </h3>
              <p className="text-xs text-cyber-muted mt-3 max-w-[200px] mx-auto leading-relaxed">
                {isHighRisk 
                  ? "Domain exhibits multiple indicators of compromise." 
                  : "Domain appears clean with no significant threat indicators."}
              </p>
            </div>
          </div>
        </div>

        {/* Column 2: Threat Indicators */}
        <div className="col-span-1 bg-[#0a0d1a]/50 backdrop-blur-md border border-white/5 rounded-xl p-6 h-full flex flex-col">
          <div className="flex items-center gap-2 mb-6 text-white">
            <Shield className="w-5 h-5 text-cyber-blue" />
            <h3 className="font-semibold tracking-wide">{t('threat_indicators')}</h3>
          </div>
          
          <div className="space-y-1 flex-1 overflow-y-auto pr-2 custom-scrollbar">
            {[
              { label: t('domain_age'), value: metrics?.domainAge || 'N/A', isBad: metrics?.domainAge.includes('day') || metrics?.domainAge.includes('week') },
              { label: t('ssl_cert'), value: metrics?.sslCertificate || 'N/A', isBad: metrics?.sslCertificate.toLowerCase().includes('invalid') || metrics?.sslCertificate.toLowerCase().includes('none') },
              { label: t('url_domain'), value: inputText ? getHostname(inputText) : 'N/A', isBad: false },
              { label: t('blacklist_status'), value: metrics?.blacklistStatus || 'N/A', isBad: !metrics?.blacklistStatus.toLowerCase().includes('clean') },
              { label: t('typosquatting'), value: metrics?.typosquatting || 'N/A', isBad: !metrics?.typosquatting.toLowerCase().includes('none') },
              { label: t('subdomains'), value: metrics?.subdomains || 'N/A', isBad: Number(metrics?.subdomains) > 5 },
            ].map((item, idx) => (
              <div key={idx} className="flex justify-between items-center py-4 border-b border-white/5 last:border-0 relative group">
                <div className="absolute inset-0 bg-white/5 opacity-0 group-hover:opacity-100 transition-opacity rounded" />
                <span className="text-[11px] text-cyber-muted z-10 relative px-2">{item.label}</span>
                <span className={cn("text-[11px] font-mono z-10 relative px-2 text-right break-words max-w-[150px]", item.label === 'URL Domain' ? "text-white" : item.isBad ? "text-cyber-red" : "text-cyber-green")}>
                  {item.value}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Column 3: Risk Profile (Radar Chart) */}
        <div className="col-span-1 bg-[#0a0d1a]/50 backdrop-blur-md border border-white/5 rounded-xl p-6 h-full flex flex-col">
          <div className="flex items-center gap-2 mb-2 text-white">
            <ActivityIcon className="w-5 h-5 text-cyber-blue" />
            <h3 className="font-semibold tracking-wide">{t('risk_profile')}</h3>
          </div>
          
          <div className="flex-1 w-full relative min-h-[200px]">
            {metrics ? (
              <ResponsiveContainer width="100%" height="100%">
                <RadarChart cx="50%" cy="50%" outerRadius="70%" data={data}>
                  <PolarGrid stroke="rgba(255,255,255,0.1)" />
                  <PolarAngleAxis dataKey="subject" tick={{ fill: 'rgba(255,255,255,0.6)', fontSize: 9 }} />
                  <PolarRadiusAxis 
                    angle={30} 
                    domain={[0, 100]} 
                    tick={false} 
                    axisLine={false}
                  />
                  <Radar
                    name="Risk"
                    dataKey="A"
                    stroke="#00f5ff"
                    fill="#00f5ff"
                    fillOpacity={0.2}
                    strokeWidth={2}
                  />
                </RadarChart>
              </ResponsiveContainer>
            ) : (
              <div className="absolute inset-0 flex items-center justify-center text-xs text-cyber-muted">
                Insufficient data for risk profile.
              </div>
            )}
          </div>
        </div>
        
      </div>
    </div>
  );
}
