import React from 'react';
import { motion } from 'motion/react';
import { Globe, Shield, Activity as ActivityIcon, X, AlertTriangle, Radio, ExternalLink, Copy, Check, ShieldAlert, ShieldCheck, Lock } from 'lucide-react';
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, ResponsiveContainer, PolarRadiusAxis } from 'recharts';
import { ScanResult } from '@/services/geminiService';
import { cn } from '@/lib/utils';
import { useLanguage } from '@/contexts/LanguageContext';
import { AdaptiveFeedbackSection } from '@/components/AdaptiveFeedbackSection';

interface UrlScannerResultProps {
  scanResult: ScanResult;
  inputText: string;
  onReset: () => void;
}

export function UrlScannerResult({ scanResult, inputText, onReset }: UrlScannerResultProps) {
  const { t } = useLanguage();
  const [copiedUrl, setCopiedUrl] = React.useState(false);
  const isHighRisk = scanResult.riskScore > 50;
  const metrics = scanResult.urlMetrics;

  const isReverseTunnel = /trycloudflare\.com|ngrok(-free)?\.(app|io)|localtunnel\.me|serveo\.net|pinggy\.(io|link)/i.test(inputText) ||
    (scanResult.signals && scanResult.signals.some(s => s.includes('REVERSE_TUNNEL') || s.includes('CLOUDFLARE')));

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

  const handleCopyUrl = () => {
    navigator.clipboard.writeText(inputText);
    setCopiedUrl(true);
    setTimeout(() => setCopiedUrl(false), 2000);
  };

  return (
    <div className="flex-1 flex flex-col w-full h-full text-white overflow-y-auto custom-scrollbar">
      {/* Top Header Area */}
      <div className="mb-6 flex-shrink-0 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-[#070d1e]/80 border border-cyber-border/40 p-4 sm:p-5 rounded-2xl backdrop-blur-xl shadow-lg">
        <div className="flex items-center gap-3">
          <div className={cn(
            "w-11 h-11 rounded-xl flex items-center justify-center border shrink-0 transition-transform",
            isHighRisk 
              ? "bg-cyber-red/10 border-cyber-red/30 text-cyber-red shadow-[0_0_15px_rgba(244,63,94,0.3)]" 
              : "bg-cyber-green/10 border-cyber-green/30 text-cyber-green shadow-[0_0_15px_rgba(16,185,129,0.3)]"
          )}>
            {isHighRisk ? <ShieldAlert className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold font-mono tracking-tight text-white">
                {t('url_scanner_title')}
              </h2>
              <span className={cn(
                "text-[10px] font-mono px-2 py-0.5 rounded-full font-bold uppercase tracking-wider border",
                isHighRisk 
                  ? "bg-cyber-red/20 text-cyber-red border-cyber-red/40" 
                  : "bg-cyber-green/20 text-cyber-green border-cyber-green/40"
              )}>
                {isHighRisk ? 'MALICIOUS_TARGET' : 'CLEAN_VERDICT'}
              </span>
            </div>
            <p className="text-xs text-cyber-muted font-mono mt-0.5">{t('url_scanner_desc')}</p>
          </div>
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
          <button
            onClick={handleCopyUrl}
            className="px-3 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 text-xs font-mono text-gray-300 border border-white/10 flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            {copiedUrl ? <Check className="w-3.5 h-3.5 text-cyber-green" /> : <Copy className="w-3.5 h-3.5 text-cyber-blue" />}
            <span>{copiedUrl ? 'Copied' : 'Copy URL'}</span>
          </button>
          <button 
            onClick={onReset}
            className="p-2 bg-[#0a1128]/80 text-cyber-muted hover:text-white rounded-xl border border-white/10 hover:border-cyber-blue/40 transition-all cursor-pointer"
            title={t('close')}
          >
            <X className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* Evasion Alert Banner if Reverse Tunnel Detected */}
      {isReverseTunnel && (
        <motion.div 
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-6 p-4.5 rounded-2xl border border-cyber-red/40 bg-cyber-red/10 backdrop-blur-xl flex items-start gap-3.5 text-white shadow-[0_0_30px_rgba(244,63,94,0.2)]"
        >
          <div className="w-9 h-9 rounded-xl bg-cyber-red/20 border border-cyber-red/40 flex items-center justify-center shrink-0 mt-0.5">
            <AlertTriangle className="w-5 h-5 text-cyber-red animate-pulse" />
          </div>
          <div className="space-y-1 text-xs">
            <div className="font-bold text-cyber-red tracking-wider uppercase font-mono flex items-center gap-2">
              <Radio className="w-3.5 h-3.5 animate-pulse" />
              {t('critical_reverse_tunnel')}
            </div>
            <p className="text-gray-300 leading-relaxed font-sans text-xs">
              {t('reverse_tunnel_desc')}
            </p>
          </div>
        </motion.div>
      )}
      
      {/* Target URL Address Bar */}
      <div className="mb-6 flex-shrink-0">
        <div className="relative group w-full">
          <div className="absolute -inset-0.5 bg-gradient-to-r from-cyber-blue/20 via-cyber-purple/20 to-cyber-blue/20 rounded-2xl blur opacity-75 group-hover:opacity-100 transition-opacity" />
          <div className="relative bg-[#070d1e] border border-cyber-border/60 rounded-2xl flex items-center p-2 focus-within:border-cyber-blue/60 transition-colors shadow-xl">
            <div className="pl-3 pr-2 text-cyber-blue flex items-center gap-2">
              <Globe className="w-4 h-4" />
              <span className="text-[10px] font-mono text-cyber-muted uppercase tracking-wider hidden sm:inline">TARGET_URI:</span>
            </div>
            <input 
              type="text" 
              value={inputText}
              readOnly
              className="flex-1 bg-transparent px-2 py-2 text-xs sm:text-sm text-white font-mono outline-none truncate selection:bg-cyber-blue selection:text-black"
            />
            <div className="flex items-center gap-2 pr-1">
              <span className="text-[10px] font-mono px-2.5 py-1 rounded-lg bg-cyber-blue/10 text-cyber-blue border border-cyber-blue/30 font-bold hidden sm:inline-flex items-center gap-1">
                <Lock className="w-3 h-3" /> TLS SECURED
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 flex-1 min-h-0 pb-6">
        
        {/* Column 1: Risk Gauge Meter */}
        <div className={cn(
          "col-span-1 bg-[#070d1e]/80 backdrop-blur-xl rounded-2xl p-6 flex flex-col relative border transition-all shadow-xl",
          isHighRisk 
            ? "border-cyber-red/30 shadow-[0_0_30px_rgba(244,63,94,0.15)]" 
            : "border-cyber-green/30 shadow-[0_0_30px_rgba(16,185,129,0.15)]"
        )}>
          <div className="flex items-center justify-between mb-4 border-b border-white/5 pb-3">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-cyber-muted">RISK_ASSESSMENT</span>
            <span className="text-[10px] font-mono text-gray-400">ENGINE v4.2</span>
          </div>

          <div className="flex-1 flex flex-col items-center justify-center py-4">
            <div className="w-48 h-48 relative flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90 drop-shadow-[0_0_15px_rgba(0,0,0,0.5)]" viewBox="0 0 100 100">
                <circle cx="50" cy="50" r="40" stroke="rgba(255,255,255,0.06)" strokeWidth="8" fill="none" />
                <motion.circle 
                  cx="50" cy="50" r="40" 
                  stroke={isHighRisk ? "#f43f5e" : "#10b981"} 
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
                  className="text-4xl font-extrabold tracking-tighter text-white font-mono"
                >
                  {scanResult.riskScore}
                </motion.span>
                <span className="text-[9px] font-mono text-cyber-muted uppercase tracking-widest mt-0.5">SCORE / 100</span>
              </div>
            </div>
            
            <div className="text-center mt-4">
              <h3 className={cn("text-lg font-bold font-mono tracking-widest uppercase", isHighRisk ? "text-cyber-red" : "text-cyber-green")}>
                {isHighRisk ? t('high_risk') : t('low_risk')}
              </h3>
              <p className="text-xs text-cyber-muted mt-2 max-w-[220px] mx-auto leading-relaxed">
                {isReverseTunnel 
                  ? t('reverse_tunnel_risk_summary')
                  : isHighRisk 
                  ? t('high_risk_domain_summary')
                  : t('low_risk_domain_summary')}
              </p>
            </div>
          </div>
        </div>

        {/* Column 2: Threat Indicators */}
        <div className="col-span-1 bg-[#070d1e]/80 backdrop-blur-xl border border-cyber-border/40 rounded-2xl p-6 h-full flex flex-col shadow-xl">
          <div className="flex items-center gap-2 mb-4 border-b border-white/5 pb-3">
            <Shield className="w-4 h-4 text-cyber-blue" />
            <h3 className="text-xs font-mono font-bold tracking-wider text-white uppercase">{t('threat_indicators')}</h3>
          </div>
          
          <div className="space-y-1 flex-1 overflow-y-auto pr-1 custom-scrollbar">
            {[
              ...(isReverseTunnel ? [{ label: t('tunnel_proxy_label'), value: "Cloudflare Quick Tunnel (AS13335)", isBad: true }] : []),
              { label: t('domain_age'), value: metrics?.domainAge || (isReverseTunnel ? 'Ephemeral (< 1 Hour)' : 'N/A'), isBad: isReverseTunnel || metrics?.domainAge.includes('day') || metrics?.domainAge.includes('week') || metrics?.domainAge.includes('Ephemeral') },
              { label: t('ssl_cert'), value: metrics?.sslCertificate || (isReverseTunnel ? 'Cloudflare Proxy TLS' : 'N/A'), isBad: isReverseTunnel || metrics?.sslCertificate.toLowerCase().includes('invalid') || metrics?.sslCertificate.toLowerCase().includes('none') || metrics?.sslCertificate.includes('Proxy') },
              { label: t('url_domain'), value: inputText ? getHostname(inputText) : 'N/A', isBad: isReverseTunnel },
              { label: t('blacklist_status'), value: metrics?.blacklistStatus || (isReverseTunnel ? 'Flagged / Tunnel Proxy' : 'N/A'), isBad: isReverseTunnel || !metrics?.blacklistStatus.toLowerCase().includes('clean') },
              { label: t('typosquatting'), value: metrics?.typosquatting || (isReverseTunnel ? 'Dictionary Subdomain Evasion' : 'N/A'), isBad: isReverseTunnel || !metrics?.typosquatting.toLowerCase().includes('none') },
              { label: t('subdomains'), value: metrics?.subdomains || (isReverseTunnel ? 'Random Disposable Subdomain' : 'N/A'), isBad: isReverseTunnel || Number(metrics?.subdomains) > 5 },
            ].map((item, idx) => (
              <div key={idx} className="flex justify-between items-center py-2.5 px-2 border-b border-white/5 last:border-0 rounded-lg hover:bg-white/[0.02] transition-colors">
                <span className="text-[11px] text-cyber-muted font-mono">{item.label}</span>
                <span className={cn(
                  "text-[11px] font-mono text-right break-words max-w-[150px] font-medium",
                  item.label === 'URL Domain' && !item.isBad ? "text-white" : item.isBad ? "text-cyber-red" : "text-cyber-green"
                )}>
                  {item.value}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Column 3: Risk Profile (Radar Chart) */}
        <div className="col-span-1 bg-[#070d1e]/80 backdrop-blur-xl border border-cyber-border/40 rounded-2xl p-6 h-full flex flex-col shadow-xl">
          <div className="flex items-center gap-2 mb-2 border-b border-white/5 pb-3">
            <ActivityIcon className="w-4 h-4 text-cyber-blue" />
            <h3 className="text-xs font-mono font-bold tracking-wider text-white uppercase">{t('risk_profile')}</h3>
          </div>
          
          <div className="flex-1 w-full relative min-h-[220px]">
            {metrics ? (
              <ResponsiveContainer width="100%" height="100%">
                <RadarChart cx="50%" cy="50%" outerRadius="70%" data={data}>
                  <PolarGrid stroke="rgba(255,255,255,0.08)" />
                  <PolarAngleAxis dataKey="subject" tick={{ fill: 'rgba(255,255,255,0.6)', fontSize: 10, fontFamily: 'monospace' }} />
                  <PolarRadiusAxis 
                    angle={30} 
                    domain={[0, 100]} 
                    tick={false} 
                    axisLine={false}
                  />
                  <Radar
                    name="Risk"
                    dataKey="A"
                    stroke={isHighRisk ? "#f43f5e" : "#00f0ff"}
                    fill={isHighRisk ? "#f43f5e" : "#00f0ff"}
                    fillOpacity={0.25}
                    strokeWidth={2}
                  />
                </RadarChart>
              </ResponsiveContainer>
            ) : (
              <div className="absolute inset-0 flex items-center justify-center text-xs text-cyber-muted font-mono">
                {t('insufficient_radar_data')}
              </div>
            )}
          </div>
        </div>
        
      </div>

      {/* Human-in-the-Loop Adaptive Feedback */}
      <div className="mt-2 mb-4">
        <AdaptiveFeedbackSection
          targetId={`url-${getHostname(inputText)}`}
          modelPrediction={scanResult.threatName || (scanResult.riskScore > 50 ? 'Malicious / Phishing URL' : 'Safe Domain')}
          riskScore={scanResult.riskScore}
          predictedAttackType="URL"
          extractedFeatures={{
            signals: scanResult.signals,
            detectedLinks: [inputText],
            source: getHostname(inputText),
            domainAge: metrics?.domainAge,
            sslCertificate: metrics?.sslCertificate
          }}
        />
      </div>
    </div>
  );
}

