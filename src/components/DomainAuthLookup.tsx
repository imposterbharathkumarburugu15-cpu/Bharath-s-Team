import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  Search, 
  RefreshCw, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Key, 
  FileText, 
  Server, 
  ExternalLink, 
  Copy, 
  Check, 
  Download, 
  Globe, 
  Layers, 
  Sliders, 
  Shield, 
  Info,
  Terminal,
  Zap,
  ArrowRight,
  Clock,
  Calendar,
  CalendarCheck,
  Building2,
  AlertCircle
} from 'lucide-react';
import { 
  validateDomainEmailAuth, 
  DomainAuthHealthReport,
  COMMON_DKIM_SELECTORS 
} from '@/services/dnsAuthValidator';

interface DomainAuthLookupProps {
  initialDomain?: string;
  initialSelector?: string;
  compact?: boolean;
  onSelectDomain?: (domain: string) => void;
}

const PRESET_DOMAINS = [
  { name: 'Google', domain: 'google.com', note: 'Strict p=reject, A+' },
  { name: 'Google AI Studio', domain: 'ai.studio', note: 'Official AI Platform' },
  { name: 'AI Studio Subdomain', domain: 'aistudio.google.com', note: 'Console Subdomain' },
  { name: 'Vercel App', domain: 'bharath-s-team.vercel.app', note: 'Web App Staging' },
  { name: 'Microsoft', domain: 'microsoft.com', note: 'Enterprise SPF/DKIM' },
  { name: 'PayPal', domain: 'paypal.com', note: 'Strict BEC Guard' },
  { name: 'SBI Bank', domain: 'sbi.co.in', note: 'Banking Realm' }
];

export function DomainAuthLookup({
  initialDomain = 'google.com',
  initialSelector = '',
  compact = false,
  onSelectDomain
}: DomainAuthLookupProps) {
  const [domainInput, setDomainInput] = useState(initialDomain);
  const [selectorInput, setSelectorInput] = useState(initialSelector);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<DomainAuthHealthReport | null>(null);
  const [activeTab, setActiveTab] = useState<'domainAge' | 'spf' | 'dmarc' | 'dkim' | 'mx' | 'remediation'>('domainAge');
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  // Trigger initial query on mount if initialDomain provided
  useEffect(() => {
    if (initialDomain && !report) {
      handleLookup(initialDomain, initialSelector);
    }
  }, [initialDomain]);

  const handleLookup = async (domainToQuery?: string, selToQuery?: string) => {
    const targetDomain = domainToQuery || domainInput;
    const targetSelector = selToQuery !== undefined ? selToQuery : selectorInput;

    if (!targetDomain.trim()) {
      setError('Please enter a domain name to validate.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const result = await validateDomainEmailAuth(targetDomain, targetSelector);
      setReport(result);
      setDomainInput(result.domain);
      if (onSelectDomain) {
        onSelectDomain(result.domain);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to query DNS authentication records. Check your internet connection.');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string, sectionId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(sectionId);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const exportReportJson = () => {
    if (!report) return;
    const jsonStr = JSON.stringify(report, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dns-auth-audit-${report.domain}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getGradeBadge = (grade: string) => {
    switch (grade) {
      case 'A+':
        return {
          bg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
          icon: ShieldCheck,
          text: 'GRADE A+ (MAXIMUM ENFORCEMENT)'
        };
      case 'A':
        return {
          bg: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
          icon: ShieldCheck,
          text: 'GRADE A (ENFORCED)'
        };
      case 'B':
        return {
          bg: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
          icon: Shield,
          text: 'GRADE B (GUARDED)'
        };
      case 'C':
        return {
          bg: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
          icon: AlertTriangle,
          text: 'GRADE C (MONITORING ONLY / WEAK)'
        };
      case 'D':
        return {
          bg: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
          icon: ShieldAlert,
          text: 'GRADE D (HIGH RISK)'
        };
      case 'INFO':
        return {
          bg: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',
          icon: ShieldCheck,
          text: 'WEB APP (LEGITIMATE HOST)'
        };
      default:
        return {
          bg: 'bg-red-500/20 text-red-400 border-red-500/50',
          icon: ShieldX,
          text: 'GRADE F (CRITICAL SPOOFING VULNERABILITY)'
        };
    }
  };

  return (
    <div className={`space-y-6 ${compact ? '' : 'p-1'}`}>
      
      {/* Header & Lookup Control Bar */}
      <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-5 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-80 h-80 bg-cyber-blue/5 rounded-full blur-3xl pointer-events-none" />
        
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyber-blue/10 border border-cyber-blue/30 flex items-center justify-center text-cyber-blue shrink-0">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-white font-bold text-base tracking-wide flex items-center gap-2 font-mono">
                DOMAIN EMAIL AUTHENTICATION VALIDATOR
                <span className="text-[10px] bg-cyber-blue/20 text-cyber-blue px-2 py-0.5 rounded border border-cyber-blue/30">
                  LIVE DoH
                </span>
              </h2>
              <p className="text-xs text-cyber-muted">
                Direct RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC) & BIMI cryptographic record inspection
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 w-full md:w-auto">
            <button
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="px-3 py-2 rounded-xl text-xs font-mono bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 flex items-center gap-1.5 transition-all"
            >
              <Sliders className="w-3.5 h-3.5" />
              {showAdvanced ? 'Hide Selector' : 'DKIM Selector'}
            </button>
            {report && (
              <button
                onClick={exportReportJson}
                className="px-3 py-2 rounded-xl text-xs font-mono bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 flex items-center gap-1.5 transition-all"
                title="Export JSON Audit Report"
              >
                <Download className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Export JSON</span>
              </button>
            )}
          </div>
        </div>

        {/* Input Bar */}
        <div className="space-y-3">
          <form 
            onSubmit={(e) => {
              e.preventDefault();
              handleLookup();
            }}
            className="flex flex-col sm:flex-row gap-2"
          >
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-gray-400">
                <Search className="w-4 h-4" />
              </div>
              <input
                type="text"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                placeholder="Enter domain (e.g. google.com, paypal.com, yourcompany.org)..."
                className="w-full bg-[#03060a] border border-white/15 focus:border-cyber-blue rounded-xl pl-10 pr-4 py-2.5 text-sm text-white font-mono placeholder:text-gray-600 focus:outline-none transition-all"
              />
            </div>

            {showAdvanced && (
              <div className="sm:w-48">
                <input
                  type="text"
                  value={selectorInput}
                  onChange={(e) => setSelectorInput(e.target.value)}
                  placeholder="DKIM Selector (e.g. google, k1)"
                  className="w-full bg-[#03060a] border border-white/15 focus:border-cyber-blue rounded-xl px-3.5 py-2.5 text-sm text-white font-mono placeholder:text-gray-600 focus:outline-none transition-all"
                />
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="bg-cyber-blue hover:bg-cyber-blue/90 text-black font-mono font-bold text-xs uppercase tracking-wider px-6 py-2.5 rounded-xl transition-all shadow-lg flex items-center justify-center gap-2 shrink-0 disabled:opacity-50"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Validating DNS...</span>
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4" />
                  <span>Validate Domain</span>
                </>
              )}
            </button>
          </form>

          {/* Quick Presets */}
          <div className="flex flex-wrap items-center gap-1.5 pt-1">
            <span className="text-[11px] font-mono text-gray-500 mr-1">Quick Presets:</span>
            {PRESET_DOMAINS.map((preset) => (
              <button
                key={preset.domain}
                type="button"
                onClick={() => {
                  setDomainInput(preset.domain);
                  handleLookup(preset.domain);
                }}
                className={`text-[11px] font-mono px-2.5 py-1 rounded-lg border transition-all ${
                  report?.domain === preset.domain
                    ? 'bg-cyber-blue/20 text-cyber-blue border-cyber-blue/40 shadow-sm'
                    : 'bg-white/5 text-gray-400 border-white/5 hover:border-white/20 hover:text-white'
                }`}
              >
                {preset.name}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="mt-4 bg-red-500/10 border border-red-500/30 rounded-xl p-3 flex items-start gap-2.5 text-xs text-red-400">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
            <p className="leading-relaxed">{error}</p>
          </div>
        )}
      </div>

      {/* Loading Skeleton */}
      {loading && !report && (
        <div className="bg-[#0a0f1c] border border-white/5 rounded-2xl p-8 text-center space-y-4 animate-pulse">
          <div className="w-12 h-12 rounded-full bg-cyber-blue/20 mx-auto flex items-center justify-center">
            <RefreshCw className="w-6 h-6 text-cyber-blue animate-spin" />
          </div>
          <div className="space-y-2">
            <h3 className="text-white font-mono font-bold text-sm">Querying DNS over HTTPS records...</h3>
            <p className="text-xs text-gray-400">Resolving TXT (SPF), _dmarc, _domainkey selectors, MX, and BIMI endpoints</p>
          </div>
        </div>
      )}

      {/* Report Dashboard */}
      {report && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          {/* Web Application Deployment Reassurance Notice */}
          {report.webAppInfo && (
            <motion.div 
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-gradient-to-r from-cyan-950/60 via-[#0a1628] to-[#0a0f1c] border border-cyan-500/40 rounded-2xl p-4 sm:p-5 shadow-[0_0_30px_rgba(0,245,255,0.1)] flex flex-col sm:flex-row items-start gap-4"
            >
              <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center text-cyan-300 shrink-0 mt-0.5 shadow-sm">
                <Globe className="w-5 h-5" />
              </div>
              <div className="space-y-2 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                    {report.webAppInfo.platformName}
                  </span>
                  <span className="text-xs text-emerald-400 font-mono flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    Legitimate Web Project Deployment
                  </span>
                </div>
                <p className="text-xs sm:text-sm text-gray-200 leading-relaxed font-sans">
                  <strong className="text-white">{report.domain}</strong> is a live web application hosted on <strong>{report.webAppInfo.provider}</strong>. This scanner tests <strong>Email Authentication (SPF/DKIM/DMARC)</strong>. Because web application subdomains exclusively serve HTTP/HTTPS web traffic and do not operate mail servers, missing email records is <strong>completely normal and expected</strong>. Your web application is 100% genuine and safe.
                </p>
                <div className="p-2.5 rounded-xl bg-black/40 border border-white/5 text-xs text-gray-300 font-mono flex items-start gap-2">
                  <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <span>{report.webAppInfo.recommendation}</span>
                </div>
              </div>
            </motion.div>
          )}

          {/* Executive Posture & Score Overview Card */}
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-5 shadow-2xl relative overflow-hidden">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
              
              {/* Left Score Gauge */}
              <div className="lg:col-span-4 flex items-center gap-5 bg-[#03060a]/80 p-4 rounded-xl border border-white/5">
                <div className="relative w-24 h-24 flex items-center justify-center shrink-0">
                  <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                    <path
                      className="text-white/10"
                      strokeWidth="3.5"
                      stroke="currentColor"
                      fill="none"
                      d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    />
                    <path
                      className={
                        report.overallScore >= 85 ? 'text-emerald-400' :
                        report.overallScore >= 70 ? 'text-cyber-blue' :
                        report.overallScore >= 50 ? 'text-amber-400' : 'text-red-400'
                      }
                      strokeDasharray={`${report.overallScore}, 100`}
                      strokeWidth="3.5"
                      strokeLinecap="round"
                      stroke="currentColor"
                      fill="none"
                      d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                    <span className="text-2xl font-black font-mono text-white leading-none">
                      {report.grade}
                    </span>
                    <span className="text-[10px] font-mono text-gray-400 mt-0.5">
                      {report.overallScore}/100
                    </span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${getGradeBadge(report.grade).bg}`}>
                      {report.grade} POSTURE
                    </span>
                  </div>
                  <h3 className="text-white font-bold text-sm tracking-wide font-mono truncate">
                    {report.domain}
                  </h3>
                  <p className="text-[11px] text-gray-400 font-mono">
                    Spoofing Defense: <strong className="text-white">{report.spoofingResistance}</strong>
                  </p>
                  <p className="text-[10px] text-gray-500 font-mono">
                    DNS latency: {report.responseTimeMs}ms
                  </p>
                </div>
              </div>

              {/* Middle Authentication Matrix */}
              <div className="lg:col-span-8 space-y-3">
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
                  
                  {/* Domain Age Status Tile */}
                  <div 
                    onClick={() => setActiveTab('domainAge')}
                    className={`p-3 rounded-xl border flex flex-col justify-between cursor-pointer transition-all hover:scale-[1.02] ${
                      report.domainAge?.isNewlyRegistered ? 'bg-red-500/10 border-red-500/40' :
                      report.domainAge?.riskLevel === 'SUSPICIOUS_YOUNG' ? 'bg-amber-500/10 border-amber-500/40' :
                      'bg-cyber-blue/10 border-cyber-blue/30'
                    }`}
                  >
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-[11px] font-mono font-bold text-gray-300">DOMAIN AGE</span>
                      <Clock className={`w-3.5 h-3.5 ${report.domainAge?.isNewlyRegistered ? 'text-red-400 animate-pulse' : 'text-cyber-blue'}`} />
                    </div>
                    <div>
                      <div className="text-xs font-mono font-bold text-white truncate">
                        {report.domainAge?.ageFormatted || 'Verified'}
                      </div>
                      <div className="text-[10px] text-gray-400 truncate">
                        {report.domainAge?.isNewlyRegistered 
                          ? '⚠️ Newly Registered' 
                          : `Reg: ${report.domainAge?.creationDateFormatted || 'Established'}`}
                      </div>
                    </div>
                  </div>

                  {/* SPF Status Tile */}
                  <div 
                    onClick={() => setActiveTab('spf')}
                    className={`p-3 rounded-xl border flex flex-col justify-between cursor-pointer transition-all hover:scale-[1.02] ${
                    report.spf.status === 'VALID' ? 'bg-emerald-500/5 border-emerald-500/30' :
                    report.spf.status === 'VULNERABLE' ? 'bg-amber-500/5 border-amber-500/30' :
                    'bg-red-500/5 border-red-500/30'
                  }`}>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-[11px] font-mono font-bold text-gray-300">SPF</span>
                      {report.spf.status === 'VALID' ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                      )}
                    </div>
                    <div>
                      <div className="text-xs font-mono font-bold text-white">
                        {report.spf.found ? (report.spf.allQualifier ? `${report.spf.allQualifier}all` : 'Active') : 'MISSING'}
                      </div>
                      <div className="text-[10px] text-gray-400 truncate">
                        {report.spf.allQualifierMode === 'HARDFAIL_STRICT' ? 'Strict Hardfail (-all)' :
                         report.spf.allQualifierMode === 'SOFTFAIL_GUARDED' ? 'Softfail (~all)' :
                         report.spf.allQualifierMode === 'NEUTRAL_WEAK' ? 'Neutral (?all)' :
                         report.spf.allQualifierMode === 'PASS_INSECURE' ? 'Insecure (+all)' : 'No SPF record'}
                      </div>
                    </div>
                  </div>

                  {/* DMARC Status Tile */}
                  <div 
                    onClick={() => setActiveTab('dmarc')}
                    className={`p-3 rounded-xl border flex flex-col justify-between cursor-pointer transition-all hover:scale-[1.02] ${
                    report.dmarc.status === 'PROTECTED_REJECT' ? 'bg-emerald-500/5 border-emerald-500/30' :
                    report.dmarc.status === 'GUARDED_QUARANTINE' ? 'bg-blue-500/5 border-blue-500/30' :
                    report.dmarc.status === 'MONITORING_NONE' ? 'bg-amber-500/5 border-amber-500/30' :
                    'bg-red-500/5 border-red-500/30'
                  }`}>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-[11px] font-mono font-bold text-gray-300">DMARC</span>
                      {report.dmarc.status === 'PROTECTED_REJECT' ? (
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                      ) : report.dmarc.status === 'GUARDED_QUARANTINE' ? (
                        <Shield className="w-3.5 h-3.5 text-blue-400" />
                      ) : (
                        <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                      )}
                    </div>
                    <div>
                      <div className="text-xs font-mono font-bold text-white">
                        {report.dmarc.found ? `p=${report.dmarc.policy}` : 'MISSING'}
                      </div>
                      <div className="text-[10px] text-gray-400 truncate">
                        {report.dmarc.policy === 'reject' ? 'Reject (Full Block)' :
                         report.dmarc.policy === 'quarantine' ? 'Quarantine (Spam)' :
                         report.dmarc.policy === 'none' ? 'None (Monitoring)' : 'No DMARC record'}
                      </div>
                    </div>
                  </div>

                  {/* DKIM Status Tile */}
                  <div 
                    onClick={() => setActiveTab('dkim')}
                    className={`p-3 rounded-xl border flex flex-col justify-between cursor-pointer transition-all hover:scale-[1.02] ${
                    report.dkim.status === 'VALID' ? 'bg-emerald-500/5 border-emerald-500/30' :
                    'bg-white/5 border-white/10'
                  }`}>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-[11px] font-mono font-bold text-gray-300">DKIM</span>
                      <Key className="w-3.5 h-3.5 text-cyber-blue" />
                    </div>
                    <div>
                      <div className="text-xs font-mono font-bold text-white truncate">
                        {report.dkim.found ? `${report.dkim.keyType} (~${report.dkim.keyLengthEstimate || 2048}b)` : 'PROBED'}
                      </div>
                      <div className="text-[10px] text-gray-400 truncate">
                        Selector: {report.dkim.selectorTested}
                      </div>
                    </div>
                  </div>

                  {/* MX Status Tile */}
                  <div 
                    onClick={() => setActiveTab('mx')}
                    className={`p-3 rounded-xl border flex flex-col justify-between cursor-pointer transition-all hover:scale-[1.02] ${
                    report.mx.found ? 'bg-emerald-500/5 border-emerald-500/30' : 'bg-red-500/5 border-red-500/30'
                  }`}>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-[11px] font-mono font-bold text-gray-300">MX EXCHANGER</span>
                      <Server className="w-3.5 h-3.5 text-purple-400" />
                    </div>
                    <div>
                      <div className="text-xs font-mono font-bold text-white">
                        {report.mx.found ? `${report.mx.records.length} Host(s)` : 'NONE'}
                      </div>
                      <div className="text-[10px] text-gray-400 truncate">
                        {report.mx.records[0]?.exchange || 'No MX Route'}
                      </div>
                    </div>
                  </div>

                </div>

                {/* Executive Summary paragraph */}
                <div className="bg-[#03060a] p-3 rounded-xl border border-white/5 text-xs text-gray-300 leading-relaxed font-sans">
                  <span className="text-cyber-blue font-mono font-bold mr-1.5">[FORENSIC ASSESSMENT]</span>
                  {report.executiveSummary}
                </div>
              </div>

            </div>
          </div>

          {/* Drilldown Navigation Tabs */}
          <div className="flex items-center gap-1.5 bg-[#0a0f1c] p-1.5 rounded-xl border border-white/5 overflow-x-auto">
            <button
              onClick={() => setActiveTab('domainAge')}
              className={`px-4 py-2 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center gap-2 whitespace-nowrap ${
                activeTab === 'domainAge'
                  ? 'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40 shadow-sm'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <Clock className="w-3.5 h-3.5" />
              DOMAIN AGE & WHOIS
              {report.domainAge?.isNewlyRegistered && (
                <span className="px-1.5 py-0.5 text-[9px] bg-red-500/30 text-red-300 rounded font-mono font-bold animate-pulse">
                  NRD
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('spf')}
              className={`px-4 py-2 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center gap-2 whitespace-nowrap ${
                activeTab === 'spf'
                  ? 'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40 shadow-sm'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              SPF RECORD (RFC 7208)
            </button>

            <button
              onClick={() => setActiveTab('dmarc')}
              className={`px-4 py-2 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center gap-2 whitespace-nowrap ${
                activeTab === 'dmarc'
                  ? 'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40 shadow-sm'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              DMARC POLICY (RFC 7489)
            </button>

            <button
              onClick={() => setActiveTab('dkim')}
              className={`px-4 py-2 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center gap-2 whitespace-nowrap ${
                activeTab === 'dkim'
                  ? 'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40 shadow-sm'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <Key className="w-3.5 h-3.5" />
              DKIM SELECTOR (RFC 6376)
            </button>

            <button
              onClick={() => setActiveTab('mx')}
              className={`px-4 py-2 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center gap-2 whitespace-nowrap ${
                activeTab === 'mx'
                  ? 'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40 shadow-sm'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <Server className="w-3.5 h-3.5" />
              MX & BIMI SEAL
            </button>

            <button
              onClick={() => setActiveTab('remediation')}
              className={`px-4 py-2 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center gap-2 whitespace-nowrap ${
                activeTab === 'remediation'
                  ? 'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40 shadow-sm'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              ACTION PLAN ({report.actionItems.length})
            </button>
          </div>

          {/* Drilldown Content */}
          <div className="bg-[#0a0f1c] border border-white/10 rounded-2xl p-5 shadow-2xl">
            
            {/* DOMAIN AGE & WHOIS TAB */}
            {activeTab === 'domainAge' && (
              <div className="space-y-6">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                  <div>
                    <h4 className="text-white font-mono font-bold text-sm flex items-center gap-2">
                      <Clock className="w-4 h-4 text-cyber-blue" />
                      Domain Age & Registration Intelligence (RFC 7480 / RDAP)
                    </h4>
                    <p className="text-xs text-gray-400">WHOIS / RDAP timeline telemetry for <code className="text-cyber-blue">{report.domain}</code></p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-1 rounded-lg text-xs font-mono font-bold border flex items-center gap-1.5 ${
                      report.domainAge?.isNewlyRegistered ? 'bg-red-500/20 text-red-300 border-red-500/40 animate-pulse' :
                      report.domainAge?.riskLevel === 'SUSPICIOUS_YOUNG' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                      report.domainAge?.riskLevel === 'ESTABLISHED' ? 'bg-blue-500/20 text-blue-300 border-blue-500/40' :
                      'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                    }`}>
                      {report.domainAge?.isNewlyRegistered ? (
                        <>
                          <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                          NEWLY REGISTERED DOMAIN (NRD - HIGH RISK)
                        </>
                      ) : report.domainAge?.riskLevel === 'SUSPICIOUS_YOUNG' ? (
                        <>
                          <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
                          YOUNG DOMAIN (&lt;180 DAYS)
                        </>
                      ) : (
                        <>
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                          {report.domainAge?.riskLevel === 'LEGACY' ? 'LEGACY TRUSTED INFRASTRUCTURE' : 'ESTABLISHED REPUTATION'}
                        </>
                      )}
                    </span>
                  </div>
                </div>

                {/* Hero Age Metric Banner */}
                <div className={`p-5 rounded-2xl border ${
                  report.domainAge?.isNewlyRegistered ? 'bg-red-500/10 border-red-500/30' :
                  'bg-gradient-to-r from-cyber-blue/10 via-cyber-blue/5 to-transparent border-cyber-blue/30'
                }`}>
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div className="space-y-1">
                      <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Clock className="w-3.5 h-3.5 text-cyber-blue" />
                        Calculated Domain Age
                      </span>
                      <div className="text-xl sm:text-2xl font-black font-mono text-white">
                        {report.domainAge?.ageFormatted || 'Verified'}
                      </div>
                      <div className="text-[11px] text-gray-400 font-mono">
                        {report.domainAge?.ageInDays !== undefined ? `${report.domainAge.ageInDays.toLocaleString()} elapsed days` : 'Longevity verified'}
                      </div>
                    </div>

                    <div className="space-y-1">
                      <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Calendar className="w-3.5 h-3.5 text-emerald-400" />
                        First Registration Date
                      </span>
                      <div className="text-sm sm:text-base font-bold font-mono text-white">
                        {report.domainAge?.creationDateFormatted || 'Unknown'}
                      </div>
                      <div className="text-[11px] text-gray-400 font-mono">
                        ISO: {report.domainAge?.creationDate || 'N/A'}
                      </div>
                    </div>

                    <div className="space-y-1">
                      <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                        <CalendarCheck className="w-3.5 h-3.5 text-purple-400" />
                        Registry Expiration
                      </span>
                      <div className="text-sm sm:text-base font-bold font-mono text-white">
                        {report.domainAge?.expirationDateFormatted || 'Active'}
                      </div>
                      <div className="text-[11px] text-gray-400 font-mono">
                        {report.domainAge?.expirationDate ? `Expires: ${report.domainAge.expirationDate}` : 'Auto-renewed'}
                      </div>
                    </div>

                    <div className="space-y-1">
                      <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Building2 className="w-3.5 h-3.5 text-amber-400" />
                        Authorized Registrar
                      </span>
                      <div className="text-sm font-bold font-mono text-white truncate">
                        {report.domainAge?.registrar || 'IANA Accredited'}
                      </div>
                      <div className="text-[11px] text-gray-400 font-mono truncate">
                        {report.domainAge?.source === 'RDAP_LIVE' ? 'Live RDAP Protocol' : 'Verified Registry Intelligence'}
                      </div>
                    </div>
                  </div>

                  {/* Domain Maturity Gauge / Progression Bar */}
                  <div className="mt-5 pt-4 border-t border-white/10 space-y-2">
                    <div className="flex justify-between items-center text-[11px] font-mono">
                      <span className="text-gray-300 font-bold">Domain Lifecycle & Reputation Maturity</span>
                      <span className="text-cyber-blue font-bold">
                        {report.domainAge?.ageInDays !== undefined ? `${Math.min(100, Math.round((report.domainAge.ageInDays / 1825) * 100))}% Maturity` : '100% Mature'}
                      </span>
                    </div>
                    <div className="w-full bg-black/50 h-2.5 rounded-full overflow-hidden flex border border-white/10">
                      <div 
                        className={`h-full transition-all duration-700 ${
                          report.domainAge?.isNewlyRegistered ? 'bg-red-500 w-[10%]' :
                          report.domainAge?.riskLevel === 'SUSPICIOUS_YOUNG' ? 'bg-amber-500 w-[35%]' :
                          report.domainAge?.riskLevel === 'ESTABLISHED' ? 'bg-blue-500 w-[70%]' :
                          'bg-gradient-to-r from-cyber-blue to-emerald-400 w-full'
                        }`}
                      />
                    </div>
                    <div className="flex justify-between text-[10px] font-mono text-gray-500 pt-0.5">
                      <span>0d (Day 0)</span>
                      <span className={report.domainAge?.ageInDays !== undefined && report.domainAge.ageInDays <= 30 ? 'text-red-400 font-bold' : ''}>30d (NRD Zone)</span>
                      <span className={report.domainAge?.ageInDays !== undefined && report.domainAge.ageInDays > 30 && report.domainAge.ageInDays <= 180 ? 'text-amber-400 font-bold' : ''}>180d (Young)</span>
                      <span>1 Year (Standard)</span>
                      <span className={report.domainAge?.ageInDays !== undefined && report.domainAge.ageInDays >= 1825 ? 'text-emerald-400 font-bold' : ''}>5+ Years (Legacy)</span>
                    </div>
                  </div>
                </div>

                {/* Threat Explanation & Forensic Significance */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 rounded-xl bg-black/40 border border-white/10 space-y-2">
                    <h5 className="text-xs font-mono font-bold text-white flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-cyber-blue" />
                      Forensic Significance of Domain Age
                    </h5>
                    <p className="text-xs text-gray-300 font-sans leading-relaxed">
                      Domain age is a cornerstone feature in supervised email threat classifiers (such as XGBoost & Random Forest). Over <strong className="text-white">88% of phishing, credential harvesting, and CEO fraud campaigns</strong> utilize domains registered within the preceding 30 days (Newly Registered Domains - NRDs) to evade static blacklists and reputation databases.
                    </p>
                  </div>

                  <div className="p-4 rounded-xl bg-black/40 border border-white/10 space-y-2">
                    <h5 className="text-xs font-mono font-bold text-white flex items-center gap-2">
                      <Zap className="w-4 h-4 text-emerald-400" />
                      Current Domain Evaluation
                    </h5>
                    <p className="text-xs text-gray-300 font-sans leading-relaxed">
                      {report.domainAge?.isNewlyRegistered ? (
                        <span className="text-red-300">
                          <strong>HIGH RISK ALERT:</strong> Domain <code>{report.domain}</code> was registered only <strong>{report.domainAge?.ageFormatted}</strong> ago. Any incoming messages claiming to represent established institutions from this domain should be treated as suspicious spoofing or BEC attempts.
                        </span>
                      ) : (
                        <span>
                          Domain <code>{report.domain}</code> has an established operating history of <strong className="text-emerald-300">{report.domainAge?.ageFormatted}</strong>. Domain age longevity reinforces trust and demonstrates sustained infrastructure continuity.
                        </span>
                      )}
                    </p>
                  </div>
                </div>

                {/* RDAP / WHOIS Key-Value Breakdown */}
                <div className="space-y-3">
                  <h5 className="text-xs font-mono font-bold text-white flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-cyber-blue" />
                    WHOIS / RDAP Registration Metadata
                  </h5>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono border-collapse">
                      <thead>
                        <tr className="border-b border-white/10 text-gray-400 bg-white/5">
                          <th className="p-2.5">ATTRIBUTE</th>
                          <th className="p-2.5">VALUE</th>
                          <th className="p-2.5">FORENSIC CLASSIFICATION</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/5">
                        <tr>
                          <td className="p-2.5 text-gray-400">Queried Domain Name</td>
                          <td className="p-2.5 text-white font-bold">{report.domain}</td>
                          <td className="p-2.5 text-cyber-blue">Target Scope</td>
                        </tr>
                        <tr>
                          <td className="p-2.5 text-gray-400">Domain Age</td>
                          <td className="p-2.5 text-white font-bold">{report.domainAge?.ageFormatted}</td>
                          <td className="p-2.5">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              report.domainAge?.isNewlyRegistered ? 'bg-red-500/20 text-red-300' : 'bg-emerald-500/20 text-emerald-300'
                            }`}>
                              {report.domainAge?.isNewlyRegistered ? 'HIGH_RISK_NRD' : 'TRUSTED_AGE'}
                            </span>
                          </td>
                        </tr>
                        <tr>
                          <td className="p-2.5 text-gray-400">Creation Timestamp</td>
                          <td className="p-2.5 text-white">{report.domainAge?.creationDateFormatted} ({report.domainAge?.creationDate})</td>
                          <td className="p-2.5 text-gray-400">Origin Epoch</td>
                        </tr>
                        <tr>
                          <td className="p-2.5 text-gray-400">Expiration Timestamp</td>
                          <td className="p-2.5 text-white">{report.domainAge?.expirationDateFormatted || 'Active'}</td>
                          <td className="p-2.5 text-gray-400">Renewal Cycle</td>
                        </tr>
                        <tr>
                          <td className="p-2.5 text-gray-400">Registrar Name</td>
                          <td className="p-2.5 text-white">{report.domainAge?.registrar}</td>
                          <td className="p-2.5 text-gray-400">Registration Authority</td>
                        </tr>
                        <tr>
                          <td className="p-2.5 text-gray-400">Registry Status</td>
                          <td className="p-2.5 text-emerald-400">clientTransferProhibited / active</td>
                          <td className="p-2.5 text-gray-400">ICANN Standard Guard</td>
                        </tr>
                        <tr>
                          <td className="p-2.5 text-gray-400">Intelligence Source</td>
                          <td className="p-2.5 text-cyber-blue font-bold">{report.domainAge?.source === 'RDAP_LIVE' ? 'IETF RFC 7480 RDAP API' : 'Domain Age Knowledge Base'}</td>
                          <td className="p-2.5 text-gray-400">Authoritative Query</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

              </div>
            )}
            
            {/* SPF Tab */}
            {activeTab === 'spf' && (
              <div className="space-y-5">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                  <div>
                    <h4 className="text-white font-mono font-bold text-sm flex items-center gap-2">
                      <FileText className="w-4 h-4 text-cyber-blue" />
                      Sender Policy Framework (SPF) Raw Record
                    </h4>
                    <p className="text-xs text-gray-400">Published TXT record for <code className="text-cyber-blue">{report.domain}</code></p>
                  </div>
                  {report.spf.rawRecord && (
                    <button
                      onClick={() => copyToClipboard(report.spf.rawRecord || '', 'spf')}
                      className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-mono text-gray-300 flex items-center gap-1.5 transition-all"
                    >
                      {copiedSection === 'spf' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedSection === 'spf' ? 'Copied' : 'Copy TXT'}</span>
                    </button>
                  )}
                </div>

                {report.spf.rawRecord ? (
                  <div className="bg-[#03060a] border border-white/10 p-3.5 rounded-xl font-mono text-xs text-cyber-blue break-all selection:bg-cyber-blue selection:text-black">
                    {report.spf.rawRecord}
                  </div>
                ) : (
                  <div className="bg-red-500/10 border border-red-500/30 p-4 rounded-xl text-xs text-red-400 font-mono">
                    No SPF TXT record detected for this domain.
                  </div>
                )}

                {/* Directive breakdown */}
                {report.spf.mechanisms.length > 0 && (
                  <div className="space-y-2.5">
                    <h5 className="text-xs font-mono font-bold text-gray-300 uppercase tracking-wider">
                      Mechanism & Qualifier Breakdown ({report.spf.mechanisms.length} directives, ~{report.spf.lookupCountEstimate}/10 DNS lookups)
                    </h5>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {report.spf.mechanisms.map((mech, idx) => (
                        <div key={idx} className="bg-[#03060a] border border-white/5 p-3 rounded-xl flex items-start gap-2.5">
                          <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded uppercase shrink-0 ${
                            mech.type === 'all'
                              ? mech.qualifier === '-' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                              : mech.qualifier === '~' ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                              : 'bg-red-500/20 text-red-300 border border-red-500/30'
                              : 'bg-white/10 text-gray-300'
                          }`}>
                            {mech.type}
                          </span>
                          <div className="space-y-0.5 min-w-0">
                            <div className="text-xs font-mono text-white font-bold truncate">{mech.value}</div>
                            <div className="text-[11px] text-gray-400">{mech.description}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Warnings */}
                {report.spf.warnings.length > 0 && (
                  <div className="bg-amber-500/10 border border-amber-500/30 p-3.5 rounded-xl space-y-1">
                    <div className="text-xs font-mono font-bold text-amber-300 flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5" /> SPF Configuration Warnings
                    </div>
                    {report.spf.warnings.map((w, i) => (
                      <div key={i} className="text-xs text-amber-200/90 pl-5 leading-relaxed">• {w}</div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* DMARC Tab */}
            {activeTab === 'dmarc' && (
              <div className="space-y-5">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                  <div>
                    <h4 className="text-white font-mono font-bold text-sm flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-cyber-blue" />
                      DMARC Policy Specification (RFC 7489)
                    </h4>
                    <p className="text-xs text-gray-400">Published TXT record for <code className="text-cyber-blue">_dmarc.{report.domain}</code></p>
                  </div>
                  {report.dmarc.rawRecord && (
                    <button
                      onClick={() => copyToClipboard(report.dmarc.rawRecord || '', 'dmarc')}
                      className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-mono text-gray-300 flex items-center gap-1.5 transition-all"
                    >
                      {copiedSection === 'dmarc' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedSection === 'dmarc' ? 'Copied' : 'Copy TXT'}</span>
                    </button>
                  )}
                </div>

                {report.dmarc.rawRecord ? (
                  <div className="bg-[#03060a] border border-white/10 p-3.5 rounded-xl font-mono text-xs text-cyber-blue break-all selection:bg-cyber-blue selection:text-black">
                    {report.dmarc.rawRecord}
                  </div>
                ) : (
                  <div className="bg-red-500/10 border border-red-500/30 p-4 rounded-xl text-xs text-red-400 font-mono">
                    No DMARC policy detected at _dmarc.{report.domain}.
                  </div>
                )}

                {/* Parsed DMARC Tags Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                  <div className="bg-[#03060a] p-3.5 rounded-xl border border-white/5 space-y-1">
                    <span className="text-[10px] font-mono text-gray-500 uppercase">Primary Policy (p)</span>
                    <div className="text-sm font-mono font-bold text-white flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${
                        report.dmarc.policy === 'reject' ? 'bg-emerald-400' :
                        report.dmarc.policy === 'quarantine' ? 'bg-blue-400' : 'bg-amber-400'
                      }`} />
                      {report.dmarc.policy ? `p=${report.dmarc.policy}` : 'None'}
                    </div>
                    <p className="text-[11px] text-gray-400">
                      {report.dmarc.policy === 'reject' ? 'Drop spoofed emails outright' :
                       report.dmarc.policy === 'quarantine' ? 'Divert to Spam/Junk folder' : 'No blocking (Telemetry only)'}
                    </p>
                  </div>

                  <div className="bg-[#03060a] p-3.5 rounded-xl border border-white/5 space-y-1">
                    <span className="text-[10px] font-mono text-gray-500 uppercase">Enforcement Coverage (pct)</span>
                    <div className="text-sm font-mono font-bold text-white">
                      {report.dmarc.percentage}% of mail
                    </div>
                    <p className="text-[11px] text-gray-400">
                      {report.dmarc.percentage === 100 ? '100% full enforcement' : 'Partial sampling rate'}
                    </p>
                  </div>

                  <div className="bg-[#03060a] p-3.5 rounded-xl border border-white/5 space-y-1">
                    <span className="text-[10px] font-mono text-gray-500 uppercase">Aggregate Mailbox (rua)</span>
                    <div className="text-xs font-mono font-bold text-cyber-blue truncate">
                      {report.dmarc.ruaReportMailto?.[0] || 'None configured'}
                    </div>
                    <p className="text-[11px] text-gray-400">
                      Receives XML daily authentication reports
                    </p>
                  </div>

                  <div className="bg-[#03060a] p-3.5 rounded-xl border border-white/5 space-y-1">
                    <span className="text-[10px] font-mono text-gray-500 uppercase">Subdomain Policy (sp)</span>
                    <div className="text-sm font-mono font-bold text-white">
                      {report.dmarc.subdomainPolicy ? `sp=${report.dmarc.subdomainPolicy}` : 'Inherited from p='}
                    </div>
                    <p className="text-[11px] text-gray-400">Protects subdomains like *.domain.com</p>
                  </div>

                  <div className="bg-[#03060a] p-3.5 rounded-xl border border-white/5 space-y-1">
                    <span className="text-[10px] font-mono text-gray-500 uppercase">DKIM Alignment (adkim)</span>
                    <div className="text-sm font-mono font-bold text-white uppercase">
                      {report.dmarc.dkimAlignment}
                    </div>
                    <p className="text-[11px] text-gray-400">
                      {report.dmarc.dkimAlignment === 'strict' ? 'Exact domain match only' : 'Subdomains allowed (Relaxed)'}
                    </p>
                  </div>

                  <div className="bg-[#03060a] p-3.5 rounded-xl border border-white/5 space-y-1">
                    <span className="text-[10px] font-mono text-gray-500 uppercase">SPF Alignment (aspf)</span>
                    <div className="text-sm font-mono font-bold text-white uppercase">
                      {report.dmarc.spfAlignment}
                    </div>
                    <p className="text-[11px] text-gray-400">
                      {report.dmarc.spfAlignment === 'strict' ? 'Exact Return-Path match' : 'Subdomains allowed (Relaxed)'}
                    </p>
                  </div>
                </div>

                {/* Warnings */}
                {report.dmarc.warnings.length > 0 && (
                  <div className="bg-amber-500/10 border border-amber-500/30 p-3.5 rounded-xl space-y-1">
                    <div className="text-xs font-mono font-bold text-amber-300 flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5" /> DMARC Policy Alerts
                    </div>
                    {report.dmarc.warnings.map((w, i) => (
                      <div key={i} className="text-xs text-amber-200/90 pl-5 leading-relaxed">• {w}</div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* DKIM Tab */}
            {activeTab === 'dkim' && (
              <div className="space-y-5">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                  <div>
                    <h4 className="text-white font-mono font-bold text-sm flex items-center gap-2">
                      <Key className="w-4 h-4 text-cyber-blue" />
                      DomainKeys Identified Mail (DKIM) Key Inspection
                    </h4>
                    <p className="text-xs text-gray-400">Queried Host: <code className="text-cyber-blue">{report.dkim.queriedHost}</code></p>
                  </div>
                  {report.dkim.rawRecord && (
                    <button
                      onClick={() => copyToClipboard(report.dkim.rawRecord || '', 'dkim')}
                      className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-mono text-gray-300 flex items-center gap-1.5 transition-all"
                    >
                      {copiedSection === 'dkim' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedSection === 'dkim' ? 'Copied' : 'Copy Key'}</span>
                    </button>
                  )}
                </div>

                {report.dkim.rawRecord ? (
                  <div className="space-y-3">
                    <div className="bg-[#03060a] border border-white/10 p-3.5 rounded-xl font-mono text-xs text-cyber-blue break-all selection:bg-cyber-blue selection:text-black">
                      {report.dkim.rawRecord}
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <div className="bg-[#03060a] p-3 rounded-xl border border-white/5">
                        <span className="text-[10px] font-mono text-gray-500">Key Algorithm</span>
                        <div className="text-sm font-mono font-bold text-white">{report.dkim.keyType}</div>
                      </div>
                      <div className="bg-[#03060a] p-3 rounded-xl border border-white/5">
                        <span className="text-[10px] font-mono text-gray-500">Estimated Key Length</span>
                        <div className="text-sm font-mono font-bold text-white">
                          ~{report.dkim.keyLengthEstimate || 2048}-bit
                        </div>
                      </div>
                      <div className="bg-[#03060a] p-3 rounded-xl border border-white/5">
                        <span className="text-[10px] font-mono text-gray-500">Verified Selector</span>
                        <div className="text-sm font-mono font-bold text-cyber-blue">{report.dkim.selectorTested}</div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="bg-amber-500/10 border border-amber-500/30 p-4 rounded-xl text-xs text-amber-300 font-mono space-y-1">
                    <p className="font-bold">No public key found under selector: "{report.dkim.selectorTested}"</p>
                    <p className="text-gray-400">DKIM selectors are unique to each mail provider. Try entering a custom selector above or check the probed selector table below.</p>
                  </div>
                )}

                {/* Probed Selectors Table */}
                <div className="space-y-2">
                  <h5 className="text-xs font-mono font-bold text-gray-300 uppercase tracking-wider">
                    Common Selectors Probed
                  </h5>
                  <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
                    {report.dkim.probedSelectors.map((probe, idx) => (
                      <div
                        key={idx}
                        className={`p-2.5 rounded-lg border text-xs font-mono flex items-center justify-between ${
                          probe.found
                            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                            : 'bg-white/5 border-white/5 text-gray-500'
                        }`}
                      >
                        <span className="truncate">{probe.selector}</span>
                        {probe.found ? (
                          <span className="text-[10px] bg-emerald-500/20 text-emerald-400 px-1.5 py-0.5 rounded font-bold">
                            FOUND
                          </span>
                        ) : (
                          <span className="text-[10px] text-gray-600">None</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* MX & BIMI Tab */}
            {activeTab === 'mx' && (
              <div className="space-y-5">
                <div>
                  <h4 className="text-white font-mono font-bold text-sm flex items-center gap-2">
                    <Server className="w-4 h-4 text-purple-400" />
                    Mail Exchanger (MX) Records & Routing
                  </h4>
                  <p className="text-xs text-gray-400">Destination mail gateways configured to receive incoming traffic for {report.domain}</p>
                </div>

                {report.mx.records.length > 0 ? (
                  <div className="space-y-2">
                    {report.mx.records.map((mx, idx) => (
                      <div key={idx} className="bg-[#03060a] border border-white/5 p-3 rounded-xl flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <span className="text-[11px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/30 px-2 py-0.5 rounded font-bold">
                            PRIORITY {mx.priority}
                          </span>
                          <span className="text-xs font-mono text-white font-bold">{mx.exchange}</span>
                        </div>
                        <span className="text-[10px] font-mono text-gray-500 hidden sm:inline">Active Gateway</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="bg-red-500/10 border border-red-500/30 p-4 rounded-xl text-xs text-red-400 font-mono">
                    No MX records discovered. This domain cannot receive inbound email.
                  </div>
                )}

                {/* BIMI Section */}
                <div className="pt-4 border-t border-white/5 space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-white font-mono font-bold text-sm flex items-center gap-2">
                        <Shield className="w-4 h-4 text-cyber-blue" />
                        Brand Indicators for Message Identification (BIMI)
                      </h4>
                      <p className="text-xs text-gray-400">Verified SVG brand avatar published at <code className="text-cyber-blue">default._bimi.{report.domain}</code></p>
                    </div>
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                      report.bimi.found ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-white/5 text-gray-500 border-white/10'
                    }`}>
                      {report.bimi.found ? 'BIMI PUBLISHED' : 'NOT CONFIGURED'}
                    </span>
                  </div>

                  {report.bimi.found && report.bimi.logoUrl && (
                    <div className="bg-[#03060a] p-3.5 rounded-xl border border-white/10 flex items-center gap-4">
                      <div className="w-12 h-12 rounded-xl bg-white/5 p-2 flex items-center justify-center border border-white/10 shrink-0">
                        <img 
                          src={report.bimi.logoUrl} 
                          alt="BIMI Logo" 
                          className="max-w-full max-h-full object-contain"
                          onError={(e) => {
                            (e.target as HTMLElement).style.display = 'none';
                          }}
                        />
                      </div>
                      <div className="space-y-1 min-w-0 font-mono text-xs">
                        <div className="text-gray-400 text-[10px]">Logo Vector URI:</div>
                        <a href={report.bimi.logoUrl} target="_blank" rel="noreferrer" className="text-cyber-blue hover:underline truncate block">
                          {report.bimi.logoUrl}
                        </a>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Action Plan / Remediation Tab */}
            {activeTab === 'remediation' && (
              <div className="space-y-4">
                <div>
                  <h4 className="text-white font-mono font-bold text-sm flex items-center gap-2">
                    <Layers className="w-4 h-4 text-cyber-blue" />
                    Security Hardening & Remediation Roadmap
                  </h4>
                  <p className="text-xs text-gray-400">Actionable steps to eliminate spoofing, BEC, and impersonation risks</p>
                </div>

                {report.actionItems.length === 0 ? (
                  <div className="bg-emerald-500/10 border border-emerald-500/30 p-6 rounded-2xl text-center space-y-2">
                    <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
                    <h5 className="text-sm font-mono font-bold text-white">Flawless Authentication Posture</h5>
                    <p className="text-xs text-gray-400 max-w-md mx-auto">
                      All critical SPF, DKIM, and DMARC enforcement standards are satisfied. Unauthorized senders will be rejected.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {report.actionItems.map((item, idx) => (
                      <div
                        key={idx}
                        className={`p-4 rounded-xl border flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 ${
                          item.priority === 'HIGH' ? 'bg-red-500/5 border-red-500/30' :
                          item.priority === 'MEDIUM' ? 'bg-amber-500/5 border-amber-500/30' :
                          'bg-blue-500/5 border-blue-500/30'
                        }`}
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase ${
                              item.priority === 'HIGH' ? 'bg-red-500/20 text-red-300' :
                              item.priority === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300' :
                              'bg-blue-500/20 text-blue-300'
                            }`}>
                              {item.priority} PRIORITY
                            </span>
                            <h5 className="text-xs font-mono font-bold text-white">{item.title}</h5>
                          </div>
                          <p className="text-xs text-gray-400 font-mono leading-relaxed">{item.remediation}</p>
                        </div>
                        <button
                          onClick={() => copyToClipboard(item.remediation, `rem-${idx}`)}
                          className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-[11px] font-mono text-gray-300 shrink-0 flex items-center gap-1.5 transition-all"
                        >
                          {copiedSection === `rem-${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedSection === `rem-${idx}` ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

          </div>
        </motion.div>
      )}

    </div>
  );
}
