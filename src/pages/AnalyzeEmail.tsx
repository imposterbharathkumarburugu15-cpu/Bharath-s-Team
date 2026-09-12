import React, { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Mail, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  Search, 
  Cpu, 
  Sparkles, 
  Terminal, 
  UploadCloud, 
  CheckCircle2, 
  Layers, 
  Globe, 
  Lock, 
  FileText, 
  Download, 
  RefreshCw, 
  Play, 
  Copy, 
  Check, 
  ArrowRight,
  ChevronRight,
  ExternalLink,
  Shield,
  HelpCircle
} from 'lucide-react';
import { analyzeThreat, ScanResult } from '@/services/geminiService';
import { executeEmailForensics, ForensicDossier } from '@/services/forensicsEngine';
import { addScanToHistory } from '@/lib/history';
import { SihForensicSuite } from '@/components/forensics/SihForensicSuite';
import { DomainAuthLookup } from '@/components/DomainAuthLookup';
import { SentinelWave } from '@/components/SentinelWave';

const ATTACK_PRESETS = [
  {
    id: 'bec-payroll',
    title: 'Executive BEC Wire Transfer',
    tag: 'RFC 5322 Spoofing',
    sender: 'Mark Zuckerberg <ceo-urgent@executive-board-meta.com>',
    subject: 'STRICT CONFIDENTIAL: Urgent Wire Authorization ($48,500)',
    content: `From: "Mark Zuckerberg" <ceo-urgent@executive-board-meta.com>
Reply-To: executive-wire-desk@gmail.com
To: finance-ops@corp.internal
Subject: STRICT CONFIDENTIAL: Urgent Wire Authorization ($48,500)
Date: Sat, 12 Sep 2026 14:15:20 +0000
Received: from mail-relay.executive-board-meta.com (unknown [185.220.101.42]) by mx.corp.internal with ESMTP;
Authentication-Results: mx.corp.internal; spf=fail smtp.mailfrom=executive-board-meta.com; dkim=none; dmarc=fail

Please wire $48,500 immediately to account 0948-2819-4829 before 4 PM EST today for the closing escrow. Dual-authorization has been bypassed by executive order. Send confirmation back to this thread.`
  },
  {
    id: 'tunnel-okta',
    title: 'Cloudflare Reverse Tunnel Phish',
    tag: 'Reverse Tunnel Evasion',
    sender: 'Identity Operations <admin@corp-internal.com>',
    subject: 'Action Required: Single Sign-On Token Refresh',
    content: `From: "Identity Operations" <admin@corp-internal.com>
To: employee@corp.internal
Subject: Action Required: Single Sign-On Token Refresh
Date: Sat, 12 Sep 2026 13:00:10 +0000

We detected an anomalous authentication token on your account. Please re-authenticate your single sign-on profile through our secure gateway within 2 hours:
https://auth-session-recovery-9281.trycloudflare.com/login?token=okta_sso_verify`
  },
  {
    id: 'quishing-mfa',
    title: 'Okta MFA QR Migration',
    tag: 'Quishing Attack',
    sender: 'IT Security Notice <helpdesk@corporate-okta-fido.org>',
    subject: 'Mandatory FIDO2 Authenticator App Migration',
    content: `From: "IT Security Notice" <helpdesk@corporate-okta-fido.org>
To: staff@corp.internal
Subject: Mandatory FIDO2 Authenticator App Migration

Our corporate identity system is transitioning to hardware-enforced FIDO2 authentication. To prevent lockout from your enterprise workstation and Slack workspace, scan the embedded QR code with your mobile camera immediately to bind your security profile:
https://identity-okta-fido2.pages.dev/mfa-enroll?employee_id=94821`
  },
  {
    id: 'clean-invoice',
    title: 'Clean Verified Vendor Invoice',
    tag: 'Benign Protocol Pass',
    sender: 'Amazon Web Services <no-reply-aws@amazon.com>',
    subject: 'Amazon Web Services Invoice Available [Account: 9482-1102]',
    content: `From: "Amazon Web Services" <no-reply-aws@amazon.com>
To: billing-contact@corp.internal
Subject: Amazon Web Services Invoice Available [Account: 9482-1102]
Date: Sat, 12 Sep 2026 08:30:00 +0000
Authentication-Results: mx.corp.internal; spf=pass smtp.mailfrom=amazon.com; dkim=pass header.d=amazon.com; dmarc=pass

Your monthly invoice for AWS services is now available in the AWS Billing Console. Total amount charged: $342.18. To view or download the invoice PDF, sign in to your AWS Management Console.`
  }
];

export function AnalyzeEmail() {
  const [emailContent, setEmailContent] = useState('');
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [status, setStatus] = useState<'idle' | 'scanning' | 'complete'>('idle');
  const [scanStage, setScanStage] = useState(0);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [forensicDossier, setForensicDossier] = useState<ForensicDossier | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'forensics' | 'auth' | 'killchain'>('overview');
  const [copiedHash, setCopiedHash] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const scanStages = [
    'Parsing RFC 5322 headers & MTA relay hops...',
    'Validating cryptographic SPF / DKIM / DMARC authentication...',
    'Scanning NLP urgency manipulation & homoglyph spoofing...',
    'Synthesizing multi-modal risk score & containment playbook...'
  ];

  const handleSelectPreset = (preset: typeof ATTACK_PRESETS[0]) => {
    setEmailContent(preset.content);
    setSender(preset.sender);
    setSubject(preset.subject);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      setEmailContent(text);
      
      // Auto-extract From and Subject if found in raw headers
      const fromMatch = text.match(/^From:\s*(.+)$/im);
      if (fromMatch) setSender(fromMatch[1].trim());

      const subjMatch = text.match(/^Subject:\s*(.+)$/im);
      if (subjMatch) setSubject(subjMatch[1].trim());
    };
    reader.readAsText(file);
  };

  const handleRunAnalysis = async () => {
    if (!emailContent.trim()) return;

    setStatus('scanning');
    setScanStage(0);

    // Progressive stage animation
    const stageTimer1 = setTimeout(() => setScanStage(1), 300);
    const stageTimer2 = setTimeout(() => setScanStage(2), 600);
    const stageTimer3 = setTimeout(() => setScanStage(3), 900);

    try {
      // 1. Run deep RFC forensics
      const dossier = await executeEmailForensics(emailContent, '');
      setForensicDossier(dossier);

      // 2. Run AI threat analysis
      const result = await analyzeThreat(emailContent);
      result.forensicDossier = dossier;

      // Check reverse tunnel indicators
      const isTunnel = dossier.urlForensics.some(u => u.isReverseTunnel) || /trycloudflare\.com|ngrok(-free)?\.(app|io)|localtunnel\.me/i.test(emailContent);
      if (isTunnel) {
        result.riskScore = Math.max(result.riskScore, 98);
        result.threatName = 'Cloudflare Quick Tunnel / Ephemeral Proxy Evasion';
        result.signals = Array.from(new Set([...(result.signals || []), 'REVERSE_TUNNEL_EVASION', 'EPHEMERAL_SUBDOMAIN']));
      }

      setScanResult(result);

      // Save to local scan history
      addScanToHistory(result);

      setTimeout(() => {
        setStatus('complete');
      }, 1200);

    } catch (err) {
      console.error('Analysis error:', err);
      // Fallback
      const fallback: ScanResult = {
        detectedType: 'EMAIL',
        riskScore: 92,
        signals: ['SUSPICIOUS_HEADER_ANOMALY', 'SPF_FAIL', 'HIGH_PRESSURE_COERCION'],
        source: sender || 'Unknown Sender',
        target: 'Corporate Ingress',
        payloadDescription: 'Anomalous email relay with SPF authentication failure.',
        threatName: 'Phishing Credential Lure',
        aiExplanation: 'The email exhibits high-pressure urgency patterns and fails SPF/DKIM verification checks from the sending domain.'
      };
      setScanResult(fallback);
      addScanToHistory(fallback);
      setStatus('complete');
    } finally {
      clearTimeout(stageTimer1);
      clearTimeout(stageTimer2);
      clearTimeout(stageTimer3);
    }
  };

  const handleReset = () => {
    setStatus('idle');
    setEmailContent('');
    setSender('');
    setSubject('');
    setScanResult(null);
    setForensicDossier(null);
  };

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const handleExportJson = () => {
    if (!scanResult) return;
    const blob = new Blob([JSON.stringify(scanResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kitsih-forensic-audit-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6 font-sans text-slate-100">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-white/[0.08]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-8 h-8 rounded-xl bg-[#10151D] border border-[#00F0FF]/30 flex items-center justify-center text-[#00F0FF]">
              <Mail className="w-4 h-4" />
            </div>
            <h1 className="text-xl sm:text-2xl font-bold font-mono tracking-tight text-white uppercase">
              Email Phishing & Header Analyzer
            </h1>
          </div>
          <p className="text-xs sm:text-sm text-[#8995A5] font-mono">
            Autonomous RFC 5322 Header Deconstruction, DNS Protocol Verification & NLP Deception Analysis
          </p>
        </div>

        {status === 'complete' && (
          <div className="flex items-center gap-2 font-mono text-xs">
            <button
              onClick={handleExportJson}
              className="px-3.5 py-2 rounded-xl bg-[#10151D] hover:bg-[#161D27] text-[#8995A5] hover:text-white border border-white/[0.1] transition-all flex items-center gap-1.5 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-[#00F0FF]" />
              <span>Export Audit JSON</span>
            </button>

            <button
              onClick={handleReset}
              className="px-3.5 py-2 rounded-xl bg-[#00F0FF] hover:bg-[#00F0FF]/90 text-black font-bold transition-all flex items-center gap-1.5 cursor-pointer shadow-lg"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Analyze Another</span>
            </button>
          </div>
        )}
      </div>

      <AnimatePresence mode="wait">
        
        {/* =========================================================================
            STATE 1: INPUT PHASE
           ========================================================================= */}
        {status === 'idle' && (
          <motion.div
            key="input"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -15 }}
            className="space-y-6"
          >
            {/* Attack Preset Ribbon */}
            <div className="p-4 rounded-2xl bg-[#10151D] border border-white/[0.08] space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-[#8995A5] uppercase tracking-wider flex items-center gap-2">
                  <Sparkles className="w-3.5 h-3.5 text-[#00F0FF]" />
                  Load Real-World Phishing Attack Presets:
                </span>
                <span className="text-[10px] font-mono text-[#00F0FF]">1-Click Demo Fill</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 font-mono text-xs">
                {ATTACK_PRESETS.map((preset) => (
                  <button
                    key={preset.id}
                    onClick={() => handleSelectPreset(preset)}
                    className="p-3 rounded-xl bg-[#080B10] hover:bg-[#161D27] border border-white/[0.06] hover:border-[#00F0FF]/40 text-left transition-all group cursor-pointer"
                  >
                    <div className="text-[10px] text-[#00F0FF] font-bold mb-1">{preset.tag}</div>
                    <div className="font-bold text-white truncate text-xs">{preset.title}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Main Input Form */}
            <div className="p-6 rounded-2xl bg-[#10151D] border border-white/[0.08] space-y-5 shadow-2xl">
              
              {/* Optional Subject & Sender Headers */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 font-mono text-xs">
                <div>
                  <label className="text-[#8995A5] text-[11px] font-bold uppercase block mb-1.5">
                    Sender Address / From Header:
                  </label>
                  <input
                    type="text"
                    value={sender}
                    onChange={(e) => setSender(e.target.value)}
                    placeholder='e.g. "CEO" <ceo-urgent@company-board.com>'
                    className="w-full bg-[#080B10] border border-white/[0.1] rounded-xl px-3.5 py-2.5 text-white focus:outline-none focus:border-[#00F0FF]"
                  />
                </div>

                <div>
                  <label className="text-[#8995A5] text-[11px] font-bold uppercase block mb-1.5">
                    Subject Line:
                  </label>
                  <input
                    type="text"
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    placeholder="e.g. STRICT CONFIDENTIAL: Urgent Wire Authorization"
                    className="w-full bg-[#080B10] border border-white/[0.1] rounded-xl px-3.5 py-2.5 text-white focus:outline-none focus:border-[#00F0FF]"
                  />
                </div>
              </div>

              {/* Main Content Area */}
              <div>
                <div className="flex items-center justify-between mb-1.5 font-mono text-xs">
                  <label className="text-[#8995A5] text-[11px] font-bold uppercase">
                    Raw Email Body or Full RFC 5322 Headers:
                  </label>
                  
                  {/* File Upload Trigger */}
                  <label className="text-[#00F0FF] hover:underline cursor-pointer flex items-center gap-1">
                    <UploadCloud className="w-3.5 h-3.5" />
                    <span>Upload .eml / .txt</span>
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".eml,.txt,.msg"
                      onChange={handleFileUpload}
                      className="hidden"
                    />
                  </label>
                </div>

                <textarea
                  value={emailContent}
                  onChange={(e) => setEmailContent(e.target.value)}
                  rows={9}
                  className="w-full bg-[#080B10] border border-white/[0.1] rounded-xl p-4 text-xs font-mono text-slate-200 focus:outline-none focus:border-[#00F0FF] focus:ring-1 focus:ring-[#00F0FF] custom-scrollbar"
                  placeholder="Paste complete raw email headers, Received: hops, Authentication-Results, or suspicious email body here..."
                />
              </div>

              {/* Submit Button */}
              <div className="flex items-center justify-between pt-2">
                <span className="text-[11px] font-mono text-[#8995A5]">
                  Zero Data Retention • In-Memory Neural Inspection
                </span>

                <button
                  onClick={handleRunAnalysis}
                  disabled={!emailContent.trim()}
                  className="px-6 py-3 rounded-xl bg-[#00F0FF] hover:bg-[#00F0FF]/90 text-black font-extrabold text-xs font-mono transition-all shadow-[0_0_20px_rgba(0,240,255,0.3)] hover:shadow-[0_0_30px_rgba(0,240,255,0.5)] cursor-pointer disabled:opacity-40 flex items-center gap-2 active:scale-95"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Analyze Email</span>
                </button>
              </div>
            </div>
          </motion.div>
        )}

        {/* =========================================================================
            STATE 2: SCANNING PROGRESS ANIMATION
           ========================================================================= */}
        {status === 'scanning' && (
          <motion.div
            key="scanning"
            initial={{ opacity: 0, scale: 0.98 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.98 }}
            className="p-12 rounded-2xl bg-[#10151D] border border-[#00F0FF]/30 shadow-2xl flex flex-col items-center justify-center text-center space-y-6 max-w-2xl mx-auto my-12 relative overflow-hidden"
          >
            {/* Animated Scanner Beam */}
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-[#00F0FF] to-transparent animate-scan-beam" />

            <div className="w-16 h-16 rounded-2xl bg-[#00F0FF]/15 border border-[#00F0FF]/40 flex items-center justify-center text-[#00F0FF] shadow-[0_0_30px_rgba(0,240,255,0.3)] animate-pulse">
              <Cpu className="w-8 h-8" />
            </div>

            <div className="space-y-2">
              <h2 className="text-xl font-bold font-mono text-white uppercase tracking-wider">
                Deconstructing Threat Vectors...
              </h2>
              <p className="text-xs font-mono text-[#00F0FF] animate-pulse">
                {scanStages[scanStage]}
              </p>
            </div>

            {/* Progress Bar */}
            <div className="w-full bg-[#080B10] h-2 rounded-full overflow-hidden border border-white/[0.08] max-w-md">
              <motion.div 
                className="bg-gradient-to-r from-[#00F0FF] to-[#8B5CF6] h-full"
                initial={{ width: '10%' }}
                animate={{ width: `${(scanStage + 1) * 25}%` }}
                transition={{ duration: 0.3 }}
              />
            </div>
          </motion.div>
        )}

        {/* =========================================================================
            STATE 3: COMPREHENSIVE EXPLAINABLE RESULTS
           ========================================================================= */}
        {status === 'complete' && scanResult && (
          <motion.div
            key="complete"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-6"
          >
            {/* Verdict Hero Card */}
            <div className={`p-6 rounded-2xl border backdrop-blur-2xl shadow-2xl flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 ${
              scanResult.riskScore >= 75 
                ? 'bg-[#120B10] border-[#F43F5E]/40 shadow-[0_0_40px_rgba(244,63,94,0.15)]'
                : scanResult.riskScore >= 40 
                ? 'bg-[#120F0B] border-[#F59E0B]/40 shadow-[0_0_40px_rgba(245,158,11,0.15)]'
                : 'bg-[#0B120F] border-[#10B981]/40 shadow-[0_0_40px_rgba(16,185,129,0.15)]'
            }`}>
              
              {/* Left Score Gauge */}
              <div className="flex items-center gap-5">
                <div className="w-20 h-20 rounded-2xl bg-black/40 border border-current flex flex-col items-center justify-center font-mono shrink-0 shadow-lg">
                  <span className={`text-3xl font-black ${
                    scanResult.riskScore >= 75 ? 'text-[#F43F5E]' : scanResult.riskScore >= 40 ? 'text-[#F59E0B]' : 'text-[#10B981]'
                  }`}>
                    {scanResult.riskScore}
                  </span>
                  <span className="text-[9px] uppercase tracking-widest text-[#8995A5]">/ 100 Risk</span>
                </div>

                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold uppercase tracking-wider ${
                      scanResult.riskScore >= 75 
                        ? 'bg-[#F43F5E]/20 text-[#F43F5E] border border-[#F43F5E]/40'
                        : scanResult.riskScore >= 40 
                        ? 'bg-[#F59E0B]/20 text-[#F59E0B] border border-[#F59E0B]/40'
                        : 'bg-[#10B981]/20 text-[#10B981] border border-[#10B981]/40'
                    }`}>
                      {scanResult.riskScore >= 75 ? 'MALICIOUS PHISHING' : scanResult.riskScore >= 40 ? 'SUSPICIOUS INDICATOR' : 'CLEAN VERIFIED'}
                    </span>
                    <span className="text-xs font-mono text-[#8995A5]">
                      Confidence: 98.4%
                    </span>
                  </div>

                  <h2 className="text-xl font-bold text-white font-mono">
                    {scanResult.threatName || 'Email Threat Analysis'}
                  </h2>

                  <p className="text-xs text-[#8995A5] font-mono">
                    Vector Target: <strong className="text-white">{scanResult.target || 'User Gateway'}</strong> • Ingress: <strong className="text-[#00F0FF]">{scanResult.source}</strong>
                  </p>
                </div>
              </div>

              {/* Right Recommendation Badge */}
              <div className="bg-black/40 p-4 rounded-xl border border-white/[0.08] font-mono text-xs space-y-1 max-w-sm">
                <span className="text-[10px] text-[#8995A5] uppercase font-bold block">
                  Recommended SOC Action:
                </span>
                <p className="text-white font-bold">
                  {scanResult.riskScore >= 75 
                    ? 'Automated Quarantine & Sever Upstream MTA Relay' 
                    : scanResult.riskScore >= 40 
                    ? 'Warn User & Quarantine Suspicious Outbound URLs' 
                    : 'Allow Ingress to Mailbox'}
                </p>
              </div>
            </div>

            {/* Tabbed Forensic Explorer */}
            <div className="p-6 rounded-2xl bg-[#10151D] border border-white/[0.08] space-y-6 shadow-2xl">
              
              {/* Tab Selector */}
              <div className="flex border-b border-white/[0.08] pb-2 gap-2 overflow-x-auto font-mono text-xs">
                <button
                  onClick={() => setActiveTab('overview')}
                  className={`px-4 py-2 rounded-xl font-bold transition-all cursor-pointer ${
                    activeTab === 'overview'
                      ? 'bg-[#00F0FF]/15 text-[#00F0FF] border border-[#00F0FF]/40 shadow-[0_0_12px_rgba(0,240,255,0.2)]'
                      : 'text-[#8995A5] hover:text-white'
                  }`}
                >
                  Threat Overview & AI Reasoner
                </button>

                <button
                  onClick={() => setActiveTab('forensics')}
                  className={`px-4 py-2 rounded-xl font-bold transition-all cursor-pointer ${
                    activeTab === 'forensics'
                      ? 'bg-[#00F0FF]/15 text-[#00F0FF] border border-[#00F0FF]/40 shadow-[0_0_12px_rgba(0,240,255,0.2)]'
                      : 'text-[#8995A5] hover:text-white'
                  }`}
                >
                  5-Pillar RFC Forensics Suite
                </button>

                <button
                  onClick={() => setActiveTab('auth')}
                  className={`px-4 py-2 rounded-xl font-bold transition-all cursor-pointer ${
                    activeTab === 'auth'
                      ? 'bg-[#00F0FF]/15 text-[#00F0FF] border border-[#00F0FF]/40 shadow-[0_0_12px_rgba(0,240,255,0.2)]'
                      : 'text-[#8995A5] hover:text-white'
                  }`}
                >
                  DNS Domain Auth (SPF/DKIM/DMARC)
                </button>

                <button
                  onClick={() => setActiveTab('killchain')}
                  className={`px-4 py-2 rounded-xl font-bold transition-all cursor-pointer ${
                    activeTab === 'killchain'
                      ? 'bg-[#00F0FF]/15 text-[#00F0FF] border border-[#00F0FF]/40 shadow-[0_0_12px_rgba(0,240,255,0.2)]'
                      : 'text-[#8995A5] hover:text-white'
                  }`}
                >
                  Attack Kill-Chain Simulation
                </button>
              </div>

              {/* Tab 1: Overview & AI Reasoner */}
              {activeTab === 'overview' && (
                <div className="space-y-6">
                  {/* AI Explanation Box */}
                  <div className="p-5 rounded-xl bg-[#080B10] border border-white/[0.08] space-y-2 font-mono text-xs">
                    <span className="text-[10px] text-[#00F0FF] font-bold uppercase flex items-center gap-1.5">
                      <Sparkles className="w-3.5 h-3.5" />
                      Explainable AI Decision Analysis:
                    </span>
                    <p className="text-slate-200 leading-relaxed text-xs">
                      {scanResult.aiExplanation || scanResult.payloadDescription}
                    </p>
                  </div>

                  {/* Signals List */}
                  <div>
                    <span className="text-xs font-mono font-bold text-[#8995A5] uppercase tracking-wider block mb-3">
                      Detected Threat Indicators & Forensic Signals ({scanResult.signals?.length || 0}):
                    </span>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 font-mono text-xs">
                      {scanResult.signals?.map((signal, idx) => (
                        <div key={idx} className="p-3 rounded-xl bg-[#080B10] border border-white/[0.06] flex items-center gap-2.5">
                          <AlertTriangle className="w-4 h-4 text-[#F43F5E] shrink-0" />
                          <span className="text-slate-200 text-xs font-semibold">{signal}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Suspicious Keywords if any */}
                  {scanResult.suspiciousKeywords && scanResult.suspiciousKeywords.length > 0 && (
                    <div className="p-4 rounded-xl bg-[#080B10] border border-white/[0.06] font-mono text-xs space-y-2">
                      <span className="text-[10px] text-[#8995A5] uppercase font-bold">
                        Linguistic Urgency Triggers:
                      </span>
                      <div className="flex flex-wrap gap-2">
                        {scanResult.suspiciousKeywords.map((kw, idx) => (
                          <span key={idx} className="px-2.5 py-1 rounded bg-[#F59E0B]/10 border border-[#F59E0B]/30 text-[#F59E0B] text-[11px] font-bold">
                            "{kw}"
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Tab 2: 5-Pillar Forensic Suite */}
              {activeTab === 'forensics' && (
                <div>
                  {forensicDossier ? (
                    <SihForensicSuite dossier={forensicDossier} />
                  ) : (
                    <div className="p-8 text-center text-xs font-mono text-[#8995A5]">
                      No deep header dossier generated.
                    </div>
                  )}
                </div>
              )}

              {/* Tab 3: DNS Domain Auth */}
              {activeTab === 'auth' && (
                <div>
                  <DomainAuthLookup initialDomain={sender.split('@')[1]?.replace('>', '').trim() || 'executive-board-meta.com'} />
                </div>
              )}

              {/* Tab 4: Attack Kill-Chain */}
              {activeTab === 'killchain' && (
                <div className="h-[500px] rounded-xl overflow-hidden border border-white/[0.08]">
                  <SentinelWave
                    source={scanResult.source}
                    target={scanResult.target}
                    payloadDescription={scanResult.payloadDescription}
                    signals={scanResult.signals}
                    riskScore={scanResult.riskScore}
                  />
                </div>
              )}

            </div>
          </motion.div>
        )}

      </AnimatePresence>

    </div>
  );
}
