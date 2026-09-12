import React, { useState } from 'react';
import { motion } from 'motion/react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Mail, 
  ArrowRight, 
  Zap, 
  Lock, 
  Cpu, 
  Layers, 
  CheckCircle2, 
  AlertTriangle, 
  Terminal, 
  Globe, 
  Sparkles, 
  Activity, 
  FileText, 
  ChevronRight,
  ExternalLink,
  Search,
  Eye,
  RefreshCw,
  Copy,
  Check,
  Mic,
  Shield
} from 'lucide-react';

interface LandingPageProps {
  onNavigateToDashboard: () => void;
  onNavigateToInboxShield: () => void;
  onNavigateToScanner: () => void;
}

const SAMPLE_ATTACKS = [
  {
    id: 'bec',
    title: 'Executive BEC Wire Transfer',
    sender: 'Mark Zuckerberg <ceo-urgent@executive-board-meta.com>',
    subject: 'STRICT CONFIDENTIAL: Immediate Wire Authorization ($48,500)',
    tag: 'RFC 5322 Spoofing',
    risk: 96,
    verdict: 'CRITICAL PHISHING / BEC',
    snippet: 'Please wire $48,500 immediately before 4 PM EST today for the closing escrow. Dual-authorization bypassed by executive order.',
    indicators: ['Header Divergence', 'Reply-To Mismatch', 'Financial Coercion', 'Spoofed Display Name']
  },
  {
    id: 'tunnel',
    title: 'Cloudflare Ephemeral Tunnel',
    sender: 'IT Helpdesk <sso-notify@corp-internal.com>',
    subject: 'Mandatory SSO Session Refresh',
    tag: 'Reverse Tunnel Evasion',
    risk: 98,
    verdict: 'CRITICAL TUNNEL EXPLOIT',
    snippet: 'Re-authenticate your corporate credentials: https://auth-session-recovery.trycloudflare.com/login',
    indicators: ['Ephemeral Reverse Tunnel', 'Cloudflare Proxy Masking', 'Zero Domain History', 'Credential Harvester']
  },
  {
    id: 'quishing',
    title: 'Okta MFA QR Code Lure',
    sender: 'Corporate Identity <mfa-reset@security-team.org>',
    subject: 'Urgent: Hardware Token Re-enrollment',
    tag: 'Quishing / Mobile Vector',
    risk: 91,
    verdict: 'MALICIOUS QUISHING',
    snippet: 'Scan the embedded QR code with your mobile camera to bind your identity token before 24h lockout.',
    indicators: ['QR Code Redirection', 'Domain Typo Squat', 'Artificial 12h Deadline', 'High-Risk CDN Host']
  }
];

export function LandingPage({ 
  onNavigateToDashboard, 
  onNavigateToInboxShield, 
  onNavigateToScanner 
}: LandingPageProps) {
  const [selectedAttack, setSelectedAttack] = useState(SAMPLE_ATTACKS[0]);
  const [isScanningPreview, setIsScanningPreview] = useState(false);

  const handleRunSampleScan = (sample: typeof SAMPLE_ATTACKS[0]) => {
    setSelectedAttack(sample);
    setIsScanningPreview(true);
    setTimeout(() => {
      setIsScanningPreview(false);
    }, 400);
  };

  return (
    <div className="min-h-screen bg-[#080B10] text-[#F1F5F9] font-sans selection:bg-[#00F0FF] selection:text-black overflow-x-hidden">
      
      {/* Background Micro Cyber Grid */}
      <div className="bg-grid opacity-35 fixed inset-0 pointer-events-none" />
      <div className="fixed top-0 right-1/4 w-96 h-96 bg-[#00F0FF]/5 rounded-full blur-[160px] pointer-events-none" />
      <div className="fixed bottom-0 left-1/4 w-96 h-96 bg-[#8B5CF6]/5 rounded-full blur-[160px] pointer-events-none" />

      {/* =========================================================================
          1. NAVIGATION BAR
         ========================================================================= */}
      <nav className="sticky top-0 z-50 backdrop-blur-xl bg-[#080B10]/85 border-b border-white/[0.08]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Logo */}
          <div className="flex items-center gap-3 cursor-pointer group" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
            <div className="relative w-9 h-9 flex items-center justify-center shrink-0">
              <svg viewBox="0 0 100 100" className="w-full h-full text-[#00F0FF] drop-shadow-[0_0_10px_rgba(0,240,255,0.8)] fill-current transition-transform duration-300 group-hover:scale-105">
                <polygon points="50 3 93 25 93 75 50 97 7 75 7 25" fill="none" stroke="currentColor" strokeWidth="4" />
                <polygon points="50 15 80 32 80 68 50 85 20 68 20 32" fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray="5 5" className="animate-[spin_12s_linear_infinite_reverse]" />
                <circle cx="50" cy="50" r="12" className="animate-pulse fill-[#00F0FF]/80" />
              </svg>
            </div>
            <div className="flex flex-col">
              <span className="font-extrabold text-base tracking-[0.18em] text-white font-mono">
                NEUROSHIELD
              </span>
              <span className="text-[9px] text-[#00F0FF] font-mono tracking-[0.25em] uppercase -mt-0.5 font-bold drop-shadow-[0_0_5px_rgba(0,240,255,0.4)]">
                AI SOC GATEWAY
              </span>
            </div>
          </div>

          {/* Nav Links */}
          <div className="hidden md:flex items-center gap-8 text-xs font-mono text-[#8995A5]">
            <a href="#features" className="hover:text-[#F1F5F9] transition-colors">Matrix Features</a>
            <a href="#pipeline" className="hover:text-[#F1F5F9] transition-colors">4-Stage Pipeline</a>
            <a href="#architecture" className="hover:text-[#F1F5F9] transition-colors">Security Architecture</a>
            <a href="#demo" className="hover:text-[#F1F5F9] transition-colors">Interactive Demo</a>
          </div>

          {/* Action CTAs */}
          <div className="flex items-center gap-3 font-mono text-xs">
            <button
              onClick={onNavigateToInboxShield}
              className="px-3.5 py-1.5 rounded-xl text-[#8995A5] hover:text-white hover:bg-white/[0.04] transition-all cursor-pointer hidden sm:inline-flex items-center gap-1.5"
            >
              <Mail className="w-3.5 h-3.5 text-[#00F0FF]" />
              <span>Inbox Shield</span>
            </button>

            <button
              onClick={onNavigateToDashboard}
              className="px-4 py-2 rounded-xl bg-[#00F0FF] hover:bg-[#00F0FF]/90 text-black font-bold transition-all shadow-[0_0_20px_rgba(0,240,255,0.3)] hover:shadow-[0_0_25px_rgba(0,240,255,0.5)] cursor-pointer active:scale-95 flex items-center gap-2"
            >
              <Zap className="w-3.5 h-3.5 fill-current" />
              <span>Enter Defense Console</span>
            </button>
          </div>
        </div>
      </nav>

      {/* =========================================================================
          2. HERO SECTION
         ========================================================================= */}
      <section className="relative pt-16 pb-24 lg:pt-24 lg:pb-32 overflow-hidden">
        {/* Glow Spheres */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-[#00F0FF]/[0.06] rounded-full blur-[160px] pointer-events-none" />
        <div className="absolute top-1/3 right-10 w-[400px] h-[400px] bg-[#8B5CF6]/[0.05] rounded-full blur-[140px] pointer-events-none" />

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
          <div className="flex flex-col items-center text-center space-y-6 max-w-4xl mx-auto">
            
            {/* Top Badge */}
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#10151D] border border-[#00F0FF]/30 text-[#00F0FF] text-xs font-mono font-medium shadow-[0_0_15px_rgba(0,240,255,0.15)]"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>NEUROSHIELD • AUTONOMOUS MULTI-CHANNEL THREAT INTERCEPTION</span>
            </motion.div>

            {/* Main Headline */}
            <motion.h1
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
              className="text-4xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight text-white font-sans leading-[1.1]"
            >
              See the threat before it reaches your inbox.
            </motion.h1>

            {/* Supporting Copy */}
            <motion.p
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
              className="text-base sm:text-xl text-[#8995A5] max-w-2xl leading-relaxed"
            >
              NeuroShield combines explainable AI, RFC 5322 multi-hop relay deconstruction, reverse tunnel interception, and synthetic voice defense to neutralize sophisticated zero-day cyber attacks.
            </motion.p>

            {/* CTAs */}
            <motion.div
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
              className="flex flex-wrap items-center justify-center gap-4 pt-2 font-mono text-xs sm:text-sm"
            >
              <button
                onClick={onNavigateToDashboard}
                className="px-6 py-3.5 rounded-xl bg-[#00F0FF] hover:bg-[#00F0FF]/90 text-black font-extrabold transition-all shadow-[0_0_25px_rgba(0,240,255,0.4)] hover:shadow-[0_0_35px_rgba(0,240,255,0.6)] cursor-pointer flex items-center gap-2.5 active:scale-95"
              >
                <span>Launch Defense Console</span>
                <ArrowRight className="w-4 h-4" />
              </button>

              <button
                onClick={onNavigateToInboxShield}
                className="px-6 py-3.5 rounded-xl bg-[#10151D] hover:bg-[#161D27] text-white font-bold border border-white/[0.12] hover:border-[#00F0FF]/40 transition-all shadow-lg cursor-pointer flex items-center gap-2"
              >
                <Mail className="w-4 h-4 text-[#00F0FF]" />
                <span>Inbox Shield & Forensics</span>
                <ChevronRight className="w-4 h-4 text-[#8995A5]" />
              </button>

              <button
                onClick={onNavigateToScanner}
                className="px-5 py-3.5 rounded-xl bg-white/5 hover:bg-white/10 text-gray-300 hover:text-white font-mono text-xs border border-white/10 transition-all cursor-pointer flex items-center gap-2"
              >
                <ShieldAlert className="w-4 h-4 text-[#F43F5E]" />
                <span>Live Scanner</span>
              </button>
            </motion.div>
          </div>

          {/* =========================================================================
              HERO CUSTOM INTERACTIVE SCANNER VISUAL
             ========================================================================= */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="mt-14 max-w-4xl mx-auto rounded-2xl bg-[#10151D] border border-white/[0.1] shadow-[0_20px_60px_rgba(0,0,0,0.8)] p-4 sm:p-6 backdrop-blur-2xl relative overflow-hidden"
          >
            {/* Top Scanning Beam */}
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-[#00F0FF] to-transparent animate-scan-beam" />

            {/* Window Header */}
            <div className="flex items-center justify-between pb-4 border-b border-white/[0.08] text-xs font-mono">
              <div className="flex items-center gap-2">
                <div className="flex gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-[#F43F5E]" />
                  <div className="w-2.5 h-2.5 rounded-full bg-[#F59E0B]" />
                  <div className="w-2.5 h-2.5 rounded-full bg-[#10B981]" />
                </div>
                <span className="text-[#8995A5] ml-2 font-bold flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-[#00F0FF]" />
                  NEUROSHIELD THREAT INTERCEPTION ENGINE v2.4
                </span>
              </div>

              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[#10B981] animate-pulse" />
                <span className="text-[10px] text-[#10B981] font-bold uppercase">AUTONOMOUS SHIELD ACTIVE</span>
              </div>
            </div>

            {/* Preset Selector Buttons */}
            <div className="pt-4 pb-3 flex flex-wrap items-center gap-2 font-mono text-xs">
              <span className="text-[10px] text-[#8995A5] uppercase font-bold mr-1">Select Attack Vector:</span>
              {SAMPLE_ATTACKS.map((sample) => (
                <button
                  key={sample.id}
                  onClick={() => handleRunSampleScan(sample)}
                  className={`px-3 py-1 rounded-lg text-[11px] font-bold transition-all border cursor-pointer ${
                    selectedAttack.id === sample.id
                      ? 'bg-[#00F0FF]/15 text-[#00F0FF] border-[#00F0FF]/50 shadow-[0_0_12px_rgba(0,240,255,0.2)]'
                      : 'bg-[#080B10] text-[#8995A5] border-white/[0.08] hover:text-white hover:border-white/[0.2]'
                  }`}
                >
                  {sample.title}
                </button>
              ))}
            </div>

            {/* Simulated Email Card */}
            <div className="bg-[#080B10] rounded-xl border border-white/[0.08] p-4 font-mono text-xs space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-white/[0.06] text-[11px]">
                <div className="truncate">
                  <span className="text-[#8995A5]">From: </span>
                  <span className="text-white font-bold">{selectedAttack.sender}</span>
                </div>
                <div className="text-[#00F0FF] text-[10px] bg-[#00F0FF]/10 px-2 py-0.5 rounded border border-[#00F0FF]/20 self-start sm:self-auto font-bold">
                  {selectedAttack.tag}
                </div>
              </div>

              <div className="text-[11px]">
                <span className="text-[#8995A5]">Subject: </span>
                <span className="text-[#F1F5F9] font-bold">{selectedAttack.subject}</span>
              </div>

              <div className="bg-[#10151D] p-3 rounded-lg text-slate-300 text-xs leading-relaxed border border-white/[0.04]">
                {selectedAttack.snippet}
              </div>

              {/* Real-Time Detection Signals */}
              <div className="pt-2 space-y-2">
                <span className="text-[10px] text-[#8995A5] uppercase font-bold block">
                  Identified Threat Indicators:
                </span>
                <div className="flex flex-wrap gap-2">
                  {selectedAttack.indicators.map((ind, idx) => (
                    <span key={idx} className="px-2.5 py-1 rounded-md bg-[#F43F5E]/10 border border-[#F43F5E]/30 text-[#F43F5E] text-[10px] font-bold flex items-center gap-1.5">
                      <AlertTriangle className="w-3 h-3" />
                      {ind}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            {/* Security Verdict Footer */}
            <div className="mt-4 p-4 rounded-xl bg-[#161D27] border border-[#F43F5E]/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-[#F43F5E]/15 border border-[#F43F5E]/40 flex items-center justify-center text-[#F43F5E] font-bold shrink-0">
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-xs font-bold text-white flex items-center gap-2">
                    <span className="text-[#F43F5E]">{selectedAttack.verdict}</span>
                    <span className="text-[10px] text-[#8995A5]">Risk Quotient: {selectedAttack.risk}/100</span>
                  </div>
                  <p className="text-[11px] text-[#8995A5]">
                    Autonomous Action: Pre-Execution Quarantine & Block Originating MTA Hop
                  </p>
                </div>
              </div>

              <button
                onClick={onNavigateToInboxShield}
                className="px-4 py-2 bg-[#00F0FF] hover:bg-[#00F0FF]/90 text-black font-bold text-xs rounded-lg transition-all cursor-pointer flex items-center gap-1.5 self-start sm:self-auto shrink-0 shadow-lg"
              >
                <span>Run Full Forensic Analysis</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </motion.div>
        </div>
      </section>

      {/* =========================================================================
          LIVE TELEMETRY STATS TICKER STRIP
         ========================================================================= */}
      <section className="border-y border-white/[0.08] bg-[#0A0E17]/90 backdrop-blur-md py-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6 text-center">
            <div className="space-y-1">
              <div className="text-3xl sm:text-4xl font-extrabold text-[#00F0FF] font-mono drop-shadow-[0_0_12px_rgba(0,240,255,0.4)]">
                99.8%
              </div>
              <div className="text-xs font-mono text-[#8995A5] uppercase tracking-wider font-semibold">
                Zero-Day Catch Rate
              </div>
            </div>
            <div className="space-y-1">
              <div className="text-3xl sm:text-4xl font-extrabold text-white font-mono">
                &lt; 18ms
              </div>
              <div className="text-xs font-mono text-[#8995A5] uppercase tracking-wider font-semibold">
                Ingress Latency
              </div>
            </div>
            <div className="space-y-1">
              <div className="text-3xl sm:text-4xl font-extrabold text-[#10B981] font-mono">
                0%
              </div>
              <div className="text-xs font-mono text-[#8995A5] uppercase tracking-wider font-semibold">
                Data Retention (Volatile)
              </div>
            </div>
            <div className="space-y-1">
              <div className="text-3xl sm:text-4xl font-extrabold text-[#8B5CF6] font-mono">
                24/7
              </div>
              <div className="text-xs font-mono text-[#8995A5] uppercase tracking-wider font-semibold">
                Autonomous AI Defense
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          3. CORE FEATURES SECTION (6-Card High-Tech Grid)
         ========================================================================= */}
      <section id="features" className="py-20 border-t border-white/[0.08] bg-[#0A0E17]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto space-y-4 mb-16">
            <span className="text-xs font-mono font-bold text-[#00F0FF] uppercase tracking-wider px-3 py-1 rounded-full bg-[#00F0FF]/10 border border-[#00F0FF]/25 inline-block">
              Multi-Vector Interception Grid
            </span>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white font-sans tracking-tight">
              Engineered for sophisticated zero-day threat actors.
            </h2>
            <p className="text-sm sm:text-base text-[#8995A5]">
              Traditional spam filters rely on static blocklists. NeuroShield inspects cognitive language, protocol authentication, and network infrastructure in real time.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            
            {/* Feature 1 */}
            <div className="p-6 rounded-2xl bg-[#10151D] border border-white/[0.08] hover:border-[#00F0FF]/40 transition-all space-y-3 group shadow-xl">
              <div className="w-10 h-10 rounded-xl bg-[#00F0FF]/10 border border-[#00F0FF]/30 flex items-center justify-center text-[#00F0FF] group-hover:scale-110 transition-transform">
                <Cpu className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-white font-sans">Explainable AI Phishing Classifier</h3>
              <p className="text-xs text-[#8995A5] leading-relaxed">
                Neural reasoning models analyze emotional urgency, financial coercion, and executive authority impersonation with clear, plain-English justifications.
              </p>
            </div>

            {/* Feature 2 */}
            <div className="p-6 rounded-2xl bg-[#10151D] border border-white/[0.08] hover:border-[#00F0FF]/40 transition-all space-y-3 group shadow-xl">
              <div className="w-10 h-10 rounded-xl bg-[#10B981]/10 border border-[#10B981]/30 flex items-center justify-center text-[#10B981] group-hover:scale-110 transition-transform">
                <Layers className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-white font-sans">RFC 5322 Multi-Hop Relay Reconstruction</h3>
              <p className="text-xs text-[#8995A5] leading-relaxed">
                Traces every MTA server hop, calculates transport latency deltas, and pinpoints origin IP geolocation across TOR exit nodes and proxy networks.
              </p>
            </div>

            {/* Feature 3 */}
            <div className="p-6 rounded-2xl bg-[#10151D] border border-white/[0.08] hover:border-[#00F0FF]/40 transition-all space-y-3 group shadow-xl">
              <div className="w-10 h-10 rounded-xl bg-[#8B5CF6]/10 border border-[#8B5CF6]/30 flex items-center justify-center text-[#8B5CF6] group-hover:scale-110 transition-transform">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-white font-sans">SPF / DKIM / DMARC Matrix</h3>
              <p className="text-xs text-[#8995A5] leading-relaxed">
                Validates cryptographic email signatures, detects SPF soft-fails, and uncovers unaligned DMARC policies before malicious emails reach user mailboxes.
              </p>
            </div>

            {/* Feature 4 */}
            <div className="p-6 rounded-2xl bg-[#10151D] border border-white/[0.08] hover:border-[#00F0FF]/40 transition-all space-y-3 group shadow-xl">
              <div className="w-10 h-10 rounded-xl bg-[#F59E0B]/10 border border-[#F59E0B]/30 flex items-center justify-center text-[#F59E0B] group-hover:scale-110 transition-transform">
                <Globe className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-white font-sans">Reverse Tunnel & Proxy Evasion</h3>
              <p className="text-xs text-[#8995A5] leading-relaxed">
                Detects ephemeral Cloudflare Quick Tunnels (*.trycloudflare.com) and Ngrok endpoints used by threat actors to bypass domain age filters.
              </p>
            </div>

            {/* Feature 5 */}
            <div className="p-6 rounded-2xl bg-[#10151D] border border-white/[0.08] hover:border-[#00F0FF]/40 transition-all space-y-3 group shadow-xl">
              <div className="w-10 h-10 rounded-xl bg-[#F43F5E]/10 border border-[#F43F5E]/30 flex items-center justify-center text-[#F43F5E] group-hover:scale-110 transition-transform">
                <Mic className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-white font-sans">Voice Clone & Deepfake Defense</h3>
              <p className="text-xs text-[#8995A5] leading-relaxed">
                Analyzes acoustic spectrum artifacts, synthetic vocoder signatures, and audio tampering in social engineering vishing attacks.
              </p>
            </div>

            {/* Feature 6 */}
            <div className="p-6 rounded-2xl bg-[#10151D] border border-white/[0.08] hover:border-[#00F0FF]/40 transition-all space-y-3 group shadow-xl">
              <div className="w-10 h-10 rounded-xl bg-[#00F0FF]/10 border border-[#00F0FF]/30 flex items-center justify-center text-[#00F0FF] group-hover:scale-110 transition-transform">
                <Lock className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-white font-sans">Immutable SOC Cryptographic Audit</h3>
              <p className="text-xs text-[#8995A5] leading-relaxed">
                Generates SHA-256 evidence digests, STIX 2.1 threat indicators, and complete SOC markdown dossiers for rapid incident response teams.
              </p>
            </div>

          </div>
        </div>
      </section>

      {/* =========================================================================
          4. 4-STEP PIPELINE
         ========================================================================= */}
      <section id="pipeline" className="py-20 border-t border-white/[0.08] bg-[#080B10]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto space-y-4 mb-16">
            <span className="text-xs font-mono font-bold text-[#00F0FF] uppercase tracking-wider px-3 py-1 rounded-full bg-[#00F0FF]/10 border border-[#00F0FF]/25 inline-block">
              Workflow Pipeline
            </span>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white font-sans tracking-tight">
              4-Step Autonomous Security Pipeline
            </h2>
            <p className="text-sm sm:text-base text-[#8995A5]">
              From ingestion to final containment verdict in under 20 milliseconds.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 relative">
            {/* Step 1 */}
            <div className="p-6 rounded-2xl bg-[#10151D] border border-white/[0.08] relative space-y-3">
              <div className="text-xs font-mono font-bold text-[#00F0FF] bg-[#00F0FF]/10 px-2.5 py-1 rounded w-fit border border-[#00F0FF]/30">
                STEP 01
              </div>
              <h3 className="text-base font-bold text-white">Ingest Live Payload</h3>
              <p className="text-xs text-[#8995A5] leading-relaxed">
                Submit raw RFC 5322 headers, web URLs, audio speech streams, or direct Gmail API live polling.
              </p>
            </div>

            {/* Step 2 */}
            <div className="p-6 rounded-2xl bg-[#10151D] border border-white/[0.08] relative space-y-3">
              <div className="text-xs font-mono font-bold text-[#00F0FF] bg-[#00F0FF]/10 px-2.5 py-1 rounded w-fit border border-[#00F0FF]/30">
                STEP 02
              </div>
              <h3 className="text-base font-bold text-white">Deconstruct Relays & DNS</h3>
              <p className="text-xs text-[#8995A5] leading-relaxed">
                NeuroShield verifies SPF/DKIM crypto signatures, parses MTA hops, and resolves sender infrastructure.
              </p>
            </div>

            {/* Step 3 */}
            <div className="p-6 rounded-2xl bg-[#10151D] border border-white/[0.08] relative space-y-3">
              <div className="text-xs font-mono font-bold text-[#00F0FF] bg-[#00F0FF]/10 px-2.5 py-1 rounded w-fit border border-[#00F0FF]/30">
                STEP 03
              </div>
              <h3 className="text-base font-bold text-white">Neural Pattern Scoring</h3>
              <p className="text-xs text-[#8995A5] leading-relaxed">
                Multi-modal AI evaluates psychological manipulation, URL link mismatches, and reverse tunnel signatures.
              </p>
            </div>

            {/* Step 4 */}
            <div className="p-6 rounded-2xl bg-[#10151D] border border-white/[0.08] relative space-y-3">
              <div className="text-xs font-mono font-bold text-[#00F0FF] bg-[#00F0FF]/10 px-2.5 py-1 rounded w-fit border border-[#00F0FF]/30">
                STEP 04
              </div>
              <h3 className="text-base font-bold text-white">Verdict & Containment</h3>
              <p className="text-xs text-[#8995A5] leading-relaxed">
                Receive an explainable risk score, clear safe/phishing verdict, and 1-click automated SOC containment scripts.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          5. TRUST & SECURITY ARCHITECTURE
         ========================================================================= */}
      <section id="architecture" className="py-20 border-t border-white/[0.08] bg-[#0A0E17]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div className="space-y-6">
              <span className="text-xs font-mono font-bold text-[#00F0FF] uppercase tracking-wider px-3 py-1 rounded-full bg-[#00F0FF]/10 border border-[#00F0FF]/25 inline-block">
                Trust & Security Architecture
              </span>
              <h2 className="text-3xl sm:text-4xl font-extrabold text-white font-sans tracking-tight">
                Privacy-first, zero persistent data retention architecture.
              </h2>
              <p className="text-sm sm:text-base text-[#8995A5] leading-relaxed">
                NeuroShield analyzes payloads in volatile memory without storing confidential contents, providing enterprise-grade protection you can trust.
              </p>

              <div className="space-y-3 font-mono text-xs">
                <div className="flex items-center gap-3 p-3 rounded-xl bg-[#10151D] border border-white/[0.06]">
                  <CheckCircle2 className="w-4 h-4 text-[#10B981] shrink-0" />
                  <span>Explainable Decision Trees — Zero black-box hallucinations</span>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-xl bg-[#10151D] border border-white/[0.06]">
                  <CheckCircle2 className="w-4 h-4 text-[#10B981] shrink-0" />
                  <span>Sub-20ms Engine Latency for Real-time Ingress Protection</span>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-xl bg-[#10151D] border border-white/[0.06]">
                  <CheckCircle2 className="w-4 h-4 text-[#10B981] shrink-0" />
                  <span>Actionable Remediation Scripts (PowerShell, iptables & RPZ)</span>
                </div>
              </div>
            </div>

            {/* Interactive Terminal / Code Snippet */}
            <div className="p-6 rounded-2xl bg-[#10151D] border border-white/[0.08] font-mono text-xs space-y-4 shadow-2xl">
              <div className="flex items-center justify-between pb-3 border-b border-white/[0.08]">
                <span className="text-[#8995A5] text-[11px] font-bold flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-[#00F0FF]" />
                  NEUROSHIELD SOC CONTAINMENT DOSSIER
                </span>
                <span className="text-[10px] text-[#10B981] font-bold">STIX 2.1 READY</span>
              </div>

              <pre className="text-slate-300 text-[11px] bg-[#080B10] p-4 rounded-xl border border-white/[0.06] overflow-x-auto leading-relaxed">
{`{
  "entity": "NeuroShield_Forensic_Dossier",
  "verdict": "CRITICAL_PHISHING",
  "riskQuotient": 96,
  "mtaRelay": {
    "originIP": "185.220.101.42 (Tor Exit Node)",
    "spfStatus": "FAIL",
    "dmarcAlignment": "UNALIGNED"
  },
  "remediation": {
    "action": "AUTONOMOUS_QUARANTINE_AND_RPZ_BLOCK",
    "command": "rpz-block --zone 'threats.local' --cname '*.trycloudflare.com.' --action DROP"
  }
}`}
              </pre>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          6. COMPARISON MATRIX (Legacy SEG vs. NeuroShield)
         ========================================================================= */}
      <section id="compare" className="py-20 border-t border-white/[0.08] bg-[#080B10]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto space-y-4 mb-16">
            <span className="text-xs font-mono font-bold text-[#00F0FF] uppercase tracking-wider px-3 py-1 rounded-full bg-[#00F0FF]/10 border border-[#00F0FF]/25 inline-block">
              Architecture Comparison
            </span>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white font-sans tracking-tight">
              Why traditional Secure Email Gateways fail.
            </h2>
            <p className="text-sm sm:text-base text-[#8995A5]">
              Modern attackers use ephemeral reverse tunnels, cognitive manipulation, and voice synthesis that bypass signature-only filters.
            </p>
          </div>

          <div className="max-w-4xl mx-auto rounded-2xl bg-[#10151D] border border-white/[0.08] overflow-hidden shadow-2xl font-mono text-xs">
            <div className="grid grid-cols-3 p-4 bg-[#161D27] border-b border-white/[0.08] font-bold text-slate-300">
              <div className="text-[#8995A5]">Capability</div>
              <div className="text-rose-400">Legacy Email Gateways</div>
              <div className="text-[#00F0FF] flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5" />
                NeuroShield Autonomous AI
              </div>
            </div>

            <div className="divide-y divide-white/[0.06]">
              <div className="grid grid-cols-3 p-4 items-center">
                <div className="text-white font-bold">Detection Vector</div>
                <div className="text-slate-400">Static Regex & Domain Blocklists</div>
                <div className="text-[#00F0FF] font-bold">Cognitive NLP & Cryptographic RFC 5322 Graph</div>
              </div>
              <div className="grid grid-cols-3 p-4 items-center">
                <div className="text-white font-bold">Reverse Tunnels (*.trycloudflare.com)</div>
                <div className="text-rose-400">❌ Blind (Trusted CDN Domain)</div>
                <div className="text-[#10B981] font-bold">✅ Ephemeral Tunnel & Proxy Evasion Interceptor</div>
              </div>
              <div className="grid grid-cols-3 p-4 items-center">
                <div className="text-white font-bold">Deepfake Voice & Vishing</div>
                <div className="text-rose-400">❌ Not Supported</div>
                <div className="text-[#10B981] font-bold">✅ Acoustic Vocoder & Tamper Forensics</div>
              </div>
              <div className="grid grid-cols-3 p-4 items-center">
                <div className="text-white font-bold">Decision Transparency</div>
                <div className="text-slate-400">Black-box spam score (1-10)</div>
                <div className="text-[#00F0FF] font-bold">Explainable AI Justifications & MITRE Mapping</div>
              </div>
              <div className="grid grid-cols-3 p-4 items-center">
                <div className="text-white font-bold">Data Privacy</div>
                <div className="text-amber-400">Stored on 3rd-party vendor servers</div>
                <div className="text-[#10B981] font-bold">100% Volatile Memory / Zero Persistent Retention</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          7. INTERACTIVE DEMO CTA
         ========================================================================= */}
      <section id="demo" className="py-20 border-t border-white/[0.08] bg-gradient-to-b from-[#080B10] via-[#0A101D] to-[#080B10] relative">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 text-center space-y-8">
          <div className="w-16 h-16 rounded-2xl bg-[#00F0FF]/15 border border-[#00F0FF]/40 flex items-center justify-center text-[#00F0FF] mx-auto shadow-[0_0_30px_rgba(0,240,255,0.3)]">
            <Zap className="w-8 h-8 fill-current" />
          </div>

          <h2 className="text-3xl sm:text-5xl font-extrabold text-white font-sans tracking-tight">
            Ready to deploy autonomous AI defense?
          </h2>

          <p className="text-base sm:text-lg text-[#8995A5] max-w-2xl mx-auto">
            Test any suspicious email, link, or voice audio stream right now with the NeuroShield multi-vector defense console.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-4 pt-2 font-mono text-xs sm:text-sm">
            <button
              onClick={onNavigateToDashboard}
              className="px-8 py-4 rounded-xl bg-[#00F0FF] hover:bg-[#00F0FF]/90 text-black font-extrabold transition-all shadow-[0_0_30px_rgba(0,240,255,0.4)] hover:shadow-[0_0_40px_rgba(0,240,255,0.6)] cursor-pointer flex items-center gap-2.5 active:scale-95"
            >
              <span>Launch Defense Console</span>
              <ArrowRight className="w-4 h-4" />
            </button>

            <button
              onClick={onNavigateToInboxShield}
              className="px-8 py-4 rounded-xl bg-[#10151D] hover:bg-[#161D27] text-white font-bold border border-white/[0.12] transition-all cursor-pointer flex items-center gap-2"
            >
              <Mail className="w-4 h-4 text-[#00F0FF]" />
              <span>Explore Inbox Shield</span>
            </button>
          </div>
        </div>
      </section>

      {/* =========================================================================
          7. FOOTER
         ========================================================================= */}
      <footer className="py-12 border-t border-white/[0.08] bg-[#05080C] text-xs font-mono text-[#8995A5]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 rounded-lg bg-[#10151D] border border-[#00F0FF]/30 flex items-center justify-center text-[#00F0FF]">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <span className="text-white font-bold tracking-wider">NEUROSHIELD</span>
            <span>— AI-Powered Multi-Channel Threat Interception Matrix</span>
          </div>

          <div className="flex items-center gap-6">
            <button onClick={onNavigateToDashboard} className="hover:text-white transition-colors cursor-pointer">
              Dashboard
            </button>
            <button onClick={onNavigateToInboxShield} className="hover:text-white transition-colors cursor-pointer">
              Inbox Shield
            </button>
            <button onClick={onNavigateToScanner} className="hover:text-white transition-colors cursor-pointer">
              Live Scanner
            </button>
            <span className="flex items-center gap-1.5 text-[#10B981]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] animate-pulse" />
              All Defense Systems Active
            </span>
          </div>
        </div>
      </footer>

    </div>
  );
}
