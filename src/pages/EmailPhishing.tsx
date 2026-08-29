import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Mail, Search, RefreshCw, LogIn, Bell, Shield, ShieldCheck, ShieldAlert, 
  AlertTriangle, FileText, Terminal, ArrowRight, Copy, Check, Download, 
  ExternalLink, Network, Globe, Server, Clock, Lock, AlertCircle, Sparkles, UploadCloud, Layers, X
} from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';
import { addScanToHistory } from '@/lib/history';
import { executeEmailForensics, ForensicDossier } from '@/services/forensicsEngine';
import { googleSignIn, googleLogout, initAuth, getAccessToken } from '@/services/googleAuth';
import { DomainAuthLookup } from '@/components/DomainAuthLookup';
import type { User } from 'firebase/auth';

// Sample Presets for instantaneous hackathon testing
const TEST_SCENARIOS = [
  {
    id: 'msft_bec',
    title: 'Microsoft 365 Account Suspension (BEC Phish)',
    tag: 'CRITICAL THREAT',
    tagColor: 'bg-red-500/10 text-red-400 border-red-500/20',
    rawHeaders: `From: "Microsoft Security" <security@m1crosoft-support.com>
To: employee@company.com
Reply-To: microsoft.verify.account@gmail.com
Return-Path: <bounce@mail.m1crosoft-support.com>
Subject: URGENT: Your Microsoft 365 account will be suspended
Message-ID: <20260827.18293@mail.m1crosoft-support.com>
Date: Thu, 27 Aug 2026 10:45:21 +0000

Received: from mail.m1crosoft-support.com (185.220.101.45)
    by mx.company.com with ESMTPS;
    Thu, 27 Aug 2026 10:45:18 +0000

Received: from unknown-host (10.20.30.15)
    by mail.m1crosoft-support.com;
    Thu, 27 Aug 2026 10:45:10 +0000

Authentication-Results: mx.company.com;
    spf=fail smtp.mailfrom=m1crosoft-support.com;
    dkim=none;
    dmarc=fail header.from=m1crosoft-support.com

Content-Type: text/html`,
    body: `URGENT ACTION REQUIRED

Your Microsoft 365 account has been flagged for suspicious activity.

Your account will be permanently suspended within 30 minutes.

To prevent suspension, verify your account immediately:

https://microsoft-security-verification.example.com/login

Failure to verify your account will result in permanent loss of access.

Regards,
Microsoft Security Team`
  },
  {
    id: 'paypal_invoice',
    title: 'PayPal Fake Invoice & Payment Diversion',
    tag: 'HIGH RISK',
    tagColor: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    rawHeaders: `From: "PayPal Billing Department" <service@paypa1-update.com>
To: accounting@enterprise.corp
Reply-To: invoice.dispute.desk@gmail.com
Return-Path: <bounce@paypa1-update.com>
Subject: INVOICE #89218: Immediate settlement required
Message-ID: <20260827.09112@paypa1-update.com>
Date: Wed, 26 Aug 2026 14:10:00 +0000

Received: from relay02.paypa1-update.com (194.26.29.110)
    by mx.enterprise.corp with ESMTP;
    Wed, 26 Aug 2026 14:09:55 +0000

Authentication-Results: mx.enterprise.corp;
    spf=fail smtp.mailfrom=paypa1-update.com;
    dkim=fail;
    dmarc=fail header.from=paypa1-update.com`,
    body: `Dear Customer,

You have a pending invoice of $1,490.00 for Bitcoin purchase on your PayPal account.

If you did not authorize this transaction, click here immediately to dispute:
http://paypal-resolution-center.example.com/dispute

Failure to respond within 2 hours will initiate automatic debit.`
  },
  {
    id: 'google_legit',
    title: 'Verified Google Workspace Notification (Legitimate)',
    tag: 'BENIGN / PASS',
    tagColor: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    rawHeaders: `From: "Google Workspace" <workspace-noreply@google.com>
To: admin@company.com
Reply-To: workspace-noreply@google.com
Return-Path: <workspace-noreply@google.com>
Subject: New Security Advisory: Admin Console Policy Update
Message-ID: <CABs9_2819.google.com>
Date: Tue, 25 Aug 2026 08:30:00 +0000

Received: from mail-wm1-x32e.google.com (209.85.128.175)
    by mx.company.com with ESMTPS;
    Tue, 25 Aug 2026 08:29:58 +0000

Authentication-Results: mx.company.com;
    spf=pass smtp.mailfrom=google.com;
    dkim=pass header.i=@google.com;
    dmarc=pass header.from=google.com`,
    body: `Hello Administrator,

This is a routine notification regarding policy updates to your Google Workspace tenant.
You can review the updated compliance settings inside your official admin dashboard at https://admin.google.com

No urgent action is required.`
  }
];

export default function EmailPhishing() {
  const { t } = useLanguage();
  const [activeTab, setActiveTab] = useState<'forensics' | 'inbox' | 'dns-lookup'>('forensics');
  const [inputMode, setInputMode] = useState<'custom' | 'demo'>('custom');
  const [selectedScenario, setSelectedScenario] = useState<string | null>(null);
  const [rawHeaderText, setRawHeaderText] = useState<string>('');
  const [bodyText, setBodyText] = useState<string>('');
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [dossier, setDossier] = useState<ForensicDossier | null>(null);
  const [dossierSource, setDossierSource] = useState<'custom' | 'demo' | 'gmail'>('custom');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [reportCopied, setReportCopied] = useState<boolean>(false);
  const [lookupDomain, setLookupDomain] = useState<string>('google.com');
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const [forensicError, setForensicError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dossierRef = useRef<HTMLDivElement>(null);

  // Live Gmail States
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [isLoadingEmails, setIsLoadingEmails] = useState(false);
  const [emails, setEmails] = useState<any[]>([]);
  const [authError, setAuthError] = useState<string | null>(null);

  // Init Google Auth listener on mount
  useEffect(() => {
    const unsubscribe = initAuth(
      (user, token) => {
        setCurrentUser(user);
        setIsAuthenticated(true);
        fetchRealEmails(token);
      },
      () => {
        setCurrentUser(null);
        setIsAuthenticated(false);
      }
    );
    return () => unsubscribe();
  }, []);

  const handleScenarioChange = (scenarioId: string) => {
    const sc = TEST_SCENARIOS.find(s => s.id === scenarioId);
    if (sc) {
      setInputMode('demo');
      setSelectedScenario(scenarioId);
      setUploadedFileName(null);
      setRawHeaderText(sc.rawHeaders);
      setBodyText(sc.body);
      handleRunForensics(sc.rawHeaders, sc.body, 'demo');
    }
  };

  const handleClearAll = () => {
    setInputMode('custom');
    setSelectedScenario(null);
    setUploadedFileName(null);
    setRawHeaderText('');
    setBodyText('');
    setForensicError(null);
    setDossier(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handlePasteClipboard = async () => {
    try {
      if (navigator.clipboard && navigator.clipboard.readText) {
        const text = await navigator.clipboard.readText();
        if (text && text.trim()) {
          setInputMode('custom');
          setSelectedScenario(null);
          setUploadedFileName('Pasted from Clipboard');
          
          const rfcSeparatorIndex = text.search(/\r?\n\r?\n/);
          if (rfcSeparatorIndex !== -1 && (text.includes('Received:') || text.includes('From:') || text.includes('Subject:'))) {
            setRawHeaderText(text.substring(0, rfcSeparatorIndex).trim());
            setBodyText(text.substring(rfcSeparatorIndex).trim());
          } else {
            setRawHeaderText(text);
          }
        }
      }
    } catch {
      // Clipboard permissions denied or unavailable
    }
  };

  const handleRunForensics = async (headers: string, body: string, source: 'custom' | 'demo' | 'gmail' = 'custom') => {
    setForensicError(null);

    let effectiveHeaders = headers ? headers.trim() : '';
    let effectiveBody = body ? body.trim() : '';

    // If both are completely empty, notify the user with guidance
    if (!effectiveHeaders && !effectiveBody) {
      setForensicError('Please paste RFC 5322 email headers, enter an email body, upload a .eml file, or select a demo scenario below.');
      return;
    }

    if (!effectiveHeaders && effectiveBody) {
      // If user pasted everything into the body textarea
      const rfcSeparatorIndex = effectiveBody.search(/\r?\n\r?\n/);
      if (rfcSeparatorIndex !== -1 && (effectiveBody.includes('From:') || effectiveBody.includes('Received:') || effectiveBody.includes('Subject:'))) {
        effectiveHeaders = effectiveBody.substring(0, rfcSeparatorIndex).trim();
        effectiveBody = effectiveBody.substring(rfcSeparatorIndex).trim();
      } else {
        effectiveHeaders = `Subject: Analyzed Custom Message\nFrom: sender@external-host.com\nContent-Type: text/plain\n\n${effectiveBody}`;
      }
    }

    setIsAnalyzing(true);

    try {
      const result = await executeEmailForensics(effectiveHeaders, effectiveBody);
      setDossier(result);
      setDossierSource(source);

      // Save active attack graph in localStorage for AttackGraph.tsx synchronization
      if (result.attackGraph) {
        try {
          localStorage.setItem('neuroshield_active_attack_graph', JSON.stringify(result.attackGraph));
        } catch {
          // Ignore localStorage quota errors
        }
      }

      // Add to global security telemetry history
      addScanToHistory({
        detectedType: 'EMAIL',
        riskScore: result.classification.riskScore,
        signals: result.contentAnalysis.signals.map(s => s.description),
        source: result.senderIdentity.fromAddress || result.originIP.ip,
        target: result.headerFields.to || 'Enterprise Inbox',
        payloadDescription: `Subject: ${result.headerFields.subject} | SPF: ${result.authentication.spf.status} | DMARC: ${result.authentication.dmarc.status}`,
        threatName: `${result.classification.threatType} (${result.classification.subtype})`
      });

      // Smooth scroll to the generated dossier
      setTimeout(() => {
        dossierRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }, 100);
    } catch (err: any) {
      console.error('Forensics execution error:', err);
      setForensicError(err?.message || 'Error occurred during forensic parsing. Please verify raw header structure.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const processEmlFile = (file: File) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = (event.target?.result as string) || '';
      if (!text.trim()) return;

      // RFC 5322 standard: headers and body are separated by an empty line (\r\n\r\n or \n\n)
      let headers = text;
      let body = '';

      const rfcSeparatorIndex = text.search(/\r?\n\r?\n/);
      if (rfcSeparatorIndex !== -1 && (text.includes('Received:') || text.includes('From:') || text.includes('Subject:'))) {
        headers = text.substring(0, rfcSeparatorIndex).trim();
        body = text.substring(rfcSeparatorIndex).trim();
      }

      setUploadedFileName(`${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
      setInputMode('custom');
      setSelectedScenario(null);
      setRawHeaderText(headers);
      setBodyText(body);
      handleRunForensics(headers, body, 'custom');
    };
    reader.readAsText(file);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      processEmlFile(file);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      processEmlFile(file);
    }
  };

  const clearUploadedFile = () => {
    setUploadedFileName(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
    handleScenarioChange(TEST_SCENARIOS[0].id);
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const downloadJsonDossier = () => {
    if (!dossier) return;
    const blob = new Blob([JSON.stringify(dossier, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `neuroshield-forensic-dossier-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadMarkdownReport = () => {
    if (!dossier) return;
    const blob = new Blob([dossier.socReportMarkdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SOC-Incident-Report-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleGoogleLogin = async () => {
    setAuthError(null);
    setIsLoadingEmails(true);
    try {
      const result = await googleSignIn();
      if (result) {
        setCurrentUser(result.user);
        setIsAuthenticated(true);
        await fetchRealEmails(result.accessToken);
      }
    } catch (error: any) {
      console.warn('OAuth Sign-in notice:', error);
      const errMsg = error?.message || 'OAuth popup cancelled or origin unverified.';
      setAuthError(errMsg);
    } finally {
      setIsLoadingEmails(false);
    }
  };

  const handleLogout = async () => {
    await googleLogout();
    setIsAuthenticated(false);
    setCurrentUser(null);
    setEmails([]);
  };

  const loadSampleInbox = () => {
    setAuthError(null);
    setIsAuthenticated(true);
    setEmails([
      {
        id: 'msg-sample-01',
        sender: 'Executive Desk <ceo.management@global-corp.info>',
        subject: 'URGENT: Confidential Acquisition Wire Instruction',
        time: 'Today, 10:14 AM',
        body: 'Please process the confidential vendor settlement wire prior to EOD audit window closing.',
        rawHeaders: TEST_SCENARIOS[0].rawHeaders
      },
      {
        id: 'msg-sample-02',
        sender: 'Billing Resolution <invoice.dispute.desk@gmail.com>',
        subject: 'Past Due Final Demand: Invoice #INV-88910',
        time: 'Yesterday, 4:45 PM',
        body: 'Your subscription is suspended. Re-verify payment billing immediately via the link attached.',
        rawHeaders: TEST_SCENARIOS[1].rawHeaders
      },
      {
        id: 'msg-sample-03',
        sender: 'IT Operations <service-notification@outlook.com>',
        subject: 'Security Alert: Password Expiring in 2 Hours',
        time: '2 days ago',
        body: 'Your single-sign-on credentials are scheduled for revocation. Update credentials now.',
        rawHeaders: TEST_SCENARIOS[2].rawHeaders
      }
    ]);
  };

  const fetchRealEmails = async (token: string) => {
    setIsLoadingEmails(true);
    setAuthError(null);
    try {
      const gRes = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10', {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await gRes.json();
      if (!gRes.ok) throw new Error(data?.error?.message || JSON.stringify(data));
      
      const detailedEmails = await Promise.all(
        (data.messages || []).map(async (msg: any) => {
          const detailRes = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}?format=full`, {
            headers: { Authorization: `Bearer ${token}` }
          });
          const detail = await detailRes.json();
          if (!detailRes.ok) throw new Error(detail?.error?.message || JSON.stringify(detail));
          const headers = detail.payload?.headers || [];
          const subject = headers.find((h: any) => h.name === 'Subject')?.value || 'No Subject';
          const sender = headers.find((h: any) => h.name === 'From')?.value || 'Unknown Sender';
          const dateStr = headers.find((h: any) => h.name === 'Date')?.value || '';
          
          // Reconstruct raw headers string
          const rawHeaderArr = headers.map((h: any) => `${h.name}: ${h.value}`).join('\n');
          const body = detail.snippet || '';

          return {
            id: msg.id,
            sender,
            subject,
            time: dateStr,
            body,
            rawHeaders: rawHeaderArr
          };
        })
      );
      
      if (detailedEmails.length > 0) {
        setEmails(detailedEmails);
      }
    } catch(err: any) {
      console.warn('Notice fetching Gmail:', err);
      setAuthError(err?.message || 'Error fetching Gmail messages.');
    } finally {
      setIsLoadingEmails(false);
    }
  };

  const inspectGmailMessage = (email: any) => {
    setInputMode('custom');
    setSelectedScenario(null);
    setUploadedFileName(`Gmail Message: ${email.subject}`);
    setRawHeaderText(email.rawHeaders);
    setBodyText(email.body);
    setActiveTab('forensics');
    handleRunForensics(email.rawHeaders, email.body, 'gmail');
  };

  return (
    <div className="flex-1 w-full h-full bg-[#03060a] overflow-y-auto custom-scrollbar p-4 sm:p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        
        {/* Navigation & Header Status */}
        <div className="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center bg-[#0a0f1c] border border-white/5 p-4 rounded-2xl shadow-xl">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyber-blue/10 border border-cyber-blue/30 flex items-center justify-center">
              <Mail className="w-5 h-5 text-cyber-blue" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-white tracking-tight flex items-center gap-2 font-mono">
                EMAIL THREAT FORENSICS & ORIGIN TRACEABILITY
              </h1>
              <p className="text-xs text-cyber-muted">RFC 5322 Protocol Verification, Relay Reconstruction & Attribution Engine</p>
            </div>
          </div>

          {/* Mode Switcher Tabs */}
          <div className="flex flex-wrap items-center bg-[#05080f] p-1 rounded-xl border border-white/5 gap-1">
            <button
              onClick={() => setActiveTab('forensics')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center gap-2 ${
                activeTab === 'forensics'
                  ? 'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40 shadow-sm'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              FORENSIC LAB & .EML
            </button>
            <button
              onClick={() => setActiveTab('inbox')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center gap-2 ${
                activeTab === 'inbox'
                  ? 'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40 shadow-sm'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <Mail className="w-3.5 h-3.5" />
              GMAIL INBOX SCANNER
            </button>
            <button
              onClick={() => setActiveTab('dns-lookup')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center gap-2 ${
                activeTab === 'dns-lookup'
                  ? 'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40 shadow-sm'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              SPF/DKIM/DMARC LOOKUP
            </button>
          </div>
        </div>

        {activeTab === 'dns-lookup' && (
          <DomainAuthLookup initialDomain={lookupDomain} />
        )}

        {activeTab === 'forensics' && (
          <div className="space-y-6">
            {/* Simulation Presets & Raw Header Input Drawer */}
            <div 
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              className={`bg-[#0a0f1c] border rounded-2xl p-5 shadow-xl relative transition-all duration-300 ${
                isDragging 
                  ? 'border-cyber-blue shadow-[0_0_30px_rgba(0,245,255,0.4)] bg-cyber-blue/5' 
                  : 'border-white/5'
              }`}
            >
              {/* Dragging Overlay */}
              {isDragging && (
                <div className="absolute inset-0 bg-black/85 backdrop-blur-md rounded-2xl z-30 flex flex-col items-center justify-center border-2 border-dashed border-cyber-blue p-6 pointer-events-none">
                  <UploadCloud className="w-12 h-12 text-cyber-blue animate-bounce mb-3" />
                  <span className="text-sm font-bold text-white uppercase tracking-widest">
                    DROP .EML OR RFC 5322 FILE HERE
                  </span>
                  <span className="text-xs text-cyber-blue font-mono mt-1">
                    Instant Header Extraction & Deep Forensic Reconstruction
                  </span>
                </div>
              )}

              {/* Mode Selection Header */}
              <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4 pb-4 border-b border-white/5">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-cyber-blue">
                      RFC 5322 FORENSIC LAB
                    </span>
                    {inputMode === 'custom' ? (
                      <span className="text-[9px] bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 px-2 py-0.5 rounded font-mono font-bold">
                        LIVE / CUSTOM INPUT MODE
                      </span>
                    ) : (
                      <span className="text-[9px] bg-amber-500/20 text-amber-300 border border-amber-500/30 px-2 py-0.5 rounded font-mono font-bold">
                        DEMO SCENARIOS MODE
                      </span>
                    )}
                  </div>
                  <h3 className="text-sm font-bold text-white">
                    {inputMode === 'custom' 
                      ? 'Analyze Your Own Raw Headers, Body Text, or Upload .EML' 
                      : 'Explore Pre-Configured Threat Scenarios'}
                  </h3>
                </div>
                
                {/* Primary Mode Toggle */}
                <div className="flex items-center bg-[#05080f] p-1 rounded-xl border border-white/10 gap-1">
                  <button
                    onClick={() => {
                      setInputMode('custom');
                      setSelectedScenario(null);
                    }}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
                      inputMode === 'custom'
                        ? 'bg-cyber-blue text-black shadow-md'
                        : 'text-gray-400 hover:text-white'
                    }`}
                  >
                    Custom / Real Data
                  </button>
                  <button
                    onClick={() => {
                      setInputMode('demo');
                      if (!selectedScenario) {
                        handleScenarioChange(TEST_SCENARIOS[0].id);
                      }
                    }}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
                      inputMode === 'demo'
                        ? 'bg-amber-400 text-black shadow-md'
                        : 'text-gray-400 hover:text-white'
                    }`}
                  >
                    Demo Presets
                  </button>
                </div>
              </div>

              {/* Demo Scenario Badges (visible in demo mode) */}
              {inputMode === 'demo' && (
                <div className="pt-3 pb-1 border-b border-white/5 flex flex-wrap items-center gap-2">
                  <span className="text-[11px] font-mono text-gray-400">Select Preset:</span>
                  {TEST_SCENARIOS.map(sc => (
                    <button
                      key={sc.id}
                      onClick={() => handleScenarioChange(sc.id)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all border ${
                        selectedScenario === sc.id
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/50 shadow-md font-bold'
                          : 'bg-black/30 text-gray-400 border-white/5 hover:border-white/20'
                      }`}
                    >
                      {sc.title.split(' (')[0]}
                    </button>
                  ))}
                </div>
              )}

              {/* Quick Actions Toolbar (Custom Mode) */}
              <div className="flex flex-wrap items-center justify-between gap-2 pt-3">
                <div className="flex flex-wrap items-center gap-2">
                  {/* .EML Upload Button */}
                  <label className="cursor-pointer px-3.5 py-1.5 rounded-lg text-xs font-mono bg-cyber-blue/15 hover:bg-cyber-blue/25 text-cyber-blue border border-cyber-blue/40 flex items-center gap-1.5 transition-all shadow-[0_0_15px_rgba(0,245,255,0.15)] hover:shadow-[0_0_20px_rgba(0,245,255,0.3)] font-bold active:scale-95">
                    <UploadCloud className="w-3.5 h-3.5" />
                    <span>Upload .EML / .MSG</span>
                    <input 
                      ref={fileInputRef}
                      type="file" 
                      accept=".eml,.msg,.txt,.log,.mbox,message/rfc822,text/plain,application/octet-stream,*" 
                      onClick={(e) => { (e.target as HTMLInputElement).value = ''; }}
                      onChange={handleFileUpload} 
                      className="hidden" 
                    />
                  </label>

                  {/* Paste Clipboard Button */}
                  <button
                    onClick={handlePasteClipboard}
                    className="px-3 py-1.5 rounded-lg text-xs font-mono bg-white/5 hover:bg-white/10 text-gray-300 hover:text-white border border-white/10 flex items-center gap-1.5 transition-all"
                  >
                    <Copy className="w-3.5 h-3.5 text-cyber-blue" />
                    <span>Paste Clipboard</span>
                  </button>

                  {/* Connect Gmail Shortcut */}
                  <button
                    onClick={() => setActiveTab('inbox')}
                    className="px-3 py-1.5 rounded-lg text-xs font-mono bg-white/5 hover:bg-white/10 text-gray-300 hover:text-white border border-white/10 flex items-center gap-1.5 transition-all"
                  >
                    <Mail className="w-3.5 h-3.5 text-red-400" />
                    <span>Connect Gmail Inbox</span>
                  </button>
                </div>

                {(rawHeaderText || bodyText || uploadedFileName) && (
                  <button
                    onClick={handleClearAll}
                    className="px-3 py-1.5 rounded-lg text-xs font-mono text-gray-400 hover:text-red-400 hover:bg-red-500/10 border border-transparent hover:border-red-500/20 flex items-center gap-1 transition-all"
                  >
                    <X className="w-3.5 h-3.5" />
                    <span>Clear All</span>
                  </button>
                )}
              </div>

              {/* Uploaded File Confirmation Banner */}
              {uploadedFileName && (
                <div className="mt-3 flex items-center justify-between bg-cyber-blue/10 border border-cyber-blue/30 rounded-xl px-3.5 py-2 text-xs font-mono text-cyber-blue">
                  <div className="flex items-center gap-2">
                    <FileText className="w-4 h-4 text-cyber-blue" />
                    <span className="text-white font-bold">Active Ingestion:</span>
                    <span>{uploadedFileName}</span>
                    <span className="text-[10px] bg-cyber-blue/20 text-cyber-blue px-2 py-0.5 rounded-md uppercase tracking-wider font-bold">Live Data</span>
                  </div>
                  <button 
                    onClick={handleClearAll}
                    className="text-gray-400 hover:text-white flex items-center gap-1 text-[11px] px-2 py-1 rounded bg-white/5 hover:bg-white/10 transition-colors"
                  >
                    <X className="w-3.5 h-3.5" />
                    <span>Clear</span>
                  </button>
                </div>
              )}

              {/* Raw Header / Body Inputs Accordion */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mt-4">
                <div>
                  <div className="flex justify-between items-center mb-1.5">
                    <label className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">
                      RFC 5322 Raw Message Headers
                    </label>
                    <span className="text-[10px] text-gray-500 font-mono">Unfolded & Multi-Hop Capable</span>
                  </div>
                  <textarea
                    rows={6}
                    value={rawHeaderText}
                    onChange={(e) => {
                      setInputMode('custom');
                      setSelectedScenario(null);
                      setRawHeaderText(e.target.value);
                    }}
                    placeholder="Paste real email headers (From:, Received:, Authentication-Results:, DKIM-Signature:)..."
                    className="w-full bg-[#05080f] border border-white/10 rounded-xl p-3 font-mono text-xs text-gray-300 focus:outline-none focus:border-cyber-blue/50 custom-scrollbar resize-none"
                  />
                </div>

                <div>
                  <div className="flex justify-between items-center mb-1.5">
                    <label className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">
                      Email Body & Embedded Content
                    </label>
                    <span className="text-[10px] text-gray-500 font-mono">NLP, Phishing & URL Extraction</span>
                  </div>
                  <textarea
                    rows={6}
                    value={bodyText}
                    onChange={(e) => {
                      setInputMode('custom');
                      setSelectedScenario(null);
                      setBodyText(e.target.value);
                    }}
                    placeholder="Paste email body or leave blank if combined above..."
                    className="w-full bg-[#05080f] border border-white/10 rounded-xl p-3 font-mono text-xs text-gray-300 focus:outline-none focus:border-cyber-blue/50 custom-scrollbar resize-none"
                  />
                </div>
              </div>

              {forensicError && (
                <div className="mt-3 flex items-center gap-2 bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-2.5 text-xs font-mono text-red-400">
                  <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                  <span>{forensicError}</span>
                </div>
              )}

              <div className="flex justify-end mt-4">
                <button
                  id="execute-deep-forensics-btn"
                  onClick={() => handleRunForensics(rawHeaderText, bodyText, inputMode)}
                  disabled={isAnalyzing}
                  className="px-6 py-3 rounded-xl font-mono text-xs font-bold uppercase tracking-widest bg-cyber-blue text-black hover:bg-cyber-blue/90 active:scale-95 shadow-[0_0_20px_rgba(0,245,255,0.3)] hover:shadow-[0_0_30px_rgba(0,245,255,0.5)] flex items-center gap-2.5 transition-all cursor-pointer disabled:opacity-50 disabled:pointer-events-none"
                >
                  {isAnalyzing ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin text-black" />
                      <span>Analyzing RFC 5322 Vectors...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4 text-black" />
                      <span>Execute Deep Forensics Pipeline</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* FORENSIC DOSSIER OUTPUT */}
            <div ref={dossierRef}>
              {dossier && (
                <motion.div
                  initial={{ opacity: 0, y: 15 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="space-y-6"
                >
                {/* 1. Threat Verdict & KPI Banner */}
                <div className="bg-[#0a0f1c] border border-white/5 rounded-2xl p-6 shadow-2xl relative overflow-hidden">
                  <div className={`absolute top-0 left-0 h-1.5 w-full ${
                    dossier.classification.verdict === 'MALICIOUS' ? 'bg-red-500' :
                    dossier.classification.verdict === 'SUSPICIOUS' ? 'bg-amber-500' : 'bg-emerald-500'
                  }`} />

                  <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-6">
                    <div className="space-y-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold tracking-widest uppercase border ${
                          dossier.classification.verdict === 'MALICIOUS' ? 'bg-red-500/10 text-red-400 border-red-500/30' :
                          dossier.classification.verdict === 'SUSPICIOUS' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
                          'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        }`}>
                          {dossier.classification.verdict} — {dossier.classification.threatType}
                        </span>
                        <span className="text-xs text-gray-400 font-mono">Confidence: {dossier.classification.confidence}%</span>
                        
                        {dossierSource === 'demo' ? (
                          <span className="text-[10px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/30 px-2 py-0.5 rounded font-bold">
                            DEMO PRESET DATA
                          </span>
                        ) : dossierSource === 'gmail' ? (
                          <span className="text-[10px] font-mono bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded font-bold">
                            LIVE GMAIL DATA
                          </span>
                        ) : (
                          <span className="text-[10px] font-mono bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 px-2 py-0.5 rounded font-bold">
                            LIVE CUSTOM INGESTION
                          </span>
                        )}
                      </div>
                      <h2 className="text-xl font-bold text-white tracking-tight">{dossier.headerFields.subject}</h2>
                      <p className="text-xs text-gray-400 font-mono">Subtype: {dossier.classification.subtype}</p>
                    </div>

                    <div className="flex items-center gap-6">
                      <div className="text-right">
                        <span className="text-[10px] font-mono uppercase tracking-widest text-gray-500 block">THREAT RISK SCORE</span>
                        <div className={`text-4xl font-black font-mono tracking-tighter ${
                          dossier.classification.riskScore > 60 ? 'text-red-500' :
                          dossier.classification.riskScore > 30 ? 'text-amber-400' : 'text-emerald-400'
                        }`}>
                          {dossier.classification.riskScore}<span className="text-xl text-gray-600">/100</span>
                        </div>
                      </div>

                      <div className="flex flex-col gap-2">
                        <button
                          onClick={downloadJsonDossier}
                          className="px-3.5 py-1.5 rounded-lg text-xs font-mono bg-white/5 hover:bg-white/10 text-white border border-white/10 flex items-center gap-1.5 transition-colors"
                        >
                          <Download className="w-3.5 h-3.5 text-cyber-blue" />
                          <span>Export JSON</span>
                        </button>
                        <button
                          onClick={downloadMarkdownReport}
                          className="px-3.5 py-1.5 rounded-lg text-xs font-mono bg-cyber-blue/10 hover:bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 flex items-center gap-1.5 transition-colors"
                        >
                          <FileText className="w-3.5 h-3.5" />
                          <span>SOC Report (.md)</span>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 2. Protocol Authentication Matrix (SPF / DKIM / DMARC) */}
                <div className="space-y-3">
                  <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 bg-[#0a0f1c] border border-white/5 p-4 rounded-xl">
                    <div className="flex items-center gap-2.5">
                      <Globe className="w-4 h-4 text-cyber-blue shrink-0" />
                      <div>
                        <span className="text-xs font-mono font-bold text-white uppercase tracking-wider block">
                          RFC AUTHENTICATION PROTOCOL STATUS
                        </span>
                        <span className="text-[11px] text-gray-400">
                          Sender Domain: <strong className="text-cyber-blue font-mono">{dossier.senderIdentity.fromDomain || 'Unknown'}</strong>
                        </span>
                      </div>
                    </div>
                    {dossier.senderIdentity.fromDomain && (
                      <button
                        onClick={() => {
                          setLookupDomain(dossier.senderIdentity.fromDomain || 'google.com');
                          setActiveTab('dns-lookup');
                        }}
                        className="px-3 py-1.5 rounded-lg bg-cyber-blue/10 hover:bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 text-xs font-mono font-bold flex items-center gap-1.5 transition-all whitespace-nowrap"
                      >
                        <Globe className="w-3.5 h-3.5" />
                        <span>Query Live DNS Records</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    )}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* SPF */}
                  <div className="bg-[#0a0f1c] border border-white/5 rounded-2xl p-5 shadow-lg">
                    <div className="flex justify-between items-center mb-3">
                      <span className="text-xs font-mono font-bold tracking-widest uppercase text-gray-400">SPF VALIDATION</span>
                      <span className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold uppercase border ${
                        dossier.authentication.spf.status === 'PASS' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                        dossier.authentication.spf.status === 'FAIL' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                        'bg-gray-500/10 text-gray-400 border-gray-500/20'
                      }`}>
                        {dossier.authentication.spf.status}
                      </span>
                    </div>
                    <p className="text-xs text-gray-300 leading-relaxed mb-3">{dossier.authentication.spf.evidence}</p>
                    <div className="text-[10px] font-mono text-gray-500 border-t border-white/5 pt-2">
                      Envelope: <span className="text-gray-300">{dossier.authentication.spf.envelopeSenderDomain || 'N/A'}</span>
                    </div>
                  </div>

                  {/* DKIM */}
                  <div className="bg-[#0a0f1c] border border-white/5 rounded-2xl p-5 shadow-lg">
                    <div className="flex justify-between items-center mb-3">
                      <span className="text-xs font-mono font-bold tracking-widest uppercase text-gray-400">DKIM CRYPTO SIGNATURE</span>
                      <span className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold uppercase border ${
                        dossier.authentication.dkim.status === 'PASS' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                        dossier.authentication.dkim.status === 'FAIL' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                        'bg-gray-500/10 text-gray-400 border-gray-500/20'
                      }`}>
                        {dossier.authentication.dkim.status}
                      </span>
                    </div>
                    <p className="text-xs text-gray-300 leading-relaxed mb-3">{dossier.authentication.dkim.evidence}</p>
                    <div className="text-[10px] font-mono text-gray-500 border-t border-white/5 pt-2">
                      Signing Domain: <span className="text-gray-300">{dossier.authentication.dkim.signingDomain || 'None'}</span>
                    </div>
                  </div>

                  {/* DMARC */}
                  <div className="bg-[#0a0f1c] border border-white/5 rounded-2xl p-5 shadow-lg">
                    <div className="flex justify-between items-center mb-3">
                      <span className="text-xs font-mono font-bold tracking-widest uppercase text-gray-400">DMARC POLICY ALIGNMENT</span>
                      <span className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold uppercase border ${
                        dossier.authentication.dmarc.status === 'PASS' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                        dossier.authentication.dmarc.status === 'FAIL' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                        'bg-gray-500/10 text-gray-400 border-gray-500/20'
                      }`}>
                        {dossier.authentication.dmarc.status}
                      </span>
                    </div>
                    <p className="text-xs text-gray-300 leading-relaxed mb-3">{dossier.authentication.dmarc.evidence}</p>
                    <div className="text-[10px] font-mono text-gray-500 border-t border-white/5 pt-2">
                      Header From: <span className="text-gray-300">{dossier.authentication.dmarc.headerFromDomain || 'N/A'}</span>
                    </div>
                  </div>
                </div>
                </div>

                {/* 3. Sender Identity & Discrepancies Matrix */}
                <div className="bg-[#0a0f1c] border border-white/5 rounded-2xl p-6 shadow-xl space-y-4">
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-cyber-blue" />
                      <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                        SENDER IDENTITY & HEADER DISCREPANCY AUDIT
                      </h3>
                    </div>
                    <span className="text-xs font-mono text-gray-400">
                      {dossier.senderIdentity.inconsistencies.length} Inconsistencies Detected
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-4 gap-3 bg-[#05080f] p-4 rounded-xl border border-white/5 text-xs font-mono">
                    <div>
                      <span className="text-gray-500 block text-[10px]">HEADER FROM:</span>
                      <span className="text-white font-medium break-all">{dossier.senderIdentity.fromAddress}</span>
                    </div>
                    <div>
                      <span className="text-gray-500 block text-[10px]">RETURN-PATH (ENVELOPE):</span>
                      <span className="text-white font-medium break-all">{dossier.senderIdentity.returnPathAddress || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-gray-500 block text-[10px]">REPLY-TO:</span>
                      <span className="text-white font-medium break-all">{dossier.senderIdentity.replyToAddress || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-gray-500 block text-[10px]">MESSAGE-ID:</span>
                      <span className="text-white font-medium break-all">{dossier.headerFields.messageId || 'N/A'}</span>
                    </div>
                  </div>

                  {dossier.senderIdentity.inconsistencies.length > 0 && (
                    <div className="space-y-2 pt-2">
                      {dossier.senderIdentity.inconsistencies.map((inc, i) => (
                        <div key={i} className="bg-red-500/5 border border-red-500/20 rounded-xl p-3 flex items-start gap-3">
                          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                          <div className="space-y-1 text-xs">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-red-400">{inc.title}</span>
                              <span className="text-[10px] font-mono px-2 py-0.2 bg-red-500/20 text-red-300 rounded">
                                {inc.severity}
                              </span>
                            </div>
                            <p className="text-gray-300">{inc.description}</p>
                            <p className="text-gray-400 text-[11px] italic font-mono">{inc.significance}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* 4. Hop-by-Hop Relay Path Reconstruction & Origin IP Card */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  {/* Relay Path Chronology */}
                  <div className="lg:col-span-2 bg-[#0a0f1c] border border-white/5 rounded-2xl p-6 shadow-xl space-y-4">
                    <div className="flex justify-between items-center">
                      <div className="flex items-center gap-2">
                        <Clock className="w-4 h-4 text-cyber-blue" />
                        <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                          RELAY PATH RECONSTRUCTION ({dossier.relayReconstruction.hopCount} HOPS)
                        </h3>
                      </div>
                      <span className="text-xs font-mono text-gray-400">
                        Transit: ~{dossier.relayReconstruction.totalTransitTimeSeconds}s
                      </span>
                    </div>

                    <div className="relative pl-6 space-y-6 border-l-2 border-white/10 my-2">
                      {dossier.relayReconstruction.chronologicalHops.map((hop, idx) => (
                        <div key={idx} className="relative group">
                          <div className="absolute -left-[31px] top-0.5 w-4 h-4 rounded-full bg-[#0a0f1c] border-2 border-cyber-blue flex items-center justify-center">
                            <div className="w-1.5 h-1.5 rounded-full bg-cyber-blue" />
                          </div>

                          <div className="bg-[#05080f] border border-white/5 rounded-xl p-3.5 space-y-2">
                            <div className="flex justify-between items-center">
                              <span className="text-xs font-mono font-bold text-cyber-blue">
                                HOP {hop.hopNumber}: {hop.sourceHostname}
                              </span>
                              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                                hop.ipType === 'Public IPv4' ? 'bg-cyber-blue/10 text-cyber-blue border-cyber-blue/30' :
                                'bg-amber-500/10 text-amber-300 border-amber-500/30'
                              }`}>
                                {hop.ipType}
                              </span>
                            </div>

                            <div className="text-xs font-mono text-gray-300 flex flex-wrap gap-x-4 gap-y-1">
                              <div>IP: <span className="text-white font-bold">{hop.sourceIP}</span></div>
                              <div>➔ Destination: <span className="text-gray-400">{hop.destinationHostname}</span></div>
                              <div>Protocol: <span className="text-gray-400">{hop.protocol}</span></div>
                            </div>

                            <div className="flex justify-between items-center text-[10px] font-mono text-gray-500 pt-1 border-t border-white/5">
                              <span>Time: {hop.timestamp || 'N/A'}</span>
                              {hop.delayToNextHopSeconds !== undefined && (
                                <span>Transit Delay: +{hop.delayToNextHopSeconds}s</span>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Origin IP & Intelligence */}
                  <div className="bg-[#0a0f1c] border border-white/5 rounded-2xl p-6 shadow-xl flex flex-col justify-between space-y-4">
                    <div>
                      <div className="flex items-center gap-2 mb-4">
                        <Globe className="w-4 h-4 text-cyber-blue" />
                        <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                          ORIGIN IP & GEOLOCATION
                        </h3>
                      </div>

                      <div className="space-y-3 bg-[#05080f] p-4 rounded-xl border border-white/5 font-mono text-xs">
                        <div>
                          <span className="text-[10px] text-gray-500 block">EARLIEST RELIABLE PUBLIC IP:</span>
                          <span className="text-base text-cyber-blue font-bold">{dossier.originIP.ip}</span>
                        </div>
                        <div>
                          <span className="text-[10px] text-gray-500 block">IP CLASSIFICATION:</span>
                          <span className="text-white">{dossier.originIP.ipType}</span>
                        </div>
                        <div>
                          <span className="text-[10px] text-gray-500 block">COUNTRY / LOCATION:</span>
                          <span className="text-white">{dossier.originIP.country}</span>
                        </div>
                        <div>
                          <span className="text-[10px] text-gray-500 block">CITY / REGION:</span>
                          <span className="text-white">{dossier.originIP.city}, {dossier.originIP.region}</span>
                        </div>
                        <div>
                          <span className="text-[10px] text-gray-500 block">ISP / ASN:</span>
                          <span className="text-white">{dossier.originIP.isp} ({dossier.originIP.asn})</span>
                        </div>
                      </div>

                      <p className="text-[11px] text-gray-400 italic mt-3 leading-relaxed">
                        Forensic Caveat: Identifies the sending mail server gateway; does not prove physical identity of the human operator.
                      </p>
                    </div>

                    <div className="pt-3 border-t border-white/5">
                      <button
                        type="button"
                        onClick={() => {
                          if (dossier.attackGraph) {
                            localStorage.setItem('neuroshield_active_attack_graph', JSON.stringify(dossier.attackGraph));
                          }
                          window.dispatchEvent(new CustomEvent('neuroshield:navigate', { detail: 'graph' }));
                          window.location.hash = '#/attack-graph';
                        }}
                        className="w-full py-2.5 rounded-xl font-mono text-xs font-bold uppercase tracking-wider bg-cyber-blue/10 hover:bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 flex items-center justify-center gap-2 transition-all duration-200 hover:shadow-[0_0_15px_rgba(0,245,255,0.2)] cursor-pointer"
                      >
                        <Network className="w-3.5 h-3.5" />
                        <span>Inspect in Attack Graph</span>
                      </button>
                    </div>
                  </div>
                </div>

                {/* 5. Indicators of Compromise (IOC) Matrix */}
                <div className="bg-[#0a0f1c] border border-white/5 rounded-2xl p-6 shadow-xl space-y-4">
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <Layers className="w-4 h-4 text-cyber-blue" />
                      <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                        EXTRACTED INDICATORS OF COMPROMISE (IOCs)
                      </h3>
                    </div>
                    <span className="text-xs font-mono text-gray-400">Ready for SIEM/EDR Ingestion</span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                    {/* IP Addresses */}
                    <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-2">
                      <span className="text-[10px] font-mono text-gray-400 font-bold uppercase block">IP ADDRESSES</span>
                      <div className="space-y-1 max-h-32 overflow-y-auto pr-1">
                        {dossier.iocs.ipAddresses.map((ipObj, i) => (
                          <div key={i} className="flex justify-between items-center text-xs font-mono bg-black/40 p-1.5 rounded border border-white/5">
                            <span className="text-white truncate">{ipObj.ip}</span>
                            <button
                              onClick={() => copyToClipboard(ipObj.ip, `ip-${i}`)}
                              className="text-gray-400 hover:text-white p-1"
                            >
                              {copiedKey === `ip-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Domains */}
                    <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-2">
                      <span className="text-[10px] font-mono text-gray-400 font-bold uppercase block">DOMAINS</span>
                      <div className="space-y-1 max-h-32 overflow-y-auto pr-1">
                        {dossier.iocs.domains.map((dom, i) => (
                          <div key={i} className="flex justify-between items-center text-xs font-mono bg-black/40 p-1.5 rounded border border-white/5">
                            <span className="text-white truncate" title={dom.domain}>{dom.domain}</span>
                            <button
                              onClick={() => copyToClipboard(dom.domain, `dom-${i}`)}
                              className="text-gray-400 hover:text-white p-1"
                            >
                              {copiedKey === `dom-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* URLs */}
                    <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-2">
                      <span className="text-[10px] font-mono text-gray-400 font-bold uppercase block">PHISHING URLS</span>
                      <div className="space-y-1 max-h-32 overflow-y-auto pr-1">
                        {dossier.iocs.urls.length > 0 ? (
                          dossier.iocs.urls.map((u, i) => (
                            <div key={i} className="flex justify-between items-center text-xs font-mono bg-black/40 p-1.5 rounded border border-white/5">
                              <span className="text-red-400 truncate" title={u}>{u}</span>
                              <button
                                onClick={() => copyToClipboard(u, `url-${i}`)}
                                className="text-gray-400 hover:text-white p-1"
                              >
                                {copiedKey === `url-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              </button>
                            </div>
                          ))
                        ) : (
                          <div className="text-xs text-gray-500 italic p-1">No embedded URLs</div>
                        )}
                      </div>
                    </div>

                    {/* Email Accounts */}
                    <div className="bg-[#05080f] p-3.5 rounded-xl border border-white/5 space-y-2">
                      <span className="text-[10px] font-mono text-gray-400 font-bold uppercase block">IDENTIFIED EMAILS</span>
                      <div className="space-y-1 max-h-32 overflow-y-auto pr-1">
                        {dossier.iocs.emailAddresses.map((em, i) => (
                          <div key={i} className="flex justify-between items-center text-xs font-mono bg-black/40 p-1.5 rounded border border-white/5">
                            <span className="text-white truncate" title={em.email}>{em.email}</span>
                            <button
                              onClick={() => copyToClipboard(em.email, `em-${i}`)}
                              className="text-gray-400 hover:text-white p-1"
                            >
                              {copiedKey === `em-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                {/* 6. Top Prioritized Forensic Findings */}
                <div className="bg-[#0a0f1c] border border-white/5 rounded-2xl p-6 shadow-xl space-y-3">
                  <div className="flex items-center gap-2 mb-2">
                    <ShieldCheck className="w-4 h-4 text-cyber-blue" />
                    <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                      TOP 5 PRIORITIZED FORENSIC FINDINGS
                    </h3>
                  </div>

                  <div className="space-y-2">
                    {dossier.topFindings.map((f, i) => (
                      <div key={i} className="flex items-start gap-3 bg-[#05080f] p-3 rounded-xl border border-white/5">
                        <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase shrink-0 mt-0.5 ${
                          f.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                          f.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                          'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30'
                        }`}>
                          {f.severity}
                        </span>
                        <p className="text-xs text-gray-300 leading-relaxed font-sans">{f.finding}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </motion.div>
            )}

            {!dossier && (
              <div className="bg-[#0a0f1c] border border-white/5 rounded-2xl p-8 text-center space-y-6">
                <div className="w-14 h-14 rounded-2xl bg-cyber-blue/10 border border-cyber-blue/30 flex items-center justify-center mx-auto text-cyber-blue shadow-[0_0_20px_rgba(0,245,255,0.15)]">
                  <Terminal className="w-7 h-7" />
                </div>
                <div className="max-w-lg mx-auto space-y-2">
                  <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider">
                    Ready for RFC 5322 Ingestion & Threat Attribution
                  </h3>
                  <p className="text-xs text-gray-400 leading-relaxed">
                    Paste raw email headers or body above, drop a <span className="text-cyber-blue font-mono">.eml</span> file, or choose from our pre-configured threat scenarios to reconstruct multi-hop SMTP routing, verify SPF/DKIM/DMARC alignment, and detect brand impersonation.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 max-w-2xl mx-auto pt-2">
                  <button
                    onClick={() => handleScenarioChange(TEST_SCENARIOS[0].id)}
                    className="p-3.5 rounded-xl bg-[#05080f] hover:bg-white/5 border border-white/10 hover:border-amber-400/40 text-left transition-all group cursor-pointer"
                  >
                    <span className="text-[10px] font-mono text-amber-400 uppercase tracking-widest block mb-1">Preset Simulation</span>
                    <span className="text-xs font-bold text-white block group-hover:text-amber-300">Microsoft 365 BEC</span>
                    <span className="text-[11px] text-gray-500">Phishing & Credential Harvest</span>
                  </button>

                  <button
                    onClick={() => handleScenarioChange(TEST_SCENARIOS[1].id)}
                    className="p-3.5 rounded-xl bg-[#05080f] hover:bg-white/5 border border-white/10 hover:border-red-400/40 text-left transition-all group cursor-pointer"
                  >
                    <span className="text-[10px] font-mono text-red-400 uppercase tracking-widest block mb-1">Preset Simulation</span>
                    <span className="text-xs font-bold text-white block group-hover:text-red-300">PayPal Fake Invoice</span>
                    <span className="text-[11px] text-gray-500">Crypto Scam & Typosquatting</span>
                  </button>

                  <button
                    onClick={() => setActiveTab('inbox')}
                    className="p-3.5 rounded-xl bg-[#05080f] hover:bg-white/5 border border-white/10 hover:border-cyber-blue/40 text-left transition-all group cursor-pointer"
                  >
                    <span className="text-[10px] font-mono text-cyber-blue uppercase tracking-widest block mb-1">Live Connection</span>
                    <span className="text-xs font-bold text-white block group-hover:text-cyber-blue">Live Gmail Scan</span>
                    <span className="text-[11px] text-gray-500">Inspect Real Inbox Emails</span>
                  </button>
                </div>
              </div>
            )}
            </div>
          </div>
        )}

        {activeTab === 'inbox' && (
          /* GMAIL LIVE INBOX VIEW */
          <div className="space-y-6">
            {!isAuthenticated ? (
              <div className="space-y-4">
                <div className="bg-cyber-blue/5 border border-cyber-blue/30 rounded-2xl p-6 flex flex-col md:flex-row justify-between items-center gap-4">
                  <div className="flex items-center gap-4">
                    <div className="w-12 h-12 rounded-xl bg-cyber-blue/10 border border-cyber-blue/30 flex items-center justify-center shrink-0">
                      <Mail className="w-6 h-6 text-cyber-blue" />
                    </div>
                    <div>
                      <h3 className="text-white font-bold text-base tracking-wide">Connect Real Gmail Account</h3>
                      <p className="text-cyber-muted text-xs">Scan and analyze live inbox messages for phishing and protocol spoofing in real time.</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 w-full md:w-auto">
                    <button 
                      onClick={() => loadSampleInbox()}
                      className="flex-1 md:flex-none font-mono text-xs font-bold uppercase tracking-widest bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 px-4 py-3 rounded-xl transition-all flex items-center justify-center gap-2"
                    >
                      <Terminal className="w-3.5 h-3.5" /> Sample Inbox
                    </button>
                    <button 
                      onClick={() => handleGoogleLogin()} 
                      disabled={isLoadingEmails}
                      className="flex-1 md:flex-none font-mono text-xs font-bold uppercase tracking-widest bg-cyber-blue text-black hover:bg-cyber-blue/90 px-6 py-3 rounded-xl transition-all shadow-lg flex items-center justify-center gap-2"
                    >
                      {isLoadingEmails ? <RefreshCw className="w-4 h-4 animate-spin" /> : <LogIn className="w-4 h-4" />}
                      Connect Gmail
                    </button>
                  </div>
                </div>

                {authError && (
                  <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex items-start gap-3">
                    <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                    <div className="text-xs space-y-1">
                      <p className="font-bold text-amber-300">Notice: {authError}</p>
                      <p className="text-gray-400 leading-relaxed">
                        If running inside a sandboxed iframe or if popup was blocked, you can also use the Sample Inbox mode to test all phishing triage and forensic graph features immediately.
                      </p>
                      <div className="pt-2">
                        <button
                          onClick={() => loadSampleInbox()}
                          className="px-3 py-1.5 rounded-lg bg-cyber-blue/20 hover:bg-cyber-blue/30 text-cyber-blue border border-cyber-blue/40 font-mono font-bold text-[11px]"
                        >
                          Load Simulated Inbox for Testing
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 bg-[#0a0f1c] p-4 rounded-xl border border-white/5">
                  <div className="flex items-center gap-2.5">
                    <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
                    <span className="text-xs font-mono font-bold text-emerald-400">
                      GMAIL API CONNECTED
                    </span>
                    {currentUser?.email && (
                      <span className="text-[11px] font-mono text-gray-400 bg-white/5 px-2 py-0.5 rounded border border-white/10">
                        {currentUser.email}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-3">
                    <button
                      onClick={async () => {
                        const token = getAccessToken();
                        if (token) {
                          await fetchRealEmails(token);
                        } else {
                          await handleGoogleLogin();
                        }
                      }}
                      className="text-xs font-mono text-cyber-blue hover:underline flex items-center gap-1.5"
                    >
                      <RefreshCw className="w-3.5 h-3.5" /> Refresh Inbox
                    </button>
                    <button
                      onClick={() => handleLogout()}
                      className="text-xs font-mono text-red-400 hover:text-red-300 hover:underline"
                    >
                      Disconnect
                    </button>
                  </div>
                </div>

                <div className="space-y-3">
                  {emails.map((email) => (
                    <div
                      key={email.id}
                      className="bg-[#0a0f1c] border border-white/5 rounded-xl p-5 hover:border-cyber-blue/30 transition-all flex flex-col md:flex-row justify-between items-start md:items-center gap-4"
                    >
                      <div className="space-y-1 flex-1">
                        <div className="flex items-center gap-2">
                          <h4 className="text-sm font-bold text-white">{email.subject}</h4>
                          <span className="text-[10px] font-mono text-gray-500">{email.time}</span>
                        </div>
                        <p className="text-xs text-gray-400 font-mono">From: {email.sender}</p>
                        <p className="text-xs text-gray-500 line-clamp-1">{email.body}</p>
                      </div>

                      <button
                        onClick={() => inspectGmailMessage(email)}
                        className="px-4 py-2 rounded-lg text-xs font-mono font-bold bg-cyber-blue/10 hover:bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 flex items-center gap-1.5 transition-colors whitespace-nowrap"
                      >
                        <Terminal className="w-3.5 h-3.5" />
                        <span>Run Forensics</span>
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

      </div>
      <style>{`
        .custom-scrollbar::-webkit-scrollbar { width: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: rgba(0,0,0,0.2); }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 6px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }
      `}</style>
    </div>
  );
}
