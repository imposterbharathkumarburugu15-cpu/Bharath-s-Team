import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Mail, Search, RefreshCw, LogIn, Bell, Shield, ShieldCheck, ShieldAlert, 
  AlertTriangle, FileText, Terminal, ArrowRight, ArrowLeft, Copy, Check, CheckCircle2, Download, 
  ExternalLink, Network, Globe, Server, Clock, Lock, AlertCircle, Sparkles, UploadCloud, Layers, X,
  ChevronDown, ChevronUp, UserCheck, Key, CreditCard, FileSearch, Flag, ThumbsUp, ThumbsDown,
  Cpu, Brain, Activity
} from 'lucide-react';
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer } from 'recharts';
import { cn } from '@/lib/utils';
import { useLanguage } from '@/contexts/LanguageContext';
import { addScanToHistory } from '@/lib/history';
import { executeEmailForensics, ForensicDossier } from '@/services/forensicsEngine';
import { NeuroShieldCore } from '@/services/core/neuroshieldCore';
import { UnifiedThreatAnalysis, UnifiedInteractionEvent } from '@/services/core/types';
import { googleSignIn, googleLogout, initAuth, getAccessToken } from '@/services/googleAuth';
import { InboxShieldView } from '@/components/InboxShieldView';
import { EmailProtectionStatus } from '@/components/EmailProtectionStatus';
import { EmailForensicsPanel } from '@/components/EmailForensicsPanel';
import { NeuralProfile } from '@/components/forensics/NeuralProfile';
import { SihForensicSuite } from '@/components/forensics/SihForensicSuite';
import { DomainAuthLookup } from '@/components/DomainAuthLookup';
import { AdaptiveFeedbackSection } from '@/components/AdaptiveFeedbackSection';
import { InboxEmailItem } from '@/data/inboxEmails';
import { 
  ingestGmailEmails, 
  EmailPollingController, 
  computeIngestionStats,
  parseSender as parseSenderUtil 
} from '@/services/gmailIngestionService';
import type { User } from 'firebase/auth';

export interface GmailEmailItem {
  id: string;
  sender: string;
  subject: string;
  time: string;
  body: string;
  rawHeaders: string;
  dossier?: ForensicDossier;
  coreAnalysis?: UnifiedThreatAnalysis;
  isAnalyzing?: boolean;
}

export default function EmailPhishing() {
  const { t } = useLanguage();

  // Mode: 'inbox' (default list) or 'incident' (single unified email view)
  const [viewMode, setViewMode] = useState<'inbox' | 'incident'>('inbox');
  const [activeIncidentTab, setActiveIncidentTab] = useState<'forensics' | 'neural' | 'sih-suite' | 'dns-auth'>('forensics');
  const [selectedEmail, setSelectedEmail] = useState<GmailEmailItem | null>(null);
  const [coreAnalysis, setCoreAnalysis] = useState<UnifiedThreatAnalysis | null>(null);
  const [dossier, setDossier] = useState<ForensicDossier | null>(null);
  const [isAnalyzingIncident, setIsAnalyzingIncident] = useState(false);

  // Expandable sections inside incident view
  const [showTechnicalEvidence, setShowTechnicalEvidence] = useState(false);
  const [showAdversarialSignals, setShowAdversarialSignals] = useState(false);
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [feedbackSubmitted, setFeedbackSubmitted] = useState<'CONFIRMED' | 'FALSE_POSITIVE' | null>(null);

  // Live Gmail Auth & Ingestion States
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [isLoadingEmails, setIsLoadingEmails] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [emails, setEmails] = useState<GmailEmailItem[]>([]);
  const [inboxEmails, setInboxEmails] = useState<InboxEmailItem[]>([]);
  const [nextPageToken, setNextPageToken] = useState<string | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);

  // Auto-Ingestion & Background Polling
  const [lastScanTimestamp, setLastScanTimestamp] = useState<string | null>(null);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [nextPollCountdown, setNextPollCountdown] = useState(0);
  const pollingControllerRef = useRef<EmailPollingController | null>(null);

  // Optional offline .eml dropzone for analysts
  const [showOfflineUploader, setShowOfflineUploader] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Protection stats
  const protectionStats = computeIngestionStats(
    inboxEmails,
    isMonitoring,
    lastScanTimestamp
  );

  // Initialize Google Auth on mount
  useEffect(() => {
    const unsubscribe = initAuth(
      (user, token) => {
        setCurrentUser(user);
        setIsAuthenticated(true);
        handleAutoIngest(token);
      },
      () => {
        setCurrentUser(null);
        setIsAuthenticated(false);
        stopPolling();
      }
    );
    return () => {
      unsubscribe();
      stopPolling();
    };
  }, []);

  // Countdown timer for next background polling cycle
  useEffect(() => {
    if (!isMonitoring) return;
    const timer = setInterval(() => {
      setNextPollCountdown(prev => (prev > 0 ? prev - 1 : 300));
    }, 1000);
    return () => clearInterval(timer);
  }, [isMonitoring]);

  // Automatic Gmail Ingestion
  const handleAutoIngest = useCallback(async (token: string) => {
    setIsLoadingEmails(true);
    setAuthError(null);
    try {
      const result = await ingestGmailEmails(token);
      setInboxEmails(result.emails);
      setNextPageToken(result.nextPageToken);
      setLastScanTimestamp(new Date().toISOString());

      setEmails(result.emails.map(e => ({
        id: e.id,
        sender: `${e.senderName} <${e.senderEmail}>`,
        subject: e.subject,
        time: e.timeString,
        body: e.body,
        rawHeaders: e.rawHeaders,
        dossier: e.dossier,
        isAnalyzing: false
      })));

      startPolling(token, result.emails.map(e => e.id));
    } catch (err: any) {
      console.warn('Auto-ingestion notice:', err);
      setAuthError(err?.message || 'Error during automatic email ingestion.');
    } finally {
      setIsLoadingEmails(false);
    }
  }, []);

  // Polling controller
  const startPolling = useCallback((token: string, existingIds: string[]) => {
    stopPolling();
    const controller = new EmailPollingController(
      token,
      (newEmails) => {
        setInboxEmails(prev => [...newEmails, ...prev]);
        setEmails(prev => [
          ...newEmails.map(e => ({
            id: e.id,
            sender: `${e.senderName} <${e.senderEmail}>`,
            subject: e.subject,
            time: e.timeString,
            body: e.body,
            rawHeaders: e.rawHeaders,
            dossier: e.dossier,
            isAnalyzing: false
          })),
          ...prev
        ]);
        setLastScanTimestamp(new Date().toISOString());
      },
      (error) => {
        console.warn('[Polling] Error:', error);
      },
      5 * 60 * 1000
    );
    controller.start(existingIds);
    pollingControllerRef.current = controller;
    setIsMonitoring(true);
    setNextPollCountdown(300);
  }, []);

  const stopPolling = useCallback(() => {
    if (pollingControllerRef.current) {
      pollingControllerRef.current.stop();
      pollingControllerRef.current = null;
    }
    setIsMonitoring(false);
  }, []);

  // Pagination
  const handleLoadMore = useCallback(async () => {
    const token = getAccessToken();
    if (!token || !nextPageToken) return;
    setIsLoadingMore(true);
    try {
      const result = await ingestGmailEmails(token, nextPageToken);
      setInboxEmails(prev => [...prev, ...result.emails]);
      setNextPageToken(result.nextPageToken);
      setEmails(prev => [
        ...prev,
        ...result.emails.map(e => ({
          id: e.id,
          sender: `${e.senderName} <${e.senderEmail}>`,
          subject: e.subject,
          time: e.timeString,
          body: e.body,
          rawHeaders: e.rawHeaders,
          dossier: e.dossier,
          isAnalyzing: false
        }))
      ]);
    } catch (err: any) {
      setAuthError(err?.message || 'Error loading more emails.');
    } finally {
      setIsLoadingMore(false);
    }
  }, [nextPageToken]);

  // Auth actions
  const handleGoogleLogin = async () => {
    setAuthError(null);
    setIsLoadingEmails(true);
    try {
      const result = await googleSignIn();
      if (result) {
        setCurrentUser(result.user);
        setIsAuthenticated(true);
        await handleAutoIngest(result.accessToken);
      }
    } catch (error: any) {
      setAuthError(error?.message || 'OAuth sign-in cancelled or failed.');
    } finally {
      setIsLoadingEmails(false);
    }
  };

  const handleLogout = async () => {
    await googleLogout();
    stopPolling();
    setIsAuthenticated(false);
    setCurrentUser(null);
    setEmails([]);
    setInboxEmails([]);
    setSelectedEmail(null);
    setCoreAnalysis(null);
    setDossier(null);
    setViewMode('inbox');
  };

  // Select an email to inspect as ONE unified incident
  const handleSelectEmailIncident = async (item: InboxEmailItem, tab: 'forensics' | 'neural' | 'sih-suite' | 'dns-auth' = 'forensics') => {
    setActiveIncidentTab(tab);
    setIsAnalyzingIncident(true);
    setFeedbackSubmitted(null);
    setShowTechnicalEvidence(false);
    setShowAdversarialSignals(false);
    setShowRawHeaders(false);

    const gmailItem: GmailEmailItem = {
      id: item.id,
      sender: `${item.senderName} <${item.senderEmail}>`,
      subject: item.subject,
      time: item.timeString,
      body: item.body,
      rawHeaders: item.rawHeaders,
      dossier: item.dossier,
      isAnalyzing: false,
    };
    setSelectedEmail(gmailItem);
    setViewMode('incident');

    try {
      // 1. Run NeuroShield Core (Context + Intent + Sensitive Data + Action Risk + Correlation)
      const event: UnifiedInteractionEvent = {
        source: 'email',
        content: item.body,
        sender: {
          identifier: item.senderEmail,
          displayName: item.senderName,
        },
        subject: item.subject,
        rawPayload: item.rawHeaders,
      };

      const analysis = await NeuroShieldCore.analyze(event);
      setCoreAnalysis(analysis);

      // 2. Run / reuse RFC deep forensic dossier (Authentication, Received routing, URLs)
      let emailDossier = item.dossier;
      if (!emailDossier) {
        try {
          const domain = item.senderEmail.split('@')[1] || 'relay.net';
          const rawHeadersFallback = item.rawHeaders && item.rawHeaders.length > 20
            ? item.rawHeaders
            : `From: ${item.senderName} <${item.senderEmail}>\nTo: enterprise-user@corp.internal\nSubject: ${item.subject}\nDate: ${new Date().toUTCString()}\nReceived: from mail.${domain} (198.51.100.24) by mx.google.com with ESMTPS; ${new Date().toUTCString()}\nAuthentication-Results: mx.google.com; dkim=pass header.i=@${domain}; spf=pass (google.com: domain of ${item.senderEmail} designates 198.51.100.24 as permitted sender) smtp.mailfrom=${item.senderEmail}; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=${domain}\n`;
          emailDossier = await executeEmailForensics(rawHeadersFallback, item.body);
        } catch (dErr) {
          console.warn('RFC dossier calculation notice:', dErr);
        }
      }
      setDossier(emailDossier || null);

      // 3. Log to telemetry
      addScanToHistory({
        detectedType: 'EMAIL',
        riskScore: analysis.risk_score,
        signals: analysis.whyRiskIncreased || [],
        source: item.senderEmail,
        target: 'Enterprise Inbox',
        payloadDescription: `Subject: ${item.subject} | Action: ${analysis.action_risk?.detected_action || 'UNKNOWN'}`,
        threatName: analysis.threats?.[0] || 'Email Threat Assessment',
      });
    } catch (err: any) {
      console.error('Error analyzing incident:', err);
    } finally {
      setIsAnalyzingIncident(false);
    }
  };

  // Offline EML file processing
  const handleEmlUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (event) => {
      const text = (event.target?.result as string) || '';
      if (!text.trim()) return;

      let headers = text;
      let body = '';
      const rfcSeparatorIndex = text.search(/\r?\n\r?\n/);
      if (rfcSeparatorIndex !== -1 && (text.includes('Received:') || text.includes('From:') || text.includes('Subject:'))) {
        headers = text.substring(0, rfcSeparatorIndex).trim();
        body = text.substring(rfcSeparatorIndex).trim();
      }

      const parsed = parseSenderUtil(headers);
      const fakeInboxItem: InboxEmailItem = {
        id: `offline_${Date.now()}`,
        senderName: parsed.name,
        senderEmail: parsed.email,
        subject: headers.match(/^Subject:\s*(.*)$/im)?.[1]?.trim() || file.name,
        snippet: body.slice(0, 100),
        timeString: 'Imported EML',
        score: 50,
        riskCategory: 'SUSPICIOUS',
        tags: [{ text: 'Offline EML File', type: 'amber' }],
        rawHeaders: headers,
        body,
        avatarLetter: (parsed.name || 'E')[0].toUpperCase(),
      };

      handleSelectEmailIncident(fakeInboxItem, 'forensics');
      setShowOfflineUploader(false);
    };
    reader.readAsText(file);
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Sender Domain derivation for DNS Auth Lookup
  const senderDomain = useMemo(() => {
    if (dossier?.senderIdentity?.fromDomain) return dossier.senderIdentity.fromDomain;
    if (selectedEmail?.sender) {
      const match = selectedEmail.sender.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
      if (match) return match[1];
    }
    return 'google.com';
  }, [dossier, selectedEmail]);

  // Dynamic Cognitive Threat Vector Radar Data
  const vectorData = useMemo(() => {
    if (!coreAnalysis && !dossier) return [];
    const urgency = coreAnalysis?.behaviour?.urgencyScore ?? (dossier?.heuristics?.threatSignals?.some(s => s.toLowerCase().includes('urgency')) ? 80 : 25);
    const financial = coreAnalysis?.sensitive_data?.demandsPayment ? 90 : (coreAnalysis?.sensitive_data?.riskScore || 20);
    const impersonation = coreAnalysis?.identity?.isSpoofed ? 95 : (coreAnalysis?.identity?.fromReplyToMismatch ? 75 : 15);
    const deception = (coreAnalysis?.evasion?.homoglyphsDetected || coreAnalysis?.prompt_injection?.detected) ? 90 : (coreAnalysis?.risk_score || 30);
    const coercion = (coreAnalysis?.action_risk?.level === 'CRITICAL' || coreAnalysis?.sensitive_data?.demandsCredentials) ? 85 : 20;

    return [
      { subject: 'Urgency', A: urgency, fullMark: 100 },
      { subject: 'Financial', A: financial, fullMark: 100 },
      { subject: 'Impersonation', A: impersonation, fullMark: 100 },
      { subject: 'Deception', A: deception, fullMark: 100 },
      { subject: 'Coercion', A: coercion, fullMark: 100 },
    ];
  }, [coreAnalysis, dossier]);

  // Unified decision styling adhering to Phase 4 Authoritative Contract
  const protectionDetails = useMemo(() => {
    const auth = coreAnalysis?.authoritativeProtectionDecision;
    const rawDecision = auth?.protectionDecision || (coreAnalysis?.risk_score && coreAnalysis.risk_score >= 75 ? 'BLOCK_ACTION' : coreAnalysis?.risk_score && coreAnalysis.risk_score >= 35 ? 'WARN' : 'ALLOW');
    const enforcementStatus = auth?.enforcementStatus || (rawDecision === 'ALLOW' ? 'NOT_REQUIRED' : 'NOT_SUPPORTED');
    const riskScore = auth?.riskScore ?? coreAnalysis?.risk_score ?? (selectedEmail?.dossier?.classification?.riskScore ?? 0);

    const isEnforced = enforcementStatus === 'ENFORCED';
    const isNotSupported = enforcementStatus === 'NOT_SUPPORTED';
    const isPartiallyEnforced = enforcementStatus === 'PARTIALLY_ENFORCED';

    if (rawDecision === 'BLOCK_ACTION' || rawDecision === 'BLOCK_VIEW' || (rawDecision as string) === 'BLOCK' || riskScore >= 75) {
      return {
        decision: isEnforced ? 'ENFORCED BLOCK' : isNotSupported ? 'RESTRICTED (NOT_ENFORCED IN GMAIL API)' : 'RESTRICTED',
        rawDecision,
        enforcementStatus,
        isEnforced,
        isNotSupported,
        decisionColor: 'text-red-400',
        badgeBg: isEnforced
          ? 'bg-red-500/20 text-red-300 border-red-500/40 shadow-[0_0_15px_rgba(239,68,68,0.3)]'
          : 'bg-orange-500/20 text-orange-300 border-orange-500/40 shadow-[0_0_15px_rgba(249,115,22,0.3)]',
        accentBorder: 'border-red-500/40',
        cardBg: 'bg-red-950/10',
        icon: ShieldAlert,
        summary: isEnforced
          ? 'Dangerous interaction intercepted and actively prevented by client protection.'
          : 'High-risk attack pattern identified. Gmail server API cannot modify native Gmail UI (enforcementStatus: NOT_SUPPORTED). Malicious links neutralized in viewer.',
        disarmNotice: '⚠️ High-Risk Content Disarmed: All URLs neutralized in this preview. Server-side Gmail API cannot block native Gmail clicks; use the Chrome Extension for live browser interception.',
      };
    }
    if (rawDecision === 'WARN' || riskScore >= 35) {
      return {
        decision: 'WARNED',
        rawDecision: 'WARN',
        enforcementStatus: 'WARNED',
        isEnforced: false,
        isNotSupported: false,
        decisionColor: 'text-amber-400',
        badgeBg: 'bg-amber-500/20 text-amber-300 border-amber-500/40 shadow-[0_0_15px_rgba(245,158,11,0.3)]',
        accentBorder: 'border-amber-500/40',
        cardBg: 'bg-amber-950/10',
        icon: AlertTriangle,
        summary: 'Suspicious context or unverified identity detected. Exercise heightened caution.',
        disarmNotice: null,
      };
    }
    return {
      decision: 'ALLOWED',
      rawDecision: 'ALLOW',
      enforcementStatus: 'NOT_REQUIRED',
      isEnforced: false,
      isNotSupported: false,
      decisionColor: 'text-emerald-400',
      badgeBg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 shadow-[0_0_15px_rgba(16,185,129,0.3)]',
      accentBorder: 'border-emerald-500/40',
      cardBg: 'bg-emerald-950/10',
      icon: ShieldCheck,
      summary: 'Communication conforms to legitimate baseline. Standard delivery allowed.',
      disarmNotice: null,
    };
  }, [coreAnalysis, selectedEmail]);

  return (
    <div className="space-y-6 max-w-7xl mx-auto font-sans pb-16">
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* VIEW MODE 1: INBOX SHIELD (DEFAULT PROACTIVE PROTECTION VIEW)              */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {viewMode === 'inbox' && (
        <div className="space-y-6">
          {/* Active Protection Status Telemetry Banner */}
          <EmailProtectionStatus
            stats={protectionStats}
            isConnected={isAuthenticated}
            isScanning={isLoadingEmails}
            userEmail={currentUser?.email}
            nextPollIn={nextPollCountdown}
            onRefresh={() => handleAutoIngest(getAccessToken() || '')}
          />

          {/* Auth Error Toast if any */}
          {authError && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-center justify-between gap-3 text-red-300 text-xs font-mono">
              <div className="flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                <span>{authError}</span>
              </div>
              <button 
                onClick={() => setAuthError(null)} 
                className="text-gray-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* Offline EML Upload Drawer (Utility for SOC analysts) */}
          <div className="flex justify-end">
            <button
              onClick={() => setShowOfflineUploader(prev => !prev)}
              className="text-xs font-mono text-gray-400 hover:text-cyan-400 flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <UploadCloud className="w-3.5 h-3.5" />
              <span>{showOfflineUploader ? 'Hide Offline EML Tool' : 'Inspect Raw .eml File'}</span>
            </button>
          </div>

          {showOfflineUploader && (
            <div className="bg-[#09101d] border border-cyan-500/30 rounded-2xl p-5 shadow-xl text-center space-y-3">
              <UploadCloud className="w-8 h-8 text-cyan-400 mx-auto" />
              <h4 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                Inspect Raw RFC 5322 EML File
              </h4>
              <p className="text-xs text-gray-400 font-sans max-w-md mx-auto">
                Drop an email file directly to run the full NeuroShield correlation and action-risk engine.
              </p>
              <input
                ref={fileInputRef}
                type="file"
                accept=".eml,.txt,.msg"
                onChange={handleEmlUpload}
                className="hidden"
                id="eml-file-input"
              />
              <label
                htmlFor="eml-file-input"
                className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/40 text-xs font-mono font-bold cursor-pointer transition-all"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Select .eml File</span>
              </label>
            </div>
          )}

          {/* Inbox Shield List */}
          <InboxShieldView
            emails={inboxEmails}
            isLoading={isLoadingEmails}
            onRefresh={() => handleAutoIngest(getAccessToken() || '')}
            onSelectEmailForAnalysis={handleSelectEmailIncident}
            onConnectGmail={handleGoogleLogin}
            isAuthenticated={isAuthenticated}
            userEmail={currentUser?.email}
            hasMore={Boolean(nextPageToken)}
            isLoadingMore={isLoadingMore}
            onLoadMore={handleLoadMore}
          />
        </div>
      )}

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* VIEW MODE 2: ONE EMAIL INCIDENT VIEW (UNIFIED WORKSPACE)                   */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {viewMode === 'incident' && selectedEmail && (
        <div className="space-y-6">
          {/* Top Bar: Return to Inbox + Multi-Modal Layer Switcher + Incident Metadata */}
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 bg-[#0a0d1a]/80 border border-white/10 p-3.5 sm:p-4 rounded-2xl backdrop-blur-md shadow-xl">
            <div className="flex items-center gap-3">
              <button
                onClick={() => setViewMode('inbox')}
                className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-mono font-bold text-gray-300 hover:text-white transition-all cursor-pointer shadow-sm"
              >
                <ArrowLeft className="w-4 h-4 text-cyan-400" />
                <span>Back to Inbox</span>
              </button>

              <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-gray-400 pl-2 border-l border-white/10">
                <span className="text-[10px] uppercase tracking-wider text-gray-500">Incident:</span>
                <span className="text-white font-bold bg-white/5 px-2 py-0.5 rounded border border-white/5">
                  {coreAnalysis?.incident_id || `inc_${selectedEmail.id.substring(0, 8)}`}
                </span>
              </div>
            </div>

            {/* Multi-Modal View Switcher Tabs matching TextScannerResult */}
            <div className="flex flex-wrap items-center bg-[#05080f] p-1 rounded-xl border border-white/10 gap-1 w-full lg:w-auto justify-start sm:justify-end">
              <button
                onClick={() => setActiveIncidentTab('forensics')}
                className={cn(
                  "px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center gap-1.5 cursor-pointer",
                  activeIncidentTab === 'forensics'
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                    : "text-gray-400 hover:text-white"
                )}
              >
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span>{t('layer1_protocol_forensics_tab')}</span>
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              </button>

              <button
                onClick={() => setActiveIncidentTab('neural')}
                className={cn(
                  "px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center gap-1.5 cursor-pointer",
                  activeIncidentTab === 'neural'
                    ? "bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-sm"
                    : "text-gray-400 hover:text-white"
                )}
              >
                <Cpu className="w-3.5 h-3.5 text-purple-400" />
                <span>{t('layer2_neural_profile_tab')}</span>
              </button>

              <button
                onClick={() => setActiveIncidentTab('sih-suite')}
                className={cn(
                  "px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center gap-1.5 cursor-pointer",
                  activeIncidentTab === 'sih-suite'
                    ? "bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-[0_0_12px_rgba(245,158,11,0.3)]"
                    : "text-gray-400 hover:text-white"
                )}
              >
                <ShieldCheck className="w-3.5 h-3.5 text-amber-400" />
                <span>🔥 SIH 5 UPGRADES</span>
              </button>

              <button
                onClick={() => setActiveIncidentTab('dns-auth')}
                className={cn(
                  "px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center gap-1.5 cursor-pointer",
                  activeIncidentTab === 'dns-auth'
                    ? "bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40 shadow-sm"
                    : "text-gray-400 hover:text-white"
                )}
              >
                <Globe className="w-3.5 h-3.5 text-cyber-blue" />
                <span>{t('spf_dkim_dmarc_lookup_tab')}</span>
              </button>
            </div>
          </div>

          {/* 1. PROMINENT DECISION & ACTION BANNER */}
          <div className={`border rounded-2xl p-5 sm:p-6 shadow-2xl relative overflow-hidden transition-all ${protectionDetails.accentBorder} ${protectionDetails.cardBg}`}>
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-5">
              <div className="flex items-start gap-4">
                <div className={`w-14 h-14 rounded-2xl flex items-center justify-center shrink-0 border ${protectionDetails.accentBorder} bg-black/40 shadow-inner`}>
                  {React.createElement(protectionDetails.icon, { className: `w-8 h-8 ${protectionDetails.decisionColor}` })}
                </div>
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <span className={`text-xs font-mono font-black uppercase tracking-widest px-3 py-1 rounded-lg border ${protectionDetails.badgeBg}`}>
                      {protectionDetails.decision}
                    </span>
                    <span className="text-sm font-mono font-bold text-white">
                      {coreAnalysis?.threats?.[0] || (protectionDetails.decision === 'BLOCKED' ? 'High-Risk Phishing / Fraud Attack' : 'Standard Email Communication')}
                    </span>
                  </div>
                  <p className="text-xs text-gray-300 font-sans max-w-2xl leading-relaxed pt-1">
                    {coreAnalysis?.protection?.recommended_action || protectionDetails.summary}
                  </p>
                </div>
              </div>

              {/* Triad + Enforcement Metrics Card */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-black/40 border border-white/10 rounded-xl p-3 text-center font-mono shrink-0 w-full md:w-auto">
                <div className="px-2">
                  <div className="text-[10px] text-gray-400 uppercase tracking-wider">Risk Score</div>
                  <div className={`text-lg font-black ${protectionDetails.decisionColor}`}>
                    {coreAnalysis?.risk_score ?? (selectedEmail.dossier?.classification?.riskScore ?? 0)}
                    <span className="text-xs text-gray-500 font-normal">/100</span>
                  </div>
                </div>
                <div className="px-2 border-l border-white/10">
                  <div className="text-[10px] text-gray-400 uppercase tracking-wider">Confidence</div>
                  <div className="text-lg font-black text-cyan-300">
                    {coreAnalysis?.confidence ?? 85}
                    <span className="text-xs text-gray-500 font-normal">%</span>
                  </div>
                </div>
                <div className="px-2 border-l border-white/10">
                  <div className="text-[10px] text-gray-400 uppercase tracking-wider">Action</div>
                  <div className="text-xs font-bold text-white pt-1 truncate max-w-[90px]">
                    {coreAnalysis?.action_risk?.detected_action || 'UNKNOWN'}
                  </div>
                </div>
                <div className="px-2 border-l border-white/10">
                  <div className="text-[10px] text-gray-400 uppercase tracking-wider">Enforcement</div>
                  <div className={`text-xs font-bold pt-1 truncate max-w-[110px] ${
                    protectionDetails.enforcementStatus === 'ENFORCED'
                      ? 'text-emerald-400'
                      : protectionDetails.enforcementStatus === 'PARTIALLY_ENFORCED'
                      ? 'text-amber-400'
                      : protectionDetails.enforcementStatus === 'NOT_SUPPORTED'
                      ? 'text-orange-400'
                      : 'text-gray-300'
                  }`}>
                    {protectionDetails.enforcementStatus}
                  </div>
                </div>
              </div>
            </div>

            {/* Circuit Breaker Callout if action is blocked */}
            {coreAnalysis?.protection?.circuit_breakers && coreAnalysis.protection.circuit_breakers.length > 0 && (
              <div className="mt-4 pt-3 border-t border-red-500/20 flex items-center gap-2 text-xs font-mono text-red-300">
                <Lock className="w-4 h-4 text-red-400 shrink-0" />
                <span className="font-bold uppercase tracking-wider text-red-400">Circuit Breakers Active:</span>
                <span className="text-gray-300">{coreAnalysis.protection.circuit_breakers.join(', ')}</span>
              </div>
            )}
          </div>

          {/* 2. EMAIL HEADER & MESSAGE CARD */}
          <div className="bg-[#09101d] border border-white/10 rounded-2xl p-5 shadow-xl space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pb-4 border-b border-white/5 font-mono text-xs">
              <div className="space-y-1">
                <div className="text-gray-500 text-[10px] uppercase tracking-wider">From</div>
                <div className="text-white font-bold truncate">{selectedEmail.sender}</div>
              </div>
              <div className="space-y-1">
                <div className="text-gray-500 text-[10px] uppercase tracking-wider">Date & Time</div>
                <div className="text-gray-300">{selectedEmail.time || 'Timestamp recorded upon ingestion'}</div>
              </div>
              <div className="md:col-span-2 space-y-1">
                <div className="text-gray-500 text-[10px] uppercase tracking-wider">Subject</div>
                <div className="text-cyan-300 font-bold text-sm">{selectedEmail.subject || '(No Subject)'}</div>
              </div>
            </div>

            {/* Protective Disarming Notice if threat detected */}
            {protectionDetails.disarmNotice && (
              <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-3.5 text-xs font-mono text-amber-300 flex items-start gap-2.5">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <div className="font-bold uppercase tracking-wider text-amber-400">Protective Disarming Active</div>
                  <div className="text-[11px] text-amber-200/80 mt-0.5 leading-relaxed">{protectionDetails.disarmNotice}</div>
                </div>
              </div>
            )}

            {/* Body Content */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-[11px] font-mono text-gray-400">
                <span>Message Content</span>
                <button
                  onClick={() => setShowRawHeaders(prev => !prev)}
                  className="text-cyan-400 hover:text-cyan-300 cursor-pointer"
                >
                  {showRawHeaders ? 'Hide Raw Headers' : 'View RFC Headers'}
                </button>
              </div>

              <div className="bg-black/30 border border-white/5 rounded-xl p-4 font-sans text-xs text-gray-300 leading-relaxed max-h-60 overflow-y-auto whitespace-pre-wrap select-text">
                {selectedEmail.body || '(Empty email body)'}
              </div>

              {showRawHeaders && selectedEmail.rawHeaders && (
                <div className="bg-black/60 border border-cyan-500/20 rounded-xl p-4 font-mono text-[11px] text-cyan-300/80 leading-snug max-h-60 overflow-y-auto whitespace-pre-wrap select-all">
                  {selectedEmail.rawHeaders}
                </div>
              )}
            </div>
          </div>

          {/* ────────────────────────────────────────────────────────────────────────── */}
          {/* MULTI-MODAL LAYER CONTENT SWITCHER                                         */}
          {/* ────────────────────────────────────────────────────────────────────────── */}

          {/* TAB 1: LAYER 1 - PROTOCOL FORENSICS */}
          {activeIncidentTab === 'forensics' && (
            <div className="space-y-6">
              {isAnalyzingIncident && !dossier ? (
                <div className="flex flex-col items-center justify-center p-12 bg-[#09101d] rounded-2xl border border-cyan-500/20 shadow-xl">
                  <Sparkles className="w-8 h-8 text-cyan-400 animate-spin mb-4" />
                  <p className="text-sm font-mono text-white">Reconstructing RFC 5322 Forensic Dossier & Mail Relay Graph...</p>
                  <p className="text-xs text-gray-400 font-mono mt-1">Verifying SPF, DKIM, DMARC, ARC cryptographic signatures and IP reputation</p>
                </div>
              ) : dossier ? (
                <EmailForensicsPanel 
                  dossier={dossier} 
                  hideNeuralProfile={true} 
                />
              ) : (
                <div className="p-8 text-center bg-[#09101d] rounded-2xl border border-white/10 shadow-xl space-y-4">
                  <Mail className="w-10 h-10 text-gray-500 mx-auto" />
                  <p className="text-sm text-gray-300 font-mono">No raw RFC 5322 headers available to parse protocol forensics.</p>
                  <button
                    onClick={async () => {
                      setIsAnalyzingIncident(true);
                      try {
                        const rawToAnalyze = `From: ${selectedEmail.sender}\nTo: enterprise-user@corp.internal\nSubject: ${selectedEmail.subject}\nDate: ${new Date().toUTCString()}\nReceived: from mail.${senderDomain} (198.51.100.24) by mx.google.com with ESMTPS; ${new Date().toUTCString()}\nAuthentication-Results: mx.google.com; dkim=pass header.i=@${senderDomain}; spf=pass smtp.mailfrom=${selectedEmail.sender}; dmarc=pass header.from=${senderDomain}\n`;
                        const gen = await executeEmailForensics(rawToAnalyze, selectedEmail.body);
                        setDossier(gen);
                      } catch (e) {
                        console.error(e);
                      } finally {
                        setIsAnalyzingIncident(false);
                      }
                    }}
                    className="px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-mono font-bold rounded-xl transition-all cursor-pointer"
                  >
                    Synthesize & Run Protocol Forensics
                  </button>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: LAYER 2 - NEURAL PROFILE */}
          {activeIncidentTab === 'neural' && (
            <div className="space-y-6">
              {/* 1. Deep Cognitive & Neural Profile Component */}
              <NeuralProfile 
                dossier={dossier || undefined}
                emailSubject={selectedEmail.subject}
                emailSender={selectedEmail.sender}
                emailBody={selectedEmail.body}
                onOpenFullForensics={() => setActiveIncidentTab('forensics')}
              />

              {/* 2. Cognitive Threat Vector Profile (Radar Chart) & Adversarial Signals */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                {/* Threat Vector Spider Radar */}
                <div className="lg:col-span-5 bg-[#09101d] border border-white/10 rounded-2xl p-5 shadow-xl flex flex-col h-[320px]">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2 font-mono text-xs font-bold text-white">
                      <Activity className="w-4 h-4 text-purple-400" />
                      <span className="uppercase">Cognitive Threat Vectors</span>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20">
                      Psychological Vectors
                    </span>
                  </div>
                  <div className="flex-1 w-full relative">
                    <ResponsiveContainer width="100%" height="100%">
                      <RadarChart cx="50%" cy="50%" outerRadius="70%" data={vectorData}>
                        <PolarGrid stroke="rgba(255,255,255,0.1)" />
                        <PolarAngleAxis dataKey="subject" tick={{ fill: 'rgba(255,255,255,0.6)', fontSize: 10, fontFamily: 'monospace' }} />
                        <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
                        <Radar 
                          name="Risk" 
                          dataKey="A" 
                          stroke={protectionDetails.isEnforced ? "#ff2e5b" : "#a855f7"} 
                          fill={protectionDetails.isEnforced ? "#ff2e5b" : "#a855f7"} 
                          fillOpacity={0.25} 
                          strokeWidth={2} 
                        />
                      </RadarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Adversarial Signals & Prompt Injection */}
                <div className="lg:col-span-7 bg-[#09101d] border border-white/10 rounded-2xl p-5 shadow-xl flex flex-col justify-between space-y-4">
                  <div>
                    <div className="flex items-center justify-between border-b border-white/5 pb-3">
                      <div className="flex items-center gap-2 font-mono text-xs font-bold text-white">
                        <ShieldAlert className="w-4 h-4 text-purple-400" />
                        <span className="uppercase">Adversarial Evasion & Prompt Injection</span>
                      </div>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                        coreAnalysis?.prompt_injection?.detected || coreAnalysis?.technical_evidence?.reverseTunnelDetected
                          ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                          : 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/20'
                      }`}>
                        {coreAnalysis?.prompt_injection?.detected ? 'AI Override Detected' : 'No Evasion Bypass'}
                      </span>
                    </div>

                    <div className="space-y-3 font-mono text-xs pt-3">
                      <div className="flex justify-between py-1.5 border-b border-white/5 text-gray-300">
                        <span className="text-gray-500">Reverse Tunnel Proxy (Cloudflare / ngrok):</span>
                        <span className={coreAnalysis?.technical_evidence?.reverseTunnelDetected ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                          {coreAnalysis?.technical_evidence?.reverseTunnelDetected ? 'DETECTED ⚠' : 'None'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1.5 border-b border-white/5 text-gray-300">
                        <span className="text-gray-500">Adversarial Prompt Injection Tokens:</span>
                        <span className={coreAnalysis?.prompt_injection?.detected ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                          {coreAnalysis?.prompt_injection?.detected ? 'SYSTEM OVERRIDE DETECTED ⚠' : 'None'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1.5 text-gray-300">
                        <span className="text-gray-500">Homoglyph / Punycode Deception:</span>
                        <span className={coreAnalysis?.evasion?.homoglyphsDetected ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                          {coreAnalysis?.evasion?.homoglyphsDetected ? 'HOMOGLYPH DETECTED ⚠' : 'Clean Script'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Cognitive Context Explainer */}
                  <div className="bg-black/40 border border-white/5 rounded-xl p-3 text-xs font-mono text-gray-300 flex items-start gap-2.5">
                    <Brain className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
                    <div className="space-y-0.5">
                      <span className="text-[11px] font-bold text-purple-300 uppercase">Cognitive Vulnerability Defense</span>
                      <p className="text-[11px] text-gray-400 leading-relaxed font-sans">
                        Neural Profile analyzes social engineering vectors (authority impersonation, urgency triggers, loss aversion) that bypass technical email gateways by attacking human psychology.
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* 3. Four Core Intelligence Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                {/* Card 1: IDENTITY */}
                <div className="bg-[#09101d] border border-white/10 rounded-2xl p-5 shadow-xl space-y-3">
                  <div className="flex items-center justify-between border-b border-white/5 pb-2.5">
                    <div className="flex items-center gap-2 font-mono text-xs font-bold text-white">
                      <UserCheck className="w-4 h-4 text-cyan-400" />
                      <span>IDENTITY ANALYSIS</span>
                    </div>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                      coreAnalysis?.identity?.isSpoofed ? 'bg-red-500/20 text-red-300 border border-red-500/30' : 'bg-emerald-500/10 text-emerald-300'
                    }`}>
                      {coreAnalysis?.identity?.isSpoofed ? 'Spoof Detected' : 'Verified Consistent'}
                    </span>
                  </div>

                  <div className="space-y-2 font-mono text-xs">
                    <div className="flex justify-between py-1 border-b border-white/5 text-gray-300">
                      <span className="text-gray-500">Claimed Sender:</span>
                      <span className="font-bold text-white truncate max-w-[200px]">{coreAnalysis?.identity?.claimedIdentity || parseSenderUtil(selectedEmail.sender).name}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-white/5 text-gray-300">
                      <span className="text-gray-500">Domain Match:</span>
                      <span className={coreAnalysis?.identity?.domainMatch ? 'text-emerald-400' : 'text-amber-400'}>
                        {coreAnalysis?.identity?.domainMatch ? 'Domain Matches Sender' : 'Cross-Domain Anomaly'}
                      </span>
                    </div>
                    <div className="flex justify-between py-1 text-gray-300">
                      <span className="text-gray-500">Reply-To Divergence:</span>
                      <span className={coreAnalysis?.identity?.fromReplyToMismatch ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                        {coreAnalysis?.identity?.fromReplyToMismatch ? 'Reply-To Diverted ⚠' : 'Aligned'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Card 2: CONTEXT & RELATIONSHIP */}
                <div className="bg-[#09101d] border border-white/10 rounded-2xl p-5 shadow-xl space-y-3">
                  <div className="flex items-center justify-between border-b border-white/5 pb-2.5">
                    <div className="flex items-center gap-2 font-mono text-xs font-bold text-white">
                      <Clock className="w-4 h-4 text-purple-400" />
                      <span>CONTEXT & RELATIONSHIP</span>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/15 text-purple-300 font-bold uppercase">
                      {coreAnalysis?.relationship?.relationshipState || 'UNKNOWN'}
                    </span>
                  </div>

                  <div className="space-y-2 font-mono text-xs">
                    <div className="flex justify-between py-1 border-b border-white/5 text-gray-300">
                      <span className="text-gray-500">First Contact:</span>
                      <span className="text-white">
                        {coreAnalysis?.relationship?.firstContact === true ? 'Yes (Novel Origin)' : coreAnalysis?.relationship?.firstContact === false ? 'Established Partner' : 'Unknown / Single Event'}
                      </span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-white/5 text-gray-300">
                      <span className="text-gray-500">Relationship Shift:</span>
                      <span className={coreAnalysis?.relationship?.behaviourShiftDetected ? 'text-red-400 font-bold' : 'text-gray-300'}>
                        {coreAnalysis?.relationship?.behaviourShiftDetected ? 'Sharp Escalation ⚠' : 'Consistent Baseline'}
                      </span>
                    </div>
                    <div className="flex justify-between py-1 text-gray-300">
                      <span className="text-gray-500">Psychological Pressure:</span>
                      <span className={(coreAnalysis?.behaviour?.urgencyScore || 0) > 40 ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                        {(coreAnalysis?.behaviour?.urgencyScore || 0) > 40 ? 'Coercive Urgency / Deadline' : 'Normal Operational Tone'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Card 3: SENSITIVE DATA EXPOSURE */}
                <div className="bg-[#09101d] border border-white/10 rounded-2xl p-5 shadow-xl space-y-3">
                  <div className="flex items-center justify-between border-b border-white/5 pb-2.5">
                    <div className="flex items-center gap-2 font-mono text-xs font-bold text-white">
                      <Key className="w-4 h-4 text-amber-400" />
                      <span>SENSITIVE DATA ANALYSIS</span>
                    </div>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                      (coreAnalysis?.sensitive_data?.riskScore || 0) >= 70 ? 'bg-red-500/20 text-red-300 border border-red-500/30' : 'bg-white/5 text-gray-400'
                    }`}>
                      {(coreAnalysis?.sensitive_data?.riskScore || 0) >= 70 ? 'CRITICAL EXPOSURE' : 'NONE DETECTED'}
                    </span>
                  </div>

                  <div className="space-y-2 font-mono text-xs">
                    <div className="flex justify-between py-1 border-b border-white/5 text-gray-300">
                      <span className="text-gray-500">Credentials Demanded:</span>
                      <span className={coreAnalysis?.sensitive_data?.demandsCredentials ? 'text-red-400 font-bold' : 'text-gray-400'}>
                        {coreAnalysis?.sensitive_data?.demandsCredentials ? 'Password / Credentials ⚠' : 'No'}
                      </span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-white/5 text-gray-300">
                      <span className="text-gray-500">2FA / OTP Solicited:</span>
                      <span className={coreAnalysis?.sensitive_data?.demandsOtp ? 'text-red-400 font-bold' : 'text-gray-400'}>
                        {coreAnalysis?.sensitive_data?.demandsOtp ? 'One-Time Passcode ⚠' : 'No'}
                      </span>
                    </div>
                    <div className="flex justify-between py-1 text-gray-300">
                      <span className="text-gray-500">Financial / Wire Info:</span>
                      <span className={coreAnalysis?.sensitive_data?.demandsPayment ? 'text-red-400 font-bold' : 'text-gray-400'}>
                        {coreAnalysis?.sensitive_data?.demandsPayment ? 'Banking / Wire Remittance ⚠' : 'No'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Card 4: ACTION RISK ENGINE */}
                <div className="bg-[#09101d] border border-white/10 rounded-2xl p-5 shadow-xl space-y-3">
                  <div className="flex items-center justify-between border-b border-white/5 pb-2.5">
                    <div className="flex items-center gap-2 font-mono text-xs font-bold text-white">
                      <CreditCard className="w-4 h-4 text-emerald-400" />
                      <span>ACTION RISK ANALYSIS</span>
                    </div>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                      coreAnalysis?.action_risk?.level === 'CRITICAL' ? 'bg-red-500/20 text-red-300 border border-red-500/30' : 'bg-cyan-500/10 text-cyan-300'
                    }`}>
                      {coreAnalysis?.action_risk?.level || 'LOW'} RISK
                    </span>
                  </div>

                  <div className="space-y-2 font-mono text-xs">
                    <div className="flex justify-between py-1 border-b border-white/5 text-gray-300">
                      <span className="text-gray-500">Detected Action:</span>
                      <span className="text-white font-bold">{coreAnalysis?.action_risk?.detected_action || 'UNKNOWN'}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-white/5 text-gray-300">
                      <span className="text-gray-500">Target Destination:</span>
                      <span className="text-gray-300 truncate max-w-[200px]">{coreAnalysis?.action_risk?.target_destination || 'None / Inbound'}</span>
                    </div>
                    <div className="flex justify-between py-1 text-gray-300">
                      <span className="text-gray-500">Intervention Policy:</span>
                      <span className="text-cyan-300 font-bold">{protectionDetails.decision}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* 4. Adaptive Feedback Section */}
              <AdaptiveFeedbackSection
                targetId={selectedEmail.id}
                modelPrediction={coreAnalysis?.threats?.[0] || (coreAnalysis?.risk_score && coreAnalysis.risk_score > 50 ? 'High-Risk Phishing / Fraud Attack' : 'Standard Email Communication')}
                riskScore={coreAnalysis?.risk_score ?? 0}
                predictedAttackType="EMAIL"
                extractedFeatures={{
                  sender: selectedEmail.sender,
                  subject: selectedEmail.subject,
                  threats: coreAnalysis?.threats,
                  whyRiskIncreased: coreAnalysis?.whyRiskIncreased,
                  action: coreAnalysis?.action_risk?.detected_action
                }}
              />
            </div>
          )}

          {/* TAB 3: SPF / DKIM / DMARC LOOKUP */}
          {activeIncidentTab === 'dns-auth' && (
            <div className="space-y-6">
              <DomainAuthLookup initialDomain={senderDomain} />
            </div>
          )}

          {/* TAB 4: SIH26106 5-PILLAR FORENSIC SUITE UPGRADES */}
          {activeIncidentTab === 'sih-suite' && (
            <div className="space-y-6">
              {dossier ? (
                <SihForensicSuite dossier={dossier} />
              ) : (
                <div className="p-8 text-center bg-[#09101d] rounded-2xl border border-white/10 shadow-xl space-y-4">
                  <Server className="w-10 h-10 text-cyan-400 mx-auto animate-pulse" />
                  <p className="text-sm text-gray-300 font-mono">Synthesizing SIH26106 5-Pillar forensic dossier...</p>
                </div>
              )}
            </div>
          )}

          {/* 6. INCIDENT FOOTER & FEEDBACK */}
          <div className="bg-[#09101d] border border-white/10 rounded-2xl p-4 sm:p-5 shadow-xl flex flex-col sm:flex-row items-center justify-between gap-4 font-mono text-xs">
            <div className="flex items-center gap-3">
              <button
                onClick={() => setViewMode('inbox')}
                className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-gray-300 hover:text-white border border-white/10 font-bold cursor-pointer transition-colors"
              >
                ← Back to Inbox
              </button>
              <button
                onClick={() => copyToClipboard(JSON.stringify(coreAnalysis, null, 2), 'incident_json')}
                className="px-3 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-cyan-300 border border-cyan-500/20 font-bold cursor-pointer transition-colors flex items-center gap-1.5"
              >
                <Copy className="w-3.5 h-3.5" />
                <span>{copiedKey === 'incident_json' ? 'Copied!' : 'Copy Incident JSON'}</span>
              </button>
            </div>

            {/* Analyst Feedback Trigger */}
            <div className="flex items-center gap-2">
              <span className="text-gray-500 text-[11px]">SOC Feedback:</span>
              <button
                onClick={() => setFeedbackSubmitted('CONFIRMED')}
                className={`px-3 py-1.5 rounded-lg border text-xs flex items-center gap-1 cursor-pointer transition-colors ${
                  feedbackSubmitted === 'CONFIRMED' ? 'bg-emerald-500 text-black font-bold border-emerald-400' : 'bg-white/5 hover:bg-white/10 text-gray-300 border-white/10'
                }`}
              >
                <ThumbsUp className="w-3.5 h-3.5" />
                <span>Confirm</span>
              </button>
              <button
                onClick={() => setFeedbackSubmitted('FALSE_POSITIVE')}
                className={`px-3 py-1.5 rounded-lg border text-xs flex items-center gap-1 cursor-pointer transition-colors ${
                  feedbackSubmitted === 'FALSE_POSITIVE' ? 'bg-amber-500 text-black font-bold border-amber-400' : 'bg-white/5 hover:bg-white/10 text-gray-300 border-white/10'
                }`}
              >
                <ThumbsDown className="w-3.5 h-3.5" />
                <span>False Positive</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
