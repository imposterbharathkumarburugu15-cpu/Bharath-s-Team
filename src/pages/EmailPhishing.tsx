import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Mail, Search, RefreshCw, LogIn, Bell, Shield, ShieldCheck, ShieldAlert, 
  AlertTriangle, FileText, Terminal, ArrowRight, ArrowLeft, Copy, Check, CheckCircle2, Download, 
  ExternalLink, Network, Globe, Server, Clock, Lock, AlertCircle, Sparkles, UploadCloud, Layers, X,
  ChevronDown, ChevronUp, UserCheck, Key, CreditCard, FileSearch, Flag, ThumbsUp, ThumbsDown
} from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';
import { addScanToHistory } from '@/lib/history';
import { executeEmailForensics, ForensicDossier } from '@/services/forensicsEngine';
import { NeuroShieldCore } from '@/services/core/neuroshieldCore';
import { UnifiedThreatAnalysis, UnifiedInteractionEvent } from '@/services/core/types';
import { googleSignIn, googleLogout, initAuth, getAccessToken } from '@/services/googleAuth';
import { InboxShieldView } from '@/components/InboxShieldView';
import { EmailProtectionStatus } from '@/components/EmailProtectionStatus';
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
  const handleSelectEmailIncident = async (item: InboxEmailItem) => {
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
      if (!emailDossier && item.rawHeaders) {
        try {
          emailDossier = await executeEmailForensics(item.rawHeaders, item.body);
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

      handleSelectEmailIncident(fakeInboxItem);
      setShowOfflineUploader(false);
    };
    reader.readAsText(file);
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

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
          {/* Top Bar: Return to Inbox + Incident Metadata */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-2 border-b border-white/10">
            <button
              onClick={() => setViewMode('inbox')}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-mono font-bold text-gray-300 hover:text-white transition-all cursor-pointer shadow-sm"
            >
              <ArrowLeft className="w-4 h-4 text-cyan-400" />
              <span>Back to Inbox</span>
            </button>

            <div className="flex items-center gap-2 text-xs font-mono text-gray-400">
              <span className="text-[10px] uppercase tracking-wider text-gray-500">Incident ID:</span>
              <span className="text-white font-bold bg-white/5 px-2 py-0.5 rounded border border-white/5">
                {coreAnalysis?.incident_id || `inc_${selectedEmail.id.substring(0, 8)}`}
              </span>
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

          {/* 3. FOUR CORE INTELLIGENCE CARDS */}
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

          {/* 4. EXPANDABLE SECTION: TECHNICAL FORENSIC EVIDENCE */}
          <div className="bg-[#09101d] border border-white/10 rounded-2xl overflow-hidden shadow-xl">
            <button
              onClick={() => setShowTechnicalEvidence(prev => !prev)}
              className="w-full p-4 sm:p-5 flex items-center justify-between text-left font-mono text-xs font-bold text-white hover:bg-white/5 transition-colors cursor-pointer"
            >
              <div className="flex items-center gap-2.5">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>TECHNICAL FORENSIC EVIDENCE (SPF, DKIM, DMARC & HOPS)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-gray-400 font-normal">
                  {showTechnicalEvidence ? 'Collapse' : 'Expand Details'}
                </span>
                {showTechnicalEvidence ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
              </div>
            </button>

            {showTechnicalEvidence && (
              <div className="p-5 border-t border-white/10 space-y-5 bg-black/30 font-mono text-xs">
                {/* Auth Badges */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-3 rounded-xl bg-white/5 border border-white/10 space-y-1">
                    <div className="text-[10px] text-gray-400 uppercase">SPF Authentication</div>
                    <div className={`font-bold ${dossier?.authentication?.spf?.status === 'PASS' ? 'text-emerald-400' : 'text-red-400'}`}>
                      {dossier?.authentication?.spf?.status || 'NOT AVAILABLE'}
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-white/5 border border-white/10 space-y-1">
                    <div className="text-[10px] text-gray-400 uppercase">DKIM Digital Signature</div>
                    <div className={`font-bold ${dossier?.authentication?.dkim?.status === 'PASS' ? 'text-emerald-400' : 'text-amber-400'}`}>
                      {dossier?.authentication?.dkim?.status || 'NOT AVAILABLE'}
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-white/5 border border-white/10 space-y-1">
                    <div className="text-[10px] text-gray-400 uppercase">DMARC Alignment</div>
                    <div className={`font-bold ${dossier?.authentication?.dmarc?.status === 'PASS' ? 'text-emerald-400' : 'text-red-400'}`}>
                      {dossier?.authentication?.dmarc?.status || 'NOT AVAILABLE'}
                    </div>
                  </div>
                </div>

                {/* Routing & Origin Server */}
                {dossier?.originIP && (
                  <div className="space-y-1.5 p-3 rounded-xl bg-white/5 border border-white/10 text-gray-300">
                    <div className="text-[10px] text-gray-500 uppercase tracking-wider">Originating Mail Server</div>
                    <div className="flex flex-wrap items-center gap-3 text-xs">
                      <span>IP: <strong className="text-white">{dossier.originIP.ip}</strong></span>
                      <span>Country: <strong className="text-white">{dossier.originIP.country || 'Global Relay'}</strong></span>
                      <span>ASN / ISP: <strong className="text-white">{dossier.originIP.asn || dossier.originIP.isp || dossier.originIP.organization || 'Cloud Infrastructure'}</strong></span>
                    </div>
                  </div>
                )}

                {/* Received Hops Chain */}
                {dossier?.relayReconstruction && dossier.relayReconstruction.chronologicalHops.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-[10px] text-gray-500 uppercase tracking-wider">
                      SMTP Hop Relay Route ({dossier.relayReconstruction.hopCount} Hops Recorded)
                    </div>
                    <div className="space-y-1.5">
                      {dossier.relayReconstruction.chronologicalHops.map((hop, idx) => (
                        <div key={idx} className="p-2 rounded-lg bg-black/40 border border-white/5 flex items-center justify-between text-[11px] text-gray-300">
                          <span>#{idx + 1} Relay: <strong className="text-white">{hop.destinationHostname || 'MX Gateway'}</strong></span>
                          <span className="text-gray-500">{hop.sourceHostname || hop.sourceIP || 'Local Transport'}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* 5. EXPANDABLE SECTION: ADVERSARIAL & EVASION SIGNALS */}
          <div className="bg-[#09101d] border border-white/10 rounded-2xl overflow-hidden shadow-xl">
            <button
              onClick={() => setShowAdversarialSignals(prev => !prev)}
              className="w-full p-4 sm:p-5 flex items-center justify-between text-left font-mono text-xs font-bold text-white hover:bg-white/5 transition-colors cursor-pointer"
            >
              <div className="flex items-center gap-2.5">
                <ShieldAlert className="w-4 h-4 text-purple-400" />
                <span>ADVERSARIAL EVASION & PROMPT INJECTION SIGNALS</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-gray-400 font-normal">
                  {showAdversarialSignals ? 'Collapse' : 'Expand Details'}
                </span>
                {showAdversarialSignals ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
              </div>
            </button>

            {showAdversarialSignals && (
              <div className="p-5 border-t border-white/10 space-y-3 bg-black/30 font-mono text-xs">
                <div className="flex justify-between py-1.5 border-b border-white/5 text-gray-300">
                  <span className="text-gray-500">Ephemeral Reverse Tunnel (Cloudflare/ngrok):</span>
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
            )}
          </div>

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
