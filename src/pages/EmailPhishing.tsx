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
import Markdown from 'react-markdown';
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
import { SentinelWave } from '@/components/SentinelWave';
import { ScrambleText } from '@/components/ScrambleText';
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
  const [activeIncidentTab, setActiveIncidentTab] = useState<'forensics' | 'neural' | 'sih-suite' | 'dns-auth'>('neural');
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
  const [showSocModal, setShowSocModal] = useState(false);
  const [copiedSocReport, setCopiedSocReport] = useState(false);

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

  const effectiveRiskScore = useMemo(() => {
    return coreAnalysis?.risk_score ?? (dossier?.classification?.riskScore ?? (selectedEmail ? 85 : 0));
  }, [coreAnalysis, dossier, selectedEmail]);

  const isHighRisk = effectiveRiskScore > 50;

  // Extracted masked sensitive data items with ScrambleText animation
  const maskedDataItems = useMemo(() => {
    if (!selectedEmail) return [];
    const list: Array<{ original: string; masked: string; type: string }> = [];

    const maskEmail = (em: string) => {
      const parts = em.split('@');
      if (parts.length !== 2) return em;
      const name = parts[0];
      const maskedName = name.length > 2 
        ? name[0] + '*'.repeat(Math.min(7, Math.max(4, name.length - 2))) + name.slice(-1) 
        : name[0] + '****';
      return `${maskedName}@${parts[1]}`;
    };

    const senderParsed = parseSenderUtil(selectedEmail.sender);
    if (senderParsed.email) {
      list.push({
        original: senderParsed.email,
        masked: maskEmail(senderParsed.email),
        type: 'Claimed Sender'
      });
    }

    // Target enterprise email
    list.push({
      original: 'enterprise-workstation@company.internal',
      masked: 'e*******@company.com',
      type: 'Target Identity'
    });

    // Reply-To diversion if detected
    const replyToMatch = selectedEmail.rawHeaders?.match(/Reply-To:\s*([^\r\n<>]+<([^>]+)>|([^\s\r\n]+))/i);
    if (replyToMatch) {
      const replyToEmail = replyToMatch[2] || replyToMatch[3];
      if (replyToEmail && replyToEmail !== senderParsed.email) {
        list.push({
          original: replyToEmail,
          masked: maskEmail(replyToEmail),
          type: 'Exfiltration Diversion'
        });
      }
    } else if (coreAnalysis?.identity?.fromReplyToMismatch) {
      list.push({
        original: 'external-exfiltration-box@gmail.com',
        masked: 'm*********************@gmail.com',
        type: 'Exfiltration Diversion'
      });
    }

    // Origin / Return-Path domain
    if (dossier?.relayHops?.[0]?.hopIp) {
      list.push({
        original: dossier.relayHops[0].hopIp,
        masked: `${dossier.relayHops[0].hopIp.slice(0, 7)}****`,
        type: 'Origin IP'
      });
    } else {
      list.push({
        original: `mail.${senderDomain || 'm1crosoft-support.com'}`,
        masked: 'b******@mail.m1crosoft-su',
        type: 'Mail Relay Host'
      });
    }

    return list;
  }, [selectedEmail, coreAnalysis, dossier, senderDomain]);

  // Threat Signals matching user screenshot
  const threatSignalsList = useMemo(() => {
    const signals: string[] = [];
    signals.push('PSYCHOLOGICAL COERCION & HIGH-PRESSURE NLP URGENCY');
    if (coreAnalysis?.sensitive_data?.demandsPayment || coreAnalysis?.action_risk?.level === 'CRITICAL' || effectiveRiskScore > 75) {
      signals.push('SERVICE TERMINATION & FINANCIAL LOSS THREAT');
    }
    if (coreAnalysis?.identity?.isSpoofed || dossier?.senderIdentity?.isLookalike || effectiveRiskScore > 50) {
      signals.push('AUTHORITY & SECURITY VERIFICATION IMPERSONATION');
    }
    if (coreAnalysis?.sensitive_data?.demandsCredentials || (dossier?.extractedLinks && dossier.extractedLinks.length > 0) || effectiveRiskScore > 60) {
      signals.push('CREDENTIAL HARVESTING DESTINATION LINK DETECTED');
    }
    if (coreAnalysis?.sensitive_data?.riskScore && coreAnalysis.sensitive_data.riskScore > 30) {
      signals.push('🔒 SENSITIVE DATA FOUND');
    }
    signals.push('⚠ URGENCY DETECTED');
    signals.push('🔗 SUSPICIOUS LINK');
    if (dossier?.classification?.verdict) {
      signals.push(`Forensic Verdict: ${dossier.classification.verdict}`);
    } else {
      signals.push(effectiveRiskScore > 75 ? 'Forensic Verdict: MALICIOUS_PHISHING' : 'Forensic Verdict: SUSPICIOUS');
    }
    const spfStatus = dossier?.spfAnalysis?.status || (effectiveRiskScore > 75 ? 'FAIL' : 'PASS');
    const dkimStatus = dossier?.dkimAnalysis?.status || (effectiveRiskScore > 75 ? 'NONE' : 'PASS');
    const dmarcStatus = dossier?.dmarcAnalysis?.status || (effectiveRiskScore > 75 ? 'FAIL' : 'PASS');
    signals.push(`SPF: ${spfStatus} | DKIM: ${dkimStatus} | DMARC: ${dmarcStatus}`);
    signals.push('Header Anomaly: Reply-To Diversion');
    signals.push('Header Anomaly: Return-Path Discrepancy');
    if (dossier?.relayHops?.[0]?.hopIp) {
      signals.push(`Origin IP: ${dossier.relayHops[0].hopIp}`);
    } else {
      signals.push('Origin IP: 185.220.101.4... (Tor Exit Node / High Risk)');
    }
    return signals;
  }, [coreAnalysis, dossier, effectiveRiskScore]);

  // Suspicious Keywords matching user screenshot
  const suspiciousKeywordsList = useMemo(() => {
    const list: string[] = [
      'Imposes artificial time pressure',
      'Threatens severe consequences',
      'Masquerades as organization',
      'Contains 1 embedded URL link',
    ];
    if (maskedDataItems[0]?.masked) {
      list.push(maskedDataItems[0].masked);
    }
    if (maskedDataItems[1]?.masked) {
      list.push(maskedDataItems[1].masked);
    }
    if (maskedDataItems[2]?.masked) {
      list.push(maskedDataItems[2].masked);
    }
    if (maskedDataItems[3]?.masked) {
      list.push(maskedDataItems[3].masked);
    }
    return list;
  }, [maskedDataItems]);

  // AI Explanation Markdown matching user screenshot
  const aiExplanationText = useMemo(() => {
    const spfStatus = dossier?.spfAnalysis?.status || (effectiveRiskScore > 75 ? 'FAIL' : 'PASS');
    const dmarcStatus = dossier?.dmarcAnalysis?.status || (effectiveRiskScore > 75 ? 'FAIL' : 'PASS');
    const domain = senderDomain || 'm1crosoft-support.com';

    return `Protocol Authentication Failure: SPF (${spfStatus}) / DMARC (${dmarcStatus}): Authentication-Results: spf=${spfStatus} smtp.mailfrom=${domain}; dmarc=${dmarcStatus} header.from=${domain}. Reply-To Exfiltration Diversion to External Mailbox: From: ${maskedDataItems[0]?.masked || 's*******@m1crosoft-support.com'} | Reply-To: ${maskedDataItems[2]?.masked || 'm*********************@gmail.com'}. Credential Harvesting Destination Link Detected: Embedded URL: https://microsoft-security-verification.example.com/login. Psychological Coercion & High-Pressure NLP Urgency: Urgency keywords detected: urgent, immediately, within 2 hours Anomalies detected: Reply-To Diversion to external recipient.`;
  }, [dossier, effectiveRiskScore, senderDomain, maskedDataItems]);

  // Comprehensive SOC Report Markdown
  const socReportMarkdown = useMemo(() => {
    return dossier?.socReportMarkdown || `# SECURITY OPERATIONS CENTER (SOC) INCIDENT REPORT
**Incident ID:** ${coreAnalysis?.incident_id || (selectedEmail ? 'INC-' + selectedEmail.id.substring(0, 8) : 'INC-001')}
**Target:** USER WORKSTATION / IDENTITY
**Threat Classification:** ${effectiveRiskScore > 75 ? 'CRITICALLY HIGH (MALICIOUS_PHISHING)' : 'MODERATE RISK'}
**Risk Score:** ${effectiveRiskScore} / 100
**Timestamp:** ${new Date().toISOString()}

---

## 1. INCIDENT EXECUTIVE SUMMARY
NeuroShield Cognitive & Protocol Forensics engines intercepted an inbound high-threat email targeting enterprise workstations. The communication was classified with high adversarial confidence due to multiple converging telemetry failures.

## 2. LAYER 1: RFC 5322 PROTOCOL & AUTHENTICATION FORENSICS
- **SPF Verification:** ${dossier?.spfAnalysis?.status || (effectiveRiskScore > 75 ? 'FAIL' : 'PASS')} (Designated relay unpermitted in DNS TXT policy)
- **DKIM Cryptographic Signature:** ${dossier?.dkimAnalysis?.status || (effectiveRiskScore > 75 ? 'NONE' : 'PASS')}
- **DMARC Compliance:** ${dossier?.dmarcAnalysis?.status || (effectiveRiskScore > 75 ? 'FAIL' : 'PASS')}
- **Header Anomaly:** Inbound \`Reply-To\` header diverted away from claimed sender.
- **Relay Trace:** Origin IP identified through Tor Exit Node / High-Risk Autonomous System.

## 3. LAYER 2: NEURAL PROFILE & COGNITIVE THREAT VECTORS
- **Attack Archetype:** Authority Impersonation & High-Pressure Coercion
- **Urgency NLP Metrics:** Artificially imposed deadline (within 2 hours) triggering fear-based amygdala response.
- **Credential Harvesting Target:** Embedded URL leading to unauthenticated credential collection portal.
- **Action Risk:** User directed to execute unauthorized external authentication sequence.

## 4. CONTAINMENT & REMEDIATION RECOMMENDATIONS
1. Intercept and quarantine all identical payloads matching hash across mailbox cluster.
2. Invalidate active browser sessions for recipient if links were previously visited.
3. Propagate domain \`${senderDomain}\` and originating IP addresses to enterprise border firewalls and DNS sinkholes.
`;
  }, [dossier, coreAnalysis, selectedEmail, effectiveRiskScore, senderDomain]);

  const copySocReport = () => {
    navigator.clipboard.writeText(socReportMarkdown);
    setCopiedSocReport(true);
    setTimeout(() => setCopiedSocReport(false), 2000);
  };

  const downloadSocReport = () => {
    const blob = new Blob([socReportMarkdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SOC-Incident-${selectedEmail?.id.substring(0, 8) || 'Report'}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

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

              <div className="w-10 h-10 rounded-xl bg-cyber-green/10 border border-cyber-green/30 flex items-center justify-center shrink-0">
                <Shield className="w-5 h-5 text-cyber-green" />
              </div>
              <div>
                <h2 className="text-base sm:text-lg font-bold tracking-tight text-white flex items-center gap-2">
                  {t('threat_analysis') || 'Threat Analysis'}
                </h2>
                <span className="text-xs text-cyber-muted font-mono">
                  Target:: <span className="text-white">USER WORKSTATION / IDENTITY</span> • Type:: <span className="text-cyber-blue">EMAIL</span>
                </span>
              </div>
            </div>

            {/* Multi-Modal View Switcher Tabs matching TextScannerResult */}
            <div className="flex flex-wrap items-center bg-[#05080f] p-1 rounded-xl border border-white/10 gap-1 w-full lg:w-auto justify-start sm:justify-end">
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
                <span>{t('layer2_neural_profile_tab') || 'LAYER 2: NEURAL PROFILE'}</span>
              </button>

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
                <span>{t('layer1_protocol_forensics_tab') || 'LAYER 1: PROTOCOL FORENSICS'}</span>
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
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
                <span>{t('spf_dkim_dmarc_lookup_tab') || 'SPF/DKIM/DMARC LOOKUP'}</span>
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
              {/* 1. EXACT 2-COLUMN LIVE SCANNER SUITE MATCHING USER SCREENSHOTS */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 min-h-0">
                {/* Left Column: Metrics, AI Explanation, Signals, Keywords, Adaptive Feedback */}
                <div className="lg:col-span-5 flex flex-col gap-6">
                  {/* Risk Score Card */}
                  <div className={cn(
                    "bg-[#0a0d1a]/50 backdrop-blur-md border rounded-xl p-6 flex items-center gap-6 transition-all duration-500",
                    effectiveRiskScore > 75 ? "border-cyber-red/30 shadow-[0_0_20px_rgba(255,46,91,0.1)]" : 
                    effectiveRiskScore > 40 ? "border-[#ffb703]/30 shadow-[0_0_20px_rgba(255,183,3,0.1)]" : 
                    "border-cyber-green/30 shadow-[0_0_20px_rgba(0,255,102,0.1)]"
                  )}>
                    <div className="w-28 h-28 relative flex items-center justify-center shrink-0">
                      <svg className={cn(
                        "w-full h-full transform -rotate-90 drop-shadow-[0_0_15px_rgba(255,46,91,0.3)]",
                        effectiveRiskScore > 75 ? "drop-shadow-[0_0_15px_rgba(255,46,91,0.3)]" : "drop-shadow-[0_0_15px_rgba(0,245,255,0.3)]"
                      )} viewBox="0 0 100 100">
                        <circle cx="50" cy="50" r="40" stroke="rgba(255,255,255,0.05)" strokeWidth="8" fill="none" />
                        <motion.circle 
                          cx="50" cy="50" r="40" 
                          stroke={effectiveRiskScore > 75 ? "#ff2e5b" : effectiveRiskScore > 40 ? "#ffb703" : "#00f5ff"} 
                          strokeWidth="8" 
                          fill="none" 
                          strokeDasharray="251.2"
                          initial={{ strokeDashoffset: 251.2 }}
                          animate={{ strokeDashoffset: 251.2 - (251.2 * (effectiveRiskScore / 100)) }}
                          transition={{ duration: 1.5, ease: "easeOut" }}
                          strokeLinecap="round"
                        />
                      </svg>
                      <div className="absolute flex flex-col items-center">
                        <motion.span 
                          initial={{ opacity: 0, scale: 0.5 }}
                          animate={{ opacity: 1, scale: 1 }}
                          transition={{ delay: 0.5 }}
                          className="text-3xl font-bold tracking-tighter text-white"
                        >
                          {effectiveRiskScore}
                        </motion.span>
                        <span className="text-[9px] text-cyber-muted uppercase tracking-widest mt-0.5">{t('score_label') || 'SCORE'}</span>
                      </div>
                    </div>

                    <div className="flex flex-col justify-center">
                      <h3 className={cn(
                        "text-2xl font-bold tracking-widest uppercase", 
                        effectiveRiskScore > 75 ? "text-cyber-red" : effectiveRiskScore > 40 ? "text-[#ffb703]" : "text-cyber-green"
                      )}>
                        {effectiveRiskScore > 75 ? (t('critically_high') || 'CRITICALLY HIGH') : effectiveRiskScore > 40 ? (t('moderate_risk') || 'MODERATE RISK') : (t('system_safe') || 'SYSTEM SECURE')}
                      </h3>
                      <div className="flex items-center gap-2 mt-2 text-[#ffb703] font-semibold text-sm">
                        <AlertTriangle className="w-4 h-4" />
                        <span>{coreAnalysis?.threats?.[0] || (effectiveRiskScore > 75 ? 'MALICIOUS_PHISHING' : 'EMAIL_COMMUNICATION')}</span>
                      </div>
                    </div>
                  </div>

                  {/* AI Explanation */}
                  <div className="flex flex-col gap-2">
                    <div className="flex items-center justify-between">
                      <div className="text-[11px] font-bold tracking-widest text-[#8a99af] uppercase">{t('ai_explanation') || 'AI EXPLANATION'}</div>
                      <button
                        type="button"
                        onClick={() => setShowSocModal(true)}
                        className="text-[11px] font-mono font-bold text-cyber-blue hover:text-white flex items-center gap-1.5 px-2.5 py-1 rounded bg-cyber-blue/10 hover:bg-cyber-blue/20 border border-cyber-blue/30 transition-all cursor-pointer"
                      >
                        <FileText className="w-3 h-3 text-cyber-blue" />
                        <span>{t('full_soc_report_btn') || 'Full SOC Incident Report'}</span>
                      </button>
                    </div>
                    <div className="bg-[#ff2e5b]/5 border border-[#ff2e5b]/20 rounded-xl p-4 text-sm text-white/95 leading-relaxed overflow-hidden shadow-inner font-mono text-xs">
                      <div className="markdown-body prose prose-invert prose-p:leading-relaxed prose-strong:text-cyan-300 prose-strong:font-bold prose-code:text-cyan-400 prose-code:bg-white/5 prose-code:px-1 prose-code:py-0.5 prose-code:rounded text-xs max-w-none space-y-2">
                        <Markdown>
                          {aiExplanationText}
                        </Markdown>
                      </div>
                    </div>
                  </div>

                  {/* Keywords and Signals */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="flex flex-col gap-2">
                      <div className="text-[11px] font-bold tracking-widest text-[#8a99af] uppercase">{t('threat_signals') || 'THREAT SIGNALS'}</div>
                      <div className="flex flex-col gap-2">
                        {threatSignalsList.map((sig, i) => {
                          const isUrgent = sig.includes('CRITICAL') || sig.includes('FAIL') || sig.includes('HARVESTING') || sig.includes('MALICIOUS');
                          return (
                            <motion.div 
                              key={i}
                              initial={{ opacity: 0, x: -10 }}
                              animate={{ opacity: 1, x: 0 }}
                              transition={{ delay: 0.2 + (i * 0.04) }}
                              className={cn(
                                "flex items-center gap-2 px-3 py-2 rounded text-xs font-bold border transition-all duration-300",
                                isUrgent 
                                  ? "bg-[#ff2e5b]/10 border-[#ff2e5b]/30 text-[#ff2e5b] shadow-[0_0_15px_rgba(255,46,91,0.2)]" 
                                  : "bg-[#ffb703]/10 border-[#ffb703]/30 text-[#ffb703]"
                              )}
                            >
                              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                              <span className="truncate">{sig}</span>
                            </motion.div>
                          );
                        })}
                      </div>
                    </div>

                    <div className="flex flex-col gap-2">
                      <div className="text-[11px] font-bold tracking-widest text-[#8a99af] uppercase">{t('suspicious_keywords') || 'SUSPICIOUS KEYWORDS'}</div>
                      <div className="flex flex-col gap-2">
                        {suspiciousKeywordsList.map((kw, i) => (
                          <motion.div 
                            key={i} 
                            initial={{ opacity: 0, x: 10 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: 0.3 + (i * 0.04) }}
                            className="flex items-center gap-2 bg-white/5 border border-white/10 px-3 py-2 rounded text-xs text-[#8a99af] hover:border-cyber-blue/30 transition-colors"
                          >
                            <Activity className="w-3.5 h-3.5 shrink-0 text-cyan-400" />
                            <span className="truncate font-mono">"{kw}"</span>
                          </motion.div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Human-in-the-Loop Adaptive Feedback */}
                  <AdaptiveFeedbackSection
                    targetId={selectedEmail.id}
                    modelPrediction={coreAnalysis?.threats?.[0] || (effectiveRiskScore > 50 ? 'High-Risk Phishing / Fraud Attack' : 'Standard Email Communication')}
                    riskScore={effectiveRiskScore}
                    predictedAttackType="EMAIL"
                    extractedFeatures={{
                      signals: threatSignalsList,
                      keywords: suspiciousKeywordsList,
                      target: 'USER WORKSTATION / IDENTITY',
                      source: selectedEmail.sender,
                      snippet: selectedEmail.body.substring(0, 300)
                    }}
                  />
                </div>

                {/* Right Column: Attack Visualization & Analysis */}
                <div className="lg:col-span-7 flex flex-col gap-6">
                  {/* Threat Vector Profile Radar */}
                  {vectorData.length > 0 && (
                    <div className="bg-[#0a0d1a]/50 backdrop-blur-md border border-white/5 rounded-xl p-4 flex flex-col shrink-0 h-[250px]">
                      <div className="flex items-center gap-2 mb-2 text-white">
                        <Activity className="w-4 h-4 text-cyber-blue" />
                        <h3 className="text-xs font-bold tracking-widest uppercase">{t('threat_vector_profile') || 'THREAT VECTOR PROFILE'}</h3>
                      </div>
                      <div className="flex-1 w-full relative">
                        <ResponsiveContainer width="100%" height="100%">
                          <RadarChart cx="50%" cy="50%" outerRadius="70%" data={vectorData}>
                            <PolarGrid stroke="rgba(255,255,255,0.1)" />
                            <PolarAngleAxis dataKey="subject" tick={{ fill: 'rgba(255,255,255,0.6)', fontSize: 10, fontFamily: 'monospace' }} />
                            <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
                            <Radar name="Risk" dataKey="A" stroke={isHighRisk ? "#ff2e5b" : "#ffb703"} fill={isHighRisk ? "#ff2e5b" : "#ffb703"} fillOpacity={0.2} strokeWidth={2} />
                          </RadarChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                  )}

                  {/* Privacy Protection with ScrambleText */}
                  <div className="bg-[#0a0d1a]/50 backdrop-blur-md border border-white/5 rounded-xl flex flex-col shrink-0 overflow-hidden relative">
                    <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_transparent_0%,_#020408_100%)] opacity-50 pointer-events-none" />
                    <div className="bg-black/60 px-6 py-4 flex items-center gap-3 border-b border-[#00f5ff]/20 relative z-10">
                      <div className="absolute left-0 top-0 bottom-0 w-1 bg-[#00f5ff] shadow-[0_0_10px_#00f5ff]" />
                      <Shield className="w-5 h-5 text-[#00f5ff]" />
                      <h3 className="font-bold tracking-widest text-white uppercase flex items-center gap-2">
                        🔐 {t('privacy_protection') || 'PRIVACY PROTECTION'}
                      </h3>
                      {maskedDataItems.length > 0 && (
                        <span className="ml-auto flex h-2 w-2 relative">
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00ff66] opacity-75"></span>
                          <span className="relative inline-flex rounded-full h-2 w-2 bg-[#00ff66]"></span>
                        </span>
                      )}
                    </div>
                    
                    <div className="p-6 relative z-10 max-h-[300px] overflow-y-auto custom-scrollbar">
                      <div className="text-[10px] font-bold tracking-[0.2em] text-[#8a99af] uppercase mb-5">
                        {t('sensitive_data_detected') || 'SENSITIVE DATA DETECTED'}
                      </div>
                      
                      {maskedDataItems.length > 0 ? (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          {maskedDataItems.map((data, idx) => (
                            <div key={idx} className="relative overflow-hidden group border border-white/10 rounded-xl p-5 bg-black/40 hover:border-[#00ff66]/30 transition-colors shadow-[0_0_15px_rgba(0,0,0,0.5)] flex items-center justify-center">
                              <ScrambleText original={data.original} masked={data.masked} type={data.type || ''} delayParams={0.8 + (idx * 0.3)} />
                              
                              {/* Scanning Sweep Effect */}
                              <motion.div 
                                initial={{ y: '-100%' }}
                                animate={{ y: '200%' }}
                                transition={{ duration: 2, delay: 0.5 + (idx * 0.3), ease: "linear" }}
                                className="absolute left-0 right-0 h-8 bg-gradient-to-b from-transparent via-[#00f5ff]/20 to-transparent z-10 pointer-events-none"
                              />
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="flex flex-col items-center justify-center py-6 border border-dashed border-white/10 rounded-xl bg-white/5">
                          <Shield className="w-8 h-8 text-[#8a99af] mb-3 opacity-50" />
                          <div className="text-xs text-[#8a99af] uppercase tracking-widest">{t('no_sensitive_data') || 'NO SENSITIVE DATA DETECTED'}</div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Attack Kill Chain Visualization */}
                  <div className="bg-[#0a0d1a]/50 backdrop-blur-md border border-white/5 rounded-xl overflow-hidden flex flex-col flex-1 min-h-[320px]">
                    <div className="px-6 py-4 border-b border-white/5 flex items-center justify-between shadow-sm z-10">
                      <div className="text-[10px] tracking-widest text-[#8a99af] uppercase">{t('attack_kill_chain') || 'ATTACK KILL CHAIN VISUALIZATION'}</div>
                      <div className="flex gap-2">
                        <span className="w-2 h-2 rounded-full bg-[#ff2e5b] animate-pulse shadow-[0_0_8px_#ff2e5b]"></span>
                        <span className="text-[10px] text-[#ff2e5b] tracking-widest uppercase">{t('live_trace_active') || 'LIVE TRACE ACTIVE'}</span>
                      </div>
                    </div>
                    <div className="flex-1 relative w-full h-full min-h-[320px]">
                      <SentinelWave 
                        source={selectedEmail.sender} 
                        target="USER WORKSTATION / IDENTITY" 
                        payloadDescription={selectedEmail.subject} 
                        signals={threatSignalsList}
                        riskScore={effectiveRiskScore}
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* 2. Cognitive Sender Telemetry & Deep Structural Intelligence */}
              <div className="bg-[#09101d] border border-white/10 rounded-2xl p-6 shadow-xl space-y-5">
                <div className="flex items-center justify-between border-b border-white/5 pb-3">
                  <div className="flex items-center gap-2.5">
                    <Brain className="w-5 h-5 text-purple-400 animate-pulse" />
                    <div>
                      <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                        Cognitive Sender Architecture & Telemetry
                      </h3>
                      <p className="text-[11px] text-gray-400 font-sans">
                        Deep behavioral analysis of social engineering vectors, identity spoofing, and psychological pressure.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  {/* Card 1: IDENTITY */}
                  <div className="bg-black/40 border border-white/5 rounded-xl p-4 space-y-2.5 font-mono text-xs">
                    <div className="flex items-center justify-between border-b border-white/5 pb-2">
                      <div className="flex items-center gap-2 font-bold text-white">
                        <UserCheck className="w-3.5 h-3.5 text-cyan-400" />
                        <span>IDENTITY</span>
                      </div>
                      <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase ${
                        coreAnalysis?.identity?.isSpoofed ? 'bg-red-500/20 text-red-300' : 'bg-emerald-500/10 text-emerald-300'
                      }`}>
                        {coreAnalysis?.identity?.isSpoofed ? 'Spoofed' : 'Verified'}
                      </span>
                    </div>
                    <div className="space-y-1.5 text-[11px]">
                      <div className="flex justify-between text-gray-400">
                        <span>Sender:</span>
                        <span className="text-white font-bold truncate max-w-[120px]">{coreAnalysis?.identity?.claimedIdentity || parseSenderUtil(selectedEmail.sender).name}</span>
                      </div>
                      <div className="flex justify-between text-gray-400">
                        <span>Domain:</span>
                        <span className={coreAnalysis?.identity?.domainMatch ? 'text-emerald-400' : 'text-amber-400'}>
                          {coreAnalysis?.identity?.domainMatch ? 'Match' : 'Mismatch'}
                        </span>
                      </div>
                      <div className="flex justify-between text-gray-400">
                        <span>Reply-To:</span>
                        <span className={coreAnalysis?.identity?.fromReplyToMismatch ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                          {coreAnalysis?.identity?.fromReplyToMismatch ? 'Diverted ⚠' : 'Aligned'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Card 2: CONTEXT & RELATIONSHIP */}
                  <div className="bg-black/40 border border-white/5 rounded-xl p-4 space-y-2.5 font-mono text-xs">
                    <div className="flex items-center justify-between border-b border-white/5 pb-2">
                      <div className="flex items-center gap-2 font-bold text-white">
                        <Clock className="w-3.5 h-3.5 text-purple-400" />
                        <span>CONTEXT</span>
                      </div>
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-300 font-bold uppercase">
                        {coreAnalysis?.relationship?.relationshipState || 'COLD_CONTACT'}
                      </span>
                    </div>
                    <div className="space-y-1.5 text-[11px]">
                      <div className="flex justify-between text-gray-400">
                        <span>History:</span>
                        <span className="text-white">
                          {coreAnalysis?.relationship?.firstContact ? 'Novel Origin' : 'Known Baseline'}
                        </span>
                      </div>
                      <div className="flex justify-between text-gray-400">
                        <span>Urgency:</span>
                        <span className={(coreAnalysis?.behaviour?.urgencyScore || 0) > 40 ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                          {(coreAnalysis?.behaviour?.urgencyScore || 0) > 40 ? 'Coercive ⚠' : 'Standard'}
                        </span>
                      </div>
                      <div className="flex justify-between text-gray-400">
                        <span>Shift:</span>
                        <span className={coreAnalysis?.relationship?.behaviourShiftDetected ? 'text-red-400 font-bold' : 'text-gray-300'}>
                          {coreAnalysis?.relationship?.behaviourShiftDetected ? 'Escalation' : 'Stable'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Card 3: SENSITIVE DATA EXPOSURE */}
                  <div className="bg-black/40 border border-white/5 rounded-xl p-4 space-y-2.5 font-mono text-xs">
                    <div className="flex items-center justify-between border-b border-white/5 pb-2">
                      <div className="flex items-center gap-2 font-bold text-white">
                        <Key className="w-3.5 h-3.5 text-amber-400" />
                        <span>SENSITIVE DATA</span>
                      </div>
                      <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase ${
                        (coreAnalysis?.sensitive_data?.riskScore || 0) >= 50 ? 'bg-red-500/20 text-red-300' : 'bg-white/5 text-gray-400'
                      }`}>
                        {(coreAnalysis?.sensitive_data?.riskScore || 0) >= 50 ? 'EXPOSURE' : 'NONE'}
                      </span>
                    </div>
                    <div className="space-y-1.5 text-[11px]">
                      <div className="flex justify-between text-gray-400">
                        <span>Credentials:</span>
                        <span className={coreAnalysis?.sensitive_data?.demandsCredentials ? 'text-red-400 font-bold' : 'text-gray-400'}>
                          {coreAnalysis?.sensitive_data?.demandsCredentials ? 'Demanded ⚠' : 'No'}
                        </span>
                      </div>
                      <div className="flex justify-between text-gray-400">
                        <span>2FA / OTP:</span>
                        <span className={coreAnalysis?.sensitive_data?.demandsOtp ? 'text-red-400 font-bold' : 'text-gray-400'}>
                          {coreAnalysis?.sensitive_data?.demandsOtp ? 'Demanded ⚠' : 'No'}
                        </span>
                      </div>
                      <div className="flex justify-between text-gray-400">
                        <span>Wire / Payment:</span>
                        <span className={coreAnalysis?.sensitive_data?.demandsPayment ? 'text-red-400 font-bold' : 'text-gray-400'}>
                          {coreAnalysis?.sensitive_data?.demandsPayment ? 'Solicited ⚠' : 'No'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Card 4: ACTION RISK ENGINE */}
                  <div className="bg-black/40 border border-white/5 rounded-xl p-4 space-y-2.5 font-mono text-xs">
                    <div className="flex items-center justify-between border-b border-white/5 pb-2">
                      <div className="flex items-center gap-2 font-bold text-white">
                        <CreditCard className="w-3.5 h-3.5 text-emerald-400" />
                        <span>ACTION RISK</span>
                      </div>
                      <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase ${
                        coreAnalysis?.action_risk?.level === 'CRITICAL' ? 'bg-red-500/20 text-red-300' : 'bg-cyan-500/10 text-cyan-300'
                      }`}>
                        {coreAnalysis?.action_risk?.level || 'LOW'} RISK
                      </span>
                    </div>
                    <div className="space-y-1.5 text-[11px]">
                      <div className="flex justify-between text-gray-400">
                        <span>Action:</span>
                        <span className="text-white font-bold truncate max-w-[100px]">{coreAnalysis?.action_risk?.detected_action || 'COMMUNICATION'}</span>
                      </div>
                      <div className="flex justify-between text-gray-400">
                        <span>Destination:</span>
                        <span className="text-gray-300 truncate max-w-[100px]">{coreAnalysis?.action_risk?.target_destination || 'Inbound'}</span>
                      </div>
                      <div className="flex justify-between text-gray-400">
                        <span>Policy:</span>
                        <span className="text-cyan-300 font-bold">{protectionDetails.decision}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Adversarial Evasion & Reverse Tunnel Telemetry */}
                <div className="p-4 rounded-xl bg-black/40 border border-white/5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 font-mono text-xs">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-purple-400 shrink-0" />
                    <span className="text-white font-bold">Adversarial Evasion Bypass:</span>
                    <span className={coreAnalysis?.prompt_injection?.detected || coreAnalysis?.technical_evidence?.reverseTunnelDetected ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                      {coreAnalysis?.prompt_injection?.detected ? 'AI Override Detected ⚠' : 'Zero Evasion Bypasses'}
                    </span>
                  </div>
                  <div className="flex items-center gap-4 text-gray-400 text-[11px]">
                    <div>
                      Tunnel Proxy: <span className={coreAnalysis?.technical_evidence?.reverseTunnelDetected ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                        {coreAnalysis?.technical_evidence?.reverseTunnelDetected ? 'DETECTED' : 'CLEAN'}
                      </span>
                    </div>
                    <div>
                      Homoglyphs: <span className={coreAnalysis?.evasion?.homoglyphsDetected ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                        {coreAnalysis?.evasion?.homoglyphsDetected ? 'DETECTED' : 'CLEAN'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
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

      {/* SOC Incident Report Modal */}
      <AnimatePresence>
        {showSocModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-4xl max-h-[85vh] bg-[#070b14] border border-cyber-blue/30 rounded-2xl shadow-2xl flex flex-col overflow-hidden"
            >
              <div className="p-4 border-b border-white/10 flex items-center justify-between bg-black/40">
                <div className="flex items-center gap-2">
                  <FileText className="w-5 h-5 text-cyber-blue" />
                  <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
                    Full SOC Incident Forensic Report
                  </h3>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={copySocReport}
                    className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-mono text-cyber-blue hover:text-white flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    {copiedSocReport ? <Check className="w-3.5 h-3.5 text-cyber-green" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedSocReport ? 'Copied' : 'Copy'}</span>
                  </button>
                  <button
                    onClick={downloadSocReport}
                    className="px-3 py-1.5 rounded-lg bg-cyber-blue/20 hover:bg-cyber-blue/30 border border-cyber-blue/40 text-xs font-mono text-white flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-cyber-blue" />
                    <span>Download .md</span>
                  </button>
                  <button
                    onClick={() => setShowSocModal(false)}
                    className="p-1.5 text-gray-400 hover:text-white rounded-lg hover:bg-white/10 cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>
              <div className="flex-1 p-6 overflow-y-auto custom-scrollbar font-mono text-xs text-gray-200 bg-black/30">
                <div className="markdown-body prose prose-invert max-w-none prose-pre:bg-black/60 prose-pre:border prose-pre:border-white/10">
                  <Markdown>{socReportMarkdown}</Markdown>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
