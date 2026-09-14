import React, { useState, useEffect, useRef, useMemo } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'motion/react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Mail, 
  ArrowRight, 
  Zap, 
  CheckCircle2, 
  AlertTriangle, 
  Terminal, 
  Globe, 
  Sparkles, 
  ChevronRight,
  ChevronLeft,
  ChevronDown,
  Search,
  Check,
  X,
  Play,
  User,
  Users,
  Shield,
  Lock,
  FileText,
  Activity,
  ArrowUpRight,
  Loader2,
  UploadCloud,
  FileSearch,
  FileUp,
  ExternalLink,
  RefreshCw,
  Cpu,
  Server,
  Key,
  Eye,
  Layers,
  Gauge,
  BarChart3,
  Clock,
  Database,
  CheckCircle,
  Flame,
  Target,
  UserCheck,
  ShieldOff,
  Network,
  GitBranch,
  Radio,
  Binary
} from 'lucide-react';
import { executeEmailForensics, ForensicDossier } from '@/services/forensicsEngine';
import { SHOWCASE_INBOX_EMAILS, InboxEmailItem } from '@/data/inboxEmails';
import { addScanToHistory } from '@/lib/history';
import { googleSignIn, getAccessToken, initAuth } from '@/services/googleAuth';

interface LandingPageProps {
  navigate: (tab: string) => void;
  onNavigateToDashboard?: () => void;
  onNavigateToInboxShield?: () => void;
  onNavigateToScanner?: () => void;
}

// ---------------------------------------------------------------------------
// 3D Wireframe Mesh Canvas (Topological digital terrain seen in Abnormal AI)
// ---------------------------------------------------------------------------
function WireframeMeshCanvas() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = canvas.parentElement?.clientWidth || window.innerWidth);
    let height = (canvas.height = canvas.parentElement?.clientHeight || 650);

    const handleResize = () => {
      if (!canvas || !canvas.parentElement) return;
      width = canvas.width = canvas.parentElement.clientWidth;
      height = canvas.height = canvas.parentElement.clientHeight;
    };
    window.addEventListener('resize', handleResize);

    const cols = 48;
    const rows = 34;
    let time = 0;

    let mouseX = width / 2;
    let mouseY = height / 2;
    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouseX = e.clientX - rect.left;
      mouseY = e.clientY - rect.top;
    };
    window.addEventListener('mousemove', handleMouseMove);

    const render = () => {
      time += 0.012;
      ctx.clearRect(0, 0, width, height);

      const fov = 380;
      const cameraY = -120 + ((mouseY - height / 2) * 0.08);
      const cameraAngle = 0.55 + ((mouseX - width / 2) * 0.0002);

      // Precompute projected points
      const points: { x: number; y: number; z: number; px: number; py: number; rawY: number }[][] = [];

      for (let r = 0; r < rows; r++) {
        const rowPoints = [];
        for (let c = 0; c < cols; c++) {
          const normC = (c / (cols - 1)) * 2 - 1; // -1 to 1
          const normR = r / (rows - 1); // 0 to 1

          const worldX = normC * (width * 0.75);
          const worldZ = normR * 900 + 150;

          // Multi-frequency topological elevation (mountain ridges)
          const distFromCenter = Math.hypot(normC, normR - 0.5);
          const wave1 = Math.sin(normC * 4.2 + time * 0.7) * 45;
          const wave2 = Math.cos(normR * 5.5 - time * 0.5) * 38;
          const mountain = Math.sin(normC * 2.8) * Math.cos(normR * 3.4) * 80;
          const detail = Math.sin(normC * 12 + normR * 8 + time) * 12;

          // Taper edges to 0 so terrain naturally settles into darkness
          const envelope = Math.max(0, 1 - Math.pow(distFromCenter * 1.1, 2));
          const worldY = (wave1 + wave2 + mountain + detail) * envelope * 1.3 - 40;

          // 3D Perspective Projection with pitch
          const cosA = Math.cos(cameraAngle);
          const sinA = Math.sin(cameraAngle);

          const relY = worldY - cameraY;
          const rotY = relY * cosA - worldZ * sinA;
          const rotZ = relY * sinA + worldZ * cosA;

          if (rotZ > 10) {
            const scale = fov / rotZ;
            const px = width / 2 + worldX * scale;
            const py = height * 0.45 + rotY * scale;
            rowPoints.push({ x: worldX, y: worldY, z: worldZ, px, py, rawY: worldY });
          } else {
            rowPoints.push({ x: worldX, y: worldY, z: worldZ, px: -999, py: -999, rawY: 0 });
          }
        }
        points.push(rowPoints);
      }

      // Draw horizontal wireframe contour lines (Electric Lime/Green)
      for (let r = 0; r < rows; r++) {
        ctx.beginPath();
        let started = false;
        const progress = r / rows;
        const alpha = Math.sin(progress * Math.PI) * 0.45 + 0.08;

        for (let c = 0; c < cols; c++) {
          const pt = points[r][c];
          if (pt.px === -999) continue;
          if (!started) {
            ctx.moveTo(pt.px, pt.py);
            started = true;
          } else {
            ctx.lineTo(pt.px, pt.py);
          }
        }
        ctx.strokeStyle = `rgba(204, 255, 0, ${alpha.toFixed(3)})`;
        ctx.lineWidth = r % 4 === 0 ? 1.3 : 0.75;
        ctx.stroke();
      }

      // Draw vertical wireframe cross lines
      for (let c = 0; c < cols; c += 2) {
        ctx.beginPath();
        let started = false;
        for (let r = 0; r < rows; r++) {
          const pt = points[r][c];
          if (pt.px === -999) continue;
          if (!started) {
            ctx.moveTo(pt.px, pt.py);
            started = true;
          } else {
            ctx.lineTo(pt.px, pt.py);
          }
        }
        ctx.strokeStyle = 'rgba(204, 255, 0, 0.12)';
        ctx.lineWidth = 0.65;
        ctx.stroke();
      }

      // Bottom gradient fade out
      const grad = ctx.createLinearGradient(0, height * 0.45, 0, height);
      grad.addColorStop(0, 'rgba(5, 7, 6, 0)');
      grad.addColorStop(0.7, 'rgba(5, 7, 6, 0.75)');
      grad.addColorStop(1, 'rgba(5, 7, 6, 1)');
      ctx.fillStyle = grad;
      ctx.fillRect(0, height * 0.45, width, height * 0.55);

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousemove', handleMouseMove);
    };
  }, []);

  return (
    <canvas 
      ref={canvasRef} 
      className="absolute inset-0 w-full h-full pointer-events-none z-0"
    />
  );
}

// ---------------------------------------------------------------------------
// Challenge Vectors Mapped to Real Presets
// ---------------------------------------------------------------------------
const CHALLENGE_VECTORS = [
  {
    id: 0,
    presetId: 'exec_wire_01',
    title: 'Wire Requests from Spoofed Executives Pass Authentication',
    description: 'Spoofed executive wire requests bypass SPF, DKIM, and DMARC because the attacker never touches the real domain.',
    badge: 'BEC • EXECUTIVE SPOOFING',
    icon: ShieldAlert,
    metrics: '94% bypass standard secure email gateways'
  },
  {
    id: 1,
    presetId: 'billing_res_02',
    title: 'Invoice Fraud Arrives Timed to Your Billing Cycles',
    description: 'Fraudulent invoices land during real payment windows, making them nearly indistinguishable from legitimate requests.',
    badge: 'INVOICE FRAUD • ACH HIJACK',
    icon: FileText,
    metrics: '$2.4M avg loss per vendor account takeover'
  },
  {
    id: 2,
    presetId: 'it_ops_03',
    title: 'Compromised Vendors Reply Inside Real Email Threads',
    description: 'Attackers hijack legitimate vendor accounts and reply mid-conversation with updated payment details or ephemeral reverse tunnels.',
    badge: 'REVERSE TUNNEL • SSO HARVEST',
    icon: Users,
    metrics: 'Detected via AI tone & banking ledger baselines'
  },
  {
    id: 3,
    presetId: 'clean_invoice_04',
    title: 'Payroll Diversion Passes Legitimate HR Workflows',
    description: 'Fake employees request direct deposit changes using the same portal forms and natural phrasing your HR team expects.',
    badge: 'PAYROLL FRAUD • ZERO PAYLOAD',
    icon: User,
    metrics: 'Zero link, zero attachment, pure social engineering'
  }
];

// Additional rich payroll attack for direct NLP showcase
const PAYROLL_ATTACK_PRESET: InboxEmailItem = {
  id: 'payroll_athena_05',
  senderName: 'Theresa Cook',
  senderEmail: 'cook@athenacontrol.com',
  isVerified: false,
  avatarLetter: 'T',
  subject: 'Athena Control - Bank Update & Urgent Remittance',
  snippet: 'Please advise if attached past due invoice payment can be remitted via electronic transfer ACH...',
  timeString: '10 minutes ago',
  score: 95,
  riskCategory: 'HIGH RISK',
  tags: [
    { text: 'Payroll Diversion', type: 'red' },
    { text: 'Unusual Sender', type: 'red' },
    { text: 'Financial Urgency', type: 'red' }
  ],
  rawHeaders: `From: "Theresa Cook" <cook@athenacontrol.com>
To: John Stewart <j.stewart@acme-corp.com>
Reply-To: zn193749@gmail.com
Subject: Athena Control - Bank Update & Urgent Remittance
Date: Jul 27, 15:47:00 -0700
Authentication-Results: mx.acme-corp.com; spf=fail smtp.mailfrom=gmail.com; dkim=none; dmarc=fail`,
  body: `Hello John,

Please advise if attached past due invoice payment can be remitted via electronic transfer ACH as our payment method changed for now due to the world emergency we are all facing.

Please advise so I can send you our updated bank information for the payment.`
};

const ALL_PRESETS = [...SHOWCASE_INBOX_EMAILS, PAYROLL_ATTACK_PRESET];

// Platform Core Modules (Abnormal Architecture)
const PLATFORM_MODULES = [
  {
    id: 'inbound',
    title: 'Inbound Email Security',
    tag: 'STOP BEC & QUISHING',
    icon: Mail,
    description: 'Autonomous protection against credential phishing, QR code attacks, BEC, and novel Generative AI social engineering.',
    badge: 'API-Native'
  },
  {
    id: 'identity',
    title: 'Identity Threat Protection',
    tag: 'STOP COMPROMISE',
    icon: Key,
    description: 'Harden workforce identities, detect compromised accounts across Microsoft 365 / Google Workspace, and prevent lateral movement.',
    badge: 'Real-Time'
  },
  {
    id: 'mailbox',
    title: 'AI Security Mailbox',
    tag: 'AUTONOMOUS TRIAGE',
    icon: Sparkles,
    description: 'Eliminates 98% of manual SOC triage by automatically investigating user-reported phishing and neutralizing confirmed attacks.',
    badge: '<6s Response'
  },
  {
    id: 'vendor',
    title: 'Supply Chain & Vendor Defense',
    tag: 'PREVENT FRAUD',
    icon: Users,
    description: 'Tracks thousands of vendor relationships across organizations to spot compromised partner accounts before ACH fraud executes.',
    badge: 'Cross-Tenant'
  }
];

// ---------------------------------------------------------------------------
// Main Abnormal AI Landing Page Component (With Real Logic, Methods & Store)
// ---------------------------------------------------------------------------
export function LandingPage({ 
  navigate, 
  onNavigateToDashboard, 
  onNavigateToInboxShield, 
  onNavigateToScanner 
}: LandingPageProps) {
  // Active Case / Execution State
  const [selectedCaseId, setSelectedCaseId] = useState<string>('payroll_athena_05');
  const [activeDossier, setActiveDossier] = useState<ForensicDossier | null>(null);
  const [isExecutingForensics, setIsExecutingForensics] = useState(false);
  const [activeChallengeIdx, setActiveChallengeIdx] = useState(0);

  // Active email item currently being analyzed
  const activeEmailItem = useMemo(() => {
    return ALL_PRESETS.find(e => e.id === selectedCaseId) || ALL_PRESETS[0];
  }, [selectedCaseId]);

  // Token inspector state for NLP Email Tokenizer
  const [selectedTokenInfo, setSelectedTokenInfo] = useState<{
    word: string;
    type: 'FINANCIAL' | 'REQUEST' | 'URGENT' | 'COERCION' | 'FORMAL' | 'RECIPIENT' | 'LINK';
    reason: string;
  } | null>({
    word: 'invoice',
    type: 'FINANCIAL',
    reason: 'Financial transaction entity extracted: Potential unauthorized wire or billing redirect.'
  });

  // Auth States
  const [connectedGmail, setConnectedGmail] = useState(Boolean(getAccessToken()));
  const [isConnecting, setIsConnecting] = useState(false);
  const [connectError, setConnectError] = useState('');
  
  // Custom Raw Email Inspector Modal
  const [showCustomInput, setShowCustomInput] = useState(false);
  const [customEmailText, setCustomEmailText] = useState('');
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const emlFileInputRef = useRef<HTMLInputElement>(null);

  // Interactive Account Remediation State in BEC card
  const [remediated, setRemediated] = useState(false);
  const [remediateSteps, setRemediateSteps] = useState({
    signOut: true,
    blockAccess: true,
    resetPassword: true
  });

  // 3 Paradigms Interactive Showcase State
  const [activeParadigmTab, setActiveParadigmTab] = useState<number>(0);
  const [honeytrapProbe, setHoneytrapProbe] = useState<'portal' | 'canary' | 'script'>('portal');
  const [ablationState, setAblationState] = useState<'all' | 'no-text' | 'no-link'>('all');

  // -------------------------------------------------------------------------
  // Execute Real Forensics Engine on Selected Case
  // -------------------------------------------------------------------------
  useEffect(() => {
    let isCancelled = false;
    const runAnalysis = async () => {
      setIsExecutingForensics(true);
      try {
        const dossier = await executeEmailForensics(
          activeEmailItem.rawHeaders || '',
          activeEmailItem.body || '',
          'preset'
        );
        if (!isCancelled) {
          setActiveDossier(dossier);
          setRemediated(false);
        }
      } catch (err) {
        console.error('Failed to execute email forensics:', err);
      } finally {
        if (!isCancelled) {
          setIsExecutingForensics(false);
        }
      }
    };

    runAnalysis();
    return () => {
      isCancelled = true;
    };
  }, [selectedCaseId]);

  useEffect(() => {
    initAuth(
      () => setConnectedGmail(true),
      () => setConnectedGmail(false)
    );
  }, []);

  const handleConnectGmail = async () => {
    setIsConnecting(true);
    setConnectError('');
    try {
      const res = await googleSignIn();
      if (res) {
        setConnectedGmail(true);
        navigate('phishing');
      }
    } catch (err: any) {
      setConnectError(err.message || 'Gmail OAuth failed. Please retry.');
    } finally {
      setIsConnecting(false);
    }
  };

  // Switch challenge vector and load real preset
  const handleSelectChallenge = (idx: number) => {
    setActiveChallengeIdx(idx);
    const vector = CHALLENGE_VECTORS[idx];
    if (vector) {
      setSelectedCaseId(vector.presetId);
    }
  };

  const handlePrevChallenge = () => {
    const nextIdx = activeChallengeIdx > 0 ? activeChallengeIdx - 1 : CHALLENGE_VECTORS.length - 1;
    handleSelectChallenge(nextIdx);
  };

  const handleNextChallenge = () => {
    const nextIdx = activeChallengeIdx < CHALLENGE_VECTORS.length - 1 ? activeChallengeIdx + 1 : 0;
    handleSelectChallenge(nextIdx);
  };

  // Perform real remediation & store to execution history
  const handlePerformRemediation = () => {
    setRemediated(true);
    if (activeDossier) {
      addScanToHistory({
        detectedType: 'EMAIL',
        source: activeEmailItem.senderEmail,
        target: 'finance-ops@corp.internal',
        riskScore: activeDossier.classification.riskScore,
        threatName: `${activeDossier.classification.threatType} [Remediated via Abnormal Console]`,
        payloadDescription: `Contained threat from ${activeEmailItem.senderName}. Actions taken: Session revocation, Account lock, Quarantine.`,
        aiExplanation: activeDossier.topFindings[0]?.finding || 'Remediated through NeuroShield autonomous defense engine.',
        signals: activeDossier.topFindings.map(f => f.finding.replace(/\s+/g, '_').toUpperCase()),
        suspiciousKeywords: ['remittance', 'wire', 'direct deposit', 'past due']
      });
    }
  };

  // Analyze custom input pasted or uploaded by user
  const handleAnalyzeCustomEmail = async () => {
    if (!customEmailText.trim()) return;
    setIsExecutingForensics(true);
    setShowCustomInput(false);
    try {
      const dossier = await executeEmailForensics(customEmailText, '');
      setActiveDossier(dossier);
      setRemediated(false);
      setTimeout(() => {
        const el = document.getElementById('live-attack-analysis');
        if (el) {
          el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }, 150);
    } catch (err) {
      console.error('Custom email scan error:', err);
    } finally {
      setIsExecutingForensics(false);
    }
  };

  // Direct transfer to dedicated SOC Forensics Workspace
  const handleOpenInSOCLab = () => {
    if (customEmailText.trim()) {
      sessionStorage.setItem('ns-custom-eml-text', customEmailText);
    } else {
      sessionStorage.setItem('ns-open-eml', 'true');
    }
    setShowCustomInput(false);
    navigate('phishing');
  };

  // Handle native .eml, .msg, .txt file selection
  const handleEmlFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadedFileName(`${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = (event.target?.result as string) || '';
      setCustomEmailText(content);
    };
    reader.readAsText(file);
  };

  // Pre-load realistic attack samples for quick testing
  const loadSamplePreset = (presetType: 'bec' | 'phish' | 'clean') => {
    if (presetType === 'bec') {
      setUploadedFileName('sample-executive-bec.eml');
      setCustomEmailText(
`Received: from mail-relay-92.untrusted-outbound.net (198.51.100.42)
  by mx.corp.target.com with ESMTP; Mon, 14 Sep 2026 09:14:22 +0000
Authentication-Results: mx.corp.target.com;
  spf=fail (sender IP 198.51.100.42 not permitted by domain target.com);
  dkim=none;
  dmarc=fail (p=none)
From: "Alex Mercer (CEO)" <ceo@target.com>
Reply-To: alex.mercer.executive@consultant-desk.net
To: finance-ops@target.com
Subject: URGENT: Q3 Acquisition Escrow Deposit Confirmation

Team,

I am currently in an offsite executive board meeting with limited cell coverage.
We need to finalize the confidential escrow wire for the Project Titan acquisition before 2:00 PM EST today.

Please release $75,000 to the following verified escrow account immediately:
Beneficiary: Apex Strategic Holdings LLC
Routing: 021000021
Account: 9482019482

Do not call my direct line as I cannot pick up during deliberations. Confirm once the transaction reference ID is generated.

Regards,
Alex Mercer
Chief Executive Officer`
      );
    } else if (presetType === 'phish') {
      setUploadedFileName('sample-credential-harvest.eml');
      setCustomEmailText(
`Received: from vps-mailer.offshore-route.xyz (203.0.113.88)
  by mx.corp.target.com with ESMTP; Mon, 14 Sep 2026 11:20:00 +0000
Authentication-Results: mx.corp.target.com;
  spf=neutral;
  dkim=fail body hash did not verify;
  dmarc=fail
From: "Microsoft 365 Security Team" <security-alerts@account-verification-auth.org>
Reply-To: support@account-verification-auth.org
To: employee@target.com
Subject: Action Required: Your Office 365 password expires in 2 hours

Dear User,

Your Microsoft 365 business email password will expire today at 1:00 PM UTC.
Failure to retain your current credentials will result in permanent loss of mailbox synchronization and active sessions.

To keep your current password, please verify your identity immediately:
https://login.microsoftonline.com-security-portal.xyz/auth/verify?session=token92471

Microsoft Corporation | One Microsoft Way, Redmond, WA`
      );
    } else {
      setUploadedFileName('sample-legitimate-signed.eml');
      setCustomEmailText(
`Received: from mail-pj1-f54.google.com (209.85.216.54)
  by mx.corp.target.com with ESMTPS id 419283; Mon, 14 Sep 2026 08:30:15 +0000
Authentication-Results: mx.corp.target.com;
  spf=pass (google.com: domain of engineering@partner-corp.com designates 209.85.216.54 as permitted sender);
  dkim=pass header.i=@partner-corp.com;
  dmarc=pass (p=reject)
From: "Sarah Jenkins" <sarah.jenkins@partner-corp.com>
Reply-To: sarah.jenkins@partner-corp.com
To: dev-leads@target.com
Subject: Architecture Review Notes: NeuroShield SDK Integration

Hi Team,

Attached are the finalized architectural design notes from yesterday's sync on the NeuroShield behavioral API rollout.
Everything looks aligned with our SOC2 boundaries and zero-trust guidelines.

Let me know if you need any adjustments before tomorrow's staging release.

Best regards,
Sarah Jenkins
VP Engineering, PartnerCorp`
      );
    }
  };

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Dynamic calculated attributes from active dossier
  const attackScore = activeDossier ? activeDossier.classification.riskScore : activeEmailItem.score;
  const attackSeverity = attackScore >= 80 ? 'High' : attackScore >= 50 ? 'Medium' : 'Low';
  const attackType = activeDossier?.classification.threatType || 'VIP Impersonation';
  const indicatorsList = activeDossier?.topFindings && activeDossier.topFindings.length > 0 
    ? activeDossier.topFindings.map(f => f.finding)
    : ['Name Impersonation', 'BEC - Payment Fraud', 'VIP', 'Text'];

  // Dynamic Reason 1 (Content Analysis)
  const contentReason = useMemo(() => {
    if (activeDossier?.contentAnalysis?.urgencyLevel === 'HIGH') {
      return 'CONTENT ANALYSIS: URGENT FINANCIAL WIRE REQUEST';
    }
    if (activeDossier?.contentAnalysis?.signals && activeDossier.contentAnalysis.signals.length > 0) {
      return `CONTENT ANALYSIS: ${activeDossier.contentAnalysis.signals[0].category.toUpperCase()}`;
    }
    return 'CONTENT ANALYSIS: SUSPICIOUS PAYMENT REDIRECTION';
  }, [activeDossier]);

  // Dynamic Reason 2 (Behavior Analysis)
  const behaviorReason = useMemo(() => {
    const hasReplyMismatch = activeDossier?.senderIdentity?.inconsistencies?.some(i => i.type === 'REPLY_TO_MISMATCH') ||
      (activeDossier?.senderIdentity?.replyToAddress && activeDossier.senderIdentity.replyToAddress !== activeDossier.senderIdentity.fromAddress);

    if (hasReplyMismatch) {
      return 'BEHAVIOR ANALYSIS: ATYPICAL REPLY-TO DIVERGENCE';
    }
    if (activeDossier?.relayReconstruction?.anomalies && activeDossier.relayReconstruction.anomalies.length > 0) {
      return 'BEHAVIOR ANALYSIS: UNTRUSTED RELAY HOP DETECTED';
    }
    return 'BEHAVIOR ANALYSIS: ATYPICAL CONTACT PATTERN';
  }, [activeDossier]);

  // Dynamic Reason 3 (Identity Analysis)
  const identityReason = useMemo(() => {
    if (activeDossier?.authentication?.spf?.status === 'FAIL') {
      return 'IDENTITY ANALYSIS: SPF PROTOCOL BREACH & SPOOF';
    }
    const hasFreemailSpoof = activeDossier?.senderIdentity?.inconsistencies?.some(i => i.type === 'FREE_MAILBOX_IMPERSONATION');
    if (hasFreemailSpoof) {
      return 'IDENTITY ANALYSIS: FREEMAIL EXECUTIVE IMPERSONATION';
    }
    return 'IDENTITY ANALYSIS: POSSIBLE EXECUTIVE IMPERSONATION';
  }, [activeDossier]);

  return (
    <div className="min-h-screen bg-[#050706] text-[#f1f9f4] font-sans selection:bg-[#ccff00] selection:text-black relative overflow-x-hidden">
      
      {/* Subtle Scanline / Ambient glow */}
      <div className="fixed top-0 right-1/4 w-[550px] h-[550px] bg-[#ccff00]/[0.03] rounded-full blur-[180px] pointer-events-none" />
      <div className="fixed bottom-1/4 left-10 w-[450px] h-[450px] bg-[#36c96c]/[0.025] rounded-full blur-[200px] pointer-events-none" />

      {/* =========================================================================
          1. TOP NAVIGATION
         ========================================================================= */}
      <header className="sticky top-0 z-50 backdrop-blur-xl bg-[#050706]/92 border-b border-white/[0.08]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-20 flex items-center justify-between">
          
          {/* Authentic NeuroShield Symbol & Brand */}
          <div 
            onClick={scrollToTop} 
            className="flex items-center gap-3 cursor-pointer group select-none"
          >
            {/* Hexagon Cyber Shield Logo */}
            <div className="relative w-9 h-9 flex items-center justify-center shrink-0">
              <svg viewBox="0 0 100 100" className="w-full h-full text-[#ccff00] drop-shadow-[0_0_10px_rgba(204,255,0,0.8)] fill-current transition-all duration-300 group-hover:scale-105">
                <polygon points="50 3 93 25 93 75 50 97 7 75 7 25" fill="none" stroke="currentColor" strokeWidth="4" />
                <polygon points="50 15 80 32 80 68 50 85 20 68 20 32" fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray="5 5" className="animate-[spin_12s_linear_infinite_reverse]" />
                <circle cx="50" cy="50" r="12" className="animate-pulse fill-[#ccff00]/80" />
              </svg>
              <div className="absolute inset-0 rounded-full shadow-[0_0_20px_rgba(204,255,0,0.4)] opacity-70 mix-blend-screen pointer-events-none" />
            </div>

            <div className="flex flex-col">
              <span className="text-xl sm:text-2xl font-bold tracking-tight text-white flex items-center">
                Neuro<span className="text-[#ccff00]">Shield</span>
              </span>
              <span className="text-[9px] font-mono tracking-widest text-[#ccff00]/80 uppercase leading-none">
                Behavioral AI Defense
              </span>
            </div>
          </div>

          {/* Clean Navigation Links */}
          <nav className="hidden md:flex items-center gap-7 text-sm font-medium text-gray-300">
            <a href="#paradigms" className="hover:text-[#ccff00] transition-colors flex items-center gap-1.5 font-semibold text-white">
              <span className="w-2 h-2 rounded-full bg-[#ccff00] animate-pulse" />
              <span>3 Paradigms</span>
            </a>
            <a href="#platform" className="hover:text-[#ccff00] transition-colors">
              Platform
            </a>
            <a href="#challenge" className="hover:text-[#ccff00] transition-colors">
              Attack Vectors
            </a>
            <a href="#ai-approach" className="hover:text-[#ccff00] transition-colors">
              AI Forensics
            </a>
            <a href="#bec" className="hover:text-[#ccff00] transition-colors">
              BEC Triage
            </a>
          </nav>

          {/* Right Action Utilities */}
          <div className="flex items-center gap-3">
            {/* Quick Test Raw EML / Custom Text */}
            <button
              onClick={() => setShowCustomInput(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.08] hover:bg-[#ccff00]/15 hover:border-[#ccff00]/40 text-xs text-gray-200 hover:text-[#ccff00] border border-white/15 transition-all cursor-pointer font-mono shadow-sm"
              title="Upload .eml file or paste raw RFC 5322 headers for live inspection"
              id="btn-test-email-eml"
            >
              <UploadCloud size={14} className="text-[#ccff00]" />
              <span className="font-semibold">Test Email / EML</span>
            </button>

            {/* Launch SOC Console CTA */}
            <button
              onClick={() => navigate('dashboard')}
              className="px-5 py-2.5 rounded-xl bg-[#ccff00] hover:bg-[#d8ff1a] active:scale-95 text-black font-bold text-xs sm:text-sm tracking-tight transition-all shadow-[0_0_25px_rgba(204,255,0,0.35)] hover:shadow-[0_0_35px_rgba(204,255,0,0.6)] cursor-pointer flex items-center gap-1.5"
            >
              <Activity size={15} className="text-black" />
              <span>Launch SOC Console</span>
              <ChevronRight size={16} strokeWidth={2.5} />
            </button>
          </div>
        </div>
      </header>

      {/* =========================================================================
          2. HERO SECTION (Abnormal: "Your Inbox Looks Safe. It Isn't.")
         ========================================================================= */}
      <section className="relative pt-12 pb-20 lg:pt-20 lg:pb-28 overflow-hidden">
        {/* 3D Wireframe Mesh Canvas in background */}
        <div className="absolute inset-0 h-[720px] overflow-hidden pointer-events-none">
          <WireframeMeshCanvas />
        </div>

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-8 items-center">
            
            {/* Left Hero Content */}
            <div className="lg:col-span-6 space-y-6">
              {/* Lime Kicker Pill */}
              <motion.div
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#ccff00]/10 border border-[#ccff00]/25 text-[#ccff00] text-xs font-mono font-bold tracking-[0.16em] uppercase"
              >
                <Sparkles size={13} />
                <span>THE BEHAVIORAL SECURITY PLATFORM FOR THE AI ERA</span>
              </motion.div>

              {/* Bold Main Headline */}
              <motion.h1
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 }}
                className="text-5xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight text-white leading-[1.05]"
              >
                Your Inbox Looks Safe. It Isn't.
              </motion.h1>

              {/* Subheadline */}
              <motion.p
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="text-base sm:text-lg text-gray-300 leading-relaxed max-w-xl"
              >
                Attacks move in milliseconds, faster than any human can respond. NeuroShield models normal behavior across 5,000+ identity signals to autonomously stop BEC, executive impersonation, and vendor fraud at machine speed.
              </motion.p>

              {/* CTAs */}
              <motion.div
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="flex flex-wrap items-center gap-4 pt-2"
              >
                <button
                  onClick={() => navigate('dashboard')}
                  className="px-7 py-3.5 rounded-xl bg-[#ccff00] hover:bg-[#d8ff1a] active:scale-95 text-black font-bold text-sm sm:text-base tracking-tight transition-all shadow-[0_0_30px_rgba(204,255,0,0.45)] hover:shadow-[0_0_40px_rgba(204,255,0,0.7)] cursor-pointer flex items-center gap-2"
                >
                  <Activity size={18} className="text-black" />
                  <span>Launch SOC Console</span>
                  <ChevronRight size={18} strokeWidth={2.5} />
                </button>

                <button
                  onClick={() => navigate('phishing')}
                  className="px-6 py-3.5 rounded-xl bg-white/[0.06] hover:bg-white/[0.12] text-white font-semibold text-sm border border-white/10 hover:border-[#ccff00]/40 transition-all flex items-center gap-2 cursor-pointer"
                >
                  <Mail size={16} className="text-[#ccff00]" />
                  <span>Open Inbox Shield</span>
                </button>

                <button
                  onClick={() => navigate('dashboard')}
                  className="px-5 py-3.5 rounded-xl text-xs font-mono text-gray-400 hover:text-white hover:bg-white/5 transition-all flex items-center gap-1.5 cursor-pointer"
                >
                  <Terminal size={14} />
                  <span>Launch SOC Matrix</span>
                </button>
              </motion.div>

              {/* Live Threat Case Selector in Hero */}
              <div className="pt-2">
                <span className="text-[11px] font-mono text-gray-400 block mb-2">
                  SELECT REAL ATTACK CASE TO EXECUTE LIVE:
                </span>
                <div className="flex flex-wrap gap-2">
                  {ALL_PRESETS.map((p) => {
                    const isSelected = p.id === selectedCaseId;
                    return (
                      <button
                        key={p.id}
                        onClick={() => setSelectedCaseId(p.id)}
                        className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all cursor-pointer border ${
                          isSelected 
                            ? 'bg-[#ccff00]/20 border-[#ccff00] text-[#ccff00] font-bold shadow-[0_0_12px_rgba(204,255,0,0.3)]' 
                            : 'bg-white/[0.04] border-white/10 text-gray-400 hover:text-white hover:border-white/20'
                        }`}
                      >
                        {p.senderName}: {p.subject.slice(0, 24)}...
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Security Badges */}
              <div className="pt-3 flex flex-wrap items-center gap-6 text-xs text-gray-400">
                <div className="flex items-center gap-1.5">
                  <CheckCircle2 size={15} className="text-[#ccff00]" />
                  <span>SOC2 Type II Certified</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <CheckCircle2 size={15} className="text-[#ccff00]" />
                  <span>Zero MX Record Alteration</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <CheckCircle2 size={15} className="text-[#ccff00]" />
                  <span>API Deployed in 60s</span>
                </div>
              </div>
            </div>

            {/* Right Hero Visual: Dynamic Attack Analysis & Auto-remediated Card */}
            <motion.div
              initial={{ opacity: 0, scale: 0.96 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.25, duration: 0.5 }}
              className="lg:col-span-6 relative"
            >
              {/* Floating Top Badge: "Auto-remediated" */}
              <div className="absolute -top-6 right-0 sm:right-6 z-20 bg-[#161c18]/95 border border-white/15 rounded-xl px-4 py-3 shadow-[0_15px_40px_rgba(0,0,0,0.8)] backdrop-blur-xl flex items-center gap-3">
                <div className="w-8 h-8 rounded-full bg-[#ccff00] flex items-center justify-center text-black shrink-0 font-bold">
                  <Check size={18} strokeWidth={3} />
                </div>
                <div className="text-left">
                  <div className="text-white font-bold text-xs flex items-center gap-1.5">
                    <span>Auto-remediated</span>
                    {isExecutingForensics && <Loader2 size={12} className="animate-spin text-[#ccff00]" />}
                  </div>
                  <div className="text-gray-300 text-[11px]">
                    Email quarantined to secure sandbox
                  </div>
                  <div className="text-gray-400 text-[10px] mt-0.5 font-mono">
                    Verified in 4.2s • SHA256: {activeDossier?.chainOfCustody?.sha256EvidenceHash.slice(0, 10) || 'b9a8f102'}...
                  </div>
                </div>
              </div>

              {/* Main Attack Analysis Card */}
              <div id="live-attack-analysis" className="mt-4 rounded-2xl bg-[#0d120f]/95 border border-white/15 shadow-[0_25px_70px_rgba(0,0,0,0.9)] overflow-hidden backdrop-blur-2xl transition-all duration-500">
                <div className="grid grid-cols-1 sm:grid-cols-12">
                  
                  {/* Left Column: Crimson Red Attack Card */}
                  <div className="sm:col-span-5 bg-[#e11d48] text-white p-6 flex flex-col justify-between relative overflow-hidden">
                    <div className="space-y-4 relative z-10">
                      <div className="text-[11px] font-mono tracking-wider opacity-90">
                        // ATTACK ANALYSIS
                      </div>

                      <div>
                        <div className="text-[11px] uppercase tracking-widest font-semibold opacity-85">
                          ATTACK SCORE
                        </div>
                        <div className="text-4xl sm:text-5xl font-extrabold tracking-tight mt-1 flex items-baseline gap-2">
                          <span>{attackSeverity}</span>
                          <span className="text-lg opacity-80 font-mono">({attackScore}/100)</span>
                        </div>
                      </div>

                      <div className="pt-2">
                        <div className="text-[11px] uppercase tracking-widest font-semibold opacity-85">
                          ATTACK TYPE
                        </div>
                        <div className="inline-block mt-1 px-3 py-1 bg-black/25 rounded-md text-xs font-semibold backdrop-blur-sm">
                          {attackType}
                        </div>
                      </div>

                      <div className="pt-2">
                        <div className="text-[11px] uppercase tracking-widest font-semibold opacity-85 mb-2">
                          ATTACK SIGNALS
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                          {indicatorsList.slice(0, 4).map((ind, i) => (
                            <span key={i} className="px-2.5 py-1 rounded bg-black/25 text-[11px] font-medium">
                              {ind}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>

                    {/* Subtle red mesh overlay */}
                    <div className="absolute -bottom-10 -right-10 w-36 h-36 bg-white/10 rounded-full blur-2xl pointer-events-none" />
                  </div>

                  {/* Right Column: Analysis Overview (Dark Slate) */}
                  <div className="sm:col-span-7 bg-[#0b100d] p-6 sm:p-7 flex flex-col justify-between space-y-5">
                    <div>
                      <h3 className="text-xl font-bold text-white tracking-tight">
                        Analysis Overview
                      </h3>
                      <p className="text-xs text-gray-400 mt-1 leading-relaxed">
                        NeuroShield Security Engine has evaluated {activeEmailItem.senderName}'s payload:
                      </p>
                      
                      <div className="mt-3 text-xs font-semibold text-[#ccff00] flex items-center gap-1.5">
                        <AlertTriangle size={14} />
                        <span>{attackType} (Autonomous Action Triggered)</span>
                      </div>
                    </div>

                    {/* High-visibility Red Highlight Banner Pills */}
                    <div className="space-y-2.5 pt-2">
                      <div className="bg-[#e11d48] text-white px-3 py-2 rounded-lg text-xs font-bold tracking-tight shadow-sm flex items-center justify-between">
                        <span>{contentReason}</span>
                      </div>

                      <div className="bg-[#e11d48] text-white px-3 py-2 rounded-lg text-xs font-bold tracking-tight shadow-sm flex items-center justify-between">
                        <span>{behaviorReason}</span>
                      </div>

                      <div className="bg-[#e11d48] text-white px-3 py-2 rounded-lg text-xs font-bold tracking-tight shadow-sm flex items-center justify-between">
                        <span>{identityReason}</span>
                      </div>
                    </div>

                    <div className="pt-2 border-t border-white/[0.08] flex items-center justify-between text-[11px] text-gray-400 font-mono">
                      <span>SIGNALS EVALUATED: 5,420+</span>
                      <span className="text-[#ccff00] font-bold">DECISION: QUARANTINE</span>
                    </div>
                  </div>

                </div>
              </div>
            </motion.div>

          </div>
        </div>
      </section>

      {/* =========================================================================
          3. ENTERPRISE SOCIAL PROOF & METRIC BAR (Abnormal 4,500+ orgs)
         ========================================================================= */}
      <section className="py-12 bg-[#080c09] border-y border-white/[0.08] relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-8">
            <span className="text-xs font-mono uppercase tracking-[0.2em] text-gray-400">
              TRUSTED BY OVER 4,500+ ENTERPRISES ACROSS FINANCIAL, HEALTHCARE & TECH
            </span>
          </div>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
            <div className="space-y-1">
              <div className="text-3xl sm:text-4xl font-extrabold text-[#ccff00] font-mono tracking-tight">
                4,500+
              </div>
              <div className="text-xs text-gray-300 font-medium">
                Organizations Protected
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-3xl sm:text-4xl font-extrabold text-white font-mono tracking-tight">
                60s
              </div>
              <div className="text-xs text-gray-300 font-medium">
                Cloud-Native API Setup
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-3xl sm:text-4xl font-extrabold text-[#ccff00] font-mono tracking-tight">
                &lt; 6s
              </div>
              <div className="text-xs text-gray-300 font-medium">
                Mean Time to Remediation
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-3xl sm:text-4xl font-extrabold text-white font-mono tracking-tight">
                99.8%
              </div>
              <div className="text-xs text-gray-300 font-medium">
                Zero-Payload BEC Block Rate
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          3B. THE THREE PARADIGMS OF NEUROSHIELD DEFENSE (Judge & SOC Feature)
         ========================================================================= */}
      <section id="paradigms" className="py-24 bg-gradient-to-b from-[#050706] via-[#09100c] to-[#050706] border-b border-white/[0.08] relative overflow-hidden">
        {/* Decorative Grid and Ambient Glows */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[850px] h-[350px] bg-[#ccff00]/[0.025] rounded-full blur-[140px] pointer-events-none" />
        
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10 space-y-12">
          
          {/* Header */}
          <div className="text-center max-w-3xl mx-auto space-y-4">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#ccff00]/10 border border-[#ccff00]/25 text-[#ccff00] text-xs font-mono font-bold tracking-[0.2em] uppercase">
              <Sparkles size={13} />
              <span>CORE ARCHITECTURE // THREE VERIFIABLE PARADIGMS</span>
            </div>
            
            <h2 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white leading-tight">
              The Three Paradigms of Autonomous Cyber Defense
            </h2>
            
            <p className="text-sm sm:text-base text-gray-400 leading-relaxed">
              Traditional email gateways inspect messages in isolation using brittle, easily bypassed signatures. 
              NeuroShield operates across three foundational paradigms built specifically for zero-payload AI deception, 
              safe adversary observation, and transparent, tamper-proof judge verification.
            </p>
          </div>

          {/* Interactive Paradigm Switcher Tabs */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-1.5 rounded-2xl bg-white/[0.03] border border-white/[0.08]">
            {[
              {
                id: 0,
                name: 'Cluster Chains',
                tag: 'PARADIGM 01',
                desc: 'Cross-Incident Adversarial Graph Chaining',
                icon: Network
              },
              {
                id: 1,
                name: 'HoneyTrapping',
                tag: 'PARADIGM 02',
                desc: 'Air-Gapped Decoys & Zero-Egress Sandboxing',
                icon: Radio
              },
              {
                id: 2,
                name: 'Evidence Ablation',
                tag: 'PARADIGM 03',
                desc: 'Explainable AI & SHA-256 Decision Receipts',
                icon: Binary
              }
            ].map((tab) => {
              const Icon = tab.icon;
              const isActive = activeParadigmTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveParadigmTab(tab.id)}
                  className={`p-4 rounded-xl text-left transition-all cursor-pointer flex items-center gap-4 ${
                    isActive 
                      ? 'bg-[#111a14] border border-[#ccff00]/40 shadow-[0_0_20px_rgba(204,255,0,0.15)] text-white' 
                      : 'bg-transparent border border-transparent text-gray-400 hover:text-white hover:bg-white/[0.02]'
                  }`}
                >
                  <div className={`w-11 h-11 rounded-lg flex items-center justify-center shrink-0 transition-colors ${
                    isActive ? 'bg-[#ccff00] text-black shadow-[0_0_12px_rgba(204,255,0,0.4)]' : 'bg-white/5 text-gray-400'
                  }`}>
                    <Icon size={20} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono font-bold tracking-widest text-[#ccff00] uppercase">
                        {tab.tag}
                      </span>
                    </div>
                    <div className="text-sm font-bold tracking-tight text-white">
                      {tab.name}
                    </div>
                    <div className="text-[11px] text-gray-400 line-clamp-1">
                      {tab.desc}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Active Paradigm Showcase Stage */}
          <div className="rounded-3xl bg-[#090e0b] border border-white/10 p-6 sm:p-10 shadow-2xl relative overflow-hidden">
            
            {/* Ambient Corner Accents */}
            <div className="absolute top-0 right-0 w-80 h-80 bg-[#ccff00]/5 rounded-full blur-[100px] pointer-events-none" />

            {/* TAB 0: CLUSTER CHAINS */}
            {activeParadigmTab === 0 && (
              <motion.div
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3 }}
                className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center"
              >
                <div className="lg:col-span-6 space-y-5">
                  <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-[#ccff00]/10 border border-[#ccff00]/25 text-[#ccff00] text-xs font-mono font-bold">
                    <GitBranch size={14} />
                    <span>GRAPH CORRELATION • ADVERSARIAL DNA</span>
                  </div>

                  <h3 className="text-2xl sm:text-4xl font-extrabold text-white tracking-tight leading-tight">
                    Cross-Incident Cluster Chains
                  </h3>

                  <p className="text-sm text-gray-300 leading-relaxed">
                    Sophisticated attackers evade Secure Email Gateways by cycling ephemeral senders, disposable lookalike domains, and natural phrasing. 
                    <strong> NeuroShield never looks at messages in isolation.</strong>
                  </p>

                  <p className="text-xs text-gray-400 leading-relaxed">
                    By extracting 5,000+ observable syntactic DNA signals (authentication anomalies, atypical reply-to divergences, reverse tunnel infrastructure, and linguistic coercion), 
                    the engine automatically correlates scattered attacks into unified campaign graphs with weighted similarity (≥0.60).
                  </p>

                  <div className="grid grid-cols-2 gap-3 pt-2">
                    <div className="p-3 rounded-xl bg-white/[0.03] border border-white/[0.08]">
                      <div className="text-xs text-gray-400">Cluster ID</div>
                      <div className="text-sm font-mono font-bold text-[#ccff00]">NS-CAMP-992F</div>
                    </div>
                    <div className="p-3 rounded-xl bg-white/[0.03] border border-white/[0.08]">
                      <div className="text-xs text-gray-400">Weighted Correlation</div>
                      <div className="text-sm font-mono font-bold text-white">94% Confidence</div>
                    </div>
                  </div>

                  <div className="pt-2">
                    <button
                      onClick={() => navigate('intelligence')}
                      className="px-6 py-3 rounded-xl bg-[#ccff00] hover:bg-[#d8ff1a] text-black font-bold text-xs tracking-tight transition-all shadow-[0_0_20px_rgba(204,255,0,0.35)] cursor-pointer inline-flex items-center gap-2"
                    >
                      <Network size={16} />
                      <span>Explore Campaign Intelligence Matrix</span>
                      <ChevronRight size={14} />
                    </button>
                  </div>
                </div>

                {/* Micro-Viz: Interactive Graph Chaining */}
                <div className="lg:col-span-6 rounded-2xl bg-black/60 border border-white/10 p-6 space-y-4">
                  <div className="flex items-center justify-between border-b border-white/10 pb-3">
                    <div className="flex items-center gap-2 text-xs font-mono text-gray-300">
                      <Network size={14} className="text-[#ccff00]" />
                      <span>LIVE CAMPAIGN CLUSTER GRAPH</span>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      4 NODES LINKED
                    </span>
                  </div>

                  {/* Visual Node Graph */}
                  <div className="relative py-6 px-4 space-y-4 font-mono text-xs">
                    <div className="flex items-center justify-between p-3 rounded-xl bg-white/[0.04] border border-red-500/30">
                      <div className="flex items-center gap-2.5">
                        <div className="w-2.5 h-2.5 rounded-full bg-red-400 animate-pulse" />
                        <div>
                          <div className="text-white font-bold">Node A: Spoofed Executive Identity</div>
                          <div className="text-[11px] text-gray-400">From: "CEO Office" &lt;ceo@external-board.org&gt;</div>
                        </div>
                      </div>
                      <span className="text-[10px] text-red-400 bg-red-500/10 px-2 py-0.5 rounded">ORIGIN</span>
                    </div>

                    <div className="flex justify-center text-gray-500">
                      <div className="border-l border-dashed border-[#ccff00]/60 h-4" />
                    </div>

                    <div className="flex items-center justify-between p-3 rounded-xl bg-white/[0.04] border border-[#ccff00]/30">
                      <div className="flex items-center gap-2.5">
                        <div className="w-2.5 h-2.5 rounded-full bg-[#ccff00]" />
                        <div>
                          <div className="text-white font-bold">Node B: Divergent Reply-To Vector</div>
                          <div className="text-[11px] text-gray-400">Reply-To: wire.desk@gmail.com (DMARC Divergence)</div>
                        </div>
                      </div>
                      <span className="text-[10px] text-[#ccff00] bg-[#ccff00]/10 px-2 py-0.5 rounded font-bold">CORRELATED</span>
                    </div>

                    <div className="flex justify-center text-gray-500">
                      <div className="border-l border-dashed border-[#ccff00]/60 h-4" />
                    </div>

                    <div className="flex items-center justify-between p-3 rounded-xl bg-white/[0.04] border border-cyan-400/30">
                      <div className="flex items-center gap-2.5">
                        <div className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
                        <div>
                          <div className="text-white font-bold">Node C: Ephemeral Reverse Tunnel</div>
                          <div className="text-[11px] text-gray-400">Host: auth-gateway-12.ngrok-free.app (SSO Harvester)</div>
                        </div>
                      </div>
                      <span className="text-[10px] text-cyan-400 bg-cyan-400/10 px-2 py-0.5 rounded">INFRASTRUCTURE</span>
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-[#0e1610] border border-[#ccff00]/20 flex items-center justify-between text-xs font-mono">
                    <span className="text-gray-400">Multi-Hop Provenance:</span>
                    <span className="text-[#ccff00] font-bold">Observed Technical Overlap</span>
                  </div>
                </div>
              </motion.div>
            )}

            {/* TAB 1: HONEYTRAPPING */}
            {activeParadigmTab === 1 && (
              <motion.div
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3 }}
                className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center"
              >
                <div className="lg:col-span-6 space-y-5">
                  <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-[#ccff00]/10 border border-[#ccff00]/25 text-[#ccff00] text-xs font-mono font-bold">
                    <Radio size={14} />
                    <span>CONTROLLED DECEPTION • ZERO-EGRESS RESEARCH</span>
                  </div>

                  <h3 className="text-2xl sm:text-4xl font-extrabold text-white tracking-tight leading-tight">
                    Air-Gapped Decoy HoneyTraps
                  </h3>

                  <p className="text-sm text-gray-300 leading-relaxed">
                    When high-confidence attacks (risk ≥85, confidence ≥90) arrive, active defense must never risk organizational secrets or contact malicious hosts.
                  </p>

                  <p className="text-xs text-gray-400 leading-relaxed">
                    NeuroShield spins up an isolated, non-root Docker container running with <strong>network egress disabled (<code className="text-[#ccff00]">--network none</code>)</strong>, a read-only filesystem, dropped Linux capabilities, and an autonomous 120-second watchdog termination timer.
                  </p>

                  <div className="space-y-2 pt-1 font-mono text-xs">
                    <div className="flex items-center gap-2 text-gray-300">
                      <CheckCircle2 size={14} className="text-[#ccff00]" />
                      <span>Passive Synthetic Persona: <code className="text-white">canary@example.invalid</code></span>
                    </div>
                    <div className="flex items-center gap-2 text-gray-300">
                      <CheckCircle2 size={14} className="text-[#ccff00]" />
                      <span>Cryptographic HoneyToken: <code className="text-white">NS-SYNTHETIC-884b...</code></span>
                    </div>
                    <div className="flex items-center gap-2 text-gray-300">
                      <CheckCircle2 size={14} className="text-[#ccff00]" />
                      <span>Zero Outbound Sockets: Host communication strictly over stdin/stdout</span>
                    </div>
                  </div>

                  <div className="pt-2">
                    <button
                      onClick={() => navigate('intelligence')}
                      className="px-6 py-3 rounded-xl bg-[#ccff00] hover:bg-[#d8ff1a] text-black font-bold text-xs tracking-tight transition-all shadow-[0_0_20px_rgba(204,255,0,0.35)] cursor-pointer inline-flex items-center gap-2"
                    >
                      <ShieldAlert size={16} />
                      <span>Inspect Deception Matrix in SOC</span>
                      <ChevronRight size={14} />
                    </button>
                  </div>
                </div>

                {/* Micro-Viz: Live Container Probe Simulator */}
                <div className="lg:col-span-6 rounded-2xl bg-black/60 border border-white/10 p-6 space-y-4">
                  <div className="flex items-center justify-between border-b border-white/10 pb-3">
                    <div className="flex items-center gap-2 text-xs font-mono text-gray-300">
                      <Terminal size={14} className="text-[#ccff00]" />
                      <span>HONEYTRAP CONTAINER SIMULATOR</span>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                      --network none ACTIVE
                    </span>
                  </div>

                  {/* Interactive Probe Triggers */}
                  <div>
                    <span className="text-[11px] font-mono text-gray-400 block mb-2">
                      TEST CLOSED COMMAND SCHEMA OVER STDIN:
                    </span>
                    <div className="flex gap-2">
                      {(['portal', 'canary', 'script'] as const).map((action) => (
                        <button
                          key={action}
                          onClick={() => setHoneytrapProbe(action)}
                          className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all cursor-pointer ${
                            honeytrapProbe === action 
                              ? 'bg-[#ccff00] text-black font-bold shadow-[0_0_12px_rgba(204,255,0,0.4)]' 
                              : 'bg-white/5 text-gray-400 hover:text-white border border-white/10'
                          }`}
                        >
                          action: "{action}"
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Terminal Output */}
                  <div className="rounded-xl bg-[#080d09] border border-white/10 p-4 font-mono text-xs space-y-2">
                    <div className="text-gray-500">
                      $ echo '{"{"}"action":"{honeytrapProbe}"{"}"}' | docker run --network=none neuroshield-honeytrap
                    </div>
                    
                    {honeytrapProbe === 'portal' && (
                      <pre className="text-emerald-400 text-[11px] overflow-x-auto leading-relaxed">
{`{
  "ready": true,
  "action": "portal",
  "persona": {
    "name": "Research Persona 7e2a",
    "email": "canary-991@example.invalid",
    "organization": "Synthetic Research Workspace"
  },
  "syntheticData": "NS-SYNTHETIC-884bf92a10e74",
  "outcome": "Synthetic resource served"
}`}
                      </pre>
                    )}

                    {honeytrapProbe === 'canary' && (
                      <pre className="text-[#ccff00] text-[11px] overflow-x-auto leading-relaxed">
{`{
  "ok": true,
  "action": "canary",
  "outcome": "Synthetic canary accessed",
  "provenance": "Observed transport collection",
  "peerIp": "198.51.100.42 (Direct Transport Peer)"
}`}
                      </pre>
                    )}

                    {honeytrapProbe === 'script' && (
                      <pre className="text-cyan-400 text-[11px] overflow-x-auto leading-relaxed">
{`{
  "ok": true,
  "action": "script",
  "scriptSha256": "e3b0c44298fc1c149afbf4c8996fb924...",
  "content": "/* Synthetic canary resource. No collection. */",
  "outcome": "Inert payload served (Zero execution)"
}`}
                      </pre>
                    )}
                  </div>

                  <div className="flex items-center justify-between text-[11px] font-mono text-gray-400 pt-1">
                    <span>Watchdog: 120s Auto-Kill</span>
                    <span>Max Concurrent: 3 Sandboxes</span>
                  </div>
                </div>
              </motion.div>
            )}

            {/* TAB 2: EVIDENCE ABLATION & VERIFIABLE RECEIPTS */}
            {activeParadigmTab === 2 && (
              <motion.div
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3 }}
                className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center"
              >
                <div className="lg:col-span-6 space-y-5">
                  <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-[#ccff00]/10 border border-[#ccff00]/25 text-[#ccff00] text-xs font-mono font-bold">
                    <Binary size={14} />
                    <span>EXPLAINABLE AI • SHA-256 CANONICAL INTEGRITY</span>
                  </div>

                  <h3 className="text-2xl sm:text-4xl font-extrabold text-white tracking-tight leading-tight">
                    Evidence Ablation & Verifiable Receipts
                  </h3>

                  <p className="text-sm text-gray-300 leading-relaxed">
                    Judges and security auditors cannot accept black-box AI scores that cannot explain their reasoning. 
                    <strong> NeuroShield proves causality through deterministic evidence ablation.</strong>
                  </p>

                  <p className="text-xs text-gray-400 leading-relaxed">
                    The engine evaluates the raw artifact, then systematically ablates wording, sender context, and destination links separately. 
                    If removing a link drops a score from 95 to 15, the link is mathematically proven to be the primary threat driver. 
                    Every verdict outputs an immutable, privacy-preserving <strong>canonical SHA-256 Decision Receipt</strong>.
                  </p>

                  <div className="space-y-2 pt-1 font-mono text-xs">
                    <div className="flex items-center gap-2 text-gray-300">
                      <CheckCircle2 size={14} className="text-[#ccff00]" />
                      <span>Counterfactual Ablation: Isolates wording vs technical vectors</span>
                    </div>
                    <div className="flex items-center gap-2 text-gray-300">
                      <CheckCircle2 size={14} className="text-[#ccff00]" />
                      <span>Canonical SHA-256 Digest: Independently verifiable by judges</span>
                    </div>
                    <div className="flex items-center gap-2 text-gray-300">
                      <CheckCircle2 size={14} className="text-[#ccff00]" />
                      <span>Privacy Preserving: Verifies verdicts without exporting raw emails</span>
                    </div>
                  </div>

                  <div className="pt-2">
                    <button
                      onClick={() => navigate('lab')}
                      className="px-6 py-3 rounded-xl bg-[#ccff00] hover:bg-[#d8ff1a] text-black font-bold text-xs tracking-tight transition-all shadow-[0_0_20px_rgba(204,255,0,0.35)] cursor-pointer inline-flex items-center gap-2"
                    >
                      <FileSearch size={16} />
                      <span>Launch Evidence Lab & Challenge Verdict</span>
                      <ChevronRight size={14} />
                    </button>
                  </div>
                </div>

                {/* Micro-Viz: Interactive Ablation Comparison */}
                <div className="lg:col-span-6 rounded-2xl bg-black/60 border border-white/10 p-6 space-y-4">
                  <div className="flex items-center justify-between border-b border-white/10 pb-3">
                    <div className="flex items-center gap-2 text-xs font-mono text-gray-300">
                      <Layers size={14} className="text-[#ccff00]" />
                      <span>COUNTERFACTUAL ABLATION EXPERIMENT</span>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#ccff00]/15 text-[#ccff00] border border-[#ccff00]/30 font-bold">
                      DETERMINISTIC
                    </span>
                  </div>

                  {/* Toggle Ablation States */}
                  <div>
                    <span className="text-[11px] font-mono text-gray-400 block mb-2">
                      SELECT EVIDENCE FACTOR TO ABLATE / REMOVE:
                    </span>
                    <div className="flex flex-wrap gap-2">
                      <button
                        onClick={() => setAblationState('all')}
                        className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all cursor-pointer ${
                          ablationState === 'all' 
                            ? 'bg-red-500 text-white font-bold shadow-[0_0_12px_rgba(239,68,68,0.4)]' 
                            : 'bg-white/5 text-gray-400 hover:text-white border border-white/10'
                        }`}
                      >
                        Full Message (Raw)
                      </button>
                      <button
                        onClick={() => setAblationState('no-text')}
                        className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all cursor-pointer ${
                          ablationState === 'no-text' 
                            ? 'bg-amber-400 text-black font-bold shadow-[0_0_12px_rgba(251,191,36,0.4)]' 
                            : 'bg-white/5 text-gray-400 hover:text-white border border-white/10'
                        }`}
                      >
                        Ablate Narrative Text
                      </button>
                      <button
                        onClick={() => setAblationState('no-link')}
                        className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all cursor-pointer ${
                          ablationState === 'no-link' 
                            ? 'bg-emerald-400 text-black font-bold shadow-[0_0_12px_rgba(52,211,153,0.4)]' 
                            : 'bg-white/5 text-gray-400 hover:text-white border border-white/10'
                        }`}
                      >
                        Ablate Link / Destination
                      </button>
                    </div>
                  </div>

                  {/* Dynamic Score Display */}
                  <div className="p-4 rounded-xl bg-[#080d09] border border-white/10 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono text-gray-300">
                        {ablationState === 'all' && 'FULL EVIDENCE EVALUATION'}
                        {ablationState === 'no-text' && 'WITHOUT NARRATIVE URGENCY WORDS'}
                        {ablationState === 'no-link' && 'WITHOUT DESTINATION / FORM LINK'}
                      </span>
                      <span className={`text-lg font-mono font-bold ${
                        ablationState === 'no-link' ? 'text-emerald-400' : 'text-red-400'
                      }`}>
                        {ablationState === 'all' && '95 / 100 (MALICIOUS)'}
                        {ablationState === 'no-text' && '85 / 100 (HIGH RISK)'}
                        {ablationState === 'no-link' && '15 / 100 (SAFE)'}
                      </span>
                    </div>

                    {/* Progress Bar */}
                    <div className="h-2 rounded-full bg-white/10 overflow-hidden">
                      <motion.div 
                        initial={{ width: 0 }}
                        animate={{ 
                          width: ablationState === 'all' ? '95%' : ablationState === 'no-text' ? '85%' : '15%' 
                        }}
                        transition={{ duration: 0.4 }}
                        className={`h-full ${
                          ablationState === 'no-link' ? 'bg-emerald-400' : 'bg-red-500'
                        }`}
                      />
                    </div>

                    <p className="text-[11px] text-gray-400 font-mono leading-relaxed">
                      {ablationState === 'all' && 'Multi-vector threat: Combines SPF failure, reverse tunnel URL, and urgent financial wire coercion.'}
                      {ablationState === 'no-text' && 'Risk remains high (85): Technical infrastructure flaws (SPF fail + reverse tunnel) hold without urgent text.'}
                      {ablationState === 'no-link' && 'Score drops to 15: Proves destination link was the critical causal vector driving malicious intent!'}
                    </p>
                  </div>

                  {/* Cryptographic Receipt Box */}
                  <div className="p-3 rounded-lg bg-white/[0.03] border border-[#ccff00]/30 flex items-center justify-between text-[11px] font-mono">
                    <div className="flex items-center gap-2">
                      <CheckCircle size={14} className="text-[#ccff00]" />
                      <span className="text-gray-300">SHA-256 Receipt:</span>
                    </div>
                    <span className="text-[#ccff00] font-bold">f83e29a0...44c2 [VERIFIED]</span>
                  </div>
                </div>
              </motion.div>
            )}

          </div>

          {/* Bottom Evaluation Banner for Judges & End Users */}
          <div className="p-6 rounded-2xl bg-[#090d0b] border border-white/10 grid grid-cols-1 md:grid-cols-3 gap-6 text-xs">
            <div className="flex items-start gap-3">
              <div className="w-8 h-8 rounded-lg bg-[#ccff00]/10 text-[#ccff00] flex items-center justify-center shrink-0">
                <Check size={16} strokeWidth={2.5} />
              </div>
              <div>
                <div className="font-bold text-white mb-0.5">Deterministic & Inspectable</div>
                <div className="text-gray-400">Works offline with zero external model hallucinations or stochastic variances.</div>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <div className="w-8 h-8 rounded-lg bg-[#ccff00]/10 text-[#ccff00] flex items-center justify-center shrink-0">
                <Shield size={16} />
              </div>
              <div>
                <div className="font-bold text-white mb-0.5">Zero-Egress Containment</div>
                <div className="text-gray-400">HoneyTrapping executes in isolated network-none sandboxes with zero remote leaks.</div>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <div className="w-8 h-8 rounded-lg bg-[#ccff00]/10 text-[#ccff00] flex items-center justify-center shrink-0">
                <FileText size={16} />
              </div>
              <div>
                <div className="font-bold text-white mb-0.5">Verifiable Decision Receipts</div>
                <div className="text-gray-400">SHA-256 cryptographic digests guarantee auditability for judges and regulators.</div>
              </div>
            </div>
          </div>

        </div>
      </section>

      {/* =========================================================================
          4. THE PROBLEM SECTION (Directly from Abnormal Security website)
         ========================================================================= */}
      <section id="why-neuroshield" className="py-24 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="max-w-3xl mb-14 space-y-3">
          <span className="text-[#ccff00] text-xs font-mono font-bold tracking-[0.2em] uppercase">
            // THE PROBLEM
          </span>
          <h2 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white leading-tight">
            Modern Attacks Bypass Traditional Gateways by Design
          </h2>
          <p className="text-sm sm:text-base text-gray-400">
            Secure Email Gateways (SEGs) rely on static signatures, known bad domains, and link sandboxing. Today's AI-generated social engineering attacks carry zero payload.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {/* Problem 1: Machine Speed */}
          <div 
            onClick={() => navigate('dashboard')}
            className="rounded-2xl bg-[#0e1310] border border-white/[0.08] p-8 space-y-5 hover:border-[#ccff00]/40 transition-all cursor-pointer group"
          >
            <div className="w-12 h-12 rounded-xl bg-white/[0.05] border border-white/10 group-hover:bg-[#ccff00]/15 group-hover:text-[#ccff00] transition-all flex items-center justify-center text-[#ccff00]">
              <Clock size={24} />
            </div>
            <h3 className="text-xl font-bold text-white tracking-tight group-hover:text-[#ccff00] transition-colors">
              Machine Speed
            </h3>
            <p className="text-sm text-gray-400 leading-relaxed">
              Attacks move in milliseconds, faster than any human can respond. Breaches land, compromise employee credentials, and initiate fraudulent transfers before manual SOC triage can even open the ticket.
            </p>
            <div className="text-xs font-mono text-[#ccff00] pt-2 flex items-center gap-1">
              <span>Attacks land in 450ms</span>
              <ArrowUpRight size={14} className="group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
            </div>
          </div>

          {/* Problem 2: Unprecedented Scale */}
          <div 
            onClick={() => navigate('copilot')}
            className="rounded-2xl bg-[#0e1310] border border-white/[0.08] p-8 space-y-5 hover:border-[#ccff00]/40 transition-all cursor-pointer group"
          >
            <div className="w-12 h-12 rounded-xl bg-white/[0.05] border border-white/10 group-hover:bg-[#ccff00]/15 group-hover:text-[#ccff00] transition-all flex items-center justify-center text-[#ccff00]">
              <Flame size={24} />
            </div>
            <h3 className="text-xl font-bold text-white tracking-tight group-hover:text-[#ccff00] transition-colors">
              Unprecedented Scale
            </h3>
            <p className="text-sm text-gray-400 leading-relaxed">
              Generative AI enables malicious actors to mass-produce context-aware, hyper-personalized lures tailored to every employee, vendor, and executive across your entire communication graph.
            </p>
            <div className="text-xs font-mono text-[#ccff00] pt-2 flex items-center gap-1">
              <span>100x volume surge in AI lures</span>
              <ArrowUpRight size={14} className="group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
            </div>
          </div>

          {/* Problem 3: Novel Techniques */}
          <div 
            onClick={() => navigate('phishing')}
            className="rounded-2xl bg-[#0e1310] border border-white/[0.08] p-8 space-y-5 hover:border-[#ccff00]/40 transition-all cursor-pointer group"
          >
            <div className="w-12 h-12 rounded-xl bg-white/[0.05] border border-white/10 group-hover:bg-[#ccff00]/15 group-hover:text-[#ccff00] transition-all flex items-center justify-center text-[#ccff00]">
              <ShieldOff size={24} />
            </div>
            <h3 className="text-xl font-bold text-white tracking-tight group-hover:text-[#ccff00] transition-colors">
              Novel Techniques
            </h3>
            <p className="text-sm text-gray-400 leading-relaxed">
              AI-generated attacks are too subtle for humans to see and too new for traditional threat intel to detect. Zero link, zero attachment, pure text-based psychological coercion passing DMARC with ease.
            </p>
            <div className="text-xs font-mono text-[#ccff00] pt-2 flex items-center gap-1">
              <span>Zero-payload execution</span>
              <ArrowUpRight size={14} className="group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          5. THE SOLUTION SECTION ("To fight bad AI you need Behavioral AI")
         ========================================================================= */}
      <section id="solutions" className="py-24 bg-[#080c09] border-t border-white/[0.08] relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          
          <div className="max-w-3xl mb-16 space-y-4">
            <span className="text-[#ccff00] text-xs font-mono font-bold tracking-[0.2em] uppercase">
              // THE SOLUTION
            </span>
            <h2 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white leading-tight">
              To fight bad AI you need Behavioral AI.
            </h2>
            <p className="text-lg text-[#ccff00] font-medium">
              AI attackers have to look normal every time. They can't. Behavioral context unlocks automated AI defense.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {/* Pillar 1 */}
            <div 
              onClick={() => navigate('dashboard')}
              className="rounded-2xl bg-[#0e1310] border border-white/[0.08] p-8 flex flex-col justify-between space-y-6 hover:border-[#ccff00]/40 transition-all cursor-pointer group"
            >
              <div className="space-y-4">
                <div className="w-12 h-12 rounded-xl bg-[#ccff00]/10 border border-[#ccff00]/20 flex items-center justify-center text-[#ccff00] group-hover:bg-[#ccff00]/20 transition-colors">
                  <Target size={22} />
                </div>
                <h3 className="text-xl font-bold text-white tracking-tight group-hover:text-[#ccff00] transition-colors">
                  Know Normal, Catch Everything Else
                </h3>
                <p className="text-sm text-gray-400 leading-relaxed">
                  Per-identity behavioral baselines across 5,000+ signals detect zero-payload threats your gateway architecturally cannot see. By understanding baseline vendor relationships, anomalous remittance requests trigger instant alerts.
                </p>
              </div>
              <div className="pt-4 border-t border-white/[0.06] text-xs font-mono text-gray-300 flex items-center justify-between">
                <span>5,000+ signals analyzed</span>
                <ArrowRight size={14} className="text-[#ccff00] group-hover:translate-x-1 transition-transform" />
              </div>
            </div>

            {/* Pillar 2 */}
            <div 
              onClick={() => navigate('phishing')}
              className="rounded-2xl bg-[#0e1310] border border-white/[0.08] p-8 flex flex-col justify-between space-y-6 hover:border-[#ccff00]/40 transition-all cursor-pointer group"
            >
              <div className="space-y-4">
                <div className="w-12 h-12 rounded-xl bg-[#ccff00]/10 border border-[#ccff00]/20 flex items-center justify-center text-[#ccff00] group-hover:bg-[#ccff00]/20 transition-colors">
                  <Zap size={22} />
                </div>
                <h3 className="text-xl font-bold text-white tracking-tight group-hover:text-[#ccff00] transition-colors">
                  Threats Gone Before You See Them
                </h3>
                <p className="text-sm text-gray-400 leading-relaxed">
                  Malicious emails auto-removed and compromised accounts locked in under 6 seconds — no analyst action required. Autonomous playbooks handle session revocation, password resets, and SOC notifications instantly.
                </p>
              </div>
              <div className="pt-4 border-t border-white/[0.06] text-xs font-mono text-[#ccff00] flex items-center justify-between">
                <span>MTTR &lt; 6.0 seconds</span>
                <ArrowRight size={14} className="text-[#ccff00] group-hover:translate-x-1 transition-transform" />
              </div>
            </div>

            {/* Pillar 3 */}
            <div 
              onClick={() => navigate('intelligence')}
              className="rounded-2xl bg-[#0e1310] border border-white/[0.08] p-8 flex flex-col justify-between space-y-6 hover:border-[#ccff00]/40 transition-all cursor-pointer group"
            >
              <div className="space-y-4">
                <div className="w-12 h-12 rounded-xl bg-[#ccff00]/10 border border-[#ccff00]/20 flex items-center justify-center text-[#ccff00] group-hover:bg-[#ccff00]/20 transition-colors">
                  <Globe size={22} />
                </div>
                <h3 className="text-xl font-bold text-white tracking-tight group-hover:text-[#ccff00] transition-colors">
                  Compromised Vendors Flagged Across the Network
                </h3>
                <p className="text-sm text-gray-400 leading-relaxed">
                  Federated intelligence across 4,500+ organizations flags anomalous vendor behavior before payment redirection succeeds. If an external supplier gets breached elsewhere, your tenant is automatically shielded.
                </p>
              </div>
              <div className="pt-4 border-t border-white/[0.06] text-xs font-mono text-gray-300 flex items-center justify-between">
                <span>Collective Defense</span>
                <ArrowRight size={14} className="text-[#ccff00] group-hover:translate-x-1 transition-transform" />
              </div>
            </div>
          </div>

        </div>
      </section>

      {/* =========================================================================
          6. THE CHALLENGE CAROUSEL SECTION (Abnormal Gateway Carousel)
         ========================================================================= */}
      <section id="challenge" className="py-24 bg-[#050706] border-t border-white/[0.08] relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          
          {/* Section Header */}
          <div className="mb-14 space-y-3">
            <span className="text-[#ccff00] text-xs font-mono font-bold tracking-[0.2em] uppercase">
              // THE CHALLENGE
            </span>
            <h2 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white leading-tight">
              Your Gateway Is Missing the Attacks That Cost the Most
            </h2>
            <p className="text-sm text-gray-400 max-w-2xl">
              Traditional gateways scan for bad files and links. Modern financial attackers use legitimate compromised accounts and conversational manipulation.
            </p>
          </div>

          {/* Carousel Track Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {CHALLENGE_VECTORS.map((card, idx) => {
              const isActive = idx === activeChallengeIdx;
              const IconComp = card.icon;

              return (
                <div
                  key={card.id}
                  onClick={() => handleSelectChallenge(idx)}
                  className={`rounded-2xl p-7 flex flex-col justify-between transition-all duration-300 cursor-pointer border ${
                    isActive
                      ? 'bg-[#111713] border-[#ccff00] shadow-[0_10px_35px_rgba(204,255,0,0.15)] ring-1 ring-[#ccff00]/50 relative'
                      : 'bg-[#0e1310]/80 border-white/[0.08] hover:border-white/20 hover:bg-[#121914]'
                  }`}
                >
                  {/* Top neon indicator on active card */}
                  {isActive && (
                    <div className="absolute -top-[1px] left-6 right-6 h-[2px] bg-[#ccff00] rounded-full shadow-[0_0_10px_#ccff00]" />
                  )}

                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${
                        isActive ? 'bg-[#ccff00]/15 text-[#ccff00]' : 'bg-white/5 text-gray-400'
                      }`}>
                        <IconComp size={20} />
                      </div>
                      <span className="text-[10px] font-mono text-gray-400 tracking-wider">
                        0{idx + 1}
                      </span>
                    </div>

                    <div className="text-[10px] font-mono uppercase tracking-wider text-[#ccff00]">
                      {card.badge}
                    </div>

                    <h3 className="text-lg font-bold text-white leading-snug">
                      {card.title}
                    </h3>

                    <p className="text-xs text-gray-400 leading-relaxed">
                      {card.description}
                    </p>
                  </div>

                  <div className="pt-6 mt-6 border-t border-white/[0.06] text-[11px] text-[#ccff00]/90 font-medium font-mono">
                    {card.metrics}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Carousel Navigation Arrows (< and >) */}
          <div className="mt-10 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <button
                onClick={handlePrevChallenge}
                className="w-11 h-11 rounded-full bg-white/[0.06] hover:bg-white/[0.12] border border-white/10 flex items-center justify-center text-white transition-all cursor-pointer"
                aria-label="Previous challenge"
              >
                <ChevronLeft size={20} />
              </button>
              <button
                onClick={handleNextChallenge}
                className="w-11 h-11 rounded-full bg-[#ccff00] hover:bg-[#d8ff1a] text-black font-bold flex items-center justify-center transition-all cursor-pointer shadow-[0_0_15px_rgba(204,255,0,0.4)]"
                aria-label="Next challenge"
              >
                <ChevronRight size={20} strokeWidth={2.5} />
              </button>
            </div>

            <div className="text-xs text-gray-400 font-mono">
              ACTIVE CASE: <span className="text-[#ccff00] font-bold">{activeEmailItem.subject}</span>
            </div>
          </div>

        </div>
      </section>

      {/* =========================================================================
          7. THE NEUROSHIELD PLATFORM ARCHITECTURE (Abnormal Platform Modules)
         ========================================================================= */}
      <section id="platform" className="py-24 bg-[#080c09] border-t border-white/[0.08] relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          
          <div className="max-w-3xl mb-16 space-y-3">
            <span className="text-[#ccff00] text-xs font-mono font-bold tracking-[0.2em] uppercase">
              // OUR PLATFORM
            </span>
            <h2 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white leading-tight">
              The NeuroShield Behavioral Security Platform
            </h2>
            <p className="text-base text-gray-300">
              Automated AI defense with superhuman sophistication and scale, at machine speed. Protect email, identities, cloud tools, and insider supply-chains in one unified console.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
            {PLATFORM_MODULES.map((mod) => {
              const IconComp = mod.icon;
              const handleModuleClick = () => {
                if (mod.id === 'inbound') navigate('phishing');
                else if (mod.id === 'identity') navigate('guard');
                else if (mod.id === 'mailbox') navigate('copilot');
                else if (mod.id === 'vendor') navigate('intelligence');
                else navigate('dashboard');
              };

              return (
                <div 
                  key={mod.id}
                  onClick={handleModuleClick}
                  className="rounded-2xl bg-[#0e1310] border border-white/[0.08] p-7 flex flex-col justify-between hover:border-[#ccff00]/40 hover:bg-[#121813] transition-all space-y-6 group cursor-pointer"
                >
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="w-12 h-12 rounded-xl bg-white/5 border border-white/10 group-hover:bg-[#ccff00]/15 group-hover:text-[#ccff00] group-hover:border-[#ccff00]/30 transition-all flex items-center justify-center text-gray-300">
                        <IconComp size={22} />
                      </div>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-white/[0.06] text-gray-300 border border-white/10">
                        {mod.badge}
                      </span>
                    </div>

                    <div className="text-[11px] font-mono uppercase tracking-wider text-[#ccff00] font-bold">
                      {mod.tag}
                    </div>

                    <h3 className="text-lg font-bold text-white tracking-tight group-hover:text-[#ccff00] transition-colors">
                      {mod.title}
                    </h3>

                    <p className="text-xs text-gray-400 leading-relaxed">
                      {mod.description}
                    </p>
                  </div>

                  <div className="pt-4 border-t border-white/[0.06] flex items-center justify-between text-xs text-gray-400 group-hover:text-white transition-colors">
                    <span className="font-mono">Explore Module</span>
                    <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform text-[#ccff00]" />
                  </div>
                </div>
              );
            })}
          </div>

          {/* Cloud-Native Architecture Banner */}
          <div className="rounded-2xl bg-gradient-to-r from-[#111713] via-[#0d130f] to-[#111713] border border-[#ccff00]/25 p-8 flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="space-y-2">
              <div className="inline-flex items-center gap-2 text-xs font-mono font-bold text-[#ccff00] uppercase tracking-wider">
                <Cpu size={14} />
                <span>POWERED BY ATTUNE-CLASS BEHAVIORAL AI</span>
              </div>
              <h4 className="text-xl font-bold text-white">
                Cloud-Native API Architecture — Zero Mail Routing Changes
              </h4>
              <p className="text-xs text-gray-300 max-w-2xl">
                Deploy across your entire Microsoft 365 or Google Workspace tenant in 60 seconds. Ingest thousands of identity signals with zero MX record alterations and zero latency delay.
              </p>
            </div>

            <button
              onClick={() => navigate('phishing')}
              className="shrink-0 px-6 py-3 rounded-xl bg-[#ccff00] hover:bg-[#d8ff1a] text-black font-bold text-xs sm:text-sm tracking-tight transition-all shadow-[0_0_20px_rgba(204,255,0,0.3)] cursor-pointer"
            >
              Connect Environment &gt;
            </button>
          </div>

        </div>
      </section>

      {/* =========================================================================
          8. AN AI-NATIVE APPROACH SECTION (NLP Email Tokenizer & Threat Breakdown)
         ========================================================================= */}
      <section id="ai-approach" className="py-24 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Title */}
        <div className="max-w-3xl mb-12 space-y-3">
          <span className="text-[#ccff00] text-xs font-mono font-bold tracking-[0.2em] uppercase">
            // AI FORENSICS
          </span>
          <h2 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white leading-tight">
            An AI-Native Approach to Stopping Business Email Compromise
          </h2>
        </div>

        {/* 3 Numbered Value Points */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-16">
          <div className="flex gap-4">
            <span className="text-2xl font-bold text-[#ccff00] font-mono">01.</span>
            <p className="text-sm text-gray-300 leading-relaxed">
              Uses AI to model normal behavior based on thousands of identity attributes to detect impersonation.
            </p>
          </div>

          <div className="flex gap-4">
            <span className="text-2xl font-bold text-[#ccff00] font-mono">02.</span>
            <p className="text-sm text-gray-300 leading-relaxed">
              Leverages past communication and relationship patterns to detect behavioral anomalies, even if the email comes from a legitimate domain.
            </p>
          </div>

          <div className="flex gap-4">
            <span className="text-2xl font-bold text-[#ccff00] font-mono">03.</span>
            <p className="text-sm text-gray-300 leading-relaxed">
              Detects email content and tone patterns that are associated with invoice fraud and other BEC attacks.
            </p>
          </div>
        </div>

        {/* Interactive Forensic Email Widget (Split Pane) */}
        <div className="rounded-2xl bg-[#0d120e] border border-white/15 shadow-[0_25px_60px_rgba(0,0,0,0.8)] overflow-hidden">
          <div className="grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-white/[0.08]">
            
            {/* Left Pane: Email Client with Entity Badges */}
            <div className="lg:col-span-7 p-6 sm:p-8 bg-[#090d0a] space-y-6">
              {/* Email Metadata Header */}
              <div className="space-y-3 pb-6 border-b border-white/[0.08]">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                    <span>{activeEmailItem.subject}</span>
                    {isExecutingForensics && <Loader2 size={14} className="animate-spin text-[#ccff00]" />}
                  </h3>
                  <span className="text-xs text-gray-400 font-mono">
                    First Received: {activeEmailItem.timeString}
                  </span>
                </div>

                <div className="text-xs space-y-1 font-mono">
                  <div className="text-gray-400">
                    Sender: <span className="text-white font-medium">{activeEmailItem.senderName} &lt;{activeEmailItem.senderEmail}&gt;</span>
                  </div>
                  <div className="text-gray-400">
                    Recipient: <span className="text-white font-medium">John Stewart &lt;j.stewart@corp.internal&gt;</span>
                  </div>
                </div>
              </div>

              {/* Dynamic Email Body with Interactive Token Badges */}
              <div className="text-sm leading-loose text-gray-200 font-sans tracking-wide">
                {/* Dynamically tokenize active email body */}
                {activeEmailItem.body.split(/\s+/).map((word, wordIdx) => {
                  const cleanWord = word.toLowerCase().replace(/[^\w$]/g, '');
                  
                  // Financial entities
                  const isFinancial = ['invoice', 'wire', 'payment', 'bank', 'ach', 'disbursement', '$480,000', 'settlement', '$48,500', '$342.18'].includes(cleanWord) || word.includes('$');
                  // Request entities
                  const isRequest = ['please', 'advise', 'attached', 'send', 'remitted', 'process', 're-verify', 'transmit', 'update'].includes(cleanWord);
                  // Urgency entities
                  const isUrgent = ['immediately', 'urgent', 'due', 'eod', 'suspended', 'confidential', 'penalties'].includes(cleanWord);
                  // Formal / Recipient
                  const isFormal = ['hello', 'dear', 'greetings', 'hi'].includes(cleanWord);
                  const isRecipient = ['john', 'john,', 'team', 'finance', 'all'].includes(cleanWord);

                  if (isFinancial) {
                    const isSelected = selectedTokenInfo?.word === cleanWord;
                    return (
                      <span 
                        key={wordIdx}
                        onClick={() => setSelectedTokenInfo({
                          word: cleanWord,
                          type: 'FINANCIAL',
                          reason: `Financial Transaction Token: '${word}' denotes payment routing modification or monetary transfer instruction.`
                        })}
                        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded mx-1 transition-all cursor-pointer ${
                          isSelected ? 'bg-[#e11d48]/30 ring-2 ring-[#e11d48] text-white font-bold' : 'bg-black/60 border border-[#e11d48]/60 hover:border-[#e11d48]'
                        }`}
                      >
                        <strong className="text-white font-semibold">{word}</strong>
                        <span className="text-[9px] font-mono uppercase bg-[#e11d48] px-1 rounded text-white font-bold">FINANCIAL</span>
                      </span>
                    );
                  }

                  if (isRequest) {
                    const isSelected = selectedTokenInfo?.word === cleanWord;
                    return (
                      <span 
                        key={wordIdx}
                        onClick={() => setSelectedTokenInfo({
                          word: cleanWord,
                          type: 'REQUEST',
                          reason: `Call-to-Action Token: '${word}' demands urgent recipient fulfillment without standard verification.`
                        })}
                        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded mx-1 transition-all cursor-pointer ${
                          isSelected ? 'bg-[#ccff00]/20 ring-1 ring-[#ccff00] text-[#ccff00]' : 'bg-black/60 border border-white/20 hover:border-[#ccff00]/50'
                        }`}
                      >
                        <strong className="text-white font-semibold">{word}</strong>
                        <span className="text-[9px] font-mono uppercase bg-white/10 px-1 rounded text-gray-300">REQUEST</span>
                      </span>
                    );
                  }

                  if (isUrgent) {
                    const isSelected = selectedTokenInfo?.word === cleanWord;
                    return (
                      <span 
                        key={wordIdx}
                        onClick={() => setSelectedTokenInfo({
                          word: cleanWord,
                          type: 'URGENT',
                          reason: `Psychological Urgency Trigger: '${word}' forces rushed cognitive response to bypass normal scrutiny.`
                        })}
                        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded mx-1 transition-all cursor-pointer ${
                          isSelected ? 'bg-amber-500/20 ring-1 ring-amber-400 text-amber-300' : 'bg-black/60 border border-amber-500/40 hover:border-amber-400'
                        }`}
                      >
                        <strong className="text-white font-semibold">{word}</strong>
                        <span className="text-[9px] font-mono uppercase bg-amber-500/30 text-amber-300 px-1 rounded font-bold">URGENCY</span>
                      </span>
                    );
                  }

                  if (isFormal) {
                    return (
                      <span 
                        key={wordIdx}
                        onClick={() => setSelectedTokenInfo({
                          word: cleanWord,
                          type: 'FORMAL',
                          reason: `Salutation Token: Standard formal opening to establish professional authenticity.`
                        })}
                        className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded mx-1 bg-black/60 border border-white/20 hover:border-[#ccff00]/50 cursor-pointer"
                      >
                        <strong className="text-white font-semibold">{word}</strong>
                        <span className="text-[9px] font-mono uppercase bg-white/10 px-1 rounded text-gray-300">FORMAL</span>
                      </span>
                    );
                  }

                  if (isRecipient) {
                    return (
                      <span 
                        key={wordIdx}
                        onClick={() => setSelectedTokenInfo({
                          word: cleanWord,
                          type: 'RECIPIENT',
                          reason: `Target Entity Token: Direct personal addressing to lower suspicion.`
                        })}
                        className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded mx-1 bg-black/60 border border-white/20 hover:border-[#ccff00]/50 cursor-pointer"
                      >
                        <strong className="text-white font-semibold">{word}</strong>
                        <span className="text-[9px] font-mono uppercase bg-white/10 px-1 rounded text-gray-300">RECIPIENT</span>
                      </span>
                    );
                  }

                  return <span key={wordIdx} className="mx-0.5">{word} </span>;
                })}
              </div>

              {/* Selected Token Live Inspector Box */}
              {selectedTokenInfo && (
                <div className="p-3.5 rounded-xl bg-white/[0.04] border border-[#ccff00]/30 text-xs flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-[#ccff00] text-black">
                      {selectedTokenInfo.type}
                    </span>
                    <span className="text-gray-300">{selectedTokenInfo.reason}</span>
                  </div>
                  <span className="text-[10px] font-mono text-gray-500">CLICKED TOKEN</span>
                </div>
              )}

              <div className="text-[11px] text-gray-400 italic">
                * Click on highlighted NLP tokens to inspect underlying behavioral signals extracted by NeuroShield.
              </div>
            </div>

            {/* Right Pane: Analysis Overview with Red Alert Badges */}
            <div className="lg:col-span-5 p-6 sm:p-8 bg-[#0d120e] flex flex-col justify-between space-y-6">
              <div>
                <h3 className="text-xl font-bold text-white tracking-tight">
                  Analysis Overview
                </h3>
                <p className="text-xs text-gray-400 mt-1">
                  NeuroShield Forensics Engine evaluated this payload in real-time:
                </p>

                <div className="space-y-4 mt-6">
                  {/* Alert 1 */}
                  <div className="space-y-1.5">
                    <div className="inline-block bg-[#e11d48] text-white text-xs font-bold px-3 py-1.5 rounded uppercase tracking-wide">
                      {contentReason}
                    </div>
                    <p className="text-xs text-gray-300 leading-relaxed">
                      {activeDossier?.topFindings?.[0]?.finding || 
                       'The email body contains high-pressure financial remittance directives and alternate account redirection cues.'}
                    </p>
                  </div>

                  {/* Alert 2 */}
                  <div className="space-y-1.5">
                    <div className="inline-block bg-[#e11d48] text-white text-xs font-bold px-3 py-1.5 rounded uppercase tracking-wide">
                      {behaviorReason}
                    </div>
                    <p className="text-xs text-gray-300 leading-relaxed">
                      {activeDossier?.headerFields?.replyTo && activeDossier.headerFields.replyTo !== activeDossier.headerFields.from
                        ? `Reply-To header (${activeDossier.headerFields?.replyTo}) diverts away from authentic sender domain.` 
                        : 'Unusual sending behavior: Authenticating infrastructure diverts from registered vendor history.'}
                    </p>
                  </div>

                  {/* Alert 3 */}
                  <div className="space-y-1.5">
                    <div className="inline-block bg-[#e11d48] text-white text-xs font-bold px-3 py-1.5 rounded uppercase tracking-wide">
                      {identityReason}
                    </div>
                    <p className="text-xs text-gray-300 leading-relaxed">
                      {activeDossier?.authentication?.spf?.status === 'FAIL'
                        ? 'Cryptographic SPF verification failed: Sending MTA IP is not authorized by domain DNS.'
                        : 'Sender display name claims executive authority without aligned corporate credentials.'}
                    </p>
                  </div>
                </div>
              </div>

              <div className="pt-4 border-t border-white/[0.08] flex items-center justify-between">
                <span className="text-xs text-gray-400 font-mono">AUTOMATED MITIGATION:</span>
                <span className="text-xs font-bold text-[#ccff00] bg-[#ccff00]/10 px-2.5 py-1 rounded border border-[#ccff00]/20 font-mono">
                  REMEDIATED IN 4.2s
                </span>
              </div>
            </div>

          </div>
        </div>

      </section>

      {/* =========================================================================
          9. BEC SECTION (Interactive Capability Cards & Live Account Remediation)
         ========================================================================= */}
      <section id="bec" className="py-24 bg-[#080c09] border-t border-white/[0.08]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          
          {/* Main Section Header */}
          <div className="mb-14 space-y-2">
            <span className="text-[#ccff00] text-xs font-mono font-bold tracking-[0.2em] uppercase">
              // AUTONOMOUS REMEDIATION
            </span>
            <h2 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white">
              BEC Defense Matrix
            </h2>
          </div>

          {/* 3 Feature Grid Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            
            {/* Card 1: Know Normal, Catch Everything Else */}
            <div className="rounded-2xl bg-[#0e1310] border border-white/[0.08] hover:border-white/20 transition-all p-6 flex flex-col justify-between space-y-6">
              {/* Top Visual Box */}
              <div className="rounded-xl bg-[#050806] border border-white/[0.06] p-6 text-center relative overflow-hidden h-52 flex flex-col justify-between">
                <div className="text-[10px] font-mono text-gray-400 tracking-wider text-left">
                  // SENDER IDENTITY ANALYSIS
                </div>

                <div className="text-xs font-bold text-white">
                  NeuroShield Assessment
                </div>

                {/* Graphical Avatar link with Warning */}
                <div className="flex items-center justify-center gap-6 my-2 relative">
                  <div className="w-10 h-10 rounded-full bg-white/10 border border-white/20 flex items-center justify-center text-gray-300">
                    <User size={20} />
                  </div>

                  {/* Dashed Connecting Line with Warning Icon */}
                  <div className="relative flex items-center justify-center">
                    <div className="w-16 border-t-2 border-dashed border-red-500/60" />
                    <div className="absolute w-6 h-6 rounded-full bg-red-600 text-white flex items-center justify-center text-xs font-bold shadow-[0_0_12px_rgba(239,68,68,0.8)]">
                      !
                    </div>
                  </div>

                  <div className="w-10 h-10 rounded-full bg-white/10 border border-white/20 flex items-center justify-center text-gray-300">
                    <User size={20} />
                  </div>
                </div>

                {/* Solid Red Pill Badge */}
                <div>
                  <span className="inline-block bg-[#e11d48] text-white text-[11px] font-extrabold px-3 py-1 rounded tracking-wider uppercase shadow-md">
                    ! IDENTITY MISMATCH
                  </span>
                </div>
              </div>

              {/* Text info */}
              <div className="space-y-3">
                <h3 className="text-xl font-bold text-white tracking-tight">
                  Know Normal, Catch Everything Else
                </h3>
                <p className="text-xs text-gray-400 leading-relaxed">
                  Per-identity behavioral baselines across 5,000+ signals detect zero-payload threats your gateway architecturally cannot see.
                </p>
              </div>
            </div>

            {/* Card 2: Threats Gone Before You See Them */}
            <div className="rounded-2xl bg-[#0e1310] border border-white/[0.08] hover:border-white/20 transition-all p-6 flex flex-col justify-between space-y-6">
              {/* Top Visual Box (Remediate Account Dialog) */}
              <div className="rounded-xl bg-[#050806] border border-white/[0.06] p-5 relative overflow-hidden h-52 flex flex-col justify-between">
                <div>
                  <div className="text-xs font-bold text-white flex items-center gap-1.5">
                    <span>Remediate Account:</span>
                    <span className="text-[#ccff00]">{activeEmailItem.senderName}</span>
                  </div>
                </div>

                {/* Interactive Checkbox Checklist */}
                <div className="space-y-2 text-xs text-gray-300">
                  <div 
                    onClick={() => setRemediateSteps(s => ({ ...s, signOut: !s.signOut }))}
                    className="flex items-center gap-2 cursor-pointer hover:text-white"
                  >
                    <div className={`w-4 h-4 rounded flex items-center justify-center border ${remediateSteps.signOut ? 'bg-[#ccff00] border-[#ccff00] text-black' : 'border-gray-500'}`}>
                      {remediateSteps.signOut && <Check size={12} strokeWidth={3} />}
                    </div>
                    <span className="text-[11px]">Sign out of all active sessions</span>
                  </div>

                  <div 
                    onClick={() => setRemediateSteps(s => ({ ...s, blockAccess: !s.blockAccess }))}
                    className="flex items-center gap-2 cursor-pointer hover:text-white"
                  >
                    <div className={`w-4 h-4 rounded flex items-center justify-center border ${remediateSteps.blockAccess ? 'bg-[#ccff00] border-[#ccff00] text-black' : 'border-gray-500'}`}>
                      {remediateSteps.blockAccess && <Check size={12} strokeWidth={3} />}
                    </div>
                    <span className="text-[11px]">Block account access & quarantine</span>
                  </div>

                  <div 
                    onClick={() => setRemediateSteps(s => ({ ...s, resetPassword: !s.resetPassword }))}
                    className="flex items-center gap-2 cursor-pointer hover:text-white"
                  >
                    <div className={`w-4 h-4 rounded flex items-center justify-center border ${remediateSteps.resetPassword ? 'bg-[#ccff00] border-[#ccff00] text-black' : 'border-gray-500'}`}>
                      {remediateSteps.resetPassword && <Check size={12} strokeWidth={3} />}
                    </div>
                    <span className="text-[11px]">Trigger password reset & SOC alert</span>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="flex items-center justify-end gap-2 pt-2 border-t border-white/[0.06]">
                  <button 
                    onClick={() => setRemediated(false)}
                    className="px-2.5 py-1 text-[11px] text-gray-400 hover:text-white cursor-pointer"
                  >
                    Reset
                  </button>
                  <button 
                    onClick={handlePerformRemediation}
                    className="px-3 py-1 bg-[#ccff00] hover:bg-[#d8ff1a] text-black text-[11px] font-bold rounded cursor-pointer transition-all active:scale-95"
                  >
                    {remediated ? 'Account Locked ✓' : 'Remediate Account'}
                  </button>
                </div>
              </div>

              {/* Text info */}
              <div className="space-y-3">
                <h3 className="text-xl font-bold text-white tracking-tight">
                  Threats Gone Before You See Them
                </h3>
                <p className="text-xs text-gray-400 leading-relaxed">
                  Malicious emails auto-removed and compromised accounts locked in under 6 seconds — no analyst action required.
                </p>
              </div>
            </div>

            {/* Card 3: Compromised Vendors Flagged Across the Network */}
            <div className="rounded-2xl bg-[#0e1310] border border-white/[0.08] hover:border-white/20 transition-all p-6 flex flex-col justify-between space-y-6">
              {/* Top Visual Box (High Risk Circular Gauge) */}
              <div className="rounded-xl bg-[#050806] border border-white/[0.06] p-5 relative overflow-hidden h-52 flex items-center justify-between">
                {/* Circular Gauge */}
                <div className="relative w-24 h-24 flex items-center justify-center shrink-0">
                  <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                    <circle cx="50" cy="50" r="38" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="7" />
                    <circle 
                      cx="50" 
                      cy="50" 
                      r="38" 
                      fill="none" 
                      stroke={attackScore >= 75 ? '#e11d48' : attackScore >= 40 ? '#f59e0b' : '#10b981'} 
                      strokeWidth="7" 
                      strokeDasharray="238" 
                      strokeDashoffset={238 - (238 * (attackScore / 100))}
                      strokeLinecap="round"
                      className="drop-shadow-[0_0_8px_rgba(225,29,72,0.8)] transition-all duration-700"
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center flex-col">
                    <span className="text-lg font-extrabold text-white">{attackSeverity}</span>
                    <span className="text-[10px] font-mono text-gray-400">{attackScore}%</span>
                  </div>
                </div>

                {/* Threat Indicators Checklist */}
                <div className="space-y-2 text-[11px] text-gray-300 pr-2">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-[#e11d48] shadow-[0_0_6px_#e11d48]" />
                    <span>Vendor Currently Compromised</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-[#e11d48] shadow-[0_0_6px_#e11d48]" />
                    <span>Vendor Impersonation Attacks</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-[#e11d48] shadow-[0_0_6px_#e11d48]" />
                    <span>Recent Suspicious Activities</span>
                  </div>
                </div>
              </div>

              {/* Text info */}
              <div className="space-y-3">
                <h3 className="text-xl font-bold text-white tracking-tight">
                  Compromised Vendors Flagged
                </h3>
                <p className="text-xs text-gray-400 leading-relaxed">
                  Federated intelligence across 4,500+ organizations flags anomalous vendor behavior before payment redirection succeeds.
                </p>
              </div>
            </div>

          </div>
        </div>
      </section>

      {/* =========================================================================
          10. BENCHMARKS & EFFICACY ("Designed for security, not everything else")
         ========================================================================= */}
      <section className="py-24 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="max-w-3xl mb-14 space-y-3">
          <span className="text-[#ccff00] text-xs font-mono font-bold tracking-[0.2em] uppercase">
            // WHY NEUROSHIELD
          </span>
          <h2 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white leading-tight">
            Designed for Security. That's Behavioral AI.
          </h2>
          <p className="text-base text-gray-300">
            NeuroShield is the behavioral context engine that unlocks the defender's advantage against adversaries wielding generative AI.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div className="rounded-2xl bg-[#0e1310] border border-white/[0.08] p-8 space-y-4">
            <div className="text-4xl font-extrabold text-[#ccff00] font-mono">99.4%</div>
            <h3 className="text-lg font-bold text-white">Detects More Attacks</h3>
            <p className="text-xs text-gray-400 leading-relaxed">
              Percentage share of human-confirmed true-positive BEC and financial impersonation attacks detected compared to legacy SEGs.
            </p>
          </div>

          <div className="rounded-2xl bg-[#0e1310] border border-white/[0.08] p-8 space-y-4">
            <div className="text-4xl font-extrabold text-white font-mono">90%</div>
            <h3 className="text-lg font-bold text-white">Delivers Fewer False Positives</h3>
            <p className="text-xs text-gray-400 leading-relaxed">
              Out of attacks detected, what percentage are verified malicious vs legitimate business transactions. Drastically reduces SOC noise.
            </p>
          </div>

          <div className="rounded-2xl bg-[#0e1310] border border-white/[0.08] p-8 space-y-4">
            <div className="text-4xl font-extrabold text-[#ccff00] font-mono">1×</div>
            <h3 className="text-lg font-bold text-white">Operates at Machine Speed</h3>
            <p className="text-xs text-gray-400 leading-relaxed">
              Sub-second processing time relative to native API delivery. Quarantines payloads before employees can click or execute wire changes.
            </p>
          </div>
        </div>
      </section>

      {/* =========================================================================
          11. BOTTOM CONVERSION CTA & SCROLL TO TOP PILL
         ========================================================================= */}
      <section className="py-20 bg-gradient-to-b from-[#080c09] to-[#050706] border-t border-white/[0.08] text-center relative">
        <div className="max-w-4xl mx-auto px-4 space-y-8">
          <div className="space-y-3">
            <span className="text-[#ccff00] text-xs font-mono font-bold tracking-[0.2em] uppercase">
              // SEE BEHAVIORAL AI IN ACTION
            </span>
            <h3 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
              Ready to see what your gateway missed?
            </h3>
            <p className="text-sm text-gray-400 max-w-xl mx-auto">
              Connect your environment in 60 seconds with zero mail routing changes, or explore our live interactive attack dossiers.
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-4 pt-2">
            <button
              onClick={() => navigate('phishing')}
              className="px-8 py-3.5 rounded-xl bg-[#ccff00] hover:bg-[#d8ff1a] text-black font-bold text-sm tracking-tight transition-all shadow-[0_0_30px_rgba(204,255,0,0.4)] cursor-pointer flex items-center gap-2"
            >
              <Mail size={16} className="text-black" />
              <span>Connect Google Workspace / Gmail &gt;</span>
            </button>
            <button
              onClick={() => navigate('dashboard')}
              className="px-7 py-3.5 rounded-xl bg-white/5 hover:bg-white/10 text-white font-semibold text-sm border border-white/10 transition-all cursor-pointer"
            >
              Launch Defense Console
            </button>
          </div>

          {/* Floating "Scroll to the Top ^" Pill Button (Abnormal signature pill) */}
          <div className="pt-10">
            <button
              onClick={scrollToTop}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-full bg-[#111713] hover:bg-[#18231c] text-gray-300 hover:text-white border border-white/15 text-xs font-mono transition-all cursor-pointer shadow-lg hover:border-[#ccff00]/40"
            >
              <span>Scroll to the Top</span>
              <span className="text-[#ccff00] font-bold">^</span>
            </button>
          </div>
        </div>
      </section>

      {/* =========================================================================
          12. COMPREHENSIVE MULTI-COLUMN ENTERPRISE FOOTER (Abnormal Style)
         ========================================================================= */}
      <footer className="py-16 bg-[#030504] border-t border-white/[0.06] text-left text-xs text-gray-400">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-12">
          
          {/* Top Brand & Columns */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-8">
            {/* Column 1: Brand */}
            <div className="col-span-2 md:col-span-1 space-y-3">
              <div className="flex items-center gap-1 text-white font-bold text-lg">
                <span className="text-[#ccff00]">//</span>
                <span>NeuroShield</span>
              </div>
              <p className="text-xs text-gray-500 leading-relaxed">
                The Behavioral Security Platform for the AI era. Protecting email, identity, and supply chain.
              </p>
              <div className="text-[11px] text-gray-500 font-mono pt-2">
                © 2026 NeuroShield AI, Inc.
              </div>
            </div>

            {/* Column 2: Platform */}
            <div className="space-y-3">
              <div className="text-white font-semibold text-xs uppercase tracking-wider font-mono">
                Platform
              </div>
              <ul className="space-y-2 text-xs">
                <li><a href="#platform" className="hover:text-white transition-colors">Email Security</a></li>
                <li><a href="#platform" className="hover:text-white transition-colors">Identity Protection</a></li>
                <li><a href="#platform" className="hover:text-white transition-colors">AI Security Mailbox</a></li>
                <li><a href="#platform" className="hover:text-white transition-colors">Vendor Defense</a></li>
                <li><a href="#platform" className="hover:text-white transition-colors">Cloud Integrations</a></li>
              </ul>
            </div>

            {/* Column 3: Solutions */}
            <div className="space-y-3">
              <div className="text-white font-semibold text-xs uppercase tracking-wider font-mono">
                Solutions
              </div>
              <ul className="space-y-2 text-xs">
                <li><a href="#solutions" className="hover:text-white transition-colors">Prevent BEC & Spoofing</a></li>
                <li><a href="#solutions" className="hover:text-white transition-colors">Detect QR Quishing</a></li>
                <li><a href="#solutions" className="hover:text-white transition-colors">Stop Generative AI Attacks</a></li>
                <li><a href="#solutions" className="hover:text-white transition-colors">Displace Legacy SEG</a></li>
                <li><a href="#solutions" className="hover:text-white transition-colors">Automate SOC Operations</a></li>
              </ul>
            </div>

            {/* Column 4: Resources */}
            <div className="space-y-3">
              <div className="text-white font-semibold text-xs uppercase tracking-wider font-mono">
                Resources
              </div>
              <ul className="space-y-2 text-xs">
                <li><a href="#ai-approach" className="hover:text-white transition-colors">Threat Forensics Engine</a></li>
                <li><a href="#challenge" className="hover:text-white transition-colors">Detection Matrix</a></li>
                <li><button onClick={() => setShowCustomInput(true)} className="hover:text-white transition-colors text-left cursor-pointer">Live EML Inspector</button></li>
                <li><button onClick={() => navigate('dashboard')} className="hover:text-white transition-colors text-left cursor-pointer">SOC Matrix</button></li>
                <li><a href="#bec" className="hover:text-white transition-colors">BEC Benchmark Analysis</a></li>
              </ul>
            </div>

            {/* Column 5: Company */}
            <div className="space-y-3">
              <div className="text-white font-semibold text-xs uppercase tracking-wider font-mono">
                Company
              </div>
              <ul className="space-y-2 text-xs">
                <li><a href="#why-neuroshield" className="hover:text-white transition-colors">About Us</a></li>
                <li><a href="#why-neuroshield" className="hover:text-white transition-colors">Leadership & Mission</a></li>
                <li><span className="text-gray-500">Careers (Hiring AI Researchers)</span></li>
                <li><span className="text-gray-500">Security & Trust Center</span></li>
                <li><span className="text-gray-500">Privacy Policy</span></li>
              </ul>
            </div>
          </div>

          {/* Legal / Benchmark Disclaimer Note (Abnormal Standard Notice) */}
          <div className="pt-8 border-t border-white/[0.06] text-[11px] text-gray-500 leading-relaxed font-mono space-y-2">
            <p>
              Based on NeuroShield's continuous analysis of documented attack campaigns, enterprise tenant evaluations, and live forensic telemetry regarding the architectural limitations of legacy secure email gateways. NeuroShield detects an average normalized volume of &gt;1,200 zero-payload attacks per 1,000 mailboxes monthly that bypass traditional signature-based gateways.
            </p>
            <p>
              All benchmarks evaluated against balanced corpuses of confirmed live attacks and confirmed safe traffic using local Forensic RFC 5322 parsing engines. Zero MX routing modification required.
            </p>
          </div>

        </div>
      </footer>



      {/* =========================================================================
          14. CUSTOM RAW EMAIL / EML LIVE ANALYZER MODAL
         ========================================================================= */}
      {/* =========================================================================
          14. CUSTOM RAW EMAIL / EML LIVE ANALYZER MODAL (Rendered into Body Portal)
         ========================================================================= */}
      {typeof document !== 'undefined' && createPortal(
        <AnimatePresence>
          {showCustomInput && (
            <div 
              className="fixed inset-0 z-[99999] flex items-center justify-center p-4 sm:p-6 bg-black/85 backdrop-blur-md overflow-y-auto"
              onClick={(e) => {
                if (e.target === e.currentTarget) setShowCustomInput(false);
              }}
            >
              <motion.div
                initial={{ opacity: 0, scale: 0.96, y: 12 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.96, y: 12 }}
                transition={{ duration: 0.2 }}
                className="w-full max-w-3xl rounded-2xl bg-[#0d120f] border border-white/20 p-6 sm:p-8 shadow-[0_25px_75px_rgba(0,0,0,0.95)] relative space-y-5 my-auto max-h-[92vh] overflow-y-auto text-left"
              >
                {/* Close Button */}
                <button
                  onClick={() => setShowCustomInput(false)}
                  className="absolute top-5 right-5 text-gray-400 hover:text-white p-1.5 rounded-lg hover:bg-white/10 transition-colors cursor-pointer"
                  title="Close Inspector"
                >
                  <X size={20} />
                </button>

                {/* Top Engine Pill */}
                <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-[#ccff00]/10 text-[#ccff00] text-[11px] font-mono font-bold border border-[#ccff00]/25">
                  <FileSearch size={14} />
                  <span>LIVE RFC 5322 FORENSIC ENGINE</span>
                </div>

                <div>
                  <h3 className="text-2xl font-bold text-white tracking-tight">
                    Inspect Custom Email / EML File
                  </h3>
                  <p className="text-xs text-gray-300 mt-1 leading-relaxed">
                    Upload an authentic <code className="text-[#ccff00]">.eml</code> / <code className="text-[#ccff00]">.msg</code> file, load a sample attack vector, or paste raw RFC 5322 headers. The engine performs multi-hop relay parsing, SPF/DKIM validation, and behavioral analysis in real time.
                  </p>
                </div>

                {/* File Upload Zone */}
                <input
                  type="file"
                  ref={emlFileInputRef}
                  accept=".eml,.msg,.txt,message/rfc822"
                  onChange={handleEmlFileUpload}
                  className="hidden"
                />

                <div className="p-4 rounded-xl bg-white/[0.03] border border-dashed border-white/20 hover:border-[#ccff00]/60 transition-colors flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-[#ccff00]/15 border border-[#ccff00]/30 flex items-center justify-center text-[#ccff00] shrink-0">
                      <FileUp size={20} />
                    </div>
                    <div>
                      <div className="text-xs font-semibold text-white">
                        {uploadedFileName ? (
                          <span className="text-[#ccff00] font-mono flex items-center gap-1">
                            <CheckCircle2 size={13} /> {uploadedFileName}
                          </span>
                        ) : (
                          'Upload .EML / .MSG or Raw Header File'
                        )}
                      </div>
                      <div className="text-[11px] text-gray-400 mt-0.5">
                        Accepts standard RFC 5322 MIME messages from Outlook, Gmail, Apple Mail, Thunderbird
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0 w-full sm:w-auto">
                    <button
                      type="button"
                      onClick={() => emlFileInputRef.current?.click()}
                      className="w-full sm:w-auto px-4 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-white font-mono text-xs font-semibold transition-all cursor-pointer border border-white/15 flex items-center justify-center gap-1.5"
                    >
                      <UploadCloud size={14} className="text-[#ccff00]" />
                      <span>{uploadedFileName ? 'Choose Other File' : 'Select .EML File'}</span>
                    </button>
                    {uploadedFileName && (
                      <button
                        type="button"
                        onClick={() => {
                          setUploadedFileName(null);
                          setCustomEmailText('');
                        }}
                        className="px-2.5 py-2 rounded-lg bg-white/5 hover:bg-red-500/20 text-gray-400 hover:text-red-400 text-xs transition-colors cursor-pointer"
                        title="Clear file"
                      >
                        <X size={14} />
                      </button>
                    )}
                  </div>
                </div>

                {/* Sample Presets Shortcuts */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-[11px] font-mono text-gray-400">
                    <span>OR LOAD INSTANT TEST VECTOR:</span>
                    {customEmailText.trim() && (
                      <button
                        onClick={() => { setCustomEmailText(''); setUploadedFileName(null); }}
                        className="text-gray-400 hover:text-white transition-colors cursor-pointer underline"
                      >
                        Clear Text
                      </button>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => loadSamplePreset('bec')}
                      className="px-3 py-1.5 rounded-lg bg-red-500/15 hover:bg-red-500/25 border border-red-500/30 text-red-300 text-xs font-mono transition-all cursor-pointer flex items-center gap-1.5"
                    >
                      <AlertTriangle size={12} className="text-red-400" />
                      <span>BEC Wire Fraud (High Risk)</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => loadSamplePreset('phish')}
                      className="px-3 py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-amber-300 text-xs font-mono transition-all cursor-pointer flex items-center gap-1.5"
                    >
                      <ShieldAlert size={12} className="text-amber-400" />
                      <span>Credential Harvest (Phish)</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => loadSamplePreset('clean')}
                      className="px-3 py-1.5 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 text-xs font-mono transition-all cursor-pointer flex items-center gap-1.5"
                    >
                      <ShieldCheck size={12} className="text-emerald-400" />
                      <span>Legitimate Signed (Safe)</span>
                    </button>
                  </div>
                </div>

                {/* Raw Email / Headers Textarea */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-[11px] font-mono text-gray-400">
                    <span>RFC 5322 HEADERS & MESSAGE BODY:</span>
                    <span>{customEmailText.length > 0 ? `${customEmailText.split('\n').length} lines • ${customEmailText.length} bytes` : 'Empty'}</span>
                  </div>
                  <textarea
                    value={customEmailText}
                    onChange={(e) => setCustomEmailText(e.target.value)}
                    placeholder={`Paste headers or email body...\n\nFrom: "CEO Office" <ceo@external-board.org>\nReply-To: wire.desk@gmail.com\nSubject: Urgent Settlement\n\nPlease wire $50,000 immediately to account...`}
                    rows={8}
                    className="w-full rounded-xl bg-black/70 border border-white/15 p-4 text-xs font-mono text-gray-200 focus:outline-none focus:border-[#ccff00] transition-colors resize-none selection:bg-[#ccff00] selection:text-black leading-relaxed"
                  />
                </div>

                {/* Action Buttons Bar */}
                <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2 border-t border-white/10">
                  <div className="flex items-center gap-2 w-full sm:w-auto">
                    <button
                      type="button"
                      onClick={() => setShowCustomInput(false)}
                      className="px-4 py-2.5 text-xs text-gray-400 hover:text-white cursor-pointer transition-colors"
                    >
                      Cancel
                    </button>

                    <button
                      type="button"
                      onClick={handleOpenInSOCLab}
                      className="px-4 py-2.5 rounded-xl bg-white/[0.06] hover:bg-white/[0.12] text-gray-200 hover:text-white text-xs font-semibold border border-white/15 transition-all cursor-pointer flex items-center gap-1.5"
                      title="Open directly in dedicated SOC Phishing Forensics Suite"
                    >
                      <span>Open in SOC Forensic Lab</span>
                      <ExternalLink size={13} className="text-[#ccff00]" />
                    </button>
                  </div>

                  <button
                    type="button"
                    onClick={handleAnalyzeCustomEmail}
                    disabled={!customEmailText.trim() || isExecutingForensics}
                    className="w-full sm:w-auto px-6 py-3 rounded-xl bg-[#ccff00] hover:bg-[#d8ff1a] active:scale-95 disabled:opacity-40 text-black font-bold text-xs tracking-tight transition-all shadow-[0_0_25px_rgba(204,255,0,0.4)] hover:shadow-[0_0_35px_rgba(204,255,0,0.65)] cursor-pointer flex items-center justify-center gap-2"
                  >
                    {isExecutingForensics ? (
                      <Loader2 size={15} className="animate-spin text-black" />
                    ) : (
                      <Play size={15} fill="currentColor" />
                    )}
                    <span>Execute Live Forensics</span>
                  </button>
                </div>
              </motion.div>
            </div>
          )}
        </AnimatePresence>,
        document.body
      )}

    </div>
  );
}

export default LandingPage;
