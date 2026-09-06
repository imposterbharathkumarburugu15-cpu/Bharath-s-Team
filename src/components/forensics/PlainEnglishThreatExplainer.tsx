import React, { useState } from 'react';
import { motion } from 'motion/react';
import { 
  ShieldAlert, CheckCircle2, XCircle, AlertTriangle, HelpCircle, 
  Mail, ExternalLink, ArrowRight, Copy, Check, Info, Lock, 
  FileWarning, Send, Users, ShieldCheck, Sparkles, ChevronDown, ChevronUp
} from 'lucide-react';
import { ForensicDossier } from '@/services/forensicsEngine';

interface PlainEnglishThreatExplainerProps {
  dossier: ForensicDossier;
  onSwitchToTechnicalView?: () => void;
}

export function PlainEnglishThreatExplainer({ 
  dossier, 
  onSwitchToTechnicalView 
}: PlainEnglishThreatExplainerProps) {
  const [copiedWarning, setCopiedWarning] = useState<boolean>(false);
  const [showGlossary, setShowGlossary] = useState<boolean>(false);
  const [checklist, setChecklist] = useState<Record<string, boolean>>({
    noClick: false,
    noDownload: false,
    reportIt: false,
    deleteMail: false
  });

  const toggleCheck = (key: string) => {
    setChecklist(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const isMalicious = dossier.classification.verdict === 'MALICIOUS' || dossier.scoreBreakdown.totalRiskScore >= 70;
  const isSuspicious = !isMalicious && (dossier.classification.verdict === 'SUSPICIOUS' || dossier.scoreBreakdown.totalRiskScore >= 40);

  const claimedSender = dossier.headerFields.from || 'Claimed Sender';
  const actualSender = dossier.senderIdentity.returnPathAddress || dossier.senderIdentity.fromAddress || 'Unknown sender server';
  const subject = dossier.headerFields.subject || 'No Subject';
  const replyTo = dossier.headerFields.replyTo;
  const hasReplyMismatch = replyTo && !claimedSender.includes(replyTo);

  // Dangerous link
  const primaryUrl = dossier.urlForensics && dossier.urlForensics.length > 0 ? dossier.urlForensics[0] : null;

  const copyWarningForTeam = () => {
    const warningText = `⚠️ SECURITY ALERT: Beware of Phishing Email!\n` +
      `Subject: "${subject}"\n` +
      `Claimed to be from: ${claimedSender}\n` +
      `Verdict: FAKE / DANGEROUS (${dossier.scoreBreakdown.totalRiskScore}/100 Risk Score)\n` +
      `Reason: This email is attempting to impersonate a trusted service. Do NOT click any links or provide your password! If you received this, report it to IT and delete it immediately.`;
    
    navigator.clipboard.writeText(warningText);
    setCopiedWarning(true);
    setTimeout(() => setCopiedWarning(false), 2000);
  };

  return (
    <div 
      id="plain-english-explainer"
      className="bg-[#080d1a] border border-cyan-500/30 rounded-2xl p-5 sm:p-7 shadow-2xl space-y-7 text-white font-sans"
    >
      {/* 1. BIG FRIENDLY VERDICT BANNER */}
      <div className={`p-5 sm:p-6 rounded-2xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-5 ${
        isMalicious 
          ? 'bg-red-950/30 border-red-500/50 shadow-[0_0_30px_rgba(239,68,68,0.2)]' 
          : isSuspicious 
          ? 'bg-amber-950/30 border-amber-500/50 shadow-[0_0_30px_rgba(245,158,11,0.2)]' 
          : 'bg-emerald-950/30 border-emerald-500/50 shadow-[0_0_30px_rgba(16,185,129,0.2)]'
      }`}>
        <div className="flex items-start gap-4">
          <div className={`w-14 h-14 rounded-2xl flex items-center justify-center shrink-0 ${
            isMalicious ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
            isSuspicious ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' :
            'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
          }`}>
            {isMalicious ? <ShieldAlert className="w-8 h-8 animate-bounce" /> :
             isSuspicious ? <AlertTriangle className="w-8 h-8" /> :
             <ShieldCheck className="w-8 h-8" />}
          </div>
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold uppercase tracking-wider ${
                isMalicious ? 'bg-red-500 text-white' :
                isSuspicious ? 'bg-amber-500 text-black' :
                'bg-emerald-500 text-white'
              }`}>
                {isMalicious ? 'DANGEROUS FAKE EMAIL' : isSuspicious ? 'SUSPICIOUS / UNVERIFIED' : 'LEGITIMATE EMAIL'}
              </span>
              <span className="text-xs text-gray-400 font-mono">
                Risk Rating: <strong className="text-white font-bold">{dossier.scoreBreakdown.totalRiskScore}/100</strong>
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              {isMalicious 
                ? 'DO NOT CLICK ANY LINKS OR REPLY TO THIS EMAIL' 
                : isSuspicious 
                ? 'CAUTION: This email could not be safely verified' 
                : 'This email appears safe to read'}
            </h2>
            <p className="text-sm sm:text-base text-gray-300 mt-1 max-w-2xl leading-relaxed">
              {isMalicious 
                ? 'Someone is pretending to be a company or person you know to trick you into clicking a link or revealing sensitive info.'
                : isSuspicious
                ? 'The sender information has inconsistencies. Be careful before sharing personal details or downloading attachments.'
                : 'The email passed all internet identity and digital signature verification checks.'}
            </p>
          </div>
        </div>

        {/* Warning Copy Button */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 w-full md:w-auto shrink-0">
          <button
            onClick={copyWarningForTeam}
            className="px-4 py-2.5 rounded-xl bg-white/10 hover:bg-white/20 text-white border border-white/15 text-xs sm:text-sm font-bold flex items-center justify-center gap-2 transition-all cursor-pointer active:scale-95"
            title="Copy plain-English warning to paste in Slack or Teams"
          >
            {copiedWarning ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4 text-cyan-400" />}
            <span>{copiedWarning ? 'Copied to Clipboard!' : 'Copy Warning for Team'}</span>
          </button>

          {onSwitchToTechnicalView && (
            <button
              onClick={onSwitchToTechnicalView}
              className="px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-black text-xs sm:text-sm font-bold font-mono flex items-center justify-center gap-2 transition-all cursor-pointer shadow-[0_0_15px_rgba(0,245,255,0.3)] active:scale-95"
            >
              <span>Switch to Technical SOC View</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* 2. THE ENVELOPE ANALOGY (Visual Comparison of the Trick) */}
      <div className="p-5 sm:p-6 rounded-2xl bg-black/40 border border-white/10 space-y-4">
        <div className="flex items-center gap-2.5">
          <Mail className="w-5 h-5 text-cyan-400" />
          <h3 className="text-base sm:text-lg font-bold text-white tracking-wide">
            How the Trick Works: The "Postal Envelope" Analogy
          </h3>
        </div>
        <p className="text-xs sm:text-sm text-gray-300 leading-relaxed">
          Think of an email just like a physical paper letter in the post. Anyone can pick up a pen and write <em>"From: The White House"</em> on the front of an envelope. But when the postal service delivers it, the tracking stamp tells you the truth about where it came from:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 font-mono">
          {/* Card 1: What they want you to see */}
          <div className="p-4 rounded-xl bg-red-950/20 border border-red-500/30 space-y-2">
            <div className="flex items-center justify-between text-xs text-red-400 font-bold">
              <span>🎭 WHAT THE ENVELOPE SAYS (FAKE)</span>
              <XCircle className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-sm font-bold text-white break-all">
              {claimedSender}
            </div>
            <p className="text-xs text-gray-400 font-sans leading-relaxed">
              This is just text written on the cover. Anyone can type this name — it does not prove who actually sent it.
            </p>
          </div>

          {/* Card 2: What the internet postal stamp actually recorded */}
          <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-500/30 space-y-2">
            <div className="flex items-center justify-between text-xs text-cyan-400 font-bold">
              <span>🔍 WHO ACTUALLY SENT IT (REALITY)</span>
              <CheckCircle2 className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-sm font-bold text-cyan-300 break-all">
              {actualSender}
            </div>
            <p className="text-xs text-gray-400 font-sans leading-relaxed">
              This is the secret return-path stamp recorded by the mail servers. It does not match the company claiming to write to you!
            </p>
          </div>
        </div>
      </div>

      {/* 3. THE 4 BIG RED FLAGS EXPLAINED SIMPLY */}
      <div className="space-y-4">
        <h3 className="text-base sm:text-lg font-bold text-white tracking-wide flex items-center gap-2">
          <Sparkles className="w-5 h-5 text-amber-400" />
          <span>The 4 Big Red Flags in Plain English</span>
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {/* Flag 1: Sender Impersonation */}
          <div className="p-4 rounded-xl bg-black/40 border border-white/10 hover:border-cyan-500/30 transition-all space-y-2">
            <div className="flex items-center gap-2 text-red-400 text-xs font-bold font-mono uppercase">
              <Users className="w-4 h-4" />
              <span>1. Impersonation (Fake Identity)</span>
            </div>
            <h4 className="text-sm sm:text-base font-bold text-white">
              The email is wearing a costume
            </h4>
            <p className="text-xs sm:text-sm text-gray-300 leading-relaxed">
              The email claims to come from <strong>{claimedSender}</strong>, but the sender does not own or operate that organization's email server.
            </p>
          </div>

          {/* Flag 2: Fake Emergency */}
          <div className="p-4 rounded-xl bg-black/40 border border-white/10 hover:border-cyan-500/30 transition-all space-y-2">
            <div className="flex items-center gap-2 text-amber-400 text-xs font-bold font-mono uppercase">
              <AlertTriangle className="w-4 h-4" />
              <span>2. The Fake Rush (Panic Trick)</span>
            </div>
            <h4 className="text-sm sm:text-base font-bold text-white">
              They want you to panic and rush
            </h4>
            <p className="text-xs sm:text-sm text-gray-300 leading-relaxed">
              Phrases like <em>"urgent"</em> or <em>"account will close in 2 hours"</em> are designed to make you act fast before your common sense catches up.
            </p>
          </div>

          {/* Flag 3: The Sneaky Link */}
          <div className="p-4 rounded-xl bg-black/40 border border-white/10 hover:border-cyan-500/30 transition-all space-y-2">
            <div className="flex items-center gap-2 text-purple-400 text-xs font-bold font-mono uppercase">
              <ExternalLink className="w-4 h-4" />
              <span>3. The Sneaky Link</span>
            </div>
            <h4 className="text-sm sm:text-base font-bold text-white">
              The button leads to a counterfeit page
            </h4>
            <p className="text-xs sm:text-sm text-gray-300 leading-relaxed">
              {primaryUrl ? (
                <>
                  The link points to <span className="font-mono text-cyan-300 break-all">{primaryUrl.domain}</span>, which is a scam landing site built to steal passwords.
                </>
              ) : (
                'Links in this email direct you to unverified external websites designed to collect your company credentials.'
              )}
            </p>
          </div>

          {/* Flag 4: Failed Internet Safety Seals */}
          <div className="p-4 rounded-xl bg-black/40 border border-white/10 hover:border-cyan-500/30 transition-all space-y-2">
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-bold font-mono uppercase">
              <Lock className="w-4 h-4" />
              <span>4. Counterfeit Security Seals</span>
            </div>
            <h4 className="text-sm sm:text-base font-bold text-white">
              Failed the internet's digital ID check
            </h4>
            <p className="text-xs sm:text-sm text-gray-300 leading-relaxed">
              Legitimate emails come with digital verification stamps (SPF and DKIM). This email failed those checks because it wasn't sent from an authorized server.
            </p>
          </div>
        </div>
      </div>

      {/* 4. WHAT HAPPENS IF YOU CLICK? */}
      <div className="p-5 rounded-xl bg-red-950/20 border border-red-500/30 space-y-3">
        <h3 className="text-sm sm:text-base font-bold text-red-400 uppercase tracking-wider flex items-center gap-2 font-mono">
          <FileWarning className="w-4 h-4" />
          <span>What Happens If You Clicked?</span>
        </h3>
        <p className="text-xs sm:text-sm text-gray-200 leading-relaxed">
          If someone clicked a link or entered their password, the credentials were sent immediately to the attacker's server. The attacker can now log into that person's email, access company files, or send fake messages to coworkers asking for money.
        </p>
      </div>

      {/* 5. WHAT YOU SHOULD DO RIGHT NOW (Checklist) */}
      <div className="p-5 sm:p-6 rounded-2xl bg-[#05080f] border border-cyan-500/20 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-base sm:text-lg font-bold text-white flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            <span>What You Should Do Right Now (Action Checklist)</span>
          </h3>
          <span className="text-xs text-gray-400 font-mono">
            {Object.values(checklist).filter(Boolean).length}/4 Completed
          </span>
        </div>

        <div className="space-y-2.5">
          <div 
            onClick={() => toggleCheck('noClick')}
            className={`p-3 sm:p-4 rounded-xl border flex items-center gap-3 cursor-pointer transition-all ${
              checklist.noClick ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-200' : 'bg-black/40 border-white/10 text-gray-300 hover:border-white/20'
            }`}
          >
            <div className={`w-5 h-5 rounded flex items-center justify-center shrink-0 border ${
              checklist.noClick ? 'bg-emerald-500 border-emerald-500 text-black' : 'border-gray-500'
            }`}>
              {checklist.noClick && <Check className="w-3.5 h-3.5" />}
            </div>
            <div className="text-xs sm:text-sm">
              <strong className="text-white">1. Do NOT click any links, buttons, or reply: </strong>
              Treat all buttons in this email as dangerous traps.
            </div>
          </div>

          <div 
            onClick={() => toggleCheck('noDownload')}
            className={`p-3 sm:p-4 rounded-xl border flex items-center gap-3 cursor-pointer transition-all ${
              checklist.noDownload ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-200' : 'bg-black/40 border-white/10 text-gray-300 hover:border-white/20'
            }`}
          >
            <div className={`w-5 h-5 rounded flex items-center justify-center shrink-0 border ${
              checklist.noDownload ? 'bg-emerald-500 border-emerald-500 text-black' : 'border-gray-500'
            }`}>
              {checklist.noDownload && <Check className="w-3.5 h-3.5" />}
            </div>
            <div className="text-xs sm:text-sm">
              <strong className="text-white">2. Do NOT download or preview attachments: </strong>
              Invoices or PDF receipts in fake emails often contain spyware.
            </div>
          </div>

          <div 
            onClick={() => toggleCheck('reportIt')}
            className={`p-3 sm:p-4 rounded-xl border flex items-center gap-3 cursor-pointer transition-all ${
              checklist.reportIt ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-200' : 'bg-black/40 border-white/10 text-gray-300 hover:border-white/20'
            }`}
          >
            <div className={`w-5 h-5 rounded flex items-center justify-center shrink-0 border ${
              checklist.reportIt ? 'bg-emerald-500 border-emerald-500 text-black' : 'border-gray-500'
            }`}>
              {checklist.reportIt && <Check className="w-3.5 h-3.5" />}
            </div>
            <div className="text-xs sm:text-sm">
              <strong className="text-white">3. Report it to your IT / Security Team: </strong>
              Click "Report Phishing" in Gmail or forward it to your company security address.
            </div>
          </div>

          <div 
            onClick={() => toggleCheck('deleteMail')}
            className={`p-3 sm:p-4 rounded-xl border flex items-center gap-3 cursor-pointer transition-all ${
              checklist.deleteMail ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-200' : 'bg-black/40 border-white/10 text-gray-300 hover:border-white/20'
            }`}
          >
            <div className={`w-5 h-5 rounded flex items-center justify-center shrink-0 border ${
              checklist.deleteMail ? 'bg-emerald-500 border-emerald-500 text-black' : 'border-gray-500'
            }`}>
              {checklist.deleteMail && <Check className="w-3.5 h-3.5" />}
            </div>
            <div className="text-xs sm:text-sm">
              <strong className="text-white">4. Delete the message and empty your Trash bin: </strong>
              Prevent accidental clicks later by permanently deleting it.
            </div>
          </div>
        </div>
      </div>

      {/* 6. PLAIN-ENGLISH GLOSSARY (Decode Tech Jargon) */}
      <div className="pt-2 border-t border-white/10">
        <button
          onClick={() => setShowGlossary(!showGlossary)}
          className="w-full flex items-center justify-between text-xs sm:text-sm text-gray-400 hover:text-cyan-400 transition-colors py-2 cursor-pointer font-mono"
        >
          <span className="flex items-center gap-2">
            <HelpCircle className="w-4 h-4 text-cyan-400" />
            <strong className="text-white">Plain-English Glossary: What do those technical security words mean?</strong>
          </span>
          {showGlossary ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>

        {showGlossary && (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-3">
            <div className="p-3 rounded-lg bg-black/50 border border-white/10 space-y-1">
              <span className="text-xs font-mono font-bold text-cyan-300">SPF (The Guest List)</span>
              <p className="text-xs text-gray-400 leading-relaxed font-sans">
                A public list published by companies saying which internet servers are allowed to deliver their mail.
              </p>
            </div>

            <div className="p-3 rounded-lg bg-black/50 border border-white/10 space-y-1">
              <span className="text-xs font-mono font-bold text-purple-300">DKIM (The Wax Seal)</span>
              <p className="text-xs text-gray-400 leading-relaxed font-sans">
                A digital cryptographic stamp that proves the email was not modified or tampered with on its way to you.
              </p>
            </div>

            <div className="p-3 rounded-lg bg-black/50 border border-white/10 space-y-1">
              <span className="text-xs font-mono font-bold text-emerald-300">DMARC (The Bouncer)</span>
              <p className="text-xs text-gray-400 leading-relaxed font-sans">
                The rule telling Gmail or Outlook what to do if an email fails the guest list or wax seal (e.g. reject or quarantine it).
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
