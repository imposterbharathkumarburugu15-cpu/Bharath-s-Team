import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  OctagonAlert, 
  ArrowLeft, 
  ExternalLink, 
  Check, 
  ThumbsUp, 
  ThumbsDown, 
  AlertOctagon, 
  MessageSquare, 
  Sparkles,
  Info,
  Layers,
  FileSearch,
  Lock,
  ArrowRight
} from 'lucide-react';
import { UnifiedIncidentObject, GuardState, SafeAlternative, GuardWarningCard as IGuardWarningCard } from '@/services/core/types';
import { submitIncidentFeedback } from '@/services/feedbackService';

interface GuardWarningCardProps {
  incident: UnifiedIncidentObject;
  onNavigateToForensics?: (incident: UnifiedIncidentObject) => void;
  onGoBack?: () => void;
  onSafeAlternative?: (alt: SafeAlternative) => void;
}

export function GuardWarningCard({
  incident,
  onNavigateToForensics,
  onGoBack,
  onSafeAlternative,
}: GuardWarningCardProps) {
  const [feedbackSubmitted, setFeedbackSubmitted] = useState<string | null>(null);
  const [userComment, setUserComment] = useState('');
  const [showCommentBox, setShowCommentBox] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const protection = incident.protection;
  const cardData = protection?.warning_card;
  const safeAlt = protection?.safe_alternative || cardData?.safe_alternative;

  // Derive visual state adhering strictly to real enforcement status
  const isEnforced = incident.enforcementStatus === 'ENFORCED';
  const isNotSupported = incident.enforcementStatus === 'NOT_SUPPORTED';
  const isPartiallyEnforced = incident.enforcementStatus === 'PARTIALLY_ENFORCED';

  const guardState: GuardState =
    cardData?.state ||
    (protection?.decision === 'BLOCK' || protection?.decision === 'BLOCK_ACTION' || protection?.decision === 'BLOCK_VIEW'
      ? (isEnforced ? 'BLOCKED' : 'HIGH_RISK')
      : incident.risk_level === 'CRITICAL' || incident.risk_level === 'HIGH'
      ? 'HIGH_RISK'
      : incident.risk_level === 'MEDIUM'
      ? 'SUSPICIOUS'
      : 'SAFE');

  const stateConfigs = {
    SAFE: {
      badge: '🟢 SAFE',
      badgeClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      borderClass: 'border-emerald-500/40 shadow-emerald-950/20',
      bgGradient: 'from-emerald-950/20 via-slate-900 to-slate-900',
      icon: ShieldCheck,
      iconColor: 'text-emerald-400',
      actionBoxBorder: 'border-emerald-500',
      actionTextColor: 'text-emerald-400',
      defaultTitle: 'Verified Safe Interaction',
      defaultSummary: 'No malicious deception, credential theft, or fraud detected.',
    },
    SUSPICIOUS: {
      badge: '🟡 WARNED',
      badgeClass: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      borderClass: 'border-amber-500/40 shadow-amber-950/20',
      bgGradient: 'from-amber-950/20 via-slate-900 to-slate-900',
      icon: AlertTriangle,
      iconColor: 'text-amber-400',
      actionBoxBorder: 'border-amber-500',
      actionTextColor: 'text-amber-400',
      defaultTitle: 'Suspicious Activity Detected',
      defaultSummary: 'Unverified origin or anomalous request signals observed.',
    },
    HIGH_RISK: {
      badge: isNotSupported ? '⚠️ RESTRICTED (NOT_ENFORCED)' : isPartiallyEnforced ? '🟠 PARTIALLY ENFORCED' : '🔴 HIGH RISK',
      badgeClass: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
      borderClass: 'border-orange-500/40 shadow-orange-950/30',
      bgGradient: 'from-orange-950/25 via-slate-900 to-slate-900',
      icon: ShieldAlert,
      iconColor: 'text-orange-400',
      actionBoxBorder: 'border-orange-500',
      actionTextColor: 'text-orange-400',
      defaultTitle: isNotSupported ? 'Dangerous Interaction - Client Blocking Not Supported' : 'High-Risk Interaction Restrained',
      defaultSummary: isNotSupported
        ? 'Dangerous action detected, but the current client does not support automated blocking (NOT_SUPPORTED). Exercise extreme caution.'
        : 'Strong indicators of credential harvesting, spoofing, or financial lure.',
    },
    BLOCKED: {
      badge: '⛔ ENFORCED BLOCK',
      badgeClass: 'bg-red-500/15 text-red-400 border-red-500/40',
      borderClass: 'border-red-500/50 shadow-red-950/40',
      bgGradient: 'from-red-950/30 via-slate-900 to-slate-900',
      icon: OctagonAlert,
      iconColor: 'text-red-400',
      actionBoxBorder: 'border-red-500',
      actionTextColor: 'text-red-400',
      defaultTitle: 'Threat Blocked & Enforced',
      defaultSummary: 'Dangerous interaction was intercepted and actively prevented by NeuroShield enforcement.',
    },
  };

  const config = stateConfigs[guardState] || stateConfigs.SAFE;
  const StateIcon = config.icon;

  const handleFeedback = async (type: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'MISSED_THREAT') => {
    setIsSubmitting(true);
    try {
      await submitIncidentFeedback({
        incident_id: incident.incident_id,
        feedback: type,
        user_comment: userComment,
        source: incident.source,
        risk_score: incident.risk_score,
        threat_type: incident.attack_types?.[0] || 'Phishing / Deception',
      });
      setFeedbackSubmitted(type);
    } catch (err) {
      console.warn('Feedback submit error:', err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className={`w-full rounded-xl border bg-gradient-to-b ${config.bgGradient} ${config.borderClass} p-6 shadow-2xl transition-all`}
    >
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className={`p-2.5 rounded-lg bg-slate-900/80 border border-slate-700/60 ${config.iconColor}`}>
            <StateIcon className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold tracking-wider text-slate-400 uppercase">
                NEUROSHIELD GUARD
              </span>
              <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full border ${config.badgeClass}`}>
                {config.badge}
              </span>
            </div>
            <h3 className="text-lg font-bold text-white mt-0.5">
              {cardData?.title || config.defaultTitle}
            </h3>
          </div>
        </div>

        {/* Severity, Confidence & Real Enforcement pills */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="px-2.5 py-1 bg-slate-900/90 rounded-md border border-slate-800 text-right font-mono">
            <span className="text-[9px] uppercase text-slate-400 block">Risk Score</span>
            <span className={`text-xs font-bold ${config.iconColor}`}>
              {incident.risk_score}/100
            </span>
          </div>
          <div className="px-2.5 py-1 bg-slate-900/90 rounded-md border border-slate-800 text-right font-mono">
            <span className="text-[9px] uppercase text-slate-400 block">Confidence</span>
            <span className="text-xs font-bold text-cyan-400">
              {incident.confidence}%
            </span>
          </div>
          <div className="px-2.5 py-1 bg-slate-900/90 rounded-md border border-slate-800 text-right font-mono">
            <span className="text-[9px] uppercase text-slate-400 block">Enforcement</span>
            <span className={`text-xs font-bold ${
              incident.enforcementStatus === 'ENFORCED'
                ? 'text-emerald-400'
                : incident.enforcementStatus === 'PARTIALLY_ENFORCED'
                ? 'text-amber-400'
                : incident.enforcementStatus === 'NOT_SUPPORTED'
                ? 'text-yellow-500'
                : incident.enforcementStatus === 'FAILED'
                ? 'text-red-400'
                : 'text-slate-300'
            }`}>
              {incident.enforcementStatus || incident.authoritativeProtectionDecision?.enforcementStatus || 'NOT_REQUIRED'}
            </span>
          </div>
        </div>
      </div>

      {/* Enforcement Telemetry Badge Bar */}
      <div className="mt-3 py-2 px-3 rounded-lg bg-slate-950/80 border border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono">
        <div className="flex items-center gap-2">
          <span className="text-slate-400">Decision:</span>
          <span className="font-bold text-white px-2 py-0.5 rounded bg-slate-900 border border-slate-700">
            {incident.authoritativeProtectionDecision?.protectionDecision || incident.protection?.decision || 'ALLOW'}
          </span>
          <span className="text-slate-400 ml-1">Action:</span>
          <span className="font-bold text-cyan-300">
            {incident.authoritativeProtectionDecision?.requestedAction || incident.action_risk?.detected_action || 'UNKNOWN'}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-slate-400">Client:</span>
          <span className="text-slate-300 font-bold">
            {incident.client || (incident as any)?.metadata?.client || 'guard_web_simulator'}
          </span>
          <span className="text-slate-400 ml-1">Level:</span>
          <span className="text-slate-300">
            {incident.enforcementLevel || incident.authoritativeProtectionDecision?.enforcementLevel || 'CLIENT'}
          </span>
        </div>
      </div>

      {/* Core Summary (Jargon-free) */}
      <div className="mt-4 text-sm text-slate-200 leading-relaxed">
        {cardData?.summary || protection?.recommended_action || config.defaultSummary}
      </div>

      {/* Risk Detected Box */}
      <div className="mt-3 text-xs text-slate-400 flex items-start gap-2 bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
        <Info className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-slate-300">Observation: </strong>
          {cardData?.risk_detected ||
            (incident.whyRiskIncreased && incident.whyRiskIncreased[0]) ||
            'Pattern analyzed across identity, intent, technical markers, and relationship signals.'}
        </div>
      </div>

      {/* ACTION-AWARE WARNING (Central Guard Rule: Warn before dangerous action) */}
      <div className={`mt-4 rounded-lg bg-slate-950 p-4 border-l-4 ${config.actionBoxBorder} border-y border-r border-slate-800`}>
        <div className="text-[11px] uppercase tracking-wider font-mono font-bold text-slate-400">
          Required Protective Action
        </div>
        <div className={`text-base font-extrabold tracking-wide mt-1 ${config.actionTextColor}`}>
          {cardData?.required_action || protection?.recommended_action?.toUpperCase() || 'PROCEED NORMALLY'}
        </div>
      </div>

      {/* PHASE 7.5 SECURITY INTELLIGENCE TELEMETRY */}
      {(incident.dynamic_trust || incident.identity_continuity || incident.evasion?.detected || incident.campaign_fingerprint) && (
        <div className="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
          {incident.dynamic_trust && (
            <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-2.5">
              <span className="text-[10px] uppercase font-mono text-slate-400 block">Dynamic Trust</span>
              <span className={`font-mono font-bold ${incident.dynamic_trust.current_trust < 40 ? 'text-red-400' : incident.dynamic_trust.current_trust < 70 ? 'text-amber-400' : 'text-emerald-400'}`}>
                {incident.dynamic_trust.current_trust}/100 ({incident.dynamic_trust.trust_level})
              </span>
            </div>
          )}
          {incident.identity_continuity && (
            <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-2.5">
              <span className="text-[10px] uppercase font-mono text-slate-400 block">Identity Continuity</span>
              <span className={`font-mono font-bold ${incident.identity_continuity.identity_mismatch ? 'text-red-400' : incident.identity_continuity.identity_novelty ? 'text-amber-400' : 'text-emerald-400'}`}>
                {incident.identity_continuity.historical_identity_analysis}
              </span>
            </div>
          )}
          {incident.evasion && (
            <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-2.5">
              <span className="text-[10px] uppercase font-mono text-slate-400 block">Evasion Defense</span>
              <span className={`font-mono font-bold ${incident.evasion.detected ? 'text-orange-400' : 'text-slate-400'}`}>
                {incident.evasion.detected ? `${incident.evasion.techniques.length} Technique(s)` : 'None Detected'}
              </span>
            </div>
          )}
          {incident.campaign_fingerprint && (
            <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-2.5">
              <span className="text-[10px] uppercase font-mono text-slate-400 block">Campaign Hash</span>
              <span className="font-mono font-bold text-sky-400 truncate block">
                {incident.campaign_fingerprint.fingerprint_hash.substring(0, 10)}...
              </span>
            </div>
          )}
        </div>
      )}

      {/* SAFE ALTERNATIVE (Safe Exit Workflow) */}
      {safeAlt && (
        <div className="mt-4 rounded-lg bg-sky-950/20 border border-sky-800/40 p-4">
          <div className="flex items-center gap-2 text-sky-400 text-xs font-bold uppercase tracking-wider">
            <Sparkles className="w-4 h-4" />
            Safe Alternative: {safeAlt.title}
          </div>
          <p className="text-xs text-slate-300 mt-1 leading-relaxed">
            {safeAlt.guidance}
          </p>
          {safeAlt.safe_url && (
            <div className="mt-2 text-xs font-mono text-sky-300 truncate bg-slate-900/80 px-2.5 py-1 rounded border border-sky-900/50">
              Verified Target: {safeAlt.safe_url}
            </div>
          )}
        </div>
      )}

      {/* Action Buttons */}
      <div className="mt-5 flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-slate-800/80">
        <div className="flex items-center gap-2">
          {onGoBack && (
            <button
              onClick={onGoBack}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold rounded-lg border border-slate-700 transition flex items-center gap-1.5 cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              Go Back
            </button>
          )}
          {safeAlt && onSafeAlternative && (
            <button
              onClick={() => onSafeAlternative(safeAlt)}
              className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white text-xs font-bold rounded-lg shadow-md transition flex items-center gap-1.5 cursor-pointer"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              {safeAlt.action_label}
            </button>
          )}
        </div>

        {onNavigateToForensics && (
          <button
            onClick={() => onNavigateToForensics(incident)}
            className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 text-sky-400 hover:text-sky-300 text-xs font-mono font-medium rounded-lg border border-sky-900/50 transition flex items-center gap-1.5 cursor-pointer"
          >
            <FileSearch className="w-3.5 h-3.5" />
            View Forensic Evidence Graph
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Human-In-The-Loop Feedback Widget */}
      <div className="mt-5 pt-4 border-t border-slate-800/60 bg-slate-950/40 -mx-6 -mb-6 p-5 rounded-b-xl">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-xs font-medium text-slate-400">
            Did NeuroShield handle this correctly?
          </span>

          <div className="flex items-center gap-1.5">
            <button
              onClick={() => handleFeedback('TRUE_POSITIVE')}
              disabled={isSubmitting || feedbackSubmitted !== null}
              className={`px-3 py-1.5 rounded text-xs font-medium border transition flex items-center gap-1.5 cursor-pointer ${
                feedbackSubmitted === 'TRUE_POSITIVE'
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50'
                  : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border-slate-800'
              }`}
            >
              <ThumbsUp className="w-3 h-3 text-emerald-400" />
              Threat Confirmed
            </button>

            <button
              onClick={() => handleFeedback('FALSE_POSITIVE')}
              disabled={isSubmitting || feedbackSubmitted !== null}
              className={`px-3 py-1.5 rounded text-xs font-medium border transition flex items-center gap-1.5 cursor-pointer ${
                feedbackSubmitted === 'FALSE_POSITIVE'
                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/50'
                  : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border-slate-800'
              }`}
            >
              <AlertTriangle className="w-3 h-3 text-amber-400" />
              False Alarm
            </button>

            <button
              onClick={() => handleFeedback('MISSED_THREAT')}
              disabled={isSubmitting || feedbackSubmitted !== null}
              className={`px-3 py-1.5 rounded text-xs font-medium border transition flex items-center gap-1.5 cursor-pointer ${
                feedbackSubmitted === 'MISSED_THREAT'
                  ? 'bg-red-500/20 text-red-300 border-red-500/50'
                  : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border-slate-800'
              }`}
            >
              <AlertOctagon className="w-3 h-3 text-red-400" />
              Missed Threat
            </button>

            <button
              onClick={() => setShowCommentBox(!showCommentBox)}
              className="p-1.5 text-slate-400 hover:text-slate-200 rounded border border-slate-800 bg-slate-900 cursor-pointer"
              title="Add feedback comment"
            >
              <MessageSquare className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Optional Comment Box */}
        <AnimatePresence>
          {showCommentBox && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="mt-3 overflow-hidden"
            >
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="Optional analyst note or user context..."
                  value={userComment}
                  onChange={(e) => setUserComment(e.target.value)}
                  className="flex-1 bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 outline-none focus:border-sky-500"
                />
                <button
                  onClick={() => handleFeedback('TRUE_POSITIVE')}
                  disabled={isSubmitting}
                  className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white text-xs font-bold rounded cursor-pointer"
                >
                  Submit
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {feedbackSubmitted && (
          <div className="mt-2 text-[11px] text-emerald-400 flex items-center gap-1 font-mono">
            <Check className="w-3.5 h-3.5" />
            Feedback saved and synchronized to Human-in-the-Loop calibration pipeline.
          </div>
        )}
      </div>
    </motion.div>
  );
}
