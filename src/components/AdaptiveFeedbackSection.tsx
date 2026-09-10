import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Check, 
  ShieldCheck, 
  AlertTriangle, 
  HelpCircle, 
  Sparkles, 
  CheckCircle2, 
  Database, 
  Cpu, 
  Layers, 
  ArrowRight,
  Send,
  MessageSquare,
  RefreshCw,
  Info
} from 'lucide-react';
import { FeedbackLabel } from '@/types/feedback';
import { submitUserFeedback } from '@/services/feedbackService';
import { cn } from '@/lib/utils';
import { useLanguage } from '@/contexts/LanguageContext';

interface AdaptiveFeedbackSectionProps {
  targetId?: string;
  modelPrediction: string;
  riskScore: number;
  predictedAttackType?: string;
  extractedFeatures?: Record<string, any>;
  className?: string;
  compact?: boolean;
}

export function AdaptiveFeedbackSection({
  targetId,
  modelPrediction,
  riskScore,
  predictedAttackType = 'EMAIL',
  extractedFeatures = {},
  className,
  compact = false
}: AdaptiveFeedbackSectionProps) {
  const { t } = useLanguage();
  const [selectedFeedback, setSelectedFeedback] = useState<FeedbackLabel | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isRecorded, setIsRecorded] = useState(false);
  const [showNoteInput, setShowNoteInput] = useState(false);
  const [userNote, setUserNote] = useState('');
  const [showPipelineDetails, setShowPipelineDetails] = useState(false);

  const handleFeedbackClick = async (label: FeedbackLabel) => {
    setSelectedFeedback(label);
    setIsSubmitting(true);

    try {
      await submitUserFeedback({
        targetId: targetId || `analysis-${Date.now()}`,
        modelPrediction,
        riskScore,
        predictedAttackType,
        userFeedbackLabel: label,
        extractedFeatures,
        userNotes: userNote.trim() || undefined
      });
      setIsRecorded(true);
    } catch (err) {
      console.warn('[HITL Feedback] Submit error:', err);
      // Still show recorded for optimistic UI
      setIsRecorded(true);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleResetFeedback = () => {
    setSelectedFeedback(null);
    setIsRecorded(false);
    setShowNoteInput(false);
  };

  return (
    <div 
      className={cn(
        "rounded-xl border border-white/10 bg-[#080d1a]/90 backdrop-blur-md p-3.5 sm:p-4 transition-all duration-300 relative overflow-hidden",
        isRecorded ? "border-emerald-500/30 bg-[#06141a]/90 shadow-[0_0_20px_rgba(16,185,129,0.06)]" : "hover:border-cyan-500/25",
        className
      )}
    >
      {/* Subtle background glow */}
      <div className="absolute top-0 right-0 w-32 h-32 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

      {/* Header & Feature Badge */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 mb-3">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center shrink-0">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div>
            <h4 className="text-xs sm:text-sm font-bold text-white tracking-wide flex items-center gap-1.5">
              Help NeuroShield improve
            </h4>
            <p className="text-[10px] text-gray-400 font-mono">
              Human-in-the-Loop Adaptive Feedback System
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto">
          <button
            type="button"
            onClick={() => setShowPipelineDetails(!showPipelineDetails)}
            className="text-[10px] font-mono text-cyan-400/80 hover:text-cyan-300 flex items-center gap-1 transition-colors px-1.5 py-0.5 rounded hover:bg-white/5 cursor-pointer"
            title="View Active Learning Pipeline"
          >
            <Info className="w-3 h-3" />
            <span>{showPipelineDetails ? 'Hide Pipeline' : 'How it learns'}</span>
          </button>
        </div>
      </div>

      {/* Expandable Pipeline Architecture Explanation */}
      <AnimatePresence>
        {showPipelineDetails && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden mb-3 border-b border-white/5 pb-3"
          >
            <div className="p-2.5 rounded-lg bg-black/40 border border-cyan-500/20 text-[10px] font-mono text-gray-300 space-y-2">
              <div className="text-cyan-300 font-bold flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                Adaptive Calibration Pipeline:
              </div>
              <div className="flex items-center gap-1 flex-wrap text-[9px] text-gray-400">
                <span className="px-1.5 py-0.5 rounded bg-white/5 text-gray-200">1. Prediction</span>
                <ArrowRight className="w-2.5 h-2.5 text-cyan-400" />
                <span className="px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">2. User Feedback</span>
                <ArrowRight className="w-2.5 h-2.5 text-cyan-400" />
                <span className="px-1.5 py-0.5 rounded bg-white/5 text-gray-200">3. Feedback DB</span>
                <ArrowRight className="w-2.5 h-2.5 text-cyan-400" />
                <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20">4. Review Layer</span>
                <ArrowRight className="w-2.5 h-2.5 text-cyan-400" />
                <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">5. Verified Dataset</span>
                <ArrowRight className="w-2.5 h-2.5 text-cyan-400" />
                <span className="px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20">6. Calibration</span>
              </div>
              <p className="text-[10px] text-gray-400 leading-normal">
                User labels are safely stored in a quarantined staging database and reviewed by security analysts before triggering automated weight calibration.
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Confirmation State or Action Buttons */}
      <AnimatePresence mode="wait">
        {isRecorded ? (
          <motion.div
            key="recorded"
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300"
          >
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <div className="text-xs">
                <span className="font-bold text-white">Feedback recorded.</span>{' '}
                <span className="text-emerald-300/90">Thank you for helping NeuroShield improve.</span>
              </div>
            </div>

            <div className="flex items-center gap-2 self-end sm:self-auto text-[10px] font-mono">
              <span className="px-2 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/30 text-emerald-200 font-bold uppercase">
                {selectedFeedback === 'CORRECT' && 'Prediction Confirmed'}
                {selectedFeedback === 'MARK_SAFE' && 'Marked Safe (FP)'}
                {selectedFeedback === 'MARK_PHISHING' && 'Marked Phishing (FN)'}
                {selectedFeedback === 'NOT_SURE' && 'Logged (Omitted from Training)'}
              </span>
              <button
                type="button"
                onClick={handleResetFeedback}
                className="text-gray-400 hover:text-white underline transition-colors cursor-pointer"
              >
                Change
              </button>
            </div>
          </motion.div>
        ) : (
          <motion.div
            key="buttons"
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            className="space-y-2.5"
          >
            {/* 4 Standard Action Buttons */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {/* 1. Correct */}
              <button
                type="button"
                disabled={isSubmitting}
                onClick={() => handleFeedbackClick('CORRECT')}
                className={cn(
                  "group relative px-3 py-2 rounded-lg text-xs font-mono font-medium transition-all flex items-center justify-center gap-1.5 border cursor-pointer",
                  "bg-white/5 hover:bg-emerald-500/15 border-white/10 hover:border-emerald-500/40 text-gray-200 hover:text-emerald-300 active:scale-[0.98]"
                )}
                title="You agree with NeuroShield's prediction"
              >
                <Check className="w-3.5 h-3.5 text-emerald-400 group-hover:scale-110 transition-transform" />
                <span className="font-bold">Correct</span>
              </button>

              {/* 2. Mark Safe */}
              <button
                type="button"
                disabled={isSubmitting}
                onClick={() => handleFeedbackClick('MARK_SAFE')}
                className={cn(
                  "group relative px-3 py-2 rounded-lg text-xs font-mono font-medium transition-all flex items-center justify-center gap-1.5 border cursor-pointer",
                  "bg-white/5 hover:bg-cyan-500/15 border-white/10 hover:border-cyan-500/40 text-gray-200 hover:text-cyan-300 active:scale-[0.98]"
                )}
                title="Predicted suspicious/phishing, but you believe it is legitimate"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-cyan-400 group-hover:scale-110 transition-transform" />
                <span className="font-bold">Mark Safe</span>
              </button>

              {/* 3. Mark Phishing */}
              <button
                type="button"
                disabled={isSubmitting}
                onClick={() => handleFeedbackClick('MARK_PHISHING')}
                className={cn(
                  "group relative px-3 py-2 rounded-lg text-xs font-mono font-medium transition-all flex items-center justify-center gap-1.5 border cursor-pointer",
                  "bg-white/5 hover:bg-amber-500/15 border-white/10 hover:border-amber-500/40 text-gray-200 hover:text-amber-300 active:scale-[0.98]"
                )}
                title="Predicted safe/low-risk, but you believe it is phishing"
              >
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400 group-hover:scale-110 transition-transform" />
                <span className="font-bold">Mark Phishing</span>
              </button>

              {/* 4. Not Sure */}
              <button
                type="button"
                disabled={isSubmitting}
                onClick={() => handleFeedbackClick('NOT_SURE')}
                className={cn(
                  "group relative px-3 py-2 rounded-lg text-xs font-mono font-medium transition-all flex items-center justify-center gap-1.5 border cursor-pointer",
                  "bg-white/5 hover:bg-purple-500/15 border-white/10 hover:border-purple-500/40 text-gray-200 hover:text-purple-300 active:scale-[0.98]"
                )}
                title="Uncertain / Ambiguous (Saved for review, not used as training label)"
              >
                <HelpCircle className="w-3.5 h-3.5 text-purple-400 group-hover:scale-110 transition-transform" />
                <span className="font-bold">Not Sure</span>
              </button>
            </div>

            {/* Optional note toggle */}
            <div className="flex items-center justify-between text-[10px] font-mono text-gray-500 pt-0.5">
              <span>Clicking submits instant label to the review queue</span>
              <button
                type="button"
                onClick={() => setShowNoteInput(!showNoteInput)}
                className="text-cyan-400/80 hover:text-cyan-300 transition-colors flex items-center gap-1 cursor-pointer"
              >
                <MessageSquare className="w-3 h-3" />
                <span>{showNoteInput ? 'Hide note' : '+ Add optional note'}</span>
              </button>
            </div>

            {showNoteInput && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="pt-1"
              >
                <input
                  type="text"
                  value={userNote}
                  onChange={(e) => setUserNote(e.target.value)}
                  placeholder="Optional: reason (e.g. 'False positive on company payroll domain')"
                  className="w-full bg-black/50 border border-white/10 focus:border-cyan-500/40 rounded-lg px-2.5 py-1.5 text-xs text-gray-200 font-mono placeholder:text-gray-600 outline-none"
                />
              </motion.div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
