import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Sparkles, 
  Database, 
  CheckCircle2, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  HelpCircle, 
  RefreshCw, 
  Cpu, 
  Layers, 
  ArrowRight, 
  Download, 
  Filter, 
  Search, 
  Check, 
  X, 
  Activity, 
  Sliders, 
  ExternalLink, 
  Tag, 
  Clock, 
  UserCheck, 
  BarChart3, 
  PieChart, 
  Flame,
  Zap,
  Lock,
  ArrowUpRight
} from 'lucide-react';
import { 
  FeedbackRecord, 
  FeedbackMetrics, 
  CalibrationResult, 
  ReviewStatus, 
  FeedbackLabel 
} from '@/types/feedback';
import { 
  getFeedbackDataset, 
  reviewFeedbackRecord, 
  triggerModelCalibration, 
  computeFeedbackMetrics 
} from '@/services/feedbackService';
import { cn } from '@/lib/utils';
import { useLanguage } from '@/contexts/LanguageContext';

export function FeedbackDashboard() {
  const { t } = useLanguage();
  const [records, setRecords] = useState<FeedbackRecord[]>([]);
  const [metrics, setMetrics] = useState<FeedbackMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeFilter, setActiveFilter] = useState<'ALL' | 'PENDING' | 'VERIFIED' | 'REJECTED'>('ALL');
  const [labelFilter, setLabelFilter] = useState<'ALL' | FeedbackLabel>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRecord, setSelectedRecord] = useState<FeedbackRecord | null>(null);
  
  // Calibration status
  const [isCalibrating, setIsCalibrating] = useState(false);
  const [calibrationResult, setCalibrationResult] = useState<CalibrationResult | null>(null);
  const [reviewingId, setReviewingId] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await getFeedbackDataset();
      setRecords(data.records);
      setMetrics(data.metrics);
    } catch (e) {
      console.warn('Error loading feedback:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleVerify = async (id: string, status: ReviewStatus) => {
    setReviewingId(id);
    try {
      const result = await reviewFeedbackRecord(id, status);
      if (result.success && result.record) {
        setRecords(prev => prev.map(r => r.id === id ? result.record! : r));
        setMetrics(computeFeedbackMetrics(records.map(r => r.id === id ? result.record! : r)));
        if (selectedRecord?.id === id) {
          setSelectedRecord(result.record);
        }
      }
    } finally {
      setReviewingId(null);
    }
  };

  const handleRunCalibration = async () => {
    setIsCalibrating(true);
    setCalibrationResult(null);
    try {
      // Simulate network / GPU training epoch run
      await new Promise(r => setTimeout(r, 1800));
      const res = await triggerModelCalibration();
      setCalibrationResult(res);
      await loadData();
    } finally {
      setIsCalibrating(false);
    }
  };

  const handleExportJson = () => {
    const verifiedOnly = records.filter(r => r.calibrationEligible);
    const blob = new Blob([JSON.stringify(verifiedOnly, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `neuroshield-verified-feedback-dataset-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredRecords = records.filter(r => {
    if (activeFilter !== 'ALL' && r.reviewStatus !== activeFilter) return false;
    if (labelFilter !== 'ALL' && r.userFeedbackLabel !== labelFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchPrediction = r.modelPrediction.toLowerCase().includes(q);
      const matchId = r.targetId.toLowerCase().includes(q);
      const matchSender = r.extractedFeatures?.sender?.toLowerCase().includes(q);
      const matchSubject = r.extractedFeatures?.subject?.toLowerCase().includes(q);
      const matchNotes = r.userNotes?.toLowerCase().includes(q);
      if (!matchPrediction && !matchId && !matchSender && !matchSubject && !matchNotes) return false;
    }
    return true;
  });

  return (
    <div className="flex-1 flex flex-col w-full min-h-screen bg-[#030712] text-white p-4 sm:p-6 lg:p-8 space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
              <Sparkles className="w-4 h-4 text-cyan-400" />
            </div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-mono uppercase">
              Human-in-the-Loop Adaptive Feedback System
            </h1>
          </div>
          <p className="text-xs sm:text-sm text-gray-400 font-mono">
            Quarantined Ground-Truth Annotation Pipeline & Periodic Model Calibration Dashboard
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            type="button"
            onClick={loadData}
            disabled={loading}
            className="px-3 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <RefreshCw className={cn("w-3.5 h-3.5 text-cyan-400", loading && "animate-spin")} />
            <span>Sync Pipeline</span>
          </button>

          <button
            type="button"
            onClick={handleExportJson}
            className="px-3 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export Verified Dataset</span>
          </button>

          <button
            type="button"
            onClick={handleRunCalibration}
            disabled={isCalibrating || (metrics?.verifiedDatasetSize || 0) === 0}
            className={cn(
              "px-4 py-2 rounded-lg text-xs font-mono font-bold flex items-center gap-2 transition-all cursor-pointer shadow-lg",
              isCalibrating 
                ? "bg-purple-500/30 text-purple-200 border border-purple-500/40 animate-pulse"
                : "bg-cyan-500 hover:bg-cyan-400 text-black shadow-cyan-500/20 active:scale-95"
            )}
          >
            <Zap className={cn("w-4 h-4", isCalibrating && "animate-spin")} />
            <span>{isCalibrating ? 'Calibrating Neural Weights...' : 'Run Model Calibration'}</span>
          </button>
        </div>
      </div>

      {/* Calibration Notification / Result Banner */}
      <AnimatePresence>
        {calibrationResult && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="p-4 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-200 font-mono text-xs space-y-2 relative"
          >
            <button
              onClick={() => setCalibrationResult(null)}
              className="absolute top-3 right-3 text-purple-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
            <div className="flex items-center gap-2 font-bold text-sm text-purple-300">
              <CheckCircle2 className="w-4 h-4 text-purple-400" />
              <span>{calibrationResult.message}</span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
              <div className="bg-black/40 p-2 rounded border border-purple-500/20">
                <div className="text-[10px] text-gray-400">Verified Samples Used</div>
                <div className="text-base font-bold text-white">{calibrationResult.verifiedSamplesUsed}</div>
              </div>
              <div className="bg-black/40 p-2 rounded border border-purple-500/20">
                <div className="text-[10px] text-gray-400">Previous Accuracy</div>
                <div className="text-base font-bold text-gray-300">{calibrationResult.previousAccuracy}%</div>
              </div>
              <div className="bg-black/40 p-2 rounded border border-purple-500/20">
                <div className="text-[10px] text-gray-400">Calibrated Accuracy</div>
                <div className="text-base font-bold text-emerald-400">{calibrationResult.newAccuracy}%</div>
              </div>
              <div className="bg-black/40 p-2 rounded border border-purple-500/20">
                <div className="text-[10px] text-gray-400">Accuracy Gain (Δ)</div>
                <div className="text-base font-bold text-cyan-400">+{calibrationResult.accuracyDelta}%</div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* KPI Metrics Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* 1. Total Feedback */}
        <div className="p-3.5 rounded-xl bg-[#0a0f1d] border border-white/10 flex flex-col justify-between">
          <span className="text-[11px] font-mono text-gray-400 flex items-center justify-between">
            <span>Total Feedback</span>
            <Database className="w-3.5 h-3.5 text-cyan-400" />
          </span>
          <div className="text-xl sm:text-2xl font-bold font-mono text-white mt-1">
            {metrics?.totalFeedback ?? 0}
          </div>
          <span className="text-[9px] font-mono text-cyan-400/80 mt-1">User clicks ingested</span>
        </div>

        {/* 2. Correct Predictions */}
        <div className="p-3.5 rounded-xl bg-[#0a0f1d] border border-white/10 flex flex-col justify-between">
          <span className="text-[11px] font-mono text-gray-400 flex items-center justify-between">
            <span>Correct Matches</span>
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          </span>
          <div className="text-xl sm:text-2xl font-bold font-mono text-emerald-400 mt-1">
            {metrics?.correctPredictions ?? 0}
          </div>
          <span className="text-[9px] font-mono text-emerald-400/80 mt-1">Confirmed predictions</span>
        </div>

        {/* 3. False Positives (Safe Corrections) */}
        <div className="p-3.5 rounded-xl bg-[#0a0f1d] border border-white/10 flex flex-col justify-between">
          <span className="text-[11px] font-mono text-gray-400 flex items-center justify-between">
            <span>False Positives</span>
            <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
          </span>
          <div className="text-xl sm:text-2xl font-bold font-mono text-cyan-400 mt-1">
            {metrics?.falsePositives ?? 0}
          </div>
          <span className="text-[9px] font-mono text-cyan-400/80 mt-1">Marked safe by user</span>
        </div>

        {/* 4. False Negatives (Phishing Corrections) */}
        <div className="p-3.5 rounded-xl bg-[#0a0f1d] border border-white/10 flex flex-col justify-between">
          <span className="text-[11px] font-mono text-gray-400 flex items-center justify-between">
            <span>False Negatives</span>
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          </span>
          <div className="text-xl sm:text-2xl font-bold font-mono text-amber-400 mt-1">
            {metrics?.falseNegatives ?? 0}
          </div>
          <span className="text-[9px] font-mono text-amber-400/80 mt-1">Marked phishing by user</span>
        </div>

        {/* 5. Not Sure / Unresolved */}
        <div className="p-3.5 rounded-xl bg-[#0a0f1d] border border-white/10 flex flex-col justify-between">
          <span className="text-[11px] font-mono text-gray-400 flex items-center justify-between">
            <span>Unresolved Feedback</span>
            <HelpCircle className="w-3.5 h-3.5 text-purple-400" />
          </span>
          <div className="text-xl sm:text-2xl font-bold font-mono text-purple-400 mt-1">
            {metrics?.unresolvedFeedback ?? 0}
          </div>
          <span className="text-[9px] font-mono text-purple-400/80 mt-1">Excluded from training</span>
        </div>

        {/* 6. Model Accuracy (Verified) */}
        <div className="p-3.5 rounded-xl bg-gradient-to-br from-[#0a1628] to-[#041a1a] border border-cyan-500/30 flex flex-col justify-between">
          <span className="text-[11px] font-mono text-cyan-300 flex items-center justify-between">
            <span>Verified Accuracy</span>
            <BarChart3 className="w-3.5 h-3.5 text-cyan-400" />
          </span>
          <div className="text-xl sm:text-2xl font-bold font-mono text-white mt-1">
            {metrics?.modelAccuracy ?? 94.8}%
          </div>
          <span className="text-[9px] font-mono text-emerald-400 mt-1">
            {metrics?.verifiedDatasetSize ?? 0} verified samples
          </span>
        </div>
      </div>

      {/* Learning Pipeline Architecture Blueprint */}
      <div className="p-4 sm:p-5 rounded-2xl bg-[#080d1a] border border-white/10 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Active Learning & Ground-Truth Calibration Pipeline
            </h3>
            <p className="text-xs text-gray-400 font-mono">
              Safeguarded workflow preventing noisy clicks from directly poisoning inference weights
            </p>
          </div>
          <div className="text-xs font-mono text-gray-400">
            Pipeline Health: <span className="text-emerald-400 font-bold">OPTIMAL</span>
          </div>
        </div>

        {/* 6-Stage Visual Flow */}
        <div className="grid grid-cols-1 md:grid-cols-6 gap-2 pt-2">
          {/* Stage 1: Prediction */}
          <div className="p-3 rounded-xl bg-[#050811] border border-white/10 flex flex-col justify-between space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-gray-400 font-bold">1. PREDICTION</span>
              <Cpu className="w-3.5 h-3.5 text-gray-400" />
            </div>
            <div className="text-xs font-bold text-white">NeuroShield AI</div>
            <p className="text-[10px] text-gray-400 font-mono leading-tight">
              Infers risk score (0-100) & threat signals
            </p>
            <div className="text-[10px] font-mono text-cyan-400 pt-1 border-t border-white/5">
              {metrics?.pipelineStages?.predictionCount || 1420} Scans Ingested
            </div>
          </div>

          {/* Stage 2: User Feedback */}
          <div className="p-3 rounded-xl bg-[#050811] border border-cyan-500/25 flex flex-col justify-between space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-cyan-400 font-bold">2. USER FEEDBACK</span>
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            </div>
            <div className="text-xs font-bold text-cyan-200">Human Interaction</div>
            <p className="text-[10px] text-gray-400 font-mono leading-tight">
              4 action buttons: Correct, Safe, Phish, Not Sure
            </p>
            <div className="text-[10px] font-mono text-cyan-400 pt-1 border-t border-white/5">
              {metrics?.totalFeedback || 0} User Submissions
            </div>
          </div>

          {/* Stage 3: Feedback DB */}
          <div className="p-3 rounded-xl bg-[#050811] border border-white/10 flex flex-col justify-between space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-gray-400 font-bold">3. FEEDBACK DB</span>
              <Database className="w-3.5 h-3.5 text-gray-400" />
            </div>
            <div className="text-xs font-bold text-white">Quarantine Staging</div>
            <p className="text-[10px] text-gray-400 font-mono leading-tight">
              Stores payload IDs, extracted tokens, headers
            </p>
            <div className="text-[10px] font-mono text-cyan-400 pt-1 border-t border-white/5">
              {metrics?.totalFeedback || 0} Records Staged
            </div>
          </div>

          {/* Stage 4: Validation / Review Layer */}
          <div className="p-3 rounded-xl bg-[#050811] border border-amber-500/30 flex flex-col justify-between space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-amber-400 font-bold">4. REVIEW LAYER</span>
              <UserCheck className="w-3.5 h-3.5 text-amber-400" />
            </div>
            <div className="text-xs font-bold text-amber-200">SOC Triage Layer</div>
            <p className="text-[10px] text-gray-400 font-mono leading-tight">
              Security analysts audit false positives & negatives
            </p>
            <div className="text-[10px] font-mono text-amber-400 pt-1 border-t border-white/5">
              {metrics?.pendingCount || 0} Pending Audits
            </div>
          </div>

          {/* Stage 5: Verified Dataset */}
          <div className="p-3 rounded-xl bg-[#050811] border border-emerald-500/30 flex flex-col justify-between space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-emerald-400 font-bold">5. VERIFIED DATASET</span>
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            </div>
            <div className="text-xs font-bold text-emerald-200">Ground Truth Pool</div>
            <p className="text-[10px] text-gray-400 font-mono leading-tight">
              Filtered, verified labels ready for fine-tuning
            </p>
            <div className="text-[10px] font-mono text-emerald-400 pt-1 border-t border-white/5">
              {metrics?.verifiedDatasetSize || 0} Verified Tokens
            </div>
          </div>

          {/* Stage 6: Model Calibration */}
          <div className="p-3 rounded-xl bg-[#050811] border border-purple-500/30 flex flex-col justify-between space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-purple-400 font-bold">6. CALIBRATION</span>
              <Zap className="w-3.5 h-3.5 text-purple-400" />
            </div>
            <div className="text-xs font-bold text-purple-200">Retrained Weights</div>
            <p className="text-[10px] text-gray-400 font-mono leading-tight">
              Threshold updates & heuristic re-weighting
            </p>
            <div className="text-[10px] font-mono text-purple-400 pt-1 border-t border-white/5">
              {metrics?.calibrationRuns || 3} Calibration Cycles
            </div>
          </div>
        </div>
      </div>

      {/* Main Review & Triage Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Records Table & Triage Filters */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#080d1a] p-3.5 rounded-xl border border-white/10">
            {/* Status Filter Tabs */}
            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
              {(['ALL', 'PENDING', 'VERIFIED', 'REJECTED'] as const).map(status => (
                <button
                  key={status}
                  type="button"
                  onClick={() => setActiveFilter(status)}
                  className={cn(
                    "px-2.5 py-1 rounded-lg text-xs font-mono transition-colors cursor-pointer whitespace-nowrap",
                    activeFilter === status 
                      ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold"
                      : "text-gray-400 hover:text-white hover:bg-white/5 border border-transparent"
                  )}
                >
                  {status}
                  {status === 'PENDING' && (metrics?.pendingCount ?? 0) > 0 && (
                    <span className="ml-1.5 px-1.5 py-0.2 rounded-full bg-amber-500/20 text-amber-400 text-[10px]">
                      {metrics?.pendingCount}
                    </span>
                  )}
                </button>
              ))}
            </div>

            {/* Label Filter */}
            <div className="flex items-center gap-2">
              <select
                value={labelFilter}
                onChange={(e) => setLabelFilter(e.target.value as any)}
                aria-label="Filter records by user feedback label"
                className="bg-black/50 border border-white/10 text-xs font-mono text-gray-300 rounded-lg px-2.5 py-1 outline-none focus:border-cyan-500/40"
              >
                <option value="ALL">All User Labels</option>
                <option value="CORRECT">Correct (Agreed)</option>
                <option value="MARK_SAFE">Mark Safe (False Positives)</option>
                <option value="MARK_PHISHING">Mark Phishing (False Negatives)</option>
                <option value="NOT_SURE">Not Sure (Unresolved)</option>
              </select>

              <div className="relative flex-1 sm:w-44">
                <Search className="w-3.5 h-3.5 text-gray-500 absolute left-2.5 top-2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter records..."
                  className="w-full bg-black/50 border border-white/10 rounded-lg pl-7 pr-2 py-1 text-xs font-mono text-gray-200 placeholder:text-gray-600 outline-none focus:border-cyan-500/40"
                />
              </div>
            </div>
          </div>

          {/* Records List */}
          <div className="space-y-2.5">
            {filteredRecords.length === 0 ? (
              <div className="p-8 text-center rounded-xl bg-[#080d1a] border border-white/10 font-mono text-sm text-gray-500">
                No feedback records found matching active filter.
              </div>
            ) : (
              filteredRecords.map(record => {
                const isSelected = selectedRecord?.id === record.id;
                const isPending = record.reviewStatus === 'PENDING';
                const isVerified = record.reviewStatus === 'VERIFIED';
                const isRejected = record.reviewStatus === 'REJECTED';

                return (
                  <div
                    key={record.id}
                    onClick={() => setSelectedRecord(record)}
                    className={cn(
                      "p-4 rounded-xl border transition-all cursor-pointer bg-[#080d1a]/90 hover:bg-[#0c1428]",
                      isSelected 
                        ? "border-cyan-500/60 shadow-[0_0_20px_rgba(0,245,255,0.1)]" 
                        : "border-white/10 hover:border-white/20"
                    )}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-gray-400 font-bold">
                          {record.targetId}
                        </span>
                        <span className="text-[10px] font-mono text-gray-500">
                          {new Date(record.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                        <span className={cn(
                          "px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border",
                          record.predictedAttackType === 'EMAIL' ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' :
                          record.predictedAttackType === 'CHAT' ? 'bg-purple-500/10 text-purple-400 border-purple-500/20' :
                          'bg-cyan-500/10 text-cyan-400 border-cyan-500/20'
                        )}>
                          {record.predictedAttackType}
                        </span>
                      </div>

                      {/* Review Status Badge */}
                      <div className="flex items-center gap-2">
                        <span className={cn(
                          "px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase flex items-center gap-1 border",
                          isVerified ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" :
                          isRejected ? "bg-red-500/15 text-red-300 border-red-500/30" :
                          "bg-amber-500/15 text-amber-300 border-amber-500/30"
                        )}>
                          {isVerified && <CheckCircle2 className="w-3 h-3 text-emerald-400" />}
                          {isRejected && <X className="w-3 h-3 text-red-400" />}
                          {isPending && <Clock className="w-3 h-3 text-amber-400" />}
                          <span>{record.reviewStatus}</span>
                        </span>
                      </div>
                    </div>

                    {/* Model vs User Comparison */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono mb-2">
                      <div className="bg-black/40 p-2 rounded-lg border border-white/5">
                        <span className="text-[10px] text-gray-500 uppercase block">Model Prediction</span>
                        <div className="text-white font-bold truncate">{record.modelPrediction}</div>
                        <div className="text-[10px] text-cyan-400">Risk Score: {record.riskScore}/100</div>
                      </div>

                      <div className="bg-black/40 p-2 rounded-lg border border-white/5">
                        <span className="text-[10px] text-gray-500 uppercase block">User Feedback Label</span>
                        <div className="flex items-center gap-1.5 font-bold">
                          {record.userFeedbackLabel === 'CORRECT' && <span className="text-emerald-400 flex items-center gap-1"><Check className="w-3.5 h-3.5" /> Confirmed Correct</span>}
                          {record.userFeedbackLabel === 'MARK_SAFE' && <span className="text-cyan-400 flex items-center gap-1"><ShieldCheck className="w-3.5 h-3.5" /> Marked Safe (FP Correction)</span>}
                          {record.userFeedbackLabel === 'MARK_PHISHING' && <span className="text-amber-400 flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5" /> Marked Phishing (FN Correction)</span>}
                          {record.userFeedbackLabel === 'NOT_SURE' && <span className="text-purple-400 flex items-center gap-1"><HelpCircle className="w-3.5 h-3.5" /> Not Sure (Quarantined)</span>}
                        </div>
                        <div className="text-[10px] text-gray-400 truncate">
                          {record.userNotes || 'No notes attached by user'}
                        </div>
                      </div>
                    </div>

                    {/* Quick Action Buttons for SOC Reviewer */}
                    <div className="flex items-center justify-between pt-2 border-t border-white/5">
                      <div className="flex items-center gap-1.5 text-[10px] font-mono text-gray-400">
                        {record.extractedFeatures?.signals && record.extractedFeatures.signals.length > 0 && (
                          <span className="truncate max-w-[280px]">
                            Signals: {record.extractedFeatures.signals.slice(0, 2).join(', ')}
                            {record.extractedFeatures.signals.length > 2 && ` +${record.extractedFeatures.signals.length - 2}`}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleVerify(record.id, 'VERIFIED');
                          }}
                          disabled={reviewingId === record.id}
                          className="px-2.5 py-1 rounded bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/30 text-[10px] font-mono font-bold flex items-center gap-1 transition-colors cursor-pointer"
                        >
                          <Check className="w-3 h-3" />
                          <span>Verify for Training</span>
                        </button>

                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleVerify(record.id, 'REJECTED');
                          }}
                          disabled={reviewingId === record.id}
                          className="px-2.5 py-1 rounded bg-red-500/15 hover:bg-red-500/25 text-red-300 border border-red-500/30 text-[10px] font-mono font-bold flex items-center gap-1 transition-colors cursor-pointer"
                        >
                          <X className="w-3 h-3" />
                          <span>Reject</span>
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Col: Deep Inspection & Audit Panel */}
        <div className="space-y-4">
          <div className="p-5 rounded-2xl bg-[#080d1a] border border-white/10 space-y-4 sticky top-6">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                <Tag className="w-4 h-4 text-cyan-400" />
                Ground Truth Inspection
              </h3>
              {selectedRecord && (
                <span className="text-[10px] font-mono text-gray-400">
                  {selectedRecord.id}
                </span>
              )}
            </div>

            {selectedRecord ? (
              <div className="space-y-4 font-mono text-xs">
                {/* Target Metadata */}
                <div className="space-y-1 bg-black/40 p-3 rounded-xl border border-white/5">
                  <div className="text-[10px] text-gray-500 uppercase">Target Identifier</div>
                  <div className="text-white font-bold break-all">{selectedRecord.targetId}</div>
                  {selectedRecord.extractedFeatures?.sender && (
                    <div className="text-[11px] text-gray-300 pt-1">
                      <span className="text-gray-500">Sender:</span> {selectedRecord.extractedFeatures.sender}
                    </div>
                  )}
                  {selectedRecord.extractedFeatures?.subject && (
                    <div className="text-[11px] text-gray-300">
                      <span className="text-gray-500">Subject:</span> {selectedRecord.extractedFeatures.subject}
                    </div>
                  )}
                </div>

                {/* Model Score vs Ground Truth */}
                <div className="grid grid-cols-2 gap-2">
                  <div className="bg-black/40 p-2.5 rounded-lg border border-white/5">
                    <span className="text-[10px] text-gray-500 uppercase block">Model Score</span>
                    <span className="text-base font-bold text-cyan-400">{selectedRecord.riskScore}/100</span>
                  </div>
                  <div className="bg-black/40 p-2.5 rounded-lg border border-white/5">
                    <span className="text-[10px] text-gray-500 uppercase block">Human Label</span>
                    <span className="text-base font-bold text-white uppercase">{selectedRecord.userFeedbackLabel}</span>
                  </div>
                </div>

                {/* Signals Extracted */}
                {selectedRecord.extractedFeatures?.signals && (
                  <div className="space-y-1.5">
                    <span className="text-[10px] text-gray-500 uppercase block">Extracted Detection Signals</span>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedRecord.extractedFeatures.signals.map((sig, idx) => (
                        <span 
                          key={idx} 
                          className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 text-[10px]"
                        >
                          {sig}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* User Notes */}
                {selectedRecord.userNotes && (
                  <div className="space-y-1 bg-black/40 p-2.5 rounded-lg border border-white/5">
                    <span className="text-[10px] text-gray-500 uppercase block">User Explanatory Notes</span>
                    <p className="text-gray-300 text-xs italic">{selectedRecord.userNotes}</p>
                  </div>
                )}

                {/* Reviewer Audit Action */}
                <div className="pt-2 border-t border-white/10 space-y-2">
                  <span className="text-[10px] text-gray-500 uppercase block">Audit & Training Eligibility</span>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => handleVerify(selectedRecord.id, 'VERIFIED')}
                      disabled={reviewingId === selectedRecord.id}
                      className={cn(
                        "flex-1 py-2 rounded-lg text-xs font-bold font-mono flex items-center justify-center gap-1.5 border transition-all cursor-pointer",
                        selectedRecord.reviewStatus === 'VERIFIED'
                          ? "bg-emerald-500 text-black border-emerald-400 shadow-lg shadow-emerald-500/20"
                          : "bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border-emerald-500/30"
                      )}
                    >
                      <Check className="w-3.5 h-3.5" />
                      <span>{selectedRecord.reviewStatus === 'VERIFIED' ? 'Verified (In Dataset)' : 'Verify for Dataset'}</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => handleVerify(selectedRecord.id, 'REJECTED')}
                      disabled={reviewingId === selectedRecord.id}
                      className={cn(
                        "flex-1 py-2 rounded-lg text-xs font-bold font-mono flex items-center justify-center gap-1.5 border transition-all cursor-pointer",
                        selectedRecord.reviewStatus === 'REJECTED'
                          ? "bg-red-500 text-white border-red-400 shadow-lg shadow-red-500/20"
                          : "bg-red-500/15 hover:bg-red-500/25 text-red-300 border-red-500/30"
                      )}
                    >
                      <X className="w-3.5 h-3.5" />
                      <span>Reject</span>
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-gray-500 font-mono text-xs">
                Select any feedback record from the left queue to inspect payload features and audit training labels.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
