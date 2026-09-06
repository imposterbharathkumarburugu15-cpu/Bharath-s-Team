import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  X, Copy, Check, ShieldAlert, ShieldCheck, Terminal, 
  ExternalLink, Server, Globe, Hash, AlertTriangle, FileCode
} from 'lucide-react';

export interface DrillDownTarget {
  type: 'SPF' | 'DKIM' | 'DMARC' | 'RETURN_PATH' | 'IP' | 'IOC' | 'URL' | 'NODE' | 'FINDING' | 'GENERIC';
  title: string;
  badge?: string;
  badgeColor?: 'red' | 'amber' | 'emerald' | 'cyan' | 'purple';
  summary: string;
  technicalDetails: Array<{ label: string; value: string; isMono?: boolean; copyable?: boolean }>;
  rawSnippet?: string;
  rfcStandard?: string;
  remediation?: string;
}

interface ForensicDrillDownModalProps {
  target: DrillDownTarget | null;
  onClose: () => void;
}

export function ForensicDrillDownModal({ target, onClose }: ForensicDrillDownModalProps) {
  const [copied, setCopied] = React.useState(false);

  if (!target) return null;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const badgeColorClasses = {
    red: 'bg-red-500/15 text-red-400 border-red-500/30',
    amber: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    emerald: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    cyan: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
    purple: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  }[target.badgeColor || 'cyan'];

  return (
    <AnimatePresence>
      <div 
        id="forensic-drilldown-backdrop"
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm"
        onClick={onClose}
      >
        <motion.div
          id="forensic-drilldown-container"
          initial={{ opacity: 0, scale: 0.95, y: 10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 10 }}
          onClick={(e) => e.stopPropagation()}
          className="w-full max-w-2xl max-h-[85vh] overflow-y-auto bg-[#080d1a] border border-cyan-500/30 rounded-2xl shadow-[0_0_50px_rgba(0,0,0,0.8)] flex flex-col text-white font-mono"
        >
          {/* Header */}
          <div className="p-4 border-b border-white/10 flex items-center justify-between bg-[#0b1326] sticky top-0 z-10">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <Terminal className="w-4 h-4" />
              </div>
              <div>
                <span className="text-[10px] text-gray-400 uppercase tracking-widest block">
                  ANALYST DRILL-DOWN EVIDENCE
                </span>
                <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                  {target.title}
                  {target.badge && (
                    <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${badgeColorClasses}`}>
                      {target.badge}
                    </span>
                  )}
                </h3>
              </div>
            </div>
            <button
              id="close-drilldown-btn"
              onClick={onClose}
              className="p-1.5 rounded-lg bg-white/5 hover:bg-white/15 text-gray-400 hover:text-white transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Body Content */}
          <div className="p-5 space-y-4">
            {/* Quick Summary */}
            <div className="bg-black/40 border border-white/10 rounded-xl p-3.5">
              <span className="text-[10px] text-cyan-400 uppercase tracking-wider block font-bold mb-1">
                OBSERVED FORENSIC EVALUATION
              </span>
              <p className="text-xs text-gray-200 leading-relaxed font-sans">
                {target.summary}
              </p>
            </div>

            {/* Technical Detail Grid */}
            {target.technicalDetails.length > 0 && (
              <div className="space-y-1.5">
                <span className="text-[10px] text-gray-400 uppercase tracking-wider block font-bold">
                  TECHNICAL ATTRIBUTES
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {target.technicalDetails.map((item, idx) => (
                    <div 
                      key={idx}
                      className="bg-white/5 border border-white/10 rounded-lg p-2.5 flex flex-col justify-between group"
                    >
                      <span className="text-[10px] text-gray-400 uppercase">{item.label}</span>
                      <div className="flex items-center justify-between gap-1 mt-0.5">
                        <span className={`text-xs ${item.isMono ? 'font-mono text-cyan-300 break-all' : 'text-white'}`}>
                          {item.value}
                        </span>
                        {item.copyable && (
                          <button
                            onClick={() => handleCopy(item.value)}
                            className="p-1 text-gray-500 hover:text-cyan-400 transition-colors"
                            title="Copy value"
                          >
                            <Copy className="w-3 h-3" />
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* RFC Standard Citation */}
            {target.rfcStandard && (
              <div className="flex items-center gap-2 p-2 rounded-lg bg-cyan-950/20 border border-cyan-500/20 text-[11px] text-cyan-300">
                <FileCode className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span>Reference: <strong>{target.rfcStandard}</strong></span>
              </div>
            )}

            {/* Raw Evidence Header / Log Snippet */}
            {target.rawSnippet && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-gray-400 uppercase tracking-wider font-bold">
                    RAW LOG / RFC 5322 EXTRACT
                  </span>
                  <button
                    onClick={() => handleCopy(target.rawSnippet!)}
                    className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors cursor-pointer"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copied ? 'Copied' : 'Copy Snippet'}</span>
                  </button>
                </div>
                <div className="bg-black/60 border border-cyan-500/20 rounded-xl p-3 overflow-x-auto text-[11px] text-green-400 font-mono leading-relaxed select-all">
                  <code>{target.rawSnippet}</code>
                </div>
              </div>
            )}

            {/* Recommended Action */}
            {target.remediation && (
              <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-200 text-xs">
                <div className="flex items-center gap-1.5 font-bold text-amber-400 mb-1">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>SOC TRIAGE ACTION</span>
                </div>
                <p className="leading-relaxed font-sans text-amber-100 text-[11px]">
                  {target.remediation}
                </p>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="p-3 border-t border-white/10 bg-[#0b1326] flex justify-end">
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-white text-xs font-mono transition-colors cursor-pointer"
            >
              Close Drill-down
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
