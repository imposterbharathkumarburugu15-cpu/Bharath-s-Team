import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { Shield, AlertTriangle, Link2, X, AlertCircle, Activity } from 'lucide-react';
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer } from 'recharts';
import { ScanResult } from '@/services/geminiService';
import { cn } from '@/lib/utils';
import { SentinelWave } from '@/components/SentinelWave';
import { useLanguage } from '@/contexts/LanguageContext';

interface TextScannerResultProps {
  scanResult: ScanResult;
  onReset: () => void;
}

const ScrambleText = ({ original, masked, type, delayParams }: { original: string, masked: string, type: string, delayParams: number }) => {
  const [text, setText] = useState(original);
  const [phase, setPhase] = useState<'original' | 'scrambling' | 'masked'>('original');

  useEffect(() => {
    let scrambleInterval: NodeJS.Timeout;
    const timeout = setTimeout(() => {
      setPhase('scrambling');
      let iteration = 0;
      const maxIterations = 20;
      const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
      
      scrambleInterval = setInterval(() => {
        setText(prev => {
          const splitOriginal = original.split('');
          const splitMasked = masked.split('');
          const currentLength = Math.max(splitOriginal.length, splitMasked.length);
          
          return Array.from({ length: currentLength }).map((_, index) => {
            if (index < (iteration / maxIterations) * currentLength) {
              return splitMasked[index] || '';
            }
            return chars[Math.floor(Math.random() * chars.length)];
          }).join('');
        });
        
        iteration++;
        if (iteration > maxIterations) {
          clearInterval(scrambleInterval);
          setText(masked);
          setPhase('masked');
        }
      }, 50);
    }, delayParams * 1000);

    return () => {
      clearTimeout(timeout);
      clearInterval(scrambleInterval);
    };
  }, [original, masked, delayParams]);

  return (
    <div className="flex flex-col items-center w-full">
       <div className="flex items-center justify-between w-full mb-2 px-1">
         <span className={`text-[9px] uppercase tracking-widest transition-colors duration-500 font-bold bg-white/5 px-2 py-0.5 rounded ${phase === 'masked' ? 'text-[#00ff66]' : 'text-[#8a99af]'}`}>
           {phase === 'masked' ? 'Secured Format' : type || 'Target string'}
         </span>
         {phase === 'masked' && (
           <motion.span 
             initial={{ opacity: 0, scale: 0 }}
             animate={{ opacity: 1, scale: 1 }}
             className="text-[#00ff66]"
           >
             <Shield className="w-4 h-4" />
           </motion.span>
         )}
       </div>
       <motion.div 
         initial={{ scale: 1 }}
         animate={{ 
            scale: phase === 'scrambling' ? [1, 1.02, 1] : 1,
            filter: phase === 'scrambling' ? ['blur(0px)', 'blur(2px)', 'blur(0px)'] : 'blur(0px)',
         }}
         transition={{ duration: 0.1, repeat: phase === 'scrambling' ? Infinity : 0 }}
         className={`font-mono text-sm sm:text-base font-bold break-all py-3 px-4 rounded-lg border w-full text-center transition-all duration-300 ${
           phase === 'masked' 
             ? 'text-[#00ff66] bg-[#00ff66]/10 border-[#00ff66]/40 shadow-[0_0_15px_rgba(0,255,102,0.15)]' 
             : phase === 'scrambling'
             ? 'text-[#00f5ff] bg-[#00f5ff]/10 border-[#00f5ff]/40 shadow-[0_0_15px_rgba(0,245,255,0.15)]'
             : 'text-[#ff2a55] bg-[#ff2a55]/5 border-[#ff2a55]/20 shadow-[0_0_10px_rgba(255,42,85,0.05)]'
         }`}
       >
         {phase === 'original' ? (
            <span className="line-through decoration-[#ff2a55]/50">{text}</span>
         ) : text}
       </motion.div>
    </div>
  );
};

export function TextScannerResult({ scanResult, onReset }: TextScannerResultProps) {
  const { t } = useLanguage();
  const isHighRisk = scanResult.riskScore > 50;

  const vectorData = scanResult.textMetrics ? [
    { subject: 'Urgency', A: scanResult.textMetrics.urgency, fullMark: 100 },
    { subject: 'Financial', A: scanResult.textMetrics.financial, fullMark: 100 },
    { subject: 'Impersonation', A: scanResult.textMetrics.impersonation, fullMark: 100 },
    { subject: 'Deception', A: scanResult.textMetrics.deception, fullMark: 100 },
    { subject: 'Coercion', A: scanResult.textMetrics.coercion, fullMark: 100 },
  ] : [];

  return (
    <div className="flex-1 flex flex-col w-full h-full text-white">
      {/* Header Area */}
      <div className="mb-6 flex-shrink-0 flex items-start justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-cyber-green" /> {t('threat_analysis')}
          </h2>
        </div>
        <button 
          onClick={onReset}
          className="p-2 bg-[#0a0d1a]/50 text-cyber-muted hover:text-white rounded-full border border-white/5 hover:bg-white/10 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 min-h-0">
        
        {/* Left Column: Metrics & Explanation */}
        <div className="lg:col-span-5 flex flex-col gap-6 overflow-y-auto pr-2 custom-scrollbar">
          
          {/* Risk Score Card */}
          <div className={cn(
            "bg-[#0a0d1a]/50 backdrop-blur-md border rounded-xl p-6 flex items-center gap-6 transition-all duration-500",
            scanResult.riskScore > 75 ? "border-cyber-red/30 shadow-[0_0_20px_rgba(255,46,91,0.1)]" : 
            scanResult.riskScore > 40 ? "border-[#ffb703]/30 shadow-[0_0_20px_rgba(255,183,3,0.1)]" : 
            "border-cyber-green/30 shadow-[0_0_20px_rgba(0,255,102,0.1)]"
          )}>
            <div className="w-28 h-28 relative flex items-center justify-center shrink-0">
              <svg className={cn(
                "w-full h-full transform -rotate-90 drop-shadow-[0_0_15px_rgba(255,46,91,0.3)]",
                scanResult.riskScore > 75 ? "drop-shadow-[0_0_15px_rgba(255,46,91,0.3)]" : "drop-shadow-[0_0_15px_rgba(0,245,255,0.3)]"
              )} viewBox="0 0 100 100">
                <circle cx="50" cy="50" r="40" stroke="rgba(255,255,255,0.05)" strokeWidth="8" fill="none" />
                <motion.circle 
                  cx="50" cy="50" r="40" 
                  stroke={scanResult.riskScore > 75 ? "#ff2e5b" : scanResult.riskScore > 40 ? "#ffb703" : "#00f5ff"} 
                  strokeWidth="8" 
                  fill="none" 
                  strokeDasharray="251.2"
                  initial={{ strokeDashoffset: 251.2 }}
                  animate={{ strokeDashoffset: 251.2 - (251.2 * (scanResult.riskScore / 100)) }}
                  transition={{ duration: 1.5, ease: "easeOut" }}
                  strokeLinecap="round"
                />
              </svg>
              <div className="absolute flex flex-col items-center">
                <motion.span 
                  initial={{ opacity: 0, scale: 0.5 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.5 }}
                  className="text-3xl font-bold tracking-tighter"
                >
                  {scanResult.riskScore}
                </motion.span>
                <span className="text-[9px] text-cyber-muted uppercase tracking-widest mt-0.5">Score</span>
              </div>
            </div>

            <div className="flex flex-col justify-center">
              <h3 className={cn(
                "text-2xl font-bold tracking-widest uppercase", 
                scanResult.riskScore > 75 ? "text-cyber-red" : scanResult.riskScore > 40 ? "text-[#ffb703]" : "text-cyber-green"
              )}>
                {scanResult.riskScore > 75 ? "Critically High" : scanResult.riskScore > 40 ? "Moderate Risk" : "System Safe"}
              </h3>
              {scanResult.threatName && (
                <div className="flex items-center gap-2 mt-2 text-[#ffb703] font-semibold text-sm">
                  <AlertTriangle className="w-4 h-4" />
                  {scanResult.threatName}
                </div>
              )}
            </div>
          </div>

          {/* AI Explanation */}
          <div className="flex flex-col gap-2">
            <div className="text-[11px] font-bold tracking-widest text-[#8a99af] uppercase">{t('ai_explanation')}</div>
            <div className="bg-[#ff2e5b]/5 border border-[#ff2e5b]/20 rounded-lg p-5 text-sm text-white/90 leading-relaxed rounded-tl-sm">
              {scanResult.aiExplanation || scanResult.payloadDescription}
            </div>
          </div>

          {/* Keywords and Signals */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex flex-col gap-2">
              <div className="text-[11px] font-bold tracking-widest text-[#8a99af] uppercase">Threat Signals</div>
              <div className="flex flex-col gap-2">
                {scanResult.signals && scanResult.signals.length > 0 ? (
                  scanResult.signals.map((sig, i) => {
                    const isPromptInjection = sig.includes('AI MANIPULATION');
                    return (
                      <motion.div 
                        key={i}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: 0.8 + (i * 0.1) }}
                        className={cn(
                          "flex items-center gap-2 px-3 py-2 rounded text-xs font-bold border transition-all duration-300",
                          isPromptInjection 
                            ? "bg-[#ff2e5b]/10 border-[#ff2e5b]/30 text-[#ff2e5b] shadow-[0_0_15px_rgba(255,46,91,0.2)] animate-pulse" 
                            : "bg-[#ffb703]/10 border-[#ffb703]/30 text-[#ffb703]"
                        )}
                      >
                        <AlertTriangle className={cn("w-3.5 h-3.5 shrink-0", isPromptInjection && "animate-bounce")} />
                        <span className="truncate">{sig}</span>
                      </motion.div>
                    );
                  })
                ) : (
                  <div className="text-xs text-cyber-muted italic">{t('none_detected')}</div>
                )}
              </div>
            </div>

            <div className="flex flex-col gap-2">
              <div className="text-[11px] font-bold tracking-widest text-[#8a99af] uppercase">Suspicious Keywords</div>
              <div className="flex flex-col gap-2">
                {scanResult.suspiciousKeywords && scanResult.suspiciousKeywords.length > 0 ? (
                  scanResult.suspiciousKeywords.map((kw, i) => (
                    <motion.div 
                      key={i} 
                      initial={{ opacity: 0, x: 10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 1 + (i * 0.1) }}
                      className="flex items-center gap-2 bg-white/5 border border-white/10 px-3 py-2 rounded text-xs text-[#8a99af] hover:border-cyber-blue/30 transition-colors"
                    >
                      <Activity className="w-3.5 h-3.5 shrink-0" />
                      <span className="truncate">"{kw}"</span>
                    </motion.div>
                  ))
                ) : (
                  <div className="text-xs text-cyber-muted italic">{t('none_detected')}</div>
                )}
              </div>
            </div>
          </div>



        </div>

        {/* Right Column: Attack Visualization & Analysis */}
        <div className="lg:col-span-7 flex flex-col gap-6 h-full">
          
          {/* Threat Vectors */}
          {vectorData.length > 0 && (
            <div className="bg-[#0a0d1a]/50 backdrop-blur-md border border-white/5 rounded-xl p-4 flex flex-col shrink-0 h-[250px]">
              <div className="flex items-center gap-2 mb-2 text-white">
                <Activity className="w-4 h-4 text-cyber-blue" />
                <h3 className="text-xs font-bold tracking-widest uppercase">{t('threat_vector_profile')}</h3>
              </div>
              <div className="flex-1 w-full relative">
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart cx="50%" cy="50%" outerRadius="70%" data={vectorData}>
                    <PolarGrid stroke="rgba(255,255,255,0.1)" />
                    <PolarAngleAxis dataKey="subject" tick={{ fill: 'rgba(255,255,255,0.6)', fontSize: 10 }} />
                    <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
                    <Radar name="Risk" dataKey="A" stroke={isHighRisk ? "#ff2e5b" : "#ffb703"} fill={isHighRisk ? "#ff2e5b" : "#ffb703"} fillOpacity={0.2} strokeWidth={2} />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* Privacy Protection */}
          <div className="bg-[#0a0d1a]/50 backdrop-blur-md border border-white/5 rounded-xl flex flex-col shrink-0 overflow-hidden relative">
             <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_transparent_0%,_#020408_100%)] opacity-50 pointer-events-none" />
             <div className="bg-black/60 px-6 py-4 flex items-center gap-3 border-b border-[#00f5ff]/20 relative z-10">
               <div className="absolute left-0 top-0 bottom-0 w-1 bg-[#00f5ff] shadow-[0_0_10px_#00f5ff]" />
               <Shield className="w-5 h-5 text-[#00f5ff]" />
               <h3 className="font-bold tracking-widest text-white uppercase flex items-center gap-2">
                 🔐 Privacy Protection
               </h3>
               {scanResult.maskedData && scanResult.maskedData.length > 0 && (
                 <span className="ml-auto flex h-2 w-2 relative">
                   <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00ff66] opacity-75"></span>
                   <span className="relative inline-flex rounded-full h-2 w-2 bg-[#00ff66]"></span>
                 </span>
               )}
            </div>
            
            <div className="p-6 relative z-10 max-h-[300px] overflow-y-auto custom-scrollbar">
              <div className="text-[10px] font-bold tracking-[0.2em] text-[#8a99af] uppercase mb-5">
                Sensitive Data Detected
              </div>
              
              {scanResult.maskedData && scanResult.maskedData.length > 0 ? (
                 <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                 {scanResult.maskedData.map((data, idx) => (
                   <div key={idx} className="relative overflow-hidden group border border-white/10 rounded-xl p-5 bg-black/40 hover:border-[#00ff66]/30 transition-colors shadow-[0_0_15px_rgba(0,0,0,0.5)] flex items-center justify-center">
                     <ScrambleText original={data.original} masked={data.masked} type={data.type || ''} delayParams={1 + (idx * 0.4)} />
                     
                     {/* Scanning Sweep Effect */}
                     <motion.div 
                       initial={{ y: '-100%' }}
                       animate={{ y: '200%' }}
                       transition={{ duration: 2, delay: 0.5 + (idx * 0.4), ease: "linear" }}
                       className="absolute left-0 right-0 h-8 bg-gradient-to-b from-transparent via-[#00f5ff]/20 to-transparent z-10 pointer-events-none"
                     />
                   </div>
                 ))}
                 </div>
              ) : (
                 <div className="flex flex-col items-center justify-center py-6 border border-dashed border-white/10 rounded-xl bg-white/5">
                   <Shield className="w-8 h-8 text-[#8a99af] mb-3 opacity-50" />
                   <div className="text-xs text-[#8a99af] uppercase tracking-widest">No sensitive data detected</div>
                 </div>
              )}
            </div>
          </div>

          {/* Kill Chain */}
          <div className="bg-[#0a0d1a]/50 backdrop-blur-md border border-white/5 rounded-xl overflow-hidden flex flex-col flex-1 min-h-[300px]">
            <div className="px-6 py-4 border-b border-white/5 flex items-center justify-between shadow-sm z-10">
              <div className="text-[10px] tracking-widest text-[#8a99af] uppercase">{t('attack_kill_chain')}</div>
              <div className="flex gap-2">
                <span className="w-2 h-2 rounded-full bg-[#ff2e5b] animate-pulse shadow-[0_0_8px_#ff2e5b]"></span>
                <span className="text-[10px] text-[#ff2e5b] tracking-widest uppercase">{t('live_trace_active')}</span>
              </div>
            </div>
            <div className="flex-1 relative w-full h-full">
              <SentinelWave 
                source={scanResult.source} 
                target={scanResult.target} 
                payloadDescription={scanResult.payloadDescription} 
                signals={scanResult.signals}
                riskScore={scanResult.riskScore}
              />
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
