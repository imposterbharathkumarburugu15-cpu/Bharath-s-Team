import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { Shield } from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';

export interface ScrambleTextProps {
  original: string;
  masked: string;
  type?: string;
  delayParams?: number;
}

export const ScrambleText: React.FC<ScrambleTextProps> = ({
  original,
  masked,
  type,
  delayParams = 0.5,
}) => {
  const { t } = useLanguage();
  const [text, setText] = useState(original);
  const [phase, setPhase] = useState<'original' | 'scrambling' | 'masked'>('original');

  useEffect(() => {
    let scrambleInterval: NodeJS.Timeout;
    const timeout = setTimeout(() => {
      setPhase('scrambling');
      let iteration = 0;
      const maxIterations = 20;
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()';

      scrambleInterval = setInterval(() => {
        setText((_prev) => {
          const splitOriginal = original.split('');
          const splitMasked = masked.split('');
          const currentLength = Math.max(splitOriginal.length, splitMasked.length);

          return Array.from({ length: currentLength })
            .map((_, index) => {
              if (index < (iteration / maxIterations) * currentLength) {
                return splitMasked[index] || '';
              }
              return chars[Math.floor(Math.random() * chars.length)];
            })
            .join('');
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
        <span
          className={`text-[9px] uppercase tracking-widest transition-colors duration-500 font-bold bg-white/5 px-2 py-0.5 rounded ${
            phase === 'masked' ? 'text-[#00ff66]' : 'text-[#8a99af]'
          }`}
        >
          {phase === 'masked' ? t('secured_format') : type || 'Target string'}
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
        className={`font-mono text-xs sm:text-sm font-bold break-all py-3 px-4 rounded-lg border w-full text-center transition-all duration-300 ${
          phase === 'masked'
            ? 'text-[#00ff66] bg-[#00ff66]/10 border-[#00ff66]/40 shadow-[0_0_15px_rgba(0,255,102,0.15)]'
            : phase === 'scrambling'
            ? 'text-[#00f5ff] bg-[#00f5ff]/10 border-[#00f5ff]/40 shadow-[0_0_15px_rgba(0,245,255,0.15)]'
            : 'text-[#ff2a55] bg-[#ff2a55]/5 border-[#ff2a55]/20 shadow-[0_0_10px_rgba(255,42,85,0.05)]'
        }`}
      >
        {phase === 'original' ? (
          <span className="line-through decoration-[#ff2a55]/50">{text}</span>
        ) : (
          text
        )}
      </motion.div>
    </div>
  );
};
