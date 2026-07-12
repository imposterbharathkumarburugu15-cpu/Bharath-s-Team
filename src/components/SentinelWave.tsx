import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  ShieldAlert, Mail, User, Server, RotateCcw, Pause, Play, Activity,
  Search, Cpu, Wifi, Globe, Lock, AlertCircle, Zap, Shield, ChevronRight, Hash
} from 'lucide-react';
import { cn } from '@/lib/utils';

export interface SentinelWaveProps {
  source?: string;
  target?: string;
  payloadDescription?: string;
  compact?: boolean;
  signals?: string[];
  riskScore?: number;
}

const GlitchText = ({ text, className }: { text: string; className?: string }) => {
  return (
    <div className={cn("relative inline-block", className)}>
      <motion.span 
        animate={{ 
          x: [0, -2, 2, -1, 0, 1, 0],
          opacity: [1, 0.8, 1, 0.9, 1, 0.5, 1],
          filter: ['hue-rotate(0deg)', 'hue-rotate(90deg)', 'hue-rotate(0deg)']
        }}
        transition={{ duration: 0.2, repeat: Infinity, repeatDelay: Math.random() * 5 + 2 }}
        className="relative z-10 block"
      >
        {text}
      </motion.span>
      <motion.span 
        animate={{ x: [0, 2, -2, 0], opacity: [0, 0.5, 0] }}
        transition={{ duration: 0.1, repeat: Infinity, repeatDelay: Math.random() * 5 + 2 }}
        className="absolute top-0 left-[1px] text-[#ff003c] z-0 mix-blend-screen"
      >
        {text}
      </motion.span>
      <motion.span 
        animate={{ x: [0, -2, 2, 0], opacity: [0, 0.5, 0] }}
        transition={{ duration: 0.1, repeat: Infinity, repeatDelay: Math.random() * 5 + 2 }}
        className="absolute top-0 left-[-1px] text-[#00f5ff] z-0 mix-blend-screen"
      >
        {text}
      </motion.span>
    </div>
  );
};

const HexGrid = () => (
  <svg width="100%" height="100%" className="absolute inset-0 opacity-[0.03] pointer-events-none mix-blend-screen">
    <defs>
      <pattern id="hexagons" width="40" height="69.282" patternUnits="userSpaceOnUse" patternTransform="scale(1.5)">
        <path d="M 40 17.3205 L 20 0 L 0 17.3205 L 0 51.9615 L 20 69.282 L 40 51.9615 Z M 40 51.9615 L 20 69.282 L 40 86.6025 L 60 69.282 Z M 0 51.9615 L -20 69.282 L 0 86.6025 L 20 69.282 Z" fill="none" stroke="#fff" strokeWidth="1" />
      </pattern>
    </defs>
    <rect width="100%" height="100%" fill="url(#hexagons)" />
  </svg>
);

const FloatingDataStream = () => (
  <div className="absolute inset-0 overflow-hidden pointer-events-none opacity-20">
    {Array.from({ length: 15 }).map((_, i) => (
      <motion.div
        key={i}
        className="absolute text-[8px] font-mono text-cyber-blue font-bold whitespace-nowrap opacity-0 shadow-[0_0_10px_var(--color-cyber-blue)]"
        initial={{ top: `${Math.random() * 100}%`, left: `${Math.random() * 100}%`, y: 50, filter: 'blur(3px)' }}
        animate={{ y: -150, opacity: [0, 0.5, 0], filter: ['blur(3px)', 'blur(0px)', 'blur(3px)'] }}
        transition={{ duration: Math.random() * 5 + 5, repeat: Infinity, delay: Math.random() * 5, ease: "linear" }}
      >
        {Array.from({ length: 10 }).map(() => Math.random() > 0.5 ? '0' : '1').join('')}
      </motion.div>
    ))}
  </div>
);

const NodeRings = ({ color, size = 100 }: { color: string; size?: number }) => (
  <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none" style={{ width: size, height: size }}>
    <motion.div animate={{ rotateZ: 360 }} transition={{ duration: 25, repeat: Infinity, ease: 'linear' }} className="absolute inset-0 rounded-full border-[1px] border-dashed opacity-50" style={{ borderColor: color }} />
    <motion.div animate={{ rotateZ: -360 }} transition={{ duration: 15, repeat: Infinity, ease: 'linear' }} className="absolute top-[10%] left-[10%] w-[80%] h-[80%] rounded-full border-[2px] border-dotted opacity-40 mix-blend-screen" style={{ borderColor: color }} />
    <motion.div animate={{ scale: [1, 1.2, 1], opacity: [0.2, 0.5, 0.2] }} transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }} className="absolute top-[20%] left-[20%] w-[60%] h-[60%] rounded-full blur-md" style={{ backgroundColor: color }} />
    <div className="absolute inset-0 rounded-full border-r-[2px] border-b-[2px] opacity-70 shadow-lg" style={{ borderColor: color, transform: 'rotate(45deg)', boxShadow: `0 0 15px ${color}80` }} />
  </div>
);

const TerminalFeed = () => (
  <div className="absolute top-24 right-6 w-[280px] h-[180px] overflow-hidden font-mono text-[9px] text-cyber-blue opacity-50 rounded bg-black/40 border border-cyber-blue/20 p-3 hidden xl:block backdrop-blur-sm z-10">
    <div className="border-b border-cyber-blue/30 pb-1 mb-2 text-cyber-muted font-bold flex justify-between">
      <span>SYS_LOG :: INTERCEPT</span>
      <span className="animate-pulse text-cyber-red">REC</span>
    </div>
    <motion.div animate={{ y: [0, -400] }} transition={{ duration: 25, ease: 'linear', repeat: Infinity }} className="space-y-1.5 flex flex-col-reverse">
      {Array.from({ length: 40 }).map((_, i) => (
        <div key={i} className="flex gap-2 opacity-80 hover:opacity-100 transition-opacity">
          <span className="text-[#8a99af] shrink-0">[{new Date(Date.now() - i * 4000).toISOString().split('T')[1].slice(0, 12)}]</span>
          <span className={i % 7 === 0 ? "text-[#ff2e5b]" : i % 5 === 0 ? "text-[#ffb703]" : ""}>
            {i % 7 === 0 ? 'CRIT MEM_LEAK DETECTED:' : i % 5 === 0 ? 'WARN PACKET_DROP:' : 'INFO TX_STREAM:'} 0x{Math.floor(Math.random() * 0xFFFFFF).toString(16).padStart(6, '0').toUpperCase()}
          </span>
        </div>
      ))}
    </motion.div>
  </div>
);

export function SentinelWave({ source, target, payloadDescription, compact = false, signals, riskScore = 0 }: SentinelWaveProps) {
  const [isPlaying, setIsPlaying] = useState(true);
  const [key, setKey] = useState(0);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  const hasAIManipulation = signals?.some(s => s.includes('AI MANIPULATION'));
  const hasLowRisk = riskScore < 40;

  const reset = () => {
    setKey(k => k + 1);
    setIsPlaying(true);
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isPlaying) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    setMousePos({ x, y });
  };

  const nodes = [
    { id: 'attacker', label: 'THREAT ACTOR', icon: ShieldAlert, color: '#ff2e5b', pos: { x: 150, y: 350 }, delay: 1, info: source || '185.199.108.153', geo: 'External / Tor Network', status: 'ACTIVE ORIGIN' },
    { id: 'email', label: hasAIManipulation ? 'INJECTION PAYLOAD' : 'SUSPICIOUS MESSAGE', icon: hasAIManipulation ? Cpu : Mail, color: hasAIManipulation ? '#f72585' : '#ffb703', pos: { x: 350, y: 500 }, delay: 3, info: hasAIManipulation ? 'Manipulation Attempt' : 'Social Engineering', geo: 'AWS East-1', status: 'BYPASSED DMARC' },
    { id: 'payload', label: hasAIManipulation ? 'AI PROMPT EXPLOIT' : 'MALICIOUS LINK', icon: hasAIManipulation ? Zap : Search, color: '#f72585', pos: { x: 550, y: 600 }, delay: 5, info: hasAIManipulation ? 'System Context Hijack' : (payloadDescription || 'Phishing URL'), geo: 'Obfuscated Host', status: 'EXECUTING' },
    { id: 'victim', label: hasAIManipulation ? 'AI SYSTEM / LLM' : 'TARGET USER', icon: hasAIManipulation ? Cpu : User, color: hasAIManipulation ? '#00f5ff' : '#00f5ff', pos: { x: 750, y: 400 }, delay: 7, info: hasAIManipulation ? 'GPT-4o Integration' : (target || 'Employee/Client'), geo: 'Internal Network', status: hasAIManipulation ? 'BREACHED CONTEXT' : 'COMPROMISED' },
    { id: 'c2', label: 'DATA EXPOSURE', icon: Server, color: '#adb5bd', pos: { x: 650, y: 150 }, delay: 9, info: hasAIManipulation ? 'Secrets Leak' : 'Data Theft', geo: 'Frankfurt, DE', status: 'TRANSFERRING' }
  ];

  const paths = [
    { id: 'p1', d: "M 150 350 C 250 350, 250 500, 350 500", color: '#ffb703', delay: 2 },
    { id: 'p2', d: "M 350 500 C 450 500, 450 600, 550 600", color: '#f72585', delay: 4 },
    { id: 'p3', d: "M 550 600 C 650 600, 650 400, 750 400", color: '#00f5ff', delay: 6 },
    { id: 'p4', d: "M 750 400 C 850 400, 750 150, 650 150", color: '#adb5bd', delay: 8 }
  ];

  return (
    <div 
      key={key} 
      className={cn("relative w-full bg-[#020512] overflow-hidden rounded-xl border border-cyber-border/40 font-mono shadow-[inset_0_0_80px_rgba(0,0,0,0.8)]", compact ? "h-[450px]" : "h-full min-h-[650px]")}
      onMouseMove={handleMouseMove}
      style={{ perspective: '1000px' }}
    >
      {/* Cinematic Cyber Background */}
      <div 
        className="absolute inset-0 opacity-20" 
        style={{ 
          backgroundImage: `
            linear-gradient(rgba(0, 245, 255, 0.15) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 245, 255, 0.15) 1px, transparent 1px)
          `,
          backgroundSize: '30px 30px',
          transform: `translate(${mousePos.x * -10}px, ${mousePos.y * -10}px) scale(1.1)`
        }} 
      />
      <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/stardust.png')] opacity-10 mix-blend-screen" />
      <HexGrid />
      <FloatingDataStream />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[90%] h-[70%] bg-cyber-blue/10 blur-[150px] rounded-[100%] pointer-events-none" />

      {/* Radical Radar Sweep */}
      {isPlaying && (
        <motion.div
           animate={{ rotate: 360 }}
           transition={{ duration: 8, ease: 'linear', repeat: Infinity }}
           className="absolute top-1/2 left-1/2 w-[200%] h-[200%] -translate-x-1/2 -translate-y-1/2 pointer-events-none z-[2]"
           style={{
             background: 'conic-gradient(from 0deg, transparent 0deg, transparent 270deg, rgba(0, 245, 255, 0.05) 340deg, rgba(0, 245, 255, 0.4) 360deg)',
             borderRadius: '50%'
           }}
        />
      )}

      {/* Top UI Bars */}
      {!compact && (
        <>
          <div className="absolute top-6 left-6 z-20 flex flex-col gap-1">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-black/50 border border-cyber-blue/50 shadow-[0_0_20px_rgba(0,245,255,0.3)] rounded-lg flex items-center justify-center backdrop-blur-md">
                <Shield className="w-6 h-6 text-cyber-blue" />
              </div>
              <div className="bg-black/40 backdrop-blur-md border border-cyber-border/50 px-4 py-2 rounded-lg relative overflow-hidden">
                <motion.div animate={{ x: ['-100%', '100%'] }} transition={{ duration: 3, repeat: Infinity, ease: "linear" }} className="absolute top-0 bottom-0 left-0 w-8 bg-white/10 blur-md mix-blend-overlay skew-x-12" />
                <h1 className="text-white font-bold text-lg tracking-widest font-sans flex items-center gap-2">
                  <GlitchText text="NEUROSHIELD" /><span className="text-cyber-blue">WAVE</span>
                  <motion.div animate={{ opacity: [1, 0] }} transition={{ duration: 1, repeat: Infinity }} className="w-2 h-4 bg-cyber-blue ml-2" />
                </h1>
                <p className="text-cyber-muted text-[10px] uppercase font-bold tracking-widest">Advanced Threat Telemetry</p>
              </div>
            </div>
          </div>
          
          <TerminalFeed />
        </>
      )}

      {/* Stage Wrapper (Maintains perfect aspect ratio) */}
      <div className="absolute inset-x-0 top-0 bottom-[100px] flex items-center justify-center pointer-events-none">
        <motion.div 
          className={cn("relative w-full max-w-[1000px] pointer-events-auto", compact ? "scale-90" : "")} 
          style={{ aspectRatio: '1000/700', transform: `translate(${mousePos.x * 20}px, ${mousePos.y * 20}px)` }}
        >
          {/* Connection Lines (SVG Canvas) */}
          <svg className="absolute inset-0 w-full h-full pointer-events-none" viewBox="0 0 1000 700" preserveAspectRatio="xMidYMid meet">
            {/* Defs for Glows */}
            <defs>
              <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="6" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>

            {paths.map((p) => (
              <g key={p.id}>
                 {/* Dim Background Guide Line */}
                 <path d={p.d} fill="none" stroke={p.color} strokeWidth="1" opacity="0.1" strokeDasharray="4 4" />
                 
                 {/* Main Glowing Animated Path */}
                 <motion.path 
                   d={p.d} fill="none" stroke={p.color} strokeWidth="3" strokeLinecap="round" filter="url(#glow)"
                   initial={{ pathLength: 0, opacity: 0.8 }}
                   animate={{ pathLength: isPlaying ? 1 : 0 }}
                   transition={{ duration: 1.5, delay: p.delay, ease: "easeInOut" }}
                 />
                 
                 {/* Traveling Data Packets (Simulating network stream) */}
                 {[0, 0.15, 0.3, 0.45, 0.6].map((offset, idx) => (
                   <motion.path 
                     key={idx} d={p.d} fill="none" stroke="#fff" strokeWidth={idx % 2 === 0 ? "4" : "8"} strokeLinecap="round"
                     initial={{ pathLength: 0.02, pathOffset: 0 - offset, opacity: 0 }}
                     animate={{ 
                       pathLength: 0.02, 
                       pathOffset: isPlaying ? [0 - offset, 1 - offset] : 0, 
                       opacity: isPlaying ? [0, 1, 1, 0] : 0 
                     }}
                     transition={{ duration: 2.5, delay: p.delay + 1.2 + (idx * 0.2), ease: "linear", repeat: Infinity, repeatDelay: 0.2 }}
                     style={{ filter: idx % 2 === 0 ? "blur(1px)" : "blur(4px)" }}
                   />
                 ))}
              </g>
            ))}
          </svg>

          {/* Nodes */}
          {nodes.map((node) => {
            const Icon = node.icon;
            const isHovered = hoveredNode === node.id;

            return (
              <motion.div 
                key={node.id}
                initial={{ scale: 0, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ duration: 0.5, delay: node.delay, type: 'spring', bounce: 0.5 }}
                className="absolute flex flex-col items-center justify-center -translate-x-1/2 -translate-y-1/2 group z-20"
                style={{ left: `${(node.pos.x / 1000) * 100}%`, top: `${(node.pos.y / 700) * 100}%` }}
                onMouseEnter={() => setHoveredNode(node.id)}
                onMouseLeave={() => setHoveredNode(null)}
              >
                {/* Node Impact Ripple */}
                {isPlaying && (
                  <motion.div 
                    initial={{ scale: 0.5, opacity: 0 }}
                    animate={{ scale: [1, 2.5], opacity: [0.8, 0] }}
                    transition={{ duration: 2, delay: node.delay, ease: "easeOut" }}
                    className="absolute w-20 h-20 rounded-full pointer-events-none"
                    style={{ border: `2px solid ${node.color}`, background: `radial-gradient(circle, ${node.color}40 0%, transparent 70%)` }}
                  />
                )}

                {/* Main Node Graphic */}
                <div className="relative flex items-center justify-center cursor-crosshair">
                  <NodeRings color={node.color} size={isHovered ? 110 : 80} />
                  
                  <motion.div 
                    animate={isHovered ? { scale: 1.1 } : { scale: 1 }}
                    className="relative w-14 h-14 bg-black/80 rounded-full border-[2px] flex items-center justify-center backdrop-blur-md shadow-xl overflow-hidden"
                    style={{ borderColor: node.color, boxShadow: `0 0 20px ${node.color}40` }}
                  >
                    <div className="absolute inset-0 opacity-20" style={{ backgroundColor: node.color }} />
                    <Icon className="w-6 h-6 relative z-10" style={{ color: node.color }} />
                    
                    {/* Micro scanning line inside node */}
                    <motion.div animate={{ top: ['0%', '100%'] }} transition={{ duration: 2, repeat: Infinity, ease: 'linear' }} className="absolute left-0 right-0 h-[1px] bg-white/50" />
                  </motion.div>
                </div>
                
                {/* Minimal Label (Visible when not hovered) */}
                <motion.div 
                   initial={{ opacity: 0, y: 10 }}
                   animate={{ opacity: isHovered ? 0 : 1, y: isHovered ? -10 : 0 }}
                   transition={{ duration: 0.3 }}
                   className="mt-6 bg-black/60 border rounded px-3 py-1 backdrop-blur-md pointer-events-none whitespace-nowrap"
                   style={{ borderColor: `${node.color}40` }}
                >
                  <div className="text-[10px] font-bold tracking-widest text-center uppercase" style={{ color: node.color }}>{node.label}</div>
                  {node.id === 'attacker' && <div className="text-[8px] text-cyber-muted text-center max-w-[120px] truncate">{node.info}</div>}
                  {node.id === 'victim' && <div className="text-[8px] text-cyber-muted text-center max-w-[120px] truncate">{node.info}</div>}
                </motion.div>

                {/* Advanced HUD Tooltip (Visible on Hover) */}
                <AnimatePresence>
                  {isHovered && (
                    <motion.div 
                      initial={{ opacity: 0, scale: 0.9, x: node.pos.x > 500 ? -20 : 20 }}
                      animate={{ opacity: 1, scale: 1, x: node.pos.x > 500 ? -40 : 40 }}
                      exit={{ opacity: 0, scale: 0.9 }}
                      className={cn(
                        "absolute top-1/2 -translate-y-1/2 w-64 bg-[#0a0d18]/95 border backdrop-blur-xl p-4 shadow-2xl rounded-sm z-[100] pointer-events-none before:content-[''] before:absolute before:top-1/2 before:-translate-y-1/2 before:w-8 before:h-[1px]",
                        node.pos.x > 500 ? "right-[100%] before:left-full" : "left-[100%] before:right-full"
                      )}
                      style={{ borderColor: node.color, boxShadow: `0 0 30px ${node.color}20`, ['--tw-before-bg' as any]: node.color }}
                    >
                      <div className="absolute top-0 right-0 w-4 h-4 border-t-2 border-r-2 m-1 opacity-50" style={{ borderColor: node.color }} />
                      <div className="absolute bottom-0 left-0 w-4 h-4 border-b-2 border-l-2 m-1 opacity-50" style={{ borderColor: node.color }} />
                      
                      <div className="flex items-center gap-3 mb-4 pb-2 border-b border-white/10">
                        <div className="p-1.5 rounded bg-black/50 border border-white/10"><Icon className="w-5 h-5" style={{ color: node.color }} /></div>
                        <div>
                          <div className="text-[10px] text-cyber-muted tracking-widest">NODE IDENTIFIER</div>
                          <div className="text-xs font-bold font-sans tracking-wide" style={{ color: node.color }}>{node.label}</div>
                        </div>
                      </div>
                      
                      <div className="space-y-2.5 text-[10px] font-mono leading-tight">
                        <div className="flex justify-between items-center bg-black/30 p-1.5 rounded">
                          <span className="text-cyber-muted flex items-center gap-1"><Hash className="w-3 h-3" /> ATTR</span>
                          <span className="text-white font-medium trunc max-w-[120px] truncate">{node.info}</span>
                        </div>
                        <div className="flex justify-between items-center bg-black/30 p-1.5 rounded">
                          <span className="text-cyber-muted flex items-center gap-1"><Globe className="w-3 h-3" /> GEO</span>
                          <span className="text-[#8a99af]">{node.geo}</span>
                        </div>
                        <div className="flex justify-between items-center bg-black/30 p-1.5 rounded">
                          <span className="text-cyber-muted flex items-center gap-1"><Activity className="w-3 h-3" /> STAT</span>
                          <span className="font-bold flex items-center gap-1" style={{ color: node.color }}>
                            <div className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ backgroundColor: node.color }} />
                            {node.status}
                          </span>
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            );
          })}
        </motion.div>
      </div>

      {/* Control Panel / Hex Timeline at Bottom */}
      <div className="absolute bottom-0 inset-x-0 h-[100px] bg-gradient-to-t from-black/90 to-transparent flex items-end justify-center pb-6 z-30 select-none">
        <div className="w-[95%] max-w-[1000px] flex items-center bg-black/60 border border-cyber-border/40 rounded-xl px-6 py-4 backdrop-blur-xl shadow-2xl relative">
          
          {/* Cyber accents on panel */}
          <div className="absolute top-0 left-6 w-24 h-[1px] bg-cyber-blue shadow-[0_0_10px_var(--color-cyber-blue)]" />
          <div className="absolute bottom-0 right-6 w-24 h-[1px] bg-cyber-red shadow-[0_0_10px_var(--color-cyber-red)]" />

          {/* Controls */}
          <div className="flex items-center gap-4 border-r border-white/10 pr-6">
            <button onClick={() => setIsPlaying(!isPlaying)} className="w-10 h-10 bg-cyber-blue/10 border border-cyber-blue/30 rounded-full flex items-center justify-center hover:bg-cyber-blue/20 hover:border-cyber-blue transition-all group shadow-[0_0_15px_rgba(0,245,255,0.1)]">
              {isPlaying ? <Pause className="w-4 h-4 text-cyber-blue" /> : <Play className="w-4 h-4 text-cyber-blue ml-0.5" />}
            </button>
            <button onClick={reset} className="w-8 h-8 flex items-center justify-center text-cyber-muted hover:text-white transition-colors bg-white/5 rounded-full hover:bg-white/10">
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Hexagonal Timeline */}
          <div className="flex-1 px-8 relative flex items-center justify-between">
            {/* Base timeline track */}
            <div className="absolute left-8 right-8 h-[2px] bg-white/10" />
            {/* Animated progress track */}
            <div className="absolute left-8 right-8 h-[2px] overflow-hidden">
               <motion.div 
                 initial={{ width: "0%" }}
                 animate={{ width: isPlaying ? "100%" : "auto" }}
                 transition={{ duration: 10, ease: 'linear' }}
                 className="h-full bg-cyber-blue shadow-[0_0_10px_var(--color-cyber-blue)]" 
               />
            </div>

            {/* Stages */}
            {['ATTACKER', 'MESSAGE', 'LINK EXPLOIT', 'DATA THEFT'].map((stage, idx) => (
              <div key={stage} className="relative z-10 flex flex-col items-center">
                <motion.div 
                  initial={{ backgroundColor: '#020512', borderColor: '#333' }}
                  animate={{ backgroundColor: '#00f5ff', borderColor: '#00f5ff' }}
                  transition={{ delay: 1 + (idx * 2.5) }}
                  className="w-4 h-4 flex items-center justify-center rotate-45 border-2 transition-colors duration-300 shadow-xl"
                >
                  <motion.div 
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 1 + (idx * 2.5) }}
                    className="w-1.5 h-1.5 bg-black" 
                  />
                </motion.div>
                <div className="absolute top-6 whitespace-nowrap text-[9px] font-bold tracking-widest text-[#8a99af] mb-1">{stage}</div>
                <div className="absolute -top-5 text-[8px] font-mono text-cyber-muted">T+{idx * 3}s</div>
              </div>
            ))}
          </div>
          
          <div className="border-l border-white/10 pl-6 flex items-center gap-3">
             <div className="flex flex-col text-right">
               <span className="text-[10px] text-[#8a99af] uppercase tracking-widest leading-tight">Severity Level</span>
               <span className={cn(
                 "text-sm font-bold font-sans tracking-wide",
                 riskScore > 75 ? "text-cyber-red" : riskScore > 40 ? "text-[#ffb703]" : "text-cyber-green"
               )}>
                 {riskScore > 75 ? "CRITICAL" : riskScore > 40 ? "WARNING" : "INFORMATIONAL"}
               </span>
             </div>
             <div className={cn(
               "w-10 h-10 rounded-lg flex items-center justify-center border transition-all",
               riskScore > 75 ? "bg-cyber-red/10 border-cyber-red/30" : "bg-cyber-blue/10 border-cyber-blue/30"
             )}>
               <AlertCircle className={cn(
                 "w-5 h-5",
                 riskScore > 75 ? "text-cyber-red animate-pulse" : "text-cyber-blue"
               )} />
             </div>
          </div>
        </div>
      </div>
    </div>
  );
}
