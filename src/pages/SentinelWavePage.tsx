import React, { useState } from 'react';
import { SentinelWave } from '@/components/SentinelWave';
import { Play, ChevronDown, Check } from 'lucide-react';
import { cn } from '@/lib/utils';
import { motion, AnimatePresence } from 'motion/react';

const simulations = [
  {
    id: 'sim1',
    name: "Email BEC Attack",
    description: "Business Email Compromise targeting finance executives via spoofed sender domains.",
    data: {
      source: "ceo.name@gmail.com (Spoofed)",
      target: "cfo@company.com",
      payloadDescription: "Wire Transfer Link"
    }
  },
  {
    id: 'sim2',
    name: "SMS Crypto Scam",
    description: "Smishing attack delivering fake exchange verification prompts to steal credentials.",
    data: {
      source: "+1 (555) 019-2834",
      target: "Employee Mobile Device",
      payloadDescription: "Fake Binance OTP Link"
    }
  },
  {
    id: 'sim3',
    name: "Chat Malware Delivery",
    description: "Social engineering via chat to trick employees into downloading malicious payloads.",
    data: {
      source: "WhatsApp: Unknown Int'l",
      target: "Customer Support Agent",
      payloadDescription: "Malicious Invoice PDF"
    }
  }
];

export function SentinelWavePage() {
  const [activeSimId, setActiveSimId] = useState(simulations[0].id);
  const [showPicker, setShowPicker] = useState(false);
  const activeSimulation = simulations.find(s => s.id === activeSimId)!;

  return (
    <div className="relative w-full h-full flex flex-col flex-1 bg-[#020512]">
      <div className="absolute inset-0 [&>div]:rounded-none [&>div]:border-none [&>div]:h-full [&>div]:min-h-0">
        <SentinelWave 
          key={activeSimId}
          source={activeSimulation.data.source}
          target={activeSimulation.data.target}
          payloadDescription={activeSimulation.data.payloadDescription}
        />
      </div>
      
      {/* Floating Simulation Picker */}
      <div className="absolute top-6 right-6 z-[60]">
        <div className="relative flex flex-col items-end">
          <button 
            onClick={() => setShowPicker(!showPicker)}
            className="flex items-center gap-2 bg-black/60 border border-cyber-blue/30 text-white px-4 py-2 rounded-lg backdrop-blur shadow-[0_0_15px_rgba(0,245,255,0.15)] hover:border-cyber-blue transition-colors"
          >
            <Play className="w-4 h-4 text-cyber-blue" />
            <span className="text-xs font-semibold tracking-wider">SCENARIO: {activeSimulation.name.toUpperCase()}</span>
            <ChevronDown className={cn("w-4 h-4 text-cyber-muted transition-transform", showPicker && "rotate-180")} />
          </button>
          
          <AnimatePresence>
            {showPicker && (
              <motion.div 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                className="absolute top-full right-0 mt-3 w-80 bg-[#020512]/95 border border-cyber-border rounded-lg shadow-2xl backdrop-blur-xl overflow-hidden"
              >
                {simulations.map(sim => (
                  <button
                    key={sim.id}
                    onClick={() => { setActiveSimId(sim.id); setShowPicker(false); }}
                    className="w-full text-left px-4 py-3 border-b border-white/5 hover:bg-white/5 transition-colors flex items-center justify-between group last:border-b-0"
                  >
                    <div className="flex flex-col pr-4">
                      <span className={cn("text-xs font-bold tracking-wide", activeSimId === sim.id ? "text-cyber-blue" : "text-white flex items-center gap-2")}>
                        <Play className={cn("w-3 h-3", activeSimId === sim.id ? "hidden" : "text-cyber-muted group-hover:text-cyber-blue")} />
                        {sim.name}
                      </span>
                      <span className="text-[10px] text-cyber-muted mt-0.5 line-clamp-1">{sim.description}</span>
                    </div>
                    {activeSimId === sim.id && <Check className="w-4 h-4 text-cyber-blue shadow-[0_0_10px_var(--color-cyber-blue)] rounded-full bg-cyber-blue/10 flex-shrink-0" />}
                  </button>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
