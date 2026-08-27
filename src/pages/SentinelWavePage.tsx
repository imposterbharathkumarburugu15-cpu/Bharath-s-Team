import React, { useState } from 'react';
import { SentinelWave, WAVE_SCENARIOS } from '@/components/SentinelWave';
import {
  Shield, Sparkles, BookOpen, AlertTriangle, CheckCircle2,
  Lock, Eye, HelpCircle, ArrowRight, Lightbulb, UserCheck, KeyRound, Smartphone, Mail
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { motion } from 'motion/react';

export function SentinelWavePage() {
  const [activeSimId, setActiveSimId] = useState<string>(WAVE_SCENARIOS[0].id);
  const activeScenario = WAVE_SCENARIOS.find(s => s.id === activeSimId) || WAVE_SCENARIOS[0];

  const safetyRules = [
    {
      icon: Mail,
      title: "1. Inspect the Real Email Address",
      desc: "Attackers change their display name to 'CEO' or 'Microsoft Support', but their actual address is often a fake Gmail or lookalike domain.",
      color: "#ff2e5b"
    },
    {
      icon: AlertTriangle,
      title: "2. Beware of Artificial Urgency",
      desc: "Panic words like 'Account suspended in 2 hours!' or 'Immediate wire required' are designed to make you act without thinking.",
      color: "#ffb703"
    },
    {
      icon: Eye,
      title: "3. Hover Before You Click",
      desc: "Always check where a link leads before clicking. A button might say 'Login to Microsoft', but lead to an attacker's fake website.",
      color: "#f72585"
    },
    {
      icon: Lock,
      title: "4. Never Share One-Time Passwords (OTP)",
      desc: "Real banks, companies, and IT departments will never ask you to read back a multi-factor authentication code or password.",
      color: "#00f5ff"
    }
  ];

  return (
    <div className="w-full flex flex-col gap-6 p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto overflow-y-auto custom-scrollbar">
      {/* Page Introduction Banner for Beginners */}
      <div className="bg-gradient-to-r from-[#0a0f26] via-[#0e1738] to-[#070b1c] border border-cyber-blue/30 rounded-2xl p-5 sm:p-6 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyber-blue/10 rounded-full blur-[100px] pointer-events-none" />

        <div className="relative z-10 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-2xl bg-cyber-blue/15 border border-cyber-blue/40 flex items-center justify-center shrink-0 shadow-[0_0_20px_rgba(0,245,255,0.25)]">
              <Sparkles className="w-6 h-6 text-cyber-blue" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30">
                  Interactive Security Learning
                </span>
                <span className="text-[10px] font-mono text-gray-400">Beginner Friendly</span>
              </div>
              <h1 className="text-xl sm:text-2xl font-bold text-white mt-1">
                NeuroShield Wave: Attack Journey Simulator
              </h1>
              <p className="text-xs sm:text-sm text-gray-300 mt-1 max-w-3xl leading-relaxed">
                Watch how cyber scams travel across the internet from the fraudster’s computer, through deceptive messages and fake links, to the target victim — and see how <strong>NeuroShield AI</strong> stops them in their tracks.
              </p>
            </div>
          </div>

          {/* Quick Scenario Switcher Ribbon */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            {WAVE_SCENARIOS.map((scenario) => {
              const isSelected = scenario.id === activeSimId;
              return (
                <button
                  key={scenario.id}
                  onClick={() => setActiveSimId(scenario.id)}
                  className={cn(
                    "px-3.5 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-2 cursor-pointer border",
                    isSelected
                      ? "bg-cyber-blue text-black border-cyber-blue font-bold shadow-[0_0_15px_rgba(0,245,255,0.3)]"
                      : "bg-white/5 text-gray-300 hover:text-white border-white/10 hover:border-white/20"
                  )}
                >
                  <span>{scenario.beginnerName}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Main Interactive Wave Canvas */}
      <div className="w-full h-[680px] sm:h-[720px] rounded-2xl overflow-hidden border border-cyber-blue/30 shadow-2xl">
        <SentinelWave
          key={activeSimId}
          initialScenarioId={activeSimId}
          onScenarioChange={(id) => setActiveSimId(id)}
          source={activeScenario.source}
          target={activeScenario.target}
          payloadDescription={activeScenario.payloadDescription}
        />
      </div>

      {/* Educational Guide: Cyber Safety Rules for Beginners */}
      <div className="bg-[#0a0e20] border border-white/10 rounded-2xl p-5 sm:p-6 flex flex-col gap-4">
        <div className="flex items-center justify-between border-b border-white/10 pb-3">
          <div className="flex items-center gap-2.5">
            <Lightbulb className="w-5 h-5 text-[#ffb703]" />
            <h2 className="text-sm sm:text-base font-bold text-white">
              Cyber Safety 101: 4 Golden Rules Every Beginner Should Know
            </h2>
          </div>
          <span className="text-[11px] font-mono text-gray-400">Essential Protection Habits</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {safetyRules.map((rule, idx) => {
            const Icon = rule.icon;
            return (
              <div
                key={idx}
                className="bg-black/40 border border-white/5 hover:border-white/20 rounded-xl p-4 transition-all flex flex-col justify-between group"
              >
                <div>
                  <div
                    className="w-8 h-8 rounded-lg flex items-center justify-center mb-3"
                    style={{ backgroundColor: `${rule.color}15`, border: `1px solid ${rule.color}40` }}
                  >
                    <Icon className="w-4 h-4" style={{ color: rule.color }} />
                  </div>
                  <h3 className="text-xs font-bold text-white mb-1.5">{rule.title}</h3>
                  <p className="text-[11px] text-gray-400 leading-relaxed">{rule.desc}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
