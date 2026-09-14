import React, { useState } from 'react';
import { 
  Play, 
  RotateCw, 
  ShieldCheck, 
  CheckCircle2, 
  AlertTriangle, 
  Layers, 
  Info, 
  ArrowRight, 
  Server, 
  Globe, 
  Lock, 
  Sparkles,
  RefreshCw,
  Check
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { InfrastructureObservation } from '@/types/infrastructure';

interface RotatingInfrastructureDemoProps {
  onSimulateStep?: (step: number, observation: InfrastructureObservation) => void;
}

export const RotatingInfrastructureDemo: React.FC<RotatingInfrastructureDemoProps> = ({
  onSimulateStep
}) => {
  const [currentStep, setCurrentStep] = useState<number>(1);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [hasCompleted, setHasCompleted] = useState<boolean>(false);

  const stepsData = [
    {
      step: 1,
      title: "Observation 1: Inbound Relay Point-of-Presence",
      observedIp: "185.220.101.44",
      country: "Singapore",
      flag: "🇸🇬",
      asn: "AS12345 (Equinix Asia Backbone)",
      provider: "Equinix Singapore Datacenter",
      domain: "m1crosoft-support.com",
      status: "Initial relay hop captured in RFC 5322 Received header.",
      confidence: 74,
      continuityEffect: "Baseline infrastructure node registered in case record."
    },
    {
      step: 2,
      title: "Observation 2: Infrastructure Rotation Observed",
      observedIp: "103.253.42.87",
      country: "Netherlands",
      flag: "🇳🇱",
      asn: "AS12345 (Equinix Peering Exchange)",
      provider: "Equinix European Transit",
      domain: "m1crosoft-support.com",
      status: "Egress IP altered by adversary to circumvent static IP blocklists.",
      confidence: 84,
      continuityEffect: "Observation #1 locked in historical custody. Shared backbone ASN12345 confirmed."
    },
    {
      step: 3,
      title: "Observation 3: Egress Endpoint Shift & Forensic Continuity",
      observedIp: "45.154.255.192",
      country: "United States",
      flag: "🇺🇸",
      asn: "AS67890 (Cloud Provider VPS)",
      provider: "Offshore Cloud Host",
      domain: "auth-security-verification.example.com",
      status: "URL payload destination resolved via authoritative DNS A-record.",
      confidence: 96,
      continuityEffect: "All 3 observations preserved. Domain, ASN, and redirect cluster correlated."
    }
  ];

  const handleStepClick = (stepNum: number) => {
    setCurrentStep(stepNum);
    const stepObj = stepsData[stepNum - 1];
    if (onSimulateStep && stepObj) {
      const simulatedObs: InfrastructureObservation = {
        id: `sim-obs-${stepObj.step}`,
        incidentId: 'demo-continuity-case-01',
        ip: stepObj.observedIp,
        timestamp: new Date().toISOString(),
        country: stepObj.country,
        countryFlag: stepObj.flag,
        asn: stepObj.asn,
        provider: stepObj.provider,
        domain: stepObj.domain,
        source: stepNum === 3 ? 'url-resolution' : 'received-chain',
        confidence: stepObj.confidence,
        confidenceLevel: 'HIGH',
        trustBoundary: stepNum === 1 ? 'origin' : stepNum === 2 ? 'transit' : 'external',
        reputation: stepNum === 3 ? 'MALICIOUS' : 'SUSPICIOUS',
        isCurrentActive: true,
        statusNote: stepObj.status
      };
      onSimulateStep(stepNum, simulatedObs);
    }
  };

  const handleRunFullScenario = () => {
    setIsRunning(true);
    handleStepClick(1);
    setTimeout(() => {
      handleStepClick(2);
      setTimeout(() => {
        handleStepClick(3);
        setIsRunning(false);
        setHasCompleted(true);
      }, 1500);
    }, 1500);
  };

  const activeStepData = stepsData[currentStep - 1];

  return (
    <div className="bg-[#0c130f] border-2 border-amber-500/40 rounded-2xl p-5 sm:p-6 shadow-2xl space-y-6 font-mono relative overflow-hidden">
      {/* Top Banner: Synthetic Demo Tag */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-300 shrink-0">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-bold uppercase tracking-wider text-white">
                Rotating Infrastructure — Forensic Continuity Test
              </h3>
              <span className="text-[10px] px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold">
                SIMULATION / DEMO DATA
              </span>
            </div>
            <p className="text-[11px] text-gray-400 font-sans">
              Interactive demonstration of SIH26106 core requirement: how NeuroShield maintains continuity when IP rotates.
            </p>
          </div>
        </div>

        <button
          onClick={handleRunFullScenario}
          disabled={isRunning}
          className="px-4 py-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-black font-bold text-xs flex items-center gap-2 transition-all cursor-pointer shadow-[0_0_15px_rgba(245,158,11,0.3)] disabled:opacity-50 shrink-0"
        >
          {isRunning ? <RotateCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-current" />}
          <span>{isRunning ? 'Executing Simulation...' : 'Play 3-Stage Rotation'}</span>
        </button>
      </div>

      {/* CORE STATEMENT BANNER (EXACT USER REQUIREMENT) */}
      <div className="p-4 rounded-xl bg-black/60 border border-cyan-500/40 space-y-2.5">
        <div className="flex items-center gap-2 text-cyan-300 text-xs font-bold uppercase">
          <ShieldCheck className="w-4 h-4 text-cyan-400" />
          <span>OFFICIAL SIH26106 FORENSIC STATEMENT:</span>
        </div>
        <p className="text-xs text-gray-200 leading-relaxed font-sans">
          "We do not claim to continuously locate the attacker. IP geolocation is an infrastructure intelligence signal. If an observed IP changes, NeuroShield preserves the historical observation and evaluates other relationships such as relay paths, domains, ASN/provider relationships, URLs, redirects and related incidents. This allows the investigation to maintain continuity without equating an IP with an attacker identity."
        </p>
        <div className="pt-1 flex items-center gap-2">
          <span className="text-[11px] px-2.5 py-1 rounded bg-[#ccff00]/15 text-[#ccff00] border border-[#ccff00]/30 font-bold font-mono">
            🔑 KEY STATEMENT: IP rotation changes the observation — it does not erase the evidence.
          </span>
        </div>
      </div>

      {/* Step Selector Buttons */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {stepsData.map((s) => {
          const isSelected = currentStep === s.step;
          return (
            <div
              key={s.step}
              onClick={() => handleStepClick(s.step)}
              className={cn(
                "p-4 rounded-xl border text-left transition-all cursor-pointer space-y-2",
                isSelected
                  ? "bg-amber-500/15 border-amber-400 text-white shadow-[0_0_15px_rgba(245,158,11,0.25)]"
                  : "bg-white/[0.03] border-white/10 hover:border-white/20 text-gray-400"
              )}
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase tracking-wider">
                  Stage {s.step} of 3
                </span>
                <span className="text-base">{s.flag}</span>
              </div>
              <div className="text-xs font-bold text-white tracking-wide">
                {s.title.split(':')[0]}
              </div>
              <div className="text-[11px] font-mono text-cyan-300">
                IP: {s.observedIp} ({s.country})
              </div>
            </div>
          );
        })}
      </div>

      {/* Current Step Deep-Dive Inspector */}
      {activeStepData && (
        <div className="p-5 rounded-xl bg-[#080d0a] border border-white/10 space-y-4 text-xs">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-white/10 pb-3">
            <div className="flex items-center gap-2">
              <span className="text-xl">{activeStepData.flag}</span>
              <div>
                <span className="text-sm font-bold text-white">{activeStepData.title}</span>
                <div className="text-[11px] text-gray-400 font-mono">
                  Observed IP: <strong className="text-cyan-300">{activeStepData.observedIp}</strong> • ASN: <strong className="text-white">{activeStepData.asn}</strong>
                </div>
              </div>
            </div>

            <div className="text-right">
              <span className="text-[10px] text-gray-400 uppercase block font-bold">Campaign Confidence</span>
              <span className="text-base font-bold text-amber-300">{activeStepData.confidence}% (HIGH)</span>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="p-3 rounded-lg bg-black/40 border border-white/5 space-y-1">
              <span className="text-[10px] text-gray-500 uppercase font-bold block">Adversary Behavior Observed:</span>
              <span className="text-gray-300 leading-relaxed block">{activeStepData.status}</span>
            </div>
            <div className="p-3 rounded-lg bg-black/40 border border-white/5 space-y-1">
              <span className="text-[10px] text-gray-500 uppercase font-bold block">Forensic Continuity Result:</span>
              <span className="text-emerald-300 font-bold leading-relaxed block">{activeStepData.continuityEffect}</span>
            </div>
          </div>

          {/* Demonstration Key Message */}
          <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-200 text-xs font-bold leading-relaxed">
            📢 "Individual infrastructure indicators changed. Correlation continues using remaining observable evidence."
          </div>
        </div>
      )}
    </div>
  );
};
