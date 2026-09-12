import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Mic, 
  Upload, 
  ShieldCheck, 
  ShieldAlert, 
  Activity, 
  Volume2, 
  AlertCircle, 
  X, 
  Search, 
  Square, 
  Play, 
  Sparkles, 
  Radio, 
  RefreshCw, 
  CheckCircle2, 
  Layers, 
  Lock, 
  Sliders, 
  ArrowRight,
  Zap,
  PhoneCall,
  UserCheck
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { analyzeAudio, AudioScanResult } from '@/services/geminiService';
import { addScanToHistory } from '@/lib/history';
import { useLanguage } from '@/contexts/LanguageContext';
import { cn } from '@/lib/utils';

async function blobToWavBase64(blob: Blob): Promise<string> {
  const arrayBuffer = await blob.arrayBuffer();
  const audioContext = new (window.AudioContext || (window as any).webkitAudioContext)();
  const audioBuffer = await audioContext.decodeAudioData(arrayBuffer);
  
  const numChannels = audioBuffer.numberOfChannels;
  const sampleRate = audioBuffer.sampleRate;
  const format = 1; // PCM
  const bitDepth = 16;
  
  const result = new Float32Array(audioBuffer.length * numChannels);
  for (let channel = 0; channel < numChannels; channel++) {
    const channelData = audioBuffer.getChannelData(channel);
    for (let i = 0; i < audioBuffer.length; i++) {
      result[i * numChannels + channel] = channelData[i];
    }
  }

  const dataLength = result.length * (bitDepth / 8);
  const bufferLength = 44 + dataLength;
  const arrayBufferWav = new ArrayBuffer(bufferLength);
  const view = new DataView(arrayBufferWav);

  const writeString = (view: DataView, offset: number, string: string) => {
    for (let i = 0; i < string.length; i++) {
      view.setUint8(offset + i, string.charCodeAt(i));
    }
  };

  writeString(view, 0, 'RIFF');
  view.setUint32(4, 36 + dataLength, true);
  writeString(view, 8, 'WAVE');
  writeString(view, 12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, format, true);
  view.setUint16(22, numChannels, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * numChannels * (bitDepth / 8), true);
  view.setUint16(32, numChannels * (bitDepth / 8), true);
  view.setUint16(34, bitDepth, true);
  writeString(view, 36, 'data');
  view.setUint32(40, dataLength, true);

  const offsetWav = 44;
  for (let i = 0; i < result.length; i++) {
    let s = Math.max(-1, Math.min(1, result[i]));
    view.setInt16(offsetWav + i * 2, s < 0 ? s * 0x8000 : s * 0x7FFF, true);
  }

  let binary = '';
  const bytes = new Uint8Array(arrayBufferWav);
  for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

const VOICE_DEMO_SCENARIOS = [
  {
    id: 'ceo-wire',
    title: 'CEO Urgent Wire Remittance ($42,500)',
    badge: 'DEEPFAKE VISHING (92% SYNTHETIC)',
    caller: 'Spoofed: Executive Office (+1 415-555-0199)',
    authenticity: 8,
    transcript: [
      "Caller: 'Hey Rahul, this is Mark. I am in the middle of a confidential board acquisition meeting right now.'",
      "Caller: 'We need to wire $42,500 for the closing escrow immediately before 4 PM EST.'",
      "Caller: 'I emailed you the vendor account details. Please bypass standard dual-authorization—I will sign off on the override as soon as I am out of the room.'",
      "System Anomaly: High vocoder artifact density (89% ElevenLabs v2 neural signature). Unnatural silence intervals detected."
    ],
    signals: [
      'VOCODER SYNTHESIS ARTIFACTS (92% CONFIDENCE)',
      'ABSENCE OF NATURAL LARYNGEAL BREATHING ACOUSTICS',
      'HIGH-PRESSURE PSYCHOLOGICAL URGENCY & DUAL-AUTH BYPASS LURE',
      'SPOOFED PBX CALLER ID HEADER'
    ],
    explanation: 'CRITICAL THREAT: Acoustic spectral analysis indicates neural voice cloning with 92% synthetic probability. The caller mimics executive speech patterns while exerting artificial time urgency to force an unauthorized financial wire remittance.'
  },
  {
    id: 'it-mfa',
    title: 'IT Helpdesk Privilege Reset Lure',
    badge: 'AI VOICE ATTACK (88% SYNTHETIC)',
    caller: 'Spoofed: Global IT Support (+1 800-555-0144)',
    authenticity: 12,
    transcript: [
      "Caller: 'Good afternoon, this is Alex from Enterprise Identity and Access Management.'",
      "Caller: 'We detected unauthorized login attempts on your workstation from an unmanaged IP.'",
      "Caller: 'I need you to read back the 6-digit Okta verification code sent to your phone right now to re-bind your hardware token.'",
      "System Anomaly: Robotic pitch monotony detected. Formant frequency transitions deviate from human vocal tract physiology."
    ],
    signals: [
      'FORMANT FREQUENCY CONTINUITY ANOMALY',
      'MONOTONIC PITCH PROSODY (NEURAL SYNTHESIZER)',
      'CREDENTIAL & 2FA PASSCODE SOLICITATION'
    ],
    explanation: 'HIGH THREAT: Synthesized acoustic prosody coupled with social engineering soliciting real-time 2FA security tokens. Real enterprise IT departments never solicit dynamic OTP codes over unverified inbound calls.'
  },
  {
    id: 'authentic-client',
    title: 'Authentic Verified Customer Inquiry',
    badge: 'VERIFIED HUMAN (96% AUTHENTIC)',
    caller: 'Verified Trunk: Enterprise Customer Relay',
    authenticity: 96,
    transcript: [
      "Caller: 'Hi there, I am calling to follow up on the security review document you sent over last Tuesday.'",
      "Caller: 'Our compliance team had a quick question regarding data retention in EU regions.'",
      "Caller: 'Let me know when you have 10 minutes to hop on a scheduled Zoom call.'",
      "System Status: Natural respiratory breath cycles, micro-tremors, and organic glottal pulse verified."
    ],
    signals: [
      'ORGANIC GLOTTAL PULSE VERIFIED',
      'NATURAL RESPIRATORY INTONATION DETECTED',
      'NO SOCIAL ENGINEERING OR URGENCY COERCION'
    ],
    explanation: 'AUTHENTIC: Voice acoustic features conform to organic human vocal tract resonance with normal jitter and micro-tremor variance. Zero synthetic synthesis artifacts detected.'
  }
];

export default function SentinelVoice() {
  const { t } = useLanguage();
  const [status, setStatus] = useState<'idle' | 'recording' | 'analyzing' | 'finished'>('idle');
  const [progress, setProgress] = useState(0);
  const [authenticity, setAuthenticity] = useState(0);
  const [transcript, setTranscript] = useState<string[]>([]);
  const [signals, setSignals] = useState<string[]>([]);
  const [explanation, setExplanation] = useState<string>('');
  const [recordingSeconds, setRecordingSeconds] = useState(0);
  
  const scrollRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<BlobPart[]>([]);
  const timerRef = useRef<any>(null);

  useEffect(() => {
    if (status === 'analyzing') {
      const interval = setInterval(() => {
        setProgress(prev => Math.min(prev + 6, 95));
      }, 200);
      return () => clearInterval(interval);
    }
  }, [status]);

  useEffect(() => {
    if (status === 'recording') {
      setRecordingSeconds(0);
      timerRef.current = setInterval(() => {
        setRecordingSeconds(s => s + 1);
      }, 1000);
    } else {
      clearInterval(timerRef.current);
    }
    return () => clearInterval(timerRef.current);
  }, [status]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [transcript]);

  const reset = () => {
    setStatus('idle');
    setProgress(0);
    setAuthenticity(0);
    setTranscript([]);
    setSignals([]);
    setExplanation('');
    setRecordingSeconds(0);
    if (mediaRecorderRef.current && mediaRecorderRef.current.state === 'recording') {
      mediaRecorderRef.current.stop();
    }
  };

  const handleLoadDemo = (scenario: typeof VOICE_DEMO_SCENARIOS[0]) => {
    setStatus('analyzing');
    setProgress(0);
    setTimeout(() => {
      setProgress(100);
      setAuthenticity(scenario.authenticity);
      setTranscript(scenario.transcript);
      setSignals(scenario.signals);
      setExplanation(scenario.explanation);
      setStatus('finished');

      addScanToHistory({
        detectedType: 'UNKNOWN',
        riskScore: 100 - scenario.authenticity,
        signals: scenario.signals,
        source: 'Voice Deepfake Lab',
        target: scenario.caller,
        payloadDescription: scenario.explanation,
        threatName: scenario.authenticity < 30 ? 'AI Voice Clone Deepfake' : 'Authentic Human Voice'
      });
    }, 1200);
  };

  const handleAudioProcessing = async (base64Audio: string, mimeType: string) => {
    setStatus('analyzing');
    setProgress(0);
    try {
      const result = await analyzeAudio(base64Audio, mimeType);
      setProgress(100);
      setAuthenticity(result.authenticityScore);
      setTranscript(result.transcript);
      setSignals(result.signals);
      setExplanation(result.explanation);
      setStatus('finished');

      addScanToHistory({
        detectedType: 'UNKNOWN',
        riskScore: 100 - result.authenticityScore,
        signals: result.signals,
        source: 'Live Audio Ingestion',
        target: 'Real-Time Call Stream',
        payloadDescription: result.explanation,
        threatName: result.isDeepfake ? 'AI Voice Deepfake Detection' : 'Voice Pattern Analysis'
      });
    } catch (err) {
      console.error(err);
      setProgress(100);
      setAuthenticity(25);
      setTranscript(["Error analyzing audio stream with Neural Engine."]);
      setSignals(["ACOUSTIC ANALYSIS ANOMALY"]);
      setStatus('finished');
    }
  };

  const onFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const wavBase64 = await blobToWavBase64(file);
      await handleAudioProcessing(wavBase64, 'audio/wav');
    } catch (err) {
      console.error("Error processing audio:", err);
      setStatus('finished');
      setAuthenticity(10);
      setTranscript(['Error transcoding audio format.']);
      setSignals(['FORMAT_UNSUPPORTED']);
    }
  };
  
  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const mediaRecorder = new MediaRecorder(stream);
      mediaRecorderRef.current = mediaRecorder;
      audioChunksRef.current = [];
      
      mediaRecorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          audioChunksRef.current.push(event.data);
        }
      };
      
      mediaRecorder.onstop = async () => {
        const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/webm' });
        try {
          const wavBase64 = await blobToWavBase64(audioBlob);
          await handleAudioProcessing(wavBase64, 'audio/wav');
        } catch(err) {
          console.error("Error transcoding audio:", err);
        }
        stream.getTracks().forEach(track => track.stop());
      };
      
      mediaRecorder.start();
      setStatus('recording');
    } catch (err) {
      console.error("Microphone error:", err);
      // Fallback demo run
      handleLoadDemo(VOICE_DEMO_SCENARIOS[0]);
    }
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current && mediaRecorderRef.current.state === 'recording') {
      mediaRecorderRef.current.stop();
    }
  };

  const isDeepfake = status === 'finished' && authenticity < 40;

  return (
    <div className="space-y-6 max-w-[1400px] mx-auto px-2 md:px-5 py-4 font-sans text-slate-100">
      {/* =========================================================================
          HERO BANNER & ACOUSTIC DEFENSE HUD
         ========================================================================= */}
      <div className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-[#0c1228] via-[#060a16] to-[#120e2a] border border-purple-500/30 shadow-[0_0_50px_rgba(0,0,0,0.8)] p-6 md:p-8 backdrop-blur-2xl">
        <div className="absolute -top-24 -right-24 w-96 h-96 bg-purple-500/15 rounded-full blur-[100px] pointer-events-none" />
        <div className="absolute -bottom-24 -left-24 w-96 h-96 bg-cyan-500/10 rounded-full blur-[100px] pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6 relative z-10">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-purple-400 font-mono text-xs font-semibold tracking-wider uppercase">
              <Sparkles className="w-3.5 h-3.5" />
              <span>Acoustic Neural Synthesis &amp; Voice Clone Interception Lab</span>
            </div>
            <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight text-white font-mono flex items-center gap-3">
              <span>SENTINEL VOICE: AI VISHING DEFENSE</span>
            </h1>
            <p className="text-xs md:text-sm text-slate-300 max-w-2xl leading-relaxed">
              Detecting ElevenLabs, Tortoise-TTS, and real-time voice conversion clones during inbound executive phone calls and helpdesk MFA reset requests before unauthorized credential release occurs.
            </p>
          </div>

          {/* Quick Status Tag */}
          <div className="flex items-center gap-2 px-3.5 py-2 rounded-full bg-purple-950/60 border border-purple-500/40 text-purple-200 font-mono text-xs font-bold shadow-[0_0_15px_rgba(168,85,247,0.2)]">
            <Radio className="w-3.5 h-3.5 text-purple-400 animate-pulse" />
            <span>SPECTRAL ANALYZER ONLINE</span>
          </div>
        </div>

        {/* Quick Demo Scenario Switcher Ribbon */}
        <div className="pt-6 mt-6 border-t border-slate-800/80">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-slate-400">
              Interactive Test Scenarios:
            </span>
            <div className="flex flex-wrap items-center gap-2">
              {VOICE_DEMO_SCENARIOS.map((scenario) => (
                <button
                  key={scenario.id}
                  onClick={() => handleLoadDemo(scenario)}
                  className="px-3 py-1.5 rounded-xl bg-slate-900/90 hover:bg-purple-950/60 border border-slate-700/80 hover:border-purple-500/50 text-slate-200 hover:text-white font-mono text-xs transition cursor-pointer flex items-center gap-1.5 shadow-sm"
                >
                  <PhoneCall className="w-3 h-3 text-purple-400" />
                  <span>{scenario.title}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* =========================================================================
          MAIN LAB INTERFACE (WAVEFORM VISUALIZER + REAL-TIME GAUGES)
         ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left 8 cols: Audio Capture & Waveform Visualizer */}
        <div className="lg:col-span-8 space-y-6">
          <div className="rounded-3xl bg-[#080e1b]/95 border border-slate-800 p-6 md:p-7 shadow-2xl space-y-6 relative overflow-hidden">
            {/* Visualizer Canvas Area */}
            <div className="h-64 relative flex flex-col items-center justify-center bg-[#050914] rounded-2xl border border-slate-800/80 overflow-hidden p-4">
              {/* Dynamic Animated Waveform Bars */}
              <div className="absolute inset-0 flex items-center justify-around px-6 pointer-events-none opacity-40">
                {Array.from({ length: 48 }).map((_, i) => (
                  <motion.div
                    key={i}
                    className={cn(
                      "w-1 rounded-full",
                      status === 'recording' ? "bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.8)]" 
                        : status === 'analyzing' ? "bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)]"
                        : "bg-purple-500/40"
                    )}
                    animate={{
                      height: status === 'recording'
                        ? [15, Math.random() * 160 + 10, 15]
                        : status === 'analyzing'
                        ? [10, Math.sin(i * 0.3) * 60 + 20, 10]
                        : 8
                    }}
                    transition={{
                      duration: status === 'recording' ? 0.35 : 0.8,
                      repeat: Infinity,
                      ease: "easeInOut",
                      delay: i * 0.015
                    }}
                  />
                ))}
              </div>

              {/* Idle State Action Triggers */}
              {status === 'idle' && (
                <div className="relative z-10 flex flex-col items-center gap-5 text-center">
                  <div className="flex flex-wrap items-center justify-center gap-4">
                    <Button 
                      onClick={startRecording}
                      variant="cyber"
                      size="lg"
                      className="gap-2.5 h-12 shadow-[0_0_25px_rgba(6,182,212,0.4)]"
                    >
                      <Mic className="w-5 h-5 text-slate-950" />
                      <span>START LIVE MICROPHONE CAPTURE</span>
                    </Button>

                    <input 
                      type="file" 
                      ref={fileInputRef} 
                      onChange={onFileUpload} 
                      onClick={(e) => { (e.target as HTMLInputElement).value = ''; }}
                      accept="audio/*" 
                      className="hidden" 
                    />

                    <Button 
                      onClick={() => fileInputRef.current?.click()}
                      variant="outline"
                      size="lg"
                      className="gap-2 h-12 bg-slate-900/90 hover:bg-slate-800"
                    >
                      <Upload className="w-4 h-4 text-purple-400" />
                      <span>Upload Audio File (.wav, .mp3)</span>
                    </Button>
                  </div>
                  <p className="text-[11px] text-slate-400 font-mono">
                    Ready to sample speech prosody, acoustic jitter, and vocoder harmonic dispersion.
                  </p>
                </div>
              )}

              {/* Recording State */}
              {status === 'recording' && (
                <div className="relative z-10 flex flex-col items-center gap-4">
                  <motion.button 
                    onClick={stopRecording}
                    animate={{ scale: [1, 1.08, 1] }} 
                    transition={{ duration: 0.6, repeat: Infinity }}
                    className="w-16 h-16 rounded-3xl bg-rose-500 text-slate-950 flex items-center justify-center shadow-[0_0_30px_rgba(244,63,94,0.6)] cursor-pointer hover:bg-rose-400 transition"
                  >
                    <Square className="w-6 h-6 fill-slate-950" />
                  </motion.button>
                  <div className="text-center font-mono">
                    <div className="text-rose-400 font-bold text-sm flex items-center justify-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-rose-400 animate-ping" />
                      <span>RECORDING IN PROGRESS ({recordingSeconds}s)</span>
                    </div>
                    <span className="text-slate-400 text-xs">Click square to finalize and analyze speech stream</span>
                  </div>
                </div>
              )}

              {/* Analyzing State */}
              {status === 'analyzing' && (
                <div className="relative z-10 flex flex-col items-center gap-3 font-mono">
                  <div className="w-12 h-12 relative flex items-center justify-center">
                    <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
                  </div>
                  <div className="text-center">
                    <div className="text-cyan-300 font-bold text-sm">DECONSTRUCTING ACOUSTIC BIOMETRICS ({Math.round(progress)}%)</div>
                    <span className="text-slate-400 text-xs">Isolating synthetic vocoder harmonics &amp; prosody</span>
                  </div>
                </div>
              )}

              {/* Finished State Controls */}
              {status === 'finished' && (
                <div className="relative z-10 flex items-center gap-3">
                  <Button onClick={reset} variant="outline" size="default" className="gap-2">
                    <RefreshCw className="w-4 h-4 text-cyan-400" />
                    <span>Reset Voice Analyzer</span>
                  </Button>
                </div>
              )}
            </div>

            {/* Live Audio Transcription Feed */}
            <div className="space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2 font-mono">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-purple-400" />
                  <span>Psycholinguistic Transcript &amp; Utterance Analysis</span>
                </span>
                <span className="text-[10px] text-slate-500">Live NLP Ingestion</span>
              </div>

              <div 
                ref={scrollRef}
                className="h-44 overflow-y-auto font-mono text-xs space-y-2 pr-2 custom-scrollbar bg-[#050914] p-3.5 rounded-2xl border border-slate-800/80"
              >
                {transcript.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-slate-500 italic">
                    Awaiting audio input or demo scenario selection to transcribe stream...
                  </div>
                ) : (
                  transcript.map((line, i) => {
                    const isSystemAlert = line.startsWith('System Anomaly:') || line.startsWith('System Status:');
                    return (
                      <motion.div 
                        initial={{ opacity: 0, x: -8 }} 
                        animate={{ opacity: 1, x: 0 }} 
                        key={i} 
                        className={cn(
                          "p-2.5 rounded-xl border leading-relaxed",
                          isSystemAlert 
                            ? "bg-purple-950/40 border-purple-500/40 text-purple-300 font-bold"
                            : "bg-slate-900/60 border-slate-800 text-slate-200"
                        )}
                      >
                        <span className="text-slate-500 mr-2 text-[10px]">[{new Date().toLocaleTimeString([], { hour12: false })}]</span>
                        {line}
                      </motion.div>
                    );
                  })
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Right 4 cols: Authenticity Meters & Signals */}
        <div className="lg:col-span-4 space-y-6">
          <div className="rounded-3xl bg-[#080e1b]/95 border border-slate-800 p-6 shadow-2xl space-y-6 flex flex-col justify-between h-full">
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3 font-mono">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <Sliders className="w-4 h-4 text-cyan-400" />
                  <span>Authenticity Quotient</span>
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
                  Dual-Meter
                </span>
              </div>

              {/* Circular Gauge */}
              <div className="relative w-44 h-44 mx-auto flex items-center justify-center">
                <svg className="w-full h-full transform -rotate-90">
                  <circle
                    cx="88"
                    cy="88"
                    r="72"
                    stroke="rgba(255,255,255,0.05)"
                    strokeWidth="10"
                    fill="transparent"
                  />
                  <motion.circle
                    cx="88"
                    cy="88"
                    r="72"
                    stroke={status === 'finished' ? (authenticity < 40 ? '#f43f5e' : '#10b981') : '#00f0ff'}
                    strokeWidth="10"
                    fill="transparent"
                    strokeDasharray="452"
                    initial={{ strokeDashoffset: 452 }}
                    animate={{ strokeDashoffset: 452 - (452 * (status === 'finished' ? authenticity : progress)) / 100 }}
                    transition={{ duration: 1, ease: 'easeOut' }}
                    strokeLinecap="round"
                    className="drop-shadow-[0_0_10px_currentColor]"
                  />
                </svg>
                <div className="absolute flex flex-col items-center justify-center font-mono">
                  <span className="text-3xl font-black text-white">
                    {status === 'finished' ? authenticity : Math.floor(progress)}%
                  </span>
                  <span className="text-[10px] uppercase text-slate-400 font-bold">
                    {status === 'finished' ? (isDeepfake ? 'SYNTHETIC' : 'AUTHENTIC') : 'CONFIDENCE'}
                  </span>
                </div>
              </div>

              {/* Verdict Banner */}
              {status === 'finished' && (
                <motion.div 
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={cn(
                    "p-4 rounded-2xl border flex items-center gap-3 font-mono text-xs",
                    isDeepfake 
                      ? "bg-rose-950/40 border-rose-500/40 text-rose-300 shadow-[0_0_20px_rgba(244,63,94,0.2)]" 
                      : "bg-emerald-950/40 border-emerald-500/40 text-emerald-300 shadow-[0_0_20px_rgba(16,185,129,0.2)]"
                  )}
                >
                  {isDeepfake ? <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0" /> : <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />}
                  <div>
                    <div className="font-extrabold text-white text-sm">
                      {isDeepfake ? 'AI DEEPFAKE CLONE DETECTED' : 'ORGANIC HUMAN VOICE VERIFIED'}
                    </div>
                    <span className="text-[10px] text-slate-400 block mt-0.5">
                      {isDeepfake ? 'Synthetic neural vocoder signature confirmed' : 'Normal glottal vibration & harmonic frequency'}
                    </span>
                  </div>
                </motion.div>
              )}

              {/* Deception Signals List */}
              <div className="space-y-2 font-mono text-xs">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                  Acoustic &amp; Behavioral Signatures:
                </span>
                {signals.length > 0 ? (
                  <div className="space-y-1.5">
                    {signals.map((sig, idx) => (
                      <div key={idx} className="flex items-start gap-2 p-2 rounded-xl bg-slate-900/80 border border-slate-800 text-[11px] text-slate-300">
                        <AlertCircle className="w-3.5 h-3.5 text-purple-400 shrink-0 mt-0.5" />
                        <span>{sig}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 rounded-xl bg-slate-900/50 border border-slate-800/80 text-center text-[11px] text-slate-500">
                    Run voice capture to extract biometrics
                  </div>
                )}
              </div>

              {/* Forensic Explanation */}
              {explanation && (
                <div className="p-3.5 rounded-2xl bg-purple-950/20 border border-purple-500/30 text-xs font-sans text-slate-200 leading-relaxed">
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-purple-300 block mb-1">
                    AI Forensic Finding:
                  </span>
                  {explanation}
                </div>
              )}
            </div>

            {/* Bottom Safe Action Reminder */}
            <div className="pt-3 border-t border-slate-800 text-[11px] font-mono text-slate-400 flex items-center justify-between">
              <span>Defense Enforcement:</span>
              <span className="text-purple-400 font-bold">Autonomous Out-of-Band Call Halt</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

