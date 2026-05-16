import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'motion/react';
import { Mic, Upload, ShieldCheck, ShieldAlert, Activity, Volume2, AlertCircle, X, Search, Square } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { analyzeAudio, AudioScanResult } from '@/services/geminiService';
import { addScanToHistory } from '@/lib/history';

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

export default function SentinelVoice() {
  const [status, setStatus] = useState<'idle' | 'recording' | 'analyzing' | 'finished'>('idle');
  const [progress, setProgress] = useState(0);
  const [authenticity, setAuthenticity] = useState(0);
  const [transcript, setTranscript] = useState<string[]>([]);
  const [signals, setSignals] = useState<string[]>([]);
  const [explanation, setExplanation] = useState<string>('');
  
  const scrollRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  
  // Audio recording state
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<BlobPart[]>([]);

  useEffect(() => {
    if (status === 'analyzing') {
      const interval = setInterval(() => {
        setProgress(prev => Math.min(prev + 5, 95));
      }, 300);
      return () => clearInterval(interval);
    }
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
    if (mediaRecorderRef.current && mediaRecorderRef.current.state === 'recording') {
      mediaRecorderRef.current.stop();
    }
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

      // Map to ScanResult and save to history
      addScanToHistory({
        detectedType: 'UNKNOWN',
        riskScore: 100 - result.authenticityScore,
        signals: result.signals,
        source: 'Voice Audio Analysis',
        target: 'User',
        payloadDescription: result.explanation,
        threatName: result.isDeepfake ? 'AI Voice Deepfake Detection' : 'Voice Pattern Analysis'
      });
      
    } catch (err) {
      console.error(err);
      setProgress(100);
      setAuthenticity(25);
      setTranscript(["Error analyzing audio."]);
      setSignals(["ANALYSIS ERROR"]);
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
      console.error("Error processing text:", err);
      setStatus('finished');
      setAuthenticity(10);
      setTranscript(['Error analyzing audio format.']);
      setSignals(['FORMAT UNSUPPORTED']);
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
        
        // Stop all tracks
        stream.getTracks().forEach(track => track.stop());
      };
      
      mediaRecorder.start();
      setStatus('recording');
    } catch (err) {
      console.error("Microphone access denied or error:", err);
      // Fallback
      setStatus('analyzing');
      setTimeout(() => {
        setAuthenticity(10);
        setTranscript(['Error accessing microphone.']);
        setSignals(['MIC ERROR']);
        setStatus('finished');
      }, 1000);
    }
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current && mediaRecorderRef.current.state === 'recording') {
      mediaRecorderRef.current.stop();
    }
  };

  return (
    <div className="flex-1 p-6 lg:p-8 space-y-8 overflow-y-auto custom-scrollbar relative">
      <div className="scanline" />
      
      {/* Header Area */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-black tracking-tighter text-white uppercase italic">
            Sentinel <span className="text-cyber-blue">Voice</span>
          </h2>
          <p className="text-sm text-cyber-muted font-mono tracking-widest mt-1">REAL-TIME DEEPFAKE & SCAM DETECTION</p>
        </div>
        <div className="flex gap-3">
          <div className="px-3 py-1 bg-cyber-blue/10 border border-cyber-blue/30 rounded text-[10px] text-cyber-blue font-mono flex items-center gap-2">
            <Activity className="w-3 h-3 animate-pulse" />
            LIVE FEED MONITORING
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Left Column: Input and Waveform */}
        <div className="lg:col-span-2 space-y-6 text-white">
          <Card className="bg-cyber-panel/40 backdrop-blur-xl border-cyber-border/30 overflow-hidden relative">
            <CardContent className="p-0">
              <div className="h-64 relative flex items-center justify-center bg-black/40 overflow-hidden">
                {/* Visualizer Background */}
                <div className="absolute inset-0 flex items-center justify-around px-8 opacity-20 pointer-events-none">
                  {Array.from({ length: 40 }).map((_, i) => (
                    <motion.div
                      key={i}
                      className="w-1 bg-cyber-blue"
                      animate={{
                        height: status === 'recording' ? [20, Math.random() * 150, 20] : 10
                      }}
                      transition={{
                        duration: 0.5,
                        repeat: Infinity,
                        ease: "easeInOut",
                        delay: i * 0.02
                      }}
                    />
                  ))}
                </div>

                {status === 'idle' && (
                  <div className="z-10 flex flex-col items-center gap-6">
                    <div className="flex gap-4">
                      <Button 
                        onClick={startRecording}
                        className="bg-cyber-blue text-black hover:bg-cyber-blue/80 font-bold tracking-widest flex items-center gap-2 h-12 px-6 cyber-glow-blue transition-all"
                      >
                        <Mic className="w-5 h-5" />
                        START LIVE CAPTURE
                      </Button>
                      <input 
                        type="file" 
                        ref={fileInputRef} 
                        onChange={onFileUpload} 
                        accept="audio/*" 
                        className="hidden" 
                      />
                      <Button 
                        onClick={() => fileInputRef.current?.click()}
                        variant="outline"
                        className="border-cyber-border text-white hover:bg-white/5 font-bold tracking-widest flex items-center gap-2 h-12 px-6"
                      >
                        <Upload className="w-5 h-5" />
                        UPLOAD AUDIO
                      </Button>
                    </div>
                    <p className="text-[10px] text-cyber-muted font-mono uppercase tracking-[0.2em]">Ready for acoustic signal processing...</p>
                  </div>
                )}

                {(status === 'recording' || status === 'analyzing') && (
                  <div className="z-10 flex flex-col items-center">
                    {status === 'recording' ? (
                      <motion.button 
                        onClick={stopRecording}
                        animate={{ scale: [1, 1.1, 1] }} 
                        transition={{ duration: 0.5, repeat: Infinity }}
                        className="w-16 h-16 rounded-full bg-cyber-red/20 border border-cyber-red flex items-center justify-center shadow-[0_0_20px_var(--color-cyber-red)] mb-4 hover:bg-cyber-red/40 transition-colors"
                      >
                        <Square className="w-6 h-6 text-cyber-red fill-cyber-red" />
                      </motion.button>
                    ) : (
                      <div className="w-12 h-12 mb-4 relative flex items-center justify-center">
                         <div className="absolute inset-0 border-t-2 border-cyber-blue rounded-full animate-spin" />
                      </div>
                    )}
                    <p className="text-sm font-mono tracking-widest uppercase">
                      {status === 'recording' ? 'MONITORING CALL... CLICK TO STOP' : 'DECONSTRUCTING VOICE PRINT...'}
                    </p>
                  </div>
                )}

                {status === 'finished' && (
                  <div className="z-10 flex flex-col items-center gap-4">
                    <Button onClick={reset} className="bg-white/10 hover:bg-white/20 text-white font-mono text-xs border border-white/20">
                      RESET ANALYZER
                    </Button>
                  </div>
                )}

                {/* Scanning Line */}
                {status === 'analyzing' && (
                  <motion.div 
                    initial={{ left: '-10%' }}
                    animate={{ left: '110%' }}
                    transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                    className="absolute top-0 bottom-0 w-1 bg-cyber-blue shadow-[0_0_20px_#00f5ff] z-20"
                  />
                )}
              </div>
            </CardContent>
          </Card>

          {/* Transcript Area */}
          <Card className="bg-cyber-panel/40 border-cyber-border/30">
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-xs font-mono tracking-[0.3em] uppercase text-cyber-muted">Live Transcription & Masking</h3>
                <div className="w-2 h-2 rounded-full bg-cyber-blue animate-pulse" />
              </div>
              <div 
                ref={scrollRef}
                className="h-48 overflow-y-auto font-mono text-xs space-y-3 pr-2 custom-scrollbar"
              >
                {transcript.length === 0 ? (
                  <p className="text-cyber-muted italic opacity-40">Awaiting audio feed...</p>
                ) : (
                  transcript.map((line, i) => {
                    const isAlert = line.startsWith('System:');
                    return (
                      <motion.div 
                        initial={{ opacity: 0, x: -10 }} 
                        animate={{ opacity: 1, x: 0 }} 
                        key={i} 
                        className={`p-2 rounded ${isAlert ? 'bg-cyber-red/10 border border-cyber-red/20 text-cyber-red' : 'bg-black/20 text-cyber-text/80'}`}
                      >
                        <span className="opacity-50 mr-2">[{new Date().toLocaleTimeString([], { hour12: false })}]</span>
                        {line}
                      </motion.div>
                    );
                  })
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Right Column: Results/Signals */}
        <div className="space-y-6">
          {/* Authenticity Gauge */}
          <Card className="bg-cyber-panel/40 border-cyber-border/30 text-center p-6 relative overflow-hidden h-full flex flex-col items-center justify-center">
            <div className={`absolute inset-0 bg-gradient-to-b ${status === 'finished' ? (authenticity < 30 ? 'from-cyber-red/10' : 'from-cyber-green/10') : 'from-transparent'} to-transparent`} />
            
            <h3 className="text-xs font-mono tracking-[0.3em] uppercase text-cyber-muted mb-8 relative z-10">Authenticity Meter</h3>
            
            <div className="relative w-48 h-48 mb-8">
              <svg className="w-full h-full transform -rotate-90">
                <circle
                  cx="96"
                  cy="96"
                  r="80"
                  stroke="currentColor"
                  strokeWidth="8"
                  fill="transparent"
                  className="text-white/5"
                />
                <motion.circle
                  cx="96"
                  cy="96"
                  r="80"
                  stroke="currentColor"
                  strokeWidth="12"
                  fill="transparent"
                  strokeDasharray="502"
                  initial={{ strokeDashoffset: 502 }}
                  animate={{ strokeDashoffset: 502 - (502 * (status === 'finished' ? authenticity : progress)) / 100 }}
                  className={`${status === 'finished' ? (authenticity < 30 ? 'text-cyber-red' : 'text-cyber-green') : 'text-cyber-blue'} relative z-10 drop-shadow-[0_0_10px_currentColor]`}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-4xl font-black tracking-tighter">
                  {status === 'finished' ? authenticity : Math.floor(progress)}%
                </span>
                <span className="text-[10px] font-mono uppercase text-cyber-muted">Confidence</span>
              </div>
            </div>

            {status === 'finished' && (
              <motion.div 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="space-y-4 w-full relative z-10"
              >
                <div className={`py-3 px-4 rounded-lg flex items-center justify-center gap-3 ${authenticity < 30 ? 'bg-cyber-red/20 text-cyber-red border border-cyber-red/30' : 'bg-cyber-green/20 text-cyber-green border border-cyber-green/30'}`}>
                  {authenticity < 30 ? <ShieldAlert className="w-5 h-5" /> : <ShieldCheck className="w-5 h-5" />}
                  <span className="font-bold tracking-widest text-sm">{authenticity < 30 ? 'DEEPFAKE DETECTED' : 'AUTHENTIC VOICE'}</span>
                </div>

                <div className="text-left space-y-2">
                  <p className="text-[10px] font-mono text-cyber-muted uppercase tracking-widest mb-2 border-b border-cyber-border/30 pb-1">Deception Signals</p>
                  {signals.length > 0 ? signals.map((sig, idx) => (
                    <div key={idx} className="flex items-center gap-2 text-[11px] text-cyber-red font-mono">
                      <AlertCircle className="w-3 h-3 shrink-0" />
                      {sig}
                    </div>
                  )) : (
                    <div className="text-[11px] text-cyber-green font-mono">No threat signals detected.</div>
                  )}
                  {explanation && (
                    <div className="mt-4 pt-2 border-t border-cyber-border/30 text-[11px] text-[#8a99af] font-mono leading-relaxed">
                      {explanation}
                    </div>
                  )}
                </div>
              </motion.div>
            )}

            {status === 'analyzing' && (
              <div className="space-y-2 w-full text-left font-mono text-[9px] text-cyber-blue opacity-80">
                <p className="animate-pulse">&gt; ISOLATING VOICE FREQUENCIES...</p>
                <p className="animate-pulse delay-75">&gt; CHECKING BIOMETRIC SIGNATURES...</p>
                <p className="animate-pulse delay-150">&gt; ANALYZING VOICE PRINT ANOMALIES...</p>
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
