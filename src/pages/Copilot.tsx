import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { useLanguage } from '@/contexts/LanguageContext';
import { chatWithCopilot, CopilotMessage } from '@/services/geminiService';
import { 
  Bot, 
  Send, 
  User, 
  Loader2, 
  ShieldAlert, 
  ShieldCheck,
  Cpu, 
  Sparkles, 
  Copy, 
  Check, 
  Trash2, 
  Terminal, 
  Zap, 
  Layers, 
  ArrowRight,
  RefreshCw,
  Code2,
  FileSearch,
  Lock
} from 'lucide-react';
import { cn } from '@/lib/utils';
import Markdown from 'react-markdown';

const SUGGESTED_QUERIES = [
  {
    category: 'RFC Forensics',
    icon: FileSearch,
    label: 'Analyze SPF & Return-Path alignment failure',
    prompt: 'Explain how an attacker can spoof the From display name while the Return-Path and SPF validation fail, and provide exact SOC remediation steps.'
  },
  {
    category: 'Tunnel Evasion',
    icon: Zap,
    label: 'Reverse Tunnel & Cloudflare Worker Evasion',
    prompt: 'How do adversaries utilize trycloudflare.com and ephemeral reverse tunnels to bypass legacy corporate secure web gateways (SWG)?'
  },
  {
    category: 'YARA Rule',
    icon: Code2,
    label: 'Generate YARA rule for M365 AitM Phishing Lure',
    prompt: 'Generate a production-ready YARA detection rule to flag HTML attachments containing obfuscated JavaScript redirecting to reverse proxy login portals.'
  },
  {
    category: 'Cognitive Defense',
    icon: Lock,
    label: 'Analyze Amygdala Hijack NLP Urgency in BEC',
    prompt: 'Break down how high-pressure urgency keywords in executive BEC emails exploit cognitive cognitive biases and how NeuroShield neural heuristics detect this.'
  }
];

export function Copilot() {
  const { t, language } = useLanguage();
  const [messages, setMessages] = useState<CopilotMessage[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const endOfMessagesRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    endOfMessagesRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isTyping]);

  const handleSend = async (queryText?: string) => {
    const textToSend = (queryText || inputValue).trim();
    if (!textToSend || isTyping) return;

    setInputValue('');
    const newMessages: CopilotMessage[] = [...messages, { role: 'user', content: textToSend }];
    setMessages(newMessages);
    setIsTyping(true);

    try {
      const response = await chatWithCopilot(messages, textToSend, language);
      setMessages([...newMessages, { role: 'model', content: response }]);
    } catch (error) {
      console.error(error);
      setMessages([...newMessages, { 
        role: 'model', 
        content: 'Error: Could not connect to NeuroShield Neural AI engine. Please verify network connectivity or try again.' 
      }]);
    } finally {
      setIsTyping(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleCopyMessage = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2000);
  };

  const handleClearHistory = () => {
    setMessages([]);
  };

  return (
    <div className="h-full flex flex-col pt-3 pb-4 pr-3 pl-1 lg:pl-4 overflow-hidden max-w-[1400px] mx-auto w-full font-sans">
      {/* Top Header */}
      <div className="mb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shrink-0 px-2">
        <div className="flex items-center gap-3">
          <div className="relative w-10 h-10 rounded-2xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center shadow-[0_0_20px_rgba(6,182,212,0.3)]">
            <Bot className="w-5 h-5 text-cyan-300" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
          </div>
          <div>
            <h1 className="text-xl sm:text-2xl font-black tracking-tight text-white font-mono flex items-center gap-2">
              <span>NEUROSHIELD AI COPILOT</span>
            </h1>
            <p className="text-xs text-slate-400 font-mono">
              Autonomous SOC Analyst &amp; Forensic Knowledge Assistant
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <div className="flex items-center gap-2 border border-cyan-500/30 bg-cyan-950/40 px-3 py-1.5 rounded-full text-cyan-300">
            <Cpu className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span className="text-[11px] uppercase tracking-wider font-bold">Neural Core v5.2 Active</span>
          </div>

          {messages.length > 0 && (
            <button
              onClick={handleClearHistory}
              className="p-2 rounded-xl bg-slate-900/80 hover:bg-rose-950/40 border border-slate-800 hover:border-rose-500/40 text-slate-400 hover:text-rose-300 transition cursor-pointer"
              title="Clear conversation history"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Main Chat Panel */}
      <div className="flex-1 overflow-hidden flex flex-col rounded-3xl bg-[#080e1b]/95 border border-slate-800/90 shadow-[0_0_50px_rgba(0,0,0,0.8)] backdrop-blur-2xl">
        {/* Chat Stream */}
        <div className="flex-1 overflow-y-auto px-4 py-6 md:px-8 space-y-6 custom-scrollbar">
          {messages.length === 0 && (
            <div className="h-full flex flex-col items-center justify-center text-center text-slate-400 space-y-6 py-8">
              <div className="w-16 h-16 rounded-3xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center shadow-[0_0_30px_rgba(6,182,212,0.2)]">
                <Sparkles className="w-8 h-8 text-cyan-300" />
              </div>

              <div className="space-y-2 max-w-lg">
                <h3 className="text-lg text-white font-bold font-mono uppercase tracking-wider">
                  How can I assist your investigation?
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed font-sans">
                  Query real-time threat intelligence, explain zero-day evasion techniques, dissect RFC email headers, or generate automated containment playbooks.
                </p>
              </div>

              {/* Suggested Prompt Chips */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-2xl w-full pt-2">
                {SUGGESTED_QUERIES.map((item, idx) => {
                  const Icon = item.icon;
                  return (
                    <button
                      key={idx}
                      onClick={() => handleSend(item.prompt)}
                      className="p-3.5 rounded-2xl bg-[#0b1326]/80 hover:bg-cyan-950/40 border border-slate-800/80 hover:border-cyan-500/40 transition-all text-left group cursor-pointer shadow-md flex items-start gap-3"
                    >
                      <div className="w-7 h-7 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center shrink-0 mt-0.5 text-cyan-400 group-hover:scale-110 transition-transform">
                        <Icon className="w-3.5 h-3.5" />
                      </div>
                      <div className="space-y-1 min-w-0">
                        <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-cyan-400/80 block">
                          {item.category}
                        </span>
                        <div className="text-xs font-semibold text-slate-200 group-hover:text-white transition-colors truncate">
                          {item.label}
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          <AnimatePresence initial={false}>
            {messages.map((msg, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className={cn(
                  "flex w-full gap-3.5",
                  msg.role === 'user' ? "justify-end" : "justify-start"
                )}
              >
                {msg.role === 'model' && (
                  <div className="shrink-0 w-8 h-8 rounded-xl bg-cyan-500/15 flex items-center justify-center border border-cyan-500/40 mt-1 shadow-[0_0_12px_rgba(6,182,212,0.25)] text-cyan-300">
                    <Bot className="w-4 h-4" />
                  </div>
                )}
                
                <div className={cn(
                  "max-w-[90%] md:max-w-[75%] rounded-2xl px-5 py-4 text-xs relative overflow-hidden shadow-lg leading-relaxed",
                  msg.role === 'user' 
                    ? "bg-gradient-to-r from-cyan-600 to-blue-600 text-slate-950 font-semibold border border-cyan-300/40 shadow-[0_0_20px_rgba(6,182,212,0.25)]" 
                    : "bg-[#0a1224]/90 text-slate-200 border border-slate-800 font-sans"
                )}>
                  {msg.role === 'model' && (
                    <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/80 font-mono text-[10px] text-slate-400">
                      <span className="text-cyan-400 font-bold flex items-center gap-1">
                        <Sparkles className="w-3 h-3 text-cyan-400" />
                        AI SOC Analyst Response
                      </span>
                      <button
                        onClick={() => handleCopyMessage(msg.content, idx)}
                        className="hover:text-white flex items-center gap-1 cursor-pointer transition"
                        title="Copy response"
                      >
                        {copiedIdx === idx ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedIdx === idx ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  )}

                  {msg.role === 'user' ? (
                    <div className="whitespace-pre-wrap font-sans text-xs">{msg.content}</div>
                  ) : (
                    <div className="markdown-body prose prose-invert max-w-none text-xs text-slate-200 leading-relaxed space-y-2">
                      <Markdown>{msg.content}</Markdown>
                    </div>
                  )}
                </div>

                {msg.role === 'user' && (
                  <div className="shrink-0 w-8 h-8 rounded-xl bg-slate-800 flex items-center justify-center border border-slate-700 mt-1 text-slate-300">
                    <User className="w-4 h-4" />
                  </div>
                )}
              </motion.div>
            ))}
          </AnimatePresence>

          {isTyping && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex w-full gap-3.5 justify-start">
              <div className="shrink-0 w-8 h-8 rounded-xl bg-cyan-500/15 flex items-center justify-center border border-cyan-500/40 mt-1 shadow-[0_0_12px_rgba(6,182,212,0.25)] text-cyan-300">
                <Bot className="w-4 h-4" />
              </div>
              <div className="bg-[#0a1224]/90 text-slate-200 border border-cyan-500/30 rounded-2xl px-5 py-4 flex items-center gap-2.5 font-mono text-xs shadow-lg">
                <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
                <span className="text-cyan-300 font-bold animate-pulse">Running Neural Threat Inference &amp; Telemetry Correlation...</span>
              </div>
            </motion.div>
          )}
          <div ref={endOfMessagesRef} />
        </div>

        {/* Input Bar */}
        <div className="p-4 bg-[#050a16] border-t border-slate-800/80">
          <div className="relative flex items-center max-w-4xl mx-auto">
            <textarea
              className="w-full bg-slate-900/90 border border-slate-800 focus:border-cyan-500/60 rounded-2xl px-4 py-3 text-xs text-white placeholder-slate-500 resize-none focus:outline-none focus:ring-1 focus:ring-cyan-500/40 transition-all min-h-[46px] max-h-[120px] custom-scrollbar font-mono pr-24"
              placeholder="Ask Copilot about any threat indicator, IOC, or forensic finding..."
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={handleKeyDown}
              rows={1}
            />
            <div className="absolute right-2.5 flex items-center gap-1.5">
              <button 
                onClick={() => handleSend()}
                disabled={!inputValue.trim() || isTyping}
                className="px-3.5 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold rounded-xl transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1.5 cursor-pointer shadow-[0_0_15px_rgba(6,182,212,0.3)] text-xs font-mono"
              >
                <span>Send</span>
                <Send className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
          <div className="text-center mt-2.5 flex items-center justify-center gap-2 text-[10px] text-slate-500 font-mono uppercase tracking-wider">
            <ShieldCheck className="w-3 h-3 text-emerald-400" />
            <span>NeuroShield AI Grounded Defense Pipeline • Enterprise Privacy Enforced</span>
          </div>
        </div>
      </div>
    </div>
  );
}

