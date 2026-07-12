import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { useLanguage } from '@/contexts/LanguageContext';
import { chatWithCopilot, CopilotMessage } from '@/services/geminiService';
import { Bot, Send, User, Loader2, ShieldAlert, Cpu } from 'lucide-react';
import { cn } from '@/lib/utils';
import Markdown from 'react-markdown';

export function Copilot() {
  const { t, language } = useLanguage();
  const [messages, setMessages] = useState<CopilotMessage[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const endOfMessagesRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    endOfMessagesRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isTyping]);

  const handleSend = async () => {
    if (!inputValue.trim() || isTyping) return;

    const userMessage = inputValue.trim();
    setInputValue('');
    setMessages((prev) => [...prev, { role: 'user', content: userMessage }]);
    setIsTyping(true);

    try {
      const response = await chatWithCopilot(messages, userMessage, language);
      setMessages((prev) => [...prev, { role: 'model', content: response }]);
    } catch (error) {
      console.error(error);
      setMessages((prev) => [...prev, { 
        role: 'model', 
        content: t('scanner_disclaimer') || 'Error: Could not connect to AI Engine.' 
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

  return (
    <div className="h-full flex flex-col pt-6 pb-6 pr-6 pl-2 lg:pl-6 overflow-hidden">
      <div className="mb-4 flex items-center justify-between shrink-0">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-3">
          <div className="relative">
            <Bot className="w-8 h-8 text-cyber-blue relative z-10" />
            <div className="absolute inset-0 bg-cyber-blue/30 blur-md rounded-full animate-pulse" />
          </div>
          NEUROSHIELD {t('copilot').toUpperCase()}
        </h1>
        <div className="flex items-center gap-2 border border-cyber-blue/30 bg-cyber-blue/10 px-3 py-1.5 rounded-full">
           <Cpu className="w-4 h-4 text-cyber-blue animate-pulse" />
           <span className="text-xs text-cyber-blue uppercase tracking-widest font-bold">GPT-4 OVERRIDE / GEMINI ONLINE</span>
        </div>
      </div>

      <div className="flex-1 overflow-hidden flex flex-col bg-[#0a0d1a]/50 backdrop-blur-md border border-white/5 rounded-xl shadow-[0_0_20px_rgba(0,0,0,0.5)]">
        
        {/* Chat History */}
        <div className="flex-1 overflow-y-auto px-4 py-6 md:px-8 space-y-6 custom-scrollbar">
          {messages.length === 0 && (
            <div className="h-full flex flex-col items-center justify-center text-center text-cyber-muted space-y-4">
               <Bot className="w-16 h-16 text-cyber-blue/30 mb-2" />
               <h3 className="text-lg text-white font-semibold uppercase tracking-widest">Global Intelligence Active</h3>
               <p className="max-w-md text-sm">
                 I am NeuroShield Copilot, your AI cyber-investigator. Ask me to analyze an IP, dissect a phishing campaign, or explain system logs.
               </p>
               <div className="flex flex-wrap items-center justify-center gap-3 mt-4">
                 {['Analyze a suspicious email', 'What is an attack graph?', 'Explain XSS vulnerability'].map(query => (
                   <button 
                     key={query}
                     onClick={() => setInputValue(query)}
                     className="px-3 py-1.5 rounded-full border border-white/10 bg-white/5 hover:bg-white/10 hover:border-cyber-blue/50 text-xs transition-colors"
                   >
                     {query}
                   </button>
                 ))}
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
                  "flex w-full gap-4",
                  msg.role === 'user' ? "justify-end" : "justify-start"
                )}
              >
                {msg.role === 'model' && (
                  <div className="shrink-0 w-8 h-8 rounded bg-cyber-blue/20 flex items-center justify-center border border-cyber-blue/40 mt-1 shadow-[0_0_10px_var(--color-cyber-blue-glow)]">
                    <Bot className="w-4 h-4 text-cyber-blue" />
                  </div>
                )}
                
                <div className={cn(
                  "max-w-[85%] md:max-w-[70%] rounded-lg px-4 py-3 text-sm relative overflow-hidden",
                  msg.role === 'user' 
                    ? "bg-white/10 text-white border border-white/20" 
                    : "bg-black/40 text-[#b5c4d8] border border-cyber-blue/20"
                )}>
                  {msg.role === 'model' && (
                    <div className="absolute inset-x-0 top-0 h-[1px] bg-gradient-to-r from-transparent via-cyber-blue/50 to-transparent" />
                  )}
                  {msg.role === 'user' ? (
                    <div className="whitespace-pre-wrap">{msg.content}</div>
                  ) : (
                    <div className="markdown-body prose prose-invert prose-p:leading-relaxed prose-pre:bg-black/60 prose-pre:border prose-pre:border-white/10 prose-strong:text-cyber-blue prose-a:text-cyber-green max-w-none text-sm">
                      <Markdown>{msg.content}</Markdown>
                    </div>
                  )}
                </div>

                {msg.role === 'user' && (
                  <div className="shrink-0 w-8 h-8 rounded bg-white/10 flex items-center justify-center border border-white/20 mt-1">
                    <User className="w-4 h-4 text-white/70" />
                  </div>
                )}
              </motion.div>
            ))}
          </AnimatePresence>

          {isTyping && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex w-full gap-4 justify-start">
              <div className="shrink-0 w-8 h-8 rounded bg-cyber-blue/20 flex items-center justify-center border border-cyber-blue/40 mt-1 shadow-[0_0_10px_var(--color-cyber-blue-glow)]">
                <Bot className="w-4 h-4 text-cyber-blue" />
              </div>
              <div className="bg-black/40 text-[#b5c4d8] border border-cyber-blue/20 rounded-lg px-4 py-4 flex items-center gap-2">
                 <Loader2 className="w-4 h-4 animate-spin text-cyber-blue" />
                 <span className="text-xs uppercase tracking-widest text-cyber-blue font-mono font-bold animate-pulse">Processing Analysis...</span>
              </div>
            </motion.div>
          )}
          <div ref={endOfMessagesRef} />
        </div>

        {/* Input Area */}
        <div className="p-4 bg-black/40 border-t border-white/5">
          <div className="relative flex items-end gap-2 max-w-4xl mx-auto">
            <textarea
              className="w-full bg-white/5 border border-white/10 focus:border-cyber-blue/50 rounded-lg px-4 py-3 text-sm text-white placeholder-cyber-muted resize-none focus:outline-none focus:ring-1 focus:ring-cyber-blue/50 transition-all min-h-[50px] max-h-[150px] custom-scrollbar"
              placeholder="Query the NeuroShield Intelligence array..."
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={handleKeyDown}
              rows={Math.min(5, inputValue.split('\n').length)}
              style={{ paddingRight: '3rem' }}
            />
            <button 
              onClick={handleSend}
              disabled={!inputValue.trim() || isTyping}
              className="absolute right-2 bottom-2 p-2 bg-cyber-blue hover:bg-[#00e0eb] text-black rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed group shadow-[0_0_10px_var(--color-cyber-blue-glow)]"
            >
              <Send className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
            </button>
          </div>
          <div className="text-center mt-2 flex items-center justify-center gap-2 text-[10px] text-cyber-muted uppercase tracking-widest font-mono">
             <ShieldAlert className="w-3 h-3 text-cyber-red" />
             AI queries are logged for system telemetry.
          </div>
        </div>
      </div>
    </div>
  );
}
