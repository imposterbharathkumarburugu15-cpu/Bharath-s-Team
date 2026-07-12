import React, { useState } from 'react';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Mail, 
  MessageSquare, 
  Link, 
  Globe, 
  Network, 
  Database, 
  Users, 
  User,
  GraduationCap, 
  Bell, 
  Bot, 
  Settings,
  Activity,
  Search,
  X,
  Languages,
  Terminal,
  Mic,
  Waves
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { motion, AnimatePresence } from 'motion/react';
import { useLanguage } from '@/contexts/LanguageContext';

interface NavItem {
  name: string;
  id: string;
  icon: React.ElementType;
}

const navItems: NavItem[] = [
  { name: 'dashboard', id: 'dashboard', icon: LayoutDashboard },
  { name: 'scanner', id: 'scanner', icon: ShieldAlert },
  { name: 'phishing', id: 'phishing', icon: Mail },
  { name: 'voice', id: 'voice', icon: Mic },
  { name: 'wave', id: 'wave', icon: Waves },
  { name: 'copilot', id: 'copilot', icon: Bot },
  { name: 'api', id: 'api', icon: Terminal },
  { name: 'settings', id: 'settings', icon: Settings },
];

export function Layout({ 
  children, 
  activeTab, 
  setActiveTab 
}: { 
  children: React.ReactNode;
  activeTab: string;
  setActiveTab: (id: string) => void;
}) {
  const [showCopilot, setShowCopilot] = useState(false);
  const { language, setLanguage, t } = useLanguage();

  return (
    <div className="flex h-screen w-full bg-cyber-bg overflow-hidden relative">
      <div className="bg-grid" />
      
      {/* Sidebar */}
      <aside className="w-[280px] h-full flex-shrink-0 border-r border-cyber-blue/20 bg-black/40 backdrop-blur-xl z-20 flex flex-col pt-6 pb-6 pl-5 pr-5 box-border shadow-[10px_0_30px_rgba(0,0,0,0.5)]">
        <div className="flex items-center gap-4 mb-10 px-1 relative">
          <div className="absolute -left-5 w-1 h-12 bg-cyber-blue shadow-[0_0_15px_var(--color-cyber-blue-glow)] rounded-r" />
          <div className="relative w-10 h-10 flex items-center justify-center group shrink-0">
            {/* Hexagon Base */}
            <svg viewBox="0 0 100 100" className="w-full h-full text-cyber-blue drop-shadow-[0_0_8px_rgba(0,243,255,0.8)] fill-current transition-all duration-300 group-hover:-rotate-12 group-hover:scale-110">
              <polygon points="50 3 93 25 93 75 50 97 7 75 7 25" fill="none" stroke="currentColor" strokeWidth="4" />
              <polygon points="50 15 80 32 80 68 50 85 20 68 20 32" fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray="5 5" className="animate-[spin_8s_linear_infinite_reverse]" />
              {/* Inner Core */}
              <circle cx="50" cy="50" r="12" className="animate-pulse" />
            </svg>
            <div className="absolute inset-0 rounded-full shadow-[0_0_20px_var(--color-cyber-blue-glow)] opacity-80 mix-blend-screen" />
          </div>
          <div className="leading-none flex flex-col justify-center">
            <div className="font-extrabold text-lg tracking-widest text-white drop-shadow-[0_0_8px_rgba(255,255,255,0.4)] font-sans">NEUROSHIELD</div>
            <div className="text-[8px] text-cyber-blue tracking-[0.3em] font-mono mt-1 opacity-100 uppercase drop-shadow-[0_0_5px_var(--color-cyber-blue-glow)] whitespace-nowrap">AI Gateway</div>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto space-y-1.5 custom-scrollbar pr-2">
          <motion.div 
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#5e738c] mb-3 pl-3 mt-4 flex items-center gap-2"
          >
            {t('operations')}
            <div className="flex-1 h-[1px] bg-gradient-to-r from-cyber-border to-transparent" />
          </motion.div>
          {navItems.map((item, i) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <motion.button
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={cn(
                  "w-full flex items-center px-4 py-3 text-[13px] rounded-lg transition-all duration-300 group gap-3 relative overflow-hidden font-medium tracking-wide",
                  isActive 
                    ? "bg-cyber-blue/15 text-white shadow-[inset_0_0_20px_rgba(0,243,255,0.15)] border border-cyber-blue/30" 
                    : "text-[#8a99af] hover:bg-white/5 hover:text-white border border-transparent"
                )}
              >
                {isActive && (
                  <motion.div layoutId="activeNavIndicator" className="absolute left-0 top-0 bottom-0 w-1 bg-cyber-blue shadow-[0_0_10px_var(--color-cyber-blue-glow)]" />
                )}
                <Icon className={cn(
                  "flex-shrink-0 h-4 w-4 transition-all duration-300",
                  isActive ? "text-cyber-blue drop-shadow-[0_0_5px_var(--color-cyber-blue-glow)]" : "group-hover:text-cyber-blue"
                )} />
                <span className="uppercase text-[11px] font-mono tracking-widest">{t(item.name)}</span>
              </motion.button>
            );
          })}
        </div>
        <div className="mt-8 p-4 bg-[#0a0d1a] rounded-xl border border-cyber-blue/20 relative overflow-hidden group">
          <div className="absolute inset-0 bg-gradient-to-tr from-cyber-blue/5 to-transparent pointer-events-none" />
          <div className="text-[10px] text-cyber-blue mb-2 font-mono flex items-center justify-between uppercase font-bold">
            {t('ai_status')}
            <div className="p-1 bg-cyber-blue/10 rounded flex items-center justify-center">
               <Bot className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded bg-cyber-green shadow-[0_0_8px_var(--color-cyber-green)] animate-pulse" />
              <span className="text-xs font-mono font-medium text-white">{t('operational')}</span>
            </div>
            <span className="text-[10px] font-mono text-cyber-green">99.9%</span>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col z-10 h-full overflow-hidden relative">
        {/* Top Header */}
        <header className="h-[70px] flex-shrink-0 border-b border-cyber-border/40 bg-black/20 backdrop-blur-md flex items-center justify-between px-8 z-20 shadow-md">
          <h1 className="text-2xl font-bold font-sans tracking-widest flex items-center gap-3 uppercase text-white drop-shadow-[0_0_10px_rgba(255,255,255,0.2)]">
            <span className="w-2 h-6 bg-cyber-blue/80 rounded block shadow-[0_0_10px_var(--color-cyber-blue-glow)]" />
            {t(navItems.find(n => n.id === activeTab)?.name || 'UNKNOWN')}
          </h1>
          <div className="flex items-center gap-5">
            <div className="flex items-center gap-3">
              <div className="text-[10px] uppercase font-bold text-cyber-green flex items-center gap-1 border border-cyber-green/30 bg-cyber-green/10 px-2 py-1 rounded-full shadow-[0_0_10px_var(--color-cyber-green-glow)]">
                 <div className="w-1.5 h-1.5 bg-cyber-green rounded-full animate-pulse" />
                 {t('system_secure')}
              </div>
              <div className="text-[10px] uppercase font-bold text-cyber-blue flex items-center gap-1 border border-cyber-blue/30 bg-cyber-blue/10 px-2 py-1 rounded-full shadow-[0_0_10px_var(--color-cyber-blue-glow)]">
                 <Activity className="w-3 h-3" />
                 {t('ai_models_active')}
              </div>
            </div>
            
            <div className="flex items-center gap-2 bg-white/5 px-3 py-1.5 rounded border border-cyber-border text-[#4a5568]">
               <Search className="w-3.5 h-3.5 text-[#8a99af]" />
               <input 
                 type="text" 
                 placeholder={t('search_placeholder')} 
                 className="bg-transparent text-xs focus:outline-none text-cyber-text w-64 placeholder:text-[#4a5568]"
               />
            </div>
            
            <div className="flex gap-4 items-center">
              <div className="relative group">
                <button className="flex items-center gap-2 text-cyber-muted hover:text-cyber-blue transition-colors">
                  <Languages className="w-4 h-4" />
                  <span className="text-xs uppercase">{language}</span>
                </button>
                <div className="absolute right-0 mt-2 w-32 bg-[#0a0d1a] border border-cyber-border rounded-md shadow-lg overflow-hidden opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-50">
                   <button onClick={() => setLanguage('en')} className={cn("w-full text-left px-4 py-2 text-xs hover:bg-cyber-blue/10", language === 'en' ? "text-cyber-blue" : "text-white")}>English</button>
                   <button onClick={() => setLanguage('hi')} className={cn("w-full text-left px-4 py-2 text-xs hover:bg-cyber-blue/10", language === 'hi' ? "text-cyber-blue" : "text-white")}>Hindi (हिन्दी)</button>
                   <button onClick={() => setLanguage('te')} className={cn("w-full text-left px-4 py-2 text-xs hover:bg-cyber-blue/10", language === 'te' ? "text-cyber-blue" : "text-white")}>Telugu (తెలుగు)</button>
                </div>
              </div>

              <button className="relative text-cyber-muted hover:text-cyber-blue transition-colors">
                <Bell className="w-4 h-4" />
                <div className="absolute -top-1 -right-1 flex items-center justify-center w-3 h-3 bg-cyber-red rounded-full text-[8px] text-white font-bold">3</div>
              </button>
              
              <div className="h-4 w-px bg-cyber-border" />
              
              <div className="flex items-center gap-2">
                <div className="text-right flex flex-col justify-center">
                  <div className="text-[11px] font-bold text-white">{t('soc_admin')}</div>
                  <div className="text-[9px] text-cyber-green">{t('online')}</div>
                </div>
                <div className="w-8 h-8 rounded-full border border-cyber-border bg-white/5 flex items-center justify-center">
                  <User className="w-4 h-4 text-cyber-muted" />
                </div>
              </div>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <div className={cn("flex-1 overflow-auto flex flex-col", (activeTab === 'wave' || activeTab === 'scanner') ? "p-0 gap-0" : "p-6 gap-6")}>
          {children}
        </div>
      </main>

      {/* Floating Action Button for AI Copilot */}
      <AnimatePresence>
        {!showCopilot && (
          <motion.div
             initial={{ opacity: 0, scale: 0.8 }}
             animate={{ opacity: 1, scale: 1 }}
             exit={{ opacity: 0, scale: 0.8 }}
             className="fixed bottom-6 right-6 z-[110]"
          >
            <button 
              onClick={() => setShowCopilot(true)}
              className="w-12 h-12 rounded-full bg-cyber-blue/10 border border-cyber-blue text-cyber-blue shadow-[0_0_15px_var(--color-cyber-blue-glow)] flex items-center justify-center hover:bg-cyber-blue/20 transition-all hover:scale-110 group"
            >
              <Bot className="w-6 h-6 group-hover:animate-pulse" />
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* AI Copilot Float */}
      <AnimatePresence>
        {showCopilot && (
          <motion.div 
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.95 }}
            className="fixed bottom-6 right-6 w-[320px] z-[100] glass-panel flex flex-col shadow-2xl border-cyber-blue/50"
          >
            <div className="p-2.5 px-4 border-b border-cyber-border flex items-center justify-between gap-2.5 bg-cyber-blue/10 font-semibold text-[11px] tracking-wide rounded-t-[7px]">
              <div className="flex items-center gap-2">
                <Bot className="w-3.5 h-3.5 text-cyber-blue" />
                NEUROSHIELD AI COPILOT
              </div>
              <button onClick={() => setShowCopilot(false)} className="text-cyber-muted hover:text-white transition-colors">
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
            <div className="p-3 text-[11px] leading-relaxed">
              <div className="bg-white/5 p-2 rounded-md mb-2.5 border-l-2 border-cyber-blue">
                Analyzing surge in suspicious WhatsApp messages in Hindi. Detected pattern: <span className="text-cyber-blue font-semibold">Credential Harvesting</span> targeting financial sector.
              </div>
              <div className="flex gap-2">
                <div className="flex-1 bg-black/30 border border-cyber-border rounded px-2.5 py-1.5 text-cyber-muted">
                  Ask me about current threats...
                </div>
                <button className="w-7 h-7 bg-cyber-blue rounded flex justify-center items-center">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#000" strokeWidth="3">
                    <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
                  </svg>
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
