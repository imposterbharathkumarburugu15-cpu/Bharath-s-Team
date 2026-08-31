import React, { useState, useEffect, useRef } from 'react';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Mail, 
  Network, 
  Bell, 
  Bot, 
  Settings, 
  Activity, 
  Search, 
  X, 
  Languages, 
  Terminal, 
  Mic, 
  Waves, 
  Menu, 
  ChevronRight, 
  ChevronLeft,
  User, 
  Check, 
  ExternalLink,
  Sliders,
  Sparkles,
  Zap,
  Globe,
  PanelLeftClose,
  PanelLeftOpen,
  Maximize2,
  Minimize2,
  Command,
  CornerDownLeft,
  Radio,
  FileSearch,
  ShieldCheck,
  Cpu
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { motion, AnimatePresence } from 'motion/react';
import { useLanguage } from '@/contexts/LanguageContext';

export interface NavItem {
  name: string;
  id: string;
  icon: React.ElementType;
  category: 'CORE' | 'AI_INTEL' | 'PLATFORM';
  badge?: string;
  shortcut?: string;
  description?: string;
}

export const navItems: NavItem[] = [
  // CORE DEFENSE
  { name: 'dashboard', id: 'dashboard', icon: LayoutDashboard, category: 'CORE', shortcut: '1', description: 'SOC telemetry, threat feed & KPIs' },
  { name: 'scanner', id: 'scanner', icon: ShieldAlert, category: 'CORE', badge: 'LIVE', shortcut: '2', description: 'Multimodal payload & URL vulnerability scanner' },
  { name: 'phishing', id: 'phishing', icon: Mail, category: 'CORE', badge: 'RFC 5322', shortcut: '3', description: 'Deep email header forensics & relay reconstruction' },
  { name: 'alerts', id: 'alerts', icon: Bell, category: 'CORE', badge: '3', shortcut: '4', description: 'Real-time incident response & triage' },
  
  // AI INTELLIGENCE
  { name: 'voice', id: 'voice', icon: Mic, category: 'AI_INTEL', badge: 'VOICE', shortcut: '5', description: 'Conversational audio security assistant' },
  { name: 'wave', id: 'wave', icon: Waves, category: 'AI_INTEL', badge: 'RADAR', shortcut: '6', description: 'Radio frequency & wireless anomaly detection' },
  { name: 'graph', id: 'graph', icon: Network, category: 'AI_INTEL', shortcut: '7', description: 'Interactive kill-chain & topology mapper' },
  { name: 'copilot', id: 'copilot', icon: Bot, category: 'AI_INTEL', badge: 'COPILOT', shortcut: '8', description: 'Automated SOC forensic investigator' },
  
  // PLATFORM & SETTINGS
  { name: 'api', id: 'api', icon: Terminal, category: 'PLATFORM', shortcut: '9', description: 'Enterprise REST / WebSocket API keys' },
  { name: 'settings', id: 'settings', icon: Settings, category: 'PLATFORM', shortcut: '0', description: 'Telemetry thresholds & system configuration' },
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
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('neuroshield_sidebar_collapsed');
      if (saved !== null) return saved === 'true';
      // Default to collapsed only on medium tablet screens (between 768px and 1024px)
      return window.innerWidth < 1024 && window.innerWidth >= 768;
    }
    return false;
  });
  
  const [showCopilot, setShowCopilot] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showLangDropdown, setShowLangDropdown] = useState(false);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [hoveredNavId, setHoveredNavId] = useState<string | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(0);
  
  const searchInputRef = useRef<HTMLInputElement>(null);
  const { language, setLanguage, t } = useLanguage();

  // Save collapsed state
  const toggleSidebar = () => {
    setIsSidebarCollapsed(prev => {
      const next = !prev;
      localStorage.setItem('neuroshield_sidebar_collapsed', String(next));
      return next;
    });
  };

  const handleNavClick = (id: string) => {
    setActiveTab(id);
    setIsMobileMenuOpen(false);
    setShowNotifications(false);
    setShowLangDropdown(false);
    setIsCommandPaletteOpen(false);
    setSearchQuery('');
  };

  // Keyboard Shortcuts (Cmd+K for Command Palette, Cmd+B for Sidebar, 1-9 for tabs)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Cmd/Ctrl + K => Toggle Command Palette
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsCommandPaletteOpen(prev => !prev);
        return;
      }

      // Cmd/Ctrl + B => Toggle Sidebar Collapse
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'b') {
        e.preventDefault();
        toggleSidebar();
        return;
      }

      // Escape => Close any modal/dropdown/palette
      if (e.key === 'Escape') {
        if (isCommandPaletteOpen) {
          setIsCommandPaletteOpen(false);
          setSearchQuery('');
        }
        if (showNotifications) setShowNotifications(false);
        if (showLangDropdown) setShowLangDropdown(false);
        if (isMobileMenuOpen) setIsMobileMenuOpen(false);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isCommandPaletteOpen, showNotifications, showLangDropdown, isMobileMenuOpen]);

  // Focus input when Command Palette opens
  useEffect(() => {
    if (isCommandPaletteOpen) {
      setSelectedIndex(0);
      setTimeout(() => {
        searchInputRef.current?.focus();
      }, 50);
    }
  }, [isCommandPaletteOpen]);

  // Fullscreen toggle helper
  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(() => {});
      setIsFullscreen(true);
    } else {
      if (document.exitFullscreen) {
        document.exitFullscreen().catch(() => {});
        setIsFullscreen(false);
      }
    }
  };

  const activeItem = navItems.find(n => n.id === activeTab) || navItems[0];

  // Filtered list for Command Palette
  const filteredNavItems = navItems.filter(item => {
    const term = searchQuery.toLowerCase();
    return (
      item.name.toLowerCase().includes(term) ||
      t(item.name).toLowerCase().includes(term) ||
      (item.description && item.description.toLowerCase().includes(term)) ||
      item.category.toLowerCase().includes(term)
    );
  });

  return (
    <div className="flex h-screen w-full bg-[#050811] text-white overflow-hidden relative selection:bg-cyber-blue selection:text-black font-sans">
      {/* Background Cyber Grid */}
      <div className="bg-grid absolute inset-0 opacity-30 pointer-events-none" />
      <div className="absolute top-0 right-1/4 w-96 h-96 bg-cyber-blue/5 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute bottom-0 left-1/4 w-96 h-96 bg-cyber-purple/5 rounded-full blur-[140px] pointer-events-none" />

      {/* ========================================================
          1. COMPUTER / DESKTOP SIDEBAR (Visible on md and above)
             Features: Collapsible to Icon Rail, Tooltips, Hotkeys
         ======================================================== */}
      <aside 
        className={cn(
          "hidden md:flex h-full flex-shrink-0 border-r border-cyber-border/40 bg-[#070b14]/95 backdrop-blur-2xl z-30 flex-col py-4 box-border shadow-[10px_0_30px_rgba(0,0,0,0.6)] transition-all duration-300 relative",
          isSidebarCollapsed ? "w-20 px-2.5 items-center" : "w-64 xl:w-72 px-4"
        )}
      >
        {/* Brand Header */}
        <div className={cn(
          "flex items-center gap-3 mb-6 relative w-full",
          isSidebarCollapsed ? "justify-center px-0" : "px-2 justify-between"
        )}>
          <div 
            onClick={() => handleNavClick('dashboard')} 
            className="flex items-center gap-3 cursor-pointer group"
          >
            <div className="relative w-9 h-9 flex items-center justify-center shrink-0">
              {/* Hexagon Cyber Shield Logo */}
              <svg viewBox="0 0 100 100" className="w-full h-full text-cyber-blue drop-shadow-[0_0_10px_rgba(0,243,255,0.8)] fill-current transition-all duration-300 group-hover:scale-105">
                <polygon points="50 3 93 25 93 75 50 97 7 75 7 25" fill="none" stroke="currentColor" strokeWidth="4" />
                <polygon points="50 15 80 32 80 68 50 85 20 68 20 32" fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray="5 5" className="animate-[spin_12s_linear_infinite_reverse]" />
                <circle cx="50" cy="50" r="12" className="animate-pulse fill-cyber-blue/80" />
              </svg>
              <div className="absolute inset-0 rounded-full shadow-[0_0_20px_var(--color-cyber-blue-glow)] opacity-70 mix-blend-screen pointer-events-none" />
            </div>

            {!isSidebarCollapsed && (
              <motion.div 
                initial={{ opacity: 0, x: -5 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -5 }}
                className="leading-none flex flex-col justify-center min-w-0"
              >
                <div className="font-extrabold text-sm tracking-[0.2em] text-white font-sans flex items-center gap-1.5 truncate">
                  NEUROSHIELD
                </div>
                <div className="text-[9px] text-cyber-blue tracking-[0.25em] font-mono mt-1 uppercase font-bold drop-shadow-[0_0_5px_var(--color-cyber-blue-glow)] truncate">
                  AI SOC GATEWAY
                </div>
              </motion.div>
            )}
          </div>

          {/* Desktop Sidebar Collapse Toggle Button */}
          {!isSidebarCollapsed && (
            <button
              onClick={toggleSidebar}
              title="Collapse Sidebar (Ctrl+B)"
              className="w-7 h-7 rounded-lg bg-white/5 hover:bg-cyber-blue/15 text-gray-400 hover:text-cyber-blue border border-white/5 hover:border-cyber-blue/30 flex items-center justify-center transition-all shrink-0 cursor-pointer"
            >
              <PanelLeftClose className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* If collapsed, show quick toggle button at top */}
        {isSidebarCollapsed && (
          <button
            onClick={toggleSidebar}
            title="Expand Sidebar (Ctrl+B)"
            className="w-9 h-9 mb-4 rounded-xl bg-white/5 hover:bg-cyber-blue/20 text-gray-400 hover:text-cyber-blue border border-white/10 hover:border-cyber-blue/40 flex items-center justify-center transition-all cursor-pointer"
          >
            <PanelLeftOpen className="w-4 h-4" />
          </button>
        )}

        {/* Quick Search Trigger on Sidebar (expanded only) */}
        {!isSidebarCollapsed && (
          <button
            onClick={() => setIsCommandPaletteOpen(true)}
            className="w-full mb-5 px-3 py-2 rounded-xl bg-[#090e1c] border border-cyber-border/60 hover:border-cyber-blue/50 text-gray-400 hover:text-white flex items-center justify-between transition-all group text-xs font-mono"
          >
            <div className="flex items-center gap-2">
              <Search className="w-3.5 h-3.5 text-gray-500 group-hover:text-cyber-blue transition-colors" />
              <span className="text-gray-400 group-hover:text-gray-200">Quick Command...</span>
            </div>
            <kbd className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/5 text-gray-400 border border-white/10 group-hover:border-cyber-blue/30">
              ⌘K
            </kbd>
          </button>
        )}

        {/* Navigation List */}
        <div className="flex-1 overflow-y-auto overflow-x-hidden space-y-5 custom-scrollbar w-full pr-0.5">
          {/* Section 1: Core Operations */}
          <div className="space-y-1 w-full">
            {!isSidebarCollapsed ? (
              <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#5e738c] mb-2 px-3 flex items-center gap-2 font-mono">
                <span>{t('operations')}</span>
                <div className="flex-1 h-[1px] bg-gradient-to-r from-cyber-border/40 to-transparent" />
              </div>
            ) : (
              <div className="w-full flex justify-center mb-1">
                <div className="w-4 h-[1px] bg-white/10" />
              </div>
            )}

            {navItems.filter(i => i.category === 'CORE').map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <div 
                  key={item.id} 
                  className="relative w-full"
                  onMouseEnter={() => setHoveredNavId(item.id)}
                  onMouseLeave={() => setHoveredNavId(null)}
                >
                  <button
                    onClick={() => handleNavClick(item.id)}
                    className={cn(
                      "flex items-center text-xs rounded-xl transition-all duration-200 group relative font-medium w-full cursor-pointer",
                      isSidebarCollapsed 
                        ? "w-11 h-11 mx-auto justify-center p-0" 
                        : "px-3.5 py-2.5 justify-between",
                      isActive 
                        ? "bg-gradient-to-r from-cyber-blue/20 to-cyber-blue/5 text-white border border-cyber-blue/40 shadow-[0_0_20px_rgba(0,243,255,0.15)]" 
                        : "text-gray-400 hover:bg-white/5 hover:text-white border border-transparent"
                    )}
                  >
                    <div className={cn("flex items-center", isSidebarCollapsed ? "justify-center" : "gap-3")}>
                      <Icon className={cn(
                        "h-4 w-4 transition-colors shrink-0",
                        isActive ? "text-cyber-blue drop-shadow-[0_0_6px_var(--color-cyber-blue-glow)]" : "text-gray-400 group-hover:text-cyber-blue"
                      )} />
                      {!isSidebarCollapsed && (
                        <span className="uppercase text-[11px] font-mono tracking-wider truncate">
                          {t(item.name)}
                        </span>
                      )}
                    </div>

                    {!isSidebarCollapsed && item.badge && (
                      <span className={cn(
                        "text-[9px] font-mono px-1.5 py-0.5 rounded-full font-bold shrink-0",
                        isActive ? "bg-cyber-blue text-black" : "bg-white/10 text-gray-400 group-hover:text-white"
                      )}>
                        {item.badge}
                      </span>
                    )}

                    {/* Active Accent Indicator */}
                    {isActive && (
                      <div className={cn(
                        "absolute bg-cyber-blue shadow-[0_0_10px_var(--color-cyber-blue-glow)]",
                        isSidebarCollapsed 
                          ? "-left-1 top-2.5 bottom-2.5 w-1 rounded-r" 
                          : "left-0 top-1/2 -translate-y-1/2 w-1 h-5 rounded-r"
                      )} />
                    )}
                  </button>

                  {/* Tooltip on Collapsed Mode for Computers */}
                  {isSidebarCollapsed && hoveredNavId === item.id && (
                    <div className="fixed left-20 z-50 ml-2 px-3 py-1.5 bg-[#090e1c] border border-cyber-blue/40 rounded-xl shadow-2xl text-xs font-mono whitespace-nowrap animate-in fade-in zoom-in-95 pointer-events-none">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white uppercase">{t(item.name)}</span>
                        {item.badge && (
                          <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 font-bold">
                            {item.badge}
                          </span>
                        )}
                      </div>
                      {item.description && (
                        <div className="text-[10px] text-gray-400 font-sans mt-0.5 max-w-[200px]">
                          {item.description}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Section 2: AI Intelligence */}
          <div className="space-y-1 w-full">
            {!isSidebarCollapsed ? (
              <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#5e738c] mb-2 px-3 flex items-center gap-2 font-mono">
                <span>AI INTELLIGENCE</span>
                <div className="flex-1 h-[1px] bg-gradient-to-r from-cyber-border/40 to-transparent" />
              </div>
            ) : (
              <div className="w-full flex justify-center mb-1">
                <div className="w-4 h-[1px] bg-white/10" />
              </div>
            )}

            {navItems.filter(i => i.category === 'AI_INTEL').map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <div 
                  key={item.id} 
                  className="relative w-full"
                  onMouseEnter={() => setHoveredNavId(item.id)}
                  onMouseLeave={() => setHoveredNavId(null)}
                >
                  <button
                    onClick={() => handleNavClick(item.id)}
                    className={cn(
                      "flex items-center text-xs rounded-xl transition-all duration-200 group relative font-medium w-full cursor-pointer",
                      isSidebarCollapsed 
                        ? "w-11 h-11 mx-auto justify-center p-0" 
                        : "px-3.5 py-2.5 justify-between",
                      isActive 
                        ? "bg-gradient-to-r from-cyber-blue/20 to-cyber-blue/5 text-white border border-cyber-blue/40 shadow-[0_0_20px_rgba(0,243,255,0.15)]" 
                        : "text-gray-400 hover:bg-white/5 hover:text-white border border-transparent"
                    )}
                  >
                    <div className={cn("flex items-center", isSidebarCollapsed ? "justify-center" : "gap-3")}>
                      <Icon className={cn(
                        "h-4 w-4 transition-colors shrink-0",
                        isActive ? "text-cyber-blue drop-shadow-[0_0_6px_var(--color-cyber-blue-glow)]" : "text-gray-400 group-hover:text-cyber-blue"
                      )} />
                      {!isSidebarCollapsed && (
                        <span className="uppercase text-[11px] font-mono tracking-wider truncate">
                          {t(item.name)}
                        </span>
                      )}
                    </div>

                    {!isSidebarCollapsed && item.badge && (
                      <span className={cn(
                        "text-[9px] font-mono px-1.5 py-0.5 rounded-full font-bold shrink-0",
                        isActive ? "bg-cyber-blue text-black" : "bg-white/10 text-gray-400 group-hover:text-white"
                      )}>
                        {item.badge}
                      </span>
                    )}

                    {isActive && (
                      <div className={cn(
                        "absolute bg-cyber-blue shadow-[0_0_10px_var(--color-cyber-blue-glow)]",
                        isSidebarCollapsed 
                          ? "-left-1 top-2.5 bottom-2.5 w-1 rounded-r" 
                          : "left-0 top-1/2 -translate-y-1/2 w-1 h-5 rounded-r"
                      )} />
                    )}
                  </button>

                  {/* Tooltip on Collapsed Mode for Computers */}
                  {isSidebarCollapsed && hoveredNavId === item.id && (
                    <div className="fixed left-20 z-50 ml-2 px-3 py-1.5 bg-[#090e1c] border border-cyber-blue/40 rounded-xl shadow-2xl text-xs font-mono whitespace-nowrap animate-in fade-in zoom-in-95 pointer-events-none">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white uppercase">{t(item.name)}</span>
                        {item.badge && (
                          <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 font-bold">
                            {item.badge}
                          </span>
                        )}
                      </div>
                      {item.description && (
                        <div className="text-[10px] text-gray-400 font-sans mt-0.5 max-w-[200px]">
                          {item.description}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Section 3: Platform & Settings */}
          <div className="space-y-1 w-full">
            {!isSidebarCollapsed ? (
              <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#5e738c] mb-2 px-3 flex items-center gap-2 font-mono">
                <span>SYSTEM &amp; API</span>
                <div className="flex-1 h-[1px] bg-gradient-to-r from-cyber-border/40 to-transparent" />
              </div>
            ) : (
              <div className="w-full flex justify-center mb-1">
                <div className="w-4 h-[1px] bg-white/10" />
              </div>
            )}

            {navItems.filter(i => i.category === 'PLATFORM').map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <div 
                  key={item.id} 
                  className="relative w-full"
                  onMouseEnter={() => setHoveredNavId(item.id)}
                  onMouseLeave={() => setHoveredNavId(null)}
                >
                  <button
                    onClick={() => handleNavClick(item.id)}
                    className={cn(
                      "flex items-center text-xs rounded-xl transition-all duration-200 group relative font-medium w-full cursor-pointer",
                      isSidebarCollapsed 
                        ? "w-11 h-11 mx-auto justify-center p-0" 
                        : "px-3.5 py-2.5 justify-between",
                      isActive 
                        ? "bg-gradient-to-r from-cyber-blue/20 to-cyber-blue/5 text-white border border-cyber-blue/40 shadow-[0_0_20px_rgba(0,243,255,0.15)]" 
                        : "text-gray-400 hover:bg-white/5 hover:text-white border border-transparent"
                    )}
                  >
                    <div className={cn("flex items-center", isSidebarCollapsed ? "justify-center" : "gap-3")}>
                      <Icon className={cn(
                        "h-4 w-4 transition-colors shrink-0",
                        isActive ? "text-cyber-blue drop-shadow-[0_0_6px_var(--color-cyber-blue-glow)]" : "text-gray-400 group-hover:text-cyber-blue"
                      )} />
                      {!isSidebarCollapsed && (
                        <span className="uppercase text-[11px] font-mono tracking-wider truncate">
                          {t(item.name)}
                        </span>
                      )}
                    </div>

                    {isActive && (
                      <div className={cn(
                        "absolute bg-cyber-blue shadow-[0_0_10px_var(--color-cyber-blue-glow)]",
                        isSidebarCollapsed 
                          ? "-left-1 top-2.5 bottom-2.5 w-1 rounded-r" 
                          : "left-0 top-1/2 -translate-y-1/2 w-1 h-5 rounded-r"
                      )} />
                    )}
                  </button>

                  {/* Tooltip on Collapsed Mode for Computers */}
                  {isSidebarCollapsed && hoveredNavId === item.id && (
                    <div className="fixed left-20 z-50 ml-2 px-3 py-1.5 bg-[#090e1c] border border-cyber-blue/40 rounded-xl shadow-2xl text-xs font-mono whitespace-nowrap animate-in fade-in zoom-in-95 pointer-events-none">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white uppercase">{t(item.name)}</span>
                      </div>
                      {item.description && (
                        <div className="text-[10px] text-gray-400 font-sans mt-0.5 max-w-[200px]">
                          {item.description}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* System Health Status Footer (Expanded or Compact) */}
        {!isSidebarCollapsed ? (
          <div className="mt-3 p-3 bg-[#090e1c] rounded-xl border border-cyber-border/50 relative overflow-hidden group w-full">
            <div className="text-[10px] text-cyber-blue font-mono flex items-center justify-between uppercase font-bold mb-1.5">
              <span className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
                {t('ai_status')}
              </span>
              <span className="text-cyber-green text-[10px] font-mono">99.98%</span>
            </div>
            <div className="flex items-center justify-between text-[11px] text-gray-400 font-mono">
              <span>SOC Core v2.4</span>
              <span className="text-[9px] text-cyber-blue bg-cyber-blue/10 px-1.5 py-0.5 rounded border border-cyber-blue/20">
                18ms
              </span>
            </div>
          </div>
        ) : (
          <div 
            title="AI Engine Status: Operational (99.98%)"
            className="mt-3 w-10 h-10 rounded-xl bg-[#090e1c] border border-cyber-border/50 flex items-center justify-center cursor-help text-cyber-green relative group"
          >
            <span className="w-2.5 h-2.5 rounded-full bg-cyber-green animate-pulse" />
          </div>
        )}
      </aside>

      {/* ========================================================
          2. MAIN CONTENT WRAPPER & DESKTOP TOP NAVIGATION BAR
         ======================================================== */}
      <div className="flex-1 flex flex-col z-10 h-full overflow-hidden relative min-w-0">
        {/* Top Header Bar for Desktop Computers & Mobile */}
        <header className="h-16 flex-shrink-0 border-b border-cyber-border/40 bg-[#070b14]/90 backdrop-blur-xl flex items-center justify-between px-3 sm:px-6 z-20 shadow-md">
          {/* Left: Mobile menu toggle + Breadcrumbs & Active Title */}
          <div className="flex items-center gap-3 min-w-0">
            {/* Mobile Hamburger Toggle Button (< md) */}
            <button
              onClick={() => setIsMobileMenuOpen(true)}
              className="md:hidden w-10 h-10 rounded-xl bg-white/5 border border-cyber-border/60 flex items-center justify-center text-cyber-blue hover:bg-cyber-blue/15 transition-all shrink-0 active:scale-95 cursor-pointer"
              aria-label="Open Navigation Menu"
            >
              <Menu className="w-5 h-5" />
            </button>

            {/* Mobile Brand Logo (< md) */}
            <div className="md:hidden flex items-center gap-2 shrink-0 mr-1">
              <div className="w-6 h-6 rounded-lg bg-cyber-blue/15 border border-cyber-blue/40 flex items-center justify-center text-cyber-blue">
                <ShieldAlert className="w-3.5 h-3.5" />
              </div>
            </div>

            {/* Desktop Breadcrumbs Hierarchy */}
            <div className="flex items-center gap-2 truncate">
              <span className="hidden sm:inline-block w-1.5 h-5 bg-cyber-blue rounded shadow-[0_0_8px_var(--color-cyber-blue-glow)]" />
              
              <div className="hidden lg:flex items-center gap-2 text-xs font-mono text-gray-400">
                <span className="hover:text-white cursor-pointer transition-colors" onClick={() => handleNavClick('dashboard')}>
                  NEUROSHIELD
                </span>
                <ChevronRight className="w-3 h-3 text-gray-600" />
                <span className="text-gray-400 font-bold uppercase tracking-wider">
                  {activeItem.category === 'CORE' ? 'OPERATIONS' : activeItem.category === 'AI_INTEL' ? 'AI INTEL' : 'SYSTEM'}
                </span>
                <ChevronRight className="w-3 h-3 text-gray-600" />
              </div>

              <h1 className="text-sm sm:text-base lg:text-lg font-bold font-sans tracking-wide uppercase text-white truncate drop-shadow-[0_0_8px_rgba(255,255,255,0.2)] flex items-center gap-2">
                <span>{t(activeItem.name)}</span>
                {activeItem.badge && (
                  <span className="hidden sm:inline-block text-[9px] font-mono px-2 py-0.5 rounded-full bg-cyber-blue/15 text-cyber-blue border border-cyber-blue/30 font-bold">
                    {activeItem.badge}
                  </span>
                )}
              </h1>
            </div>
          </div>

          {/* Right Controls: Quick Search, Security Badges, Fullscreen, Language, Notifications, User Profile */}
          <div className="flex items-center gap-2 sm:gap-3 shrink-0">
            {/* Live Telemetry Status Chips (Visible on large computer monitors) */}
            <div className="hidden xl:flex items-center gap-2">
              <div className="text-[10px] uppercase font-bold font-mono text-cyber-green flex items-center gap-1.5 border border-cyber-green/30 bg-cyber-green/10 px-2.5 py-1 rounded-full shadow-[0_0_8px_var(--color-cyber-green-glow)]">
                <div className="w-1.5 h-1.5 bg-cyber-green rounded-full animate-pulse" />
                {t('system_secure')}
              </div>
              <div className="text-[10px] uppercase font-bold font-mono text-cyber-blue flex items-center gap-1.5 border border-cyber-blue/30 bg-cyber-blue/10 px-2.5 py-1 rounded-full shadow-[0_0_8px_var(--color-cyber-blue-glow)]">
                <Activity className="w-3 h-3" />
                {t('ai_models_active')}
              </div>
            </div>

            {/* Global Search Bar Trigger for Computers */}
            <button
              onClick={() => setIsCommandPaletteOpen(true)}
              className="hidden sm:flex items-center gap-2.5 bg-[#0a0f1c] hover:bg-[#0d1424] px-3 py-1.5 rounded-xl border border-cyber-border/60 hover:border-cyber-blue/50 text-gray-400 hover:text-white transition-all text-xs font-mono w-44 md:w-56 lg:w-64 justify-between cursor-pointer"
            >
              <div className="flex items-center gap-2 truncate">
                <Search className="w-3.5 h-3.5 text-gray-500 shrink-0" />
                <span className="truncate text-gray-400">Search or jump to...</span>
              </div>
              <kbd className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/5 text-gray-400 border border-white/10 shrink-0">
                ⌘K
              </kbd>
            </button>

            {/* Fullscreen Workstation Toggle (Desktop Computers) */}
            <button
              onClick={toggleFullscreen}
              title={isFullscreen ? "Exit Fullscreen" : "Fullscreen SOC Mode (F11)"}
              className="hidden sm:flex w-9 h-9 rounded-xl bg-white/5 border border-cyber-border/60 text-gray-300 hover:text-white hover:border-cyber-blue/50 transition-all items-center justify-center cursor-pointer"
            >
              {isFullscreen ? <Minimize2 className="w-4 h-4 text-cyber-blue" /> : <Maximize2 className="w-4 h-4" />}
            </button>

            {/* Language Switcher Dropdown */}
            <div className="relative">
              <button 
                onClick={() => {
                  setShowLangDropdown(!showLangDropdown);
                  setShowNotifications(false);
                }}
                className="h-9 px-2.5 rounded-xl bg-white/5 border border-cyber-border/60 text-gray-300 hover:text-white hover:border-cyber-blue/50 transition-all flex items-center gap-1.5 text-xs font-mono cursor-pointer"
                aria-label="Change Language"
              >
                <Languages className="w-4 h-4 text-cyber-blue shrink-0" />
                <span className="uppercase font-bold">{language}</span>
              </button>

              {showLangDropdown && (
                <div className="absolute right-0 mt-2 w-44 bg-[#090e1c] border border-cyber-blue/40 rounded-2xl shadow-2xl overflow-hidden z-50 p-1.5 animate-in fade-in zoom-in-95">
                  <div className="px-3 py-1.5 text-[10px] font-mono text-gray-400 uppercase border-b border-white/5">
                    Select Language
                  </div>
                  <button 
                    onClick={() => { setLanguage('en'); setShowLangDropdown(false); }}
                    className={cn("w-full text-left px-3 py-2 text-xs rounded-xl flex items-center justify-between transition-colors cursor-pointer", language === 'en' ? "bg-cyber-blue/15 text-cyber-blue font-bold" : "text-gray-300 hover:bg-white/5")}
                  >
                    <span>English (EN)</span>
                    {language === 'en' && <Check className="w-3.5 h-3.5" />}
                  </button>
                  <button 
                    onClick={() => { setLanguage('hi'); setShowLangDropdown(false); }}
                    className={cn("w-full text-left px-3 py-2 text-xs rounded-xl flex items-center justify-between transition-colors cursor-pointer", language === 'hi' ? "bg-cyber-blue/15 text-cyber-blue font-bold" : "text-gray-300 hover:bg-white/5")}
                  >
                    <span>Hindi (हिन्दी)</span>
                    {language === 'hi' && <Check className="w-3.5 h-3.5" />}
                  </button>
                  <button 
                    onClick={() => { setLanguage('te'); setShowLangDropdown(false); }}
                    className={cn("w-full text-left px-3 py-2 text-xs rounded-xl flex items-center justify-between transition-colors cursor-pointer", language === 'te' ? "bg-cyber-blue/15 text-cyber-blue font-bold" : "text-gray-300 hover:bg-white/5")}
                  >
                    <span>Telugu (తెలుగు)</span>
                    {language === 'te' && <Check className="w-3.5 h-3.5" />}
                  </button>
                </div>
              )}
            </div>

            {/* Notification Bell with Incident Popover */}
            <div className="relative">
              <button 
                onClick={() => {
                  setShowNotifications(!showNotifications);
                  setShowLangDropdown(false);
                }}
                className="w-9 h-9 rounded-xl bg-white/5 border border-cyber-border/60 text-gray-300 hover:text-white hover:border-cyber-blue/50 transition-all flex items-center justify-center relative cursor-pointer"
                aria-label="View notifications"
              >
                <Bell className="w-4 h-4" />
                <span className="absolute -top-1 -right-1 flex items-center justify-center w-4 h-4 bg-cyber-red rounded-full text-[9px] text-white font-bold font-mono shadow-[0_0_8px_rgba(255,0,85,0.6)]">
                  3
                </span>
              </button>

              {showNotifications && (
                <div className="absolute right-0 mt-2 w-80 max-w-[90vw] bg-[#090e1c] border border-cyber-border/80 rounded-2xl shadow-2xl overflow-hidden z-50 animate-in fade-in zoom-in-95">
                  <div className="p-3 bg-white/5 border-b border-white/10 flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-white uppercase flex items-center gap-1.5">
                      <ShieldAlert className="w-3.5 h-3.5 text-cyber-red" />
                      Active SOC Incidents (3)
                    </span>
                    <button 
                      onClick={() => handleNavClick('alerts')} 
                      className="text-[10px] font-mono text-cyber-blue hover:underline cursor-pointer"
                    >
                      {t('view_all')}
                    </button>
                  </div>
                  <div className="divide-y divide-white/5 text-xs">
                    <div 
                      onClick={() => handleNavClick('alerts')}
                      className="p-3 hover:bg-white/5 cursor-pointer transition-colors space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[10px] text-cyber-red font-bold">INC-2024-0891</span>
                        <span className="text-[10px] text-gray-500">10m ago</span>
                      </div>
                      <div className="text-white text-[11px] font-medium">Spear Phishing / BEC Detected</div>
                      <div className="text-[10px] text-gray-400 font-mono truncate">invoice-secure@paypal-update.com</div>
                    </div>
                    <div 
                      onClick={() => handleNavClick('alerts')}
                      className="p-3 hover:bg-white/5 cursor-pointer transition-colors space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[10px] text-cyber-red font-bold">INC-2024-0890</span>
                        <span className="text-[10px] text-gray-500">25m ago</span>
                      </div>
                      <div className="text-white text-[11px] font-medium">Credential Harvester Active</div>
                      <div className="text-[10px] text-gray-400 font-mono truncate">verification-doc.com</div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* SOC Admin User Profile */}
            <div className="flex items-center gap-2 pl-1 sm:pl-2 border-l border-white/10">
              <div className="hidden md:flex flex-col text-right justify-center leading-none">
                <span className="text-xs font-bold text-white font-mono">{t('soc_admin')}</span>
                <span className="text-[9px] text-cyber-green font-mono flex items-center justify-end gap-1 mt-0.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyber-green" />
                  {t('online')}
                </span>
              </div>
              <div 
                onClick={() => handleNavClick('settings')}
                title="SOC Administrator Profile & Settings"
                className="w-9 h-9 rounded-xl border border-cyber-border/60 bg-white/5 hover:bg-cyber-blue/15 hover:border-cyber-blue/50 flex items-center justify-center text-cyber-blue shadow-sm cursor-pointer transition-all"
              >
                <User className="w-4 h-4" />
              </div>
            </div>
          </div>
        </header>

        {/* Page Content Viewport with Responsive Padding */}
        <div className={cn(
          "flex-1 overflow-y-auto overflow-x-hidden flex flex-col min-h-0",
          // On mobile (< md) add bottom padding for mobile dock, on computers (md+) no bottom dock needed!
          (activeTab === 'wave' || activeTab === 'scanner') 
            ? "p-0 pb-20 md:pb-0" 
            : "p-3.5 sm:p-5 md:p-6 pb-24 md:pb-6"
        )}>
          {children}
        </div>
      </div>

      {/* ========================================================
          3. COMMAND PALETTE MODAL (Cmd+K / Ctrl+K for Computers)
         ======================================================== */}
      <AnimatePresence>
        {isCommandPaletteOpen && (
          <div className="fixed inset-0 z-[150] flex items-start justify-center pt-20 px-4">
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => {
                setIsCommandPaletteOpen(false);
                setSearchQuery('');
              }}
              className="fixed inset-0 bg-black/80 backdrop-blur-md"
            />

            {/* Modal Box */}
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: -10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: -10 }}
              transition={{ duration: 0.15, ease: 'easeOut' }}
              className="relative w-full max-w-2xl bg-[#090e1c] border border-cyber-blue/50 rounded-2xl shadow-[0_0_50px_rgba(0,243,255,0.2)] overflow-hidden flex flex-col z-10"
            >
              {/* Search Input */}
              <div className="p-4 border-b border-cyber-border/60 flex items-center gap-3 bg-[#0a0f1e]">
                <Search className="w-5 h-5 text-cyber-blue shrink-0" />
                <input
                  ref={searchInputRef}
                  type="text"
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setSelectedIndex(0);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'ArrowDown') {
                      e.preventDefault();
                      setSelectedIndex(prev => (prev + 1) % Math.max(1, filteredNavItems.length));
                    } else if (e.key === 'ArrowUp') {
                      e.preventDefault();
                      setSelectedIndex(prev => (prev - 1 + filteredNavItems.length) % Math.max(1, filteredNavItems.length));
                    } else if (e.key === 'Enter') {
                      e.preventDefault();
                      if (filteredNavItems[selectedIndex]) {
                        handleNavClick(filteredNavItems[selectedIndex].id);
                      }
                    }
                  }}
                  placeholder="Type a module name, feature, or command..."
                  className="flex-1 bg-transparent text-sm text-white placeholder:text-gray-500 focus:outline-none font-mono"
                />
                <button
                  onClick={() => {
                    setIsCommandPaletteOpen(false);
                    setSearchQuery('');
                  }}
                  className="px-2 py-1 rounded-lg bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white text-xs font-mono border border-white/10"
                >
                  ESC
                </button>
              </div>

              {/* Navigation Items List */}
              <div className="max-h-[380px] overflow-y-auto p-2 space-y-1 custom-scrollbar">
                <div className="px-3 py-1.5 text-[10px] font-mono font-bold text-gray-400 uppercase tracking-wider flex items-center justify-between">
                  <span>AVAILABLE MODULES ({filteredNavItems.length})</span>
                  <span>PRESS ENTER ↵ TO JUMP</span>
                </div>

                {filteredNavItems.map((item, index) => {
                  const Icon = item.icon;
                  const isSelected = index === selectedIndex;
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => handleNavClick(item.id)}
                      onMouseEnter={() => setSelectedIndex(index)}
                      className={cn(
                        "w-full px-3.5 py-3 rounded-xl flex items-center justify-between text-left transition-all cursor-pointer",
                        isSelected 
                          ? "bg-cyber-blue/15 border border-cyber-blue/40 text-white shadow-[0_0_15px_rgba(0,243,255,0.1)]" 
                          : "hover:bg-white/5 border border-transparent text-gray-300"
                      )}
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <div className={cn(
                          "w-8 h-8 rounded-lg flex items-center justify-center shrink-0",
                          isSelected ? "bg-cyber-blue text-black" : "bg-white/5 text-cyber-blue"
                        )}>
                          <Icon className="w-4 h-4" />
                        </div>
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono font-bold uppercase text-white truncate">
                              {t(item.name)}
                            </span>
                            {item.badge && (
                              <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 font-bold">
                                {item.badge}
                              </span>
                            )}
                            {isActive && (
                              <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                                ACTIVE
                              </span>
                            )}
                          </div>
                          {item.description && (
                            <p className="text-[11px] text-gray-400 font-sans truncate mt-0.5">
                              {item.description}
                            </p>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        <span className="text-[10px] font-mono text-gray-500 uppercase px-2 py-0.5 rounded bg-black/40 border border-white/5">
                          {item.category}
                        </span>
                        {isSelected && (
                          <CornerDownLeft className="w-3.5 h-3.5 text-cyber-blue" />
                        )}
                      </div>
                    </button>
                  );
                })}

                {filteredNavItems.length === 0 && (
                  <div className="p-8 text-center text-gray-500 font-mono text-xs">
                    No matching modules found for "{searchQuery}"
                  </div>
                )}
              </div>

              {/* Command Palette Footer */}
              <div className="p-3 bg-[#060a14] border-t border-white/5 flex items-center justify-between text-[11px] font-mono text-gray-400">
                <div className="flex items-center gap-3">
                  <span className="flex items-center gap-1">
                    <kbd className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-[10px]">↑</kbd>
                    <kbd className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-[10px]">↓</kbd>
                    <span>Navigate</span>
                  </span>
                  <span className="flex items-center gap-1">
                    <kbd className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-[10px]">↵</kbd>
                    <span>Select</span>
                  </span>
                </div>
                <div className="flex items-center gap-1">
                  <span>Toggle Sidebar:</span>
                  <kbd className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-[10px]">Ctrl+B</kbd>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ========================================================
          4. MOBILE SLIDE-OUT DRAWER (For phone screens < md)
         ======================================================== */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsMobileMenuOpen(false)}
              className="fixed inset-0 bg-black/80 backdrop-blur-md z-[90] md:hidden"
            />

            <motion.aside
              initial={{ x: '-100%' }}
              animate={{ x: 0 }}
              exit={{ x: '-100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 280 }}
              className="fixed top-0 bottom-0 left-0 w-80 max-w-[85vw] bg-[#070b14] border-r border-cyber-border/60 z-[100] flex flex-col p-5 shadow-2xl md:hidden"
            >
              {/* Drawer Header */}
              <div className="flex items-center justify-between pb-4 border-b border-white/10 mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-xl bg-cyber-blue/15 border border-cyber-blue/40 flex items-center justify-center text-cyber-blue">
                    <ShieldAlert className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="font-extrabold text-sm tracking-widest text-white">NEUROSHIELD</div>
                    <div className="text-[8px] font-mono text-cyber-blue tracking-widest uppercase">AI SECURITY GATEWAY</div>
                  </div>
                </div>
                <button
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-gray-400 hover:text-white cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Drawer Navigation Links */}
              <div className="flex-1 overflow-y-auto space-y-4 custom-scrollbar pr-1">
                {/* Core */}
                <div className="space-y-1">
                  <div className="text-[10px] font-mono text-gray-500 uppercase tracking-widest px-2 mb-1">
                    {t('operations')}
                  </div>
                  {navItems.filter(i => i.category === 'CORE').map((item) => {
                    const Icon = item.icon;
                    const isActive = activeTab === item.id;
                    return (
                      <button
                        key={item.id}
                        onClick={() => handleNavClick(item.id)}
                        className={cn(
                          "w-full min-h-[44px] flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-mono uppercase tracking-wider transition-all cursor-pointer",
                          isActive 
                            ? "bg-cyber-blue text-black font-bold shadow-[0_0_15px_rgba(0,243,255,0.4)]" 
                            : "text-gray-300 hover:bg-white/5"
                        )}
                      >
                        <div className="flex items-center gap-3">
                          <Icon className={cn("w-4 h-4", isActive ? "text-black" : "text-cyber-blue")} />
                          <span>{t(item.name)}</span>
                        </div>
                        {item.badge && (
                          <span className={cn("text-[9px] px-2 py-0.5 rounded-full font-bold", isActive ? "bg-black text-cyber-blue" : "bg-white/10 text-gray-300")}>
                            {item.badge}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>

                {/* AI Intel */}
                <div className="space-y-1">
                  <div className="text-[10px] font-mono text-gray-500 uppercase tracking-widest px-2 mb-1">
                    AI INTELLIGENCE
                  </div>
                  {navItems.filter(i => i.category === 'AI_INTEL').map((item) => {
                    const Icon = item.icon;
                    const isActive = activeTab === item.id;
                    return (
                      <button
                        key={item.id}
                        onClick={() => handleNavClick(item.id)}
                        className={cn(
                          "w-full min-h-[44px] flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-mono uppercase tracking-wider transition-all cursor-pointer",
                          isActive 
                            ? "bg-cyber-blue text-black font-bold shadow-[0_0_15px_rgba(0,243,255,0.4)]" 
                            : "text-gray-300 hover:bg-white/5"
                        )}
                      >
                        <div className="flex items-center gap-3">
                          <Icon className={cn("w-4 h-4", isActive ? "text-black" : "text-cyber-blue")} />
                          <span>{t(item.name)}</span>
                        </div>
                        {item.badge && (
                          <span className={cn("text-[9px] px-2 py-0.5 rounded-full font-bold", isActive ? "bg-black text-cyber-blue" : "bg-white/10 text-gray-300")}>
                            {item.badge}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>

                {/* Platform */}
                <div className="space-y-1">
                  <div className="text-[10px] font-mono text-gray-500 uppercase tracking-widest px-2 mb-1">
                    SYSTEM &amp; SETTINGS
                  </div>
                  {navItems.filter(i => i.category === 'PLATFORM').map((item) => {
                    const Icon = item.icon;
                    const isActive = activeTab === item.id;
                    return (
                      <button
                        key={item.id}
                        onClick={() => handleNavClick(item.id)}
                        className={cn(
                          "w-full min-h-[44px] flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-mono uppercase tracking-wider transition-all cursor-pointer",
                          isActive 
                            ? "bg-cyber-blue text-black font-bold shadow-[0_0_15px_rgba(0,243,255,0.4)]" 
                            : "text-gray-300 hover:bg-white/5"
                        )}
                      >
                        <div className="flex items-center gap-3">
                          <Icon className={cn("w-4 h-4", isActive ? "text-black" : "text-cyber-blue")} />
                          <span>{t(item.name)}</span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Drawer Footer */}
              <div className="pt-4 border-t border-white/10 space-y-3 mt-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-gray-400">LANGUAGE</span>
                  <div className="flex gap-1.5">
                    <button
                      onClick={() => setLanguage('en')}
                      className={cn("px-2 py-1 rounded text-[10px] font-mono font-bold cursor-pointer", language === 'en' ? "bg-cyber-blue text-black" : "bg-white/5 text-gray-400")}
                    >
                      EN
                    </button>
                    <button
                      onClick={() => setLanguage('hi')}
                      className={cn("px-2 py-1 rounded text-[10px] font-mono font-bold cursor-pointer", language === 'hi' ? "bg-cyber-blue text-black" : "bg-white/5 text-gray-400")}
                    >
                      HI
                    </button>
                    <button
                      onClick={() => setLanguage('te')}
                      className={cn("px-2 py-1 rounded text-[10px] font-mono font-bold cursor-pointer", language === 'te' ? "bg-cyber-blue text-black" : "bg-white/5 text-gray-400")}
                    >
                      TE
                    </button>
                  </div>
                </div>
                <div className="flex items-center justify-between text-[10px] font-mono text-cyber-green bg-cyber-green/10 border border-cyber-green/30 p-2 rounded-xl">
                  <span className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
                    SOC ENGINES OPERATIONAL
                  </span>
                  <span>99.9%</span>
                </div>
              </div>
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      {/* ========================================================
          5. MOBILE DOCKED BOTTOM NAVIGATION BAR (< md ONLY)
             Hidden on desktop & laptops so it doesn't clutter computers!
         ======================================================== */}
      <nav className="md:hidden fixed bottom-0 left-0 right-0 z-40 bg-[#070b14]/95 backdrop-blur-2xl border-t border-cyber-border/60 px-2 py-1.5 shadow-[0_-10px_25px_rgba(0,0,0,0.8)] safe-bottom">
        <div className="flex items-center justify-around">
          {/* 1. Dashboard */}
          <button
            onClick={() => handleNavClick('dashboard')}
            className={cn(
              "flex flex-col items-center justify-center py-1 px-3 rounded-xl transition-all min-w-[56px] min-h-[44px] cursor-pointer",
              activeTab === 'dashboard' ? "text-cyber-blue" : "text-gray-400 hover:text-gray-200"
            )}
          >
            <LayoutDashboard className="w-5 h-5" />
            <span className="text-[10px] font-mono font-bold mt-1 tracking-wider">DASH</span>
          </button>

          {/* 2. Threat Scanner */}
          <button
            onClick={() => handleNavClick('scanner')}
            className={cn(
              "flex flex-col items-center justify-center py-1 px-3 rounded-xl transition-all min-w-[56px] min-h-[44px] cursor-pointer",
              activeTab === 'scanner' ? "text-cyber-blue" : "text-gray-400 hover:text-gray-200"
            )}
          >
            <ShieldAlert className="w-5 h-5" />
            <span className="text-[10px] font-mono font-bold mt-1 tracking-wider">SCAN</span>
          </button>

          {/* 3. Phishing / RFC 5322 Forensics */}
          <button
            onClick={() => handleNavClick('phishing')}
            className={cn(
              "flex flex-col items-center justify-center py-1 px-3 rounded-xl transition-all min-w-[56px] min-h-[44px] cursor-pointer",
              activeTab === 'phishing' ? "text-cyber-blue" : "text-gray-400 hover:text-gray-200"
            )}
          >
            <Mail className="w-5 h-5" />
            <span className="text-[10px] font-mono font-bold mt-1 tracking-wider">INBOX</span>
          </button>

          {/* 4. Alerts */}
          <button
            onClick={() => handleNavClick('alerts')}
            className={cn(
              "flex flex-col items-center justify-center py-1 px-3 rounded-xl transition-all min-w-[56px] min-h-[44px] relative cursor-pointer",
              activeTab === 'alerts' ? "text-cyber-blue" : "text-gray-400 hover:text-gray-200"
            )}
          >
            <div className="relative">
              <Bell className="w-5 h-5" />
              <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-cyber-red animate-pulse" />
            </div>
            <span className="text-[10px] font-mono font-bold mt-1 tracking-wider">ALERTS</span>
          </button>

          {/* 5. More Menu */}
          <button
            onClick={() => setIsMobileMenuOpen(true)}
            className="flex flex-col items-center justify-center py-1 px-3 rounded-xl transition-all min-w-[56px] min-h-[44px] text-gray-400 hover:text-cyber-blue cursor-pointer"
          >
            <Menu className="w-5 h-5" />
            <span className="text-[10px] font-mono font-bold mt-1 tracking-wider">MENU</span>
          </button>
        </div>
      </nav>

      {/* Floating Action Button for AI Copilot (Visible on desktop & mobile) */}
      <AnimatePresence>
        {!showCopilot && (
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.8 }}
            className="fixed bottom-20 md:bottom-6 right-4 sm:right-6 z-[80]"
          >
            <button 
              onClick={() => setShowCopilot(true)}
              className="w-12 h-12 rounded-full bg-cyber-blue/15 border border-cyber-blue text-cyber-blue shadow-[0_0_20px_var(--color-cyber-blue-glow)] flex items-center justify-center hover:bg-cyber-blue/30 transition-all hover:scale-105 active:scale-95 group cursor-pointer"
              aria-label="Open AI Copilot"
            >
              <Bot className="w-6 h-6 group-hover:animate-pulse" />
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* AI Copilot Float Dialog */}
      <AnimatePresence>
        {showCopilot && (
          <motion.div 
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.95 }}
            className="fixed bottom-20 md:bottom-6 right-4 sm:right-6 w-[calc(100vw-2rem)] sm:w-[360px] z-[100] bg-[#090e1c] border border-cyber-blue/50 rounded-2xl flex flex-col shadow-2xl overflow-hidden"
          >
            <div className="p-3 px-4 border-b border-cyber-border/60 flex items-center justify-between bg-cyber-blue/10 font-mono font-bold text-xs">
              <div className="flex items-center gap-2 text-cyber-blue">
                <Bot className="w-4 h-4" />
                <span>NEUROSHIELD AI COPILOT</span>
              </div>
              <button 
                onClick={() => setShowCopilot(false)} 
                className="text-gray-400 hover:text-white transition-colors p-1 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-3.5 text-xs space-y-3 font-sans">
              <div className="bg-white/5 p-2.5 rounded-xl border border-white/5 text-gray-300 leading-relaxed text-xs">
                Real-time threat monitoring active across DNS DoH and RFC 5322 email vectors. What would you like to investigate?
              </div>
              <div className="flex gap-2">
                <input 
                  type="text"
                  placeholder="Ask about threats, indicators..."
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      handleNavClick('copilot');
                    }
                  }}
                  className="flex-1 bg-black/40 border border-cyber-border/80 rounded-xl px-3 py-2 text-xs text-white placeholder:text-gray-600 focus:outline-none focus:border-cyber-blue font-mono"
                />
                <button 
                  onClick={() => handleNavClick('copilot')}
                  className="px-3 bg-cyber-blue text-black rounded-xl font-bold font-mono text-xs flex items-center justify-center hover:bg-cyber-blue/90 cursor-pointer"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
