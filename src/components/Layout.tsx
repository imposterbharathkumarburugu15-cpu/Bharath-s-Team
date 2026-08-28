import React, { useState } from 'react';
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
  User, 
  Check, 
  ExternalLink,
  Sliders,
  Sparkles,
  Zap,
  Globe
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
}

const navItems: NavItem[] = [
  // CORE DEFENSE
  { name: 'dashboard', id: 'dashboard', icon: LayoutDashboard, category: 'CORE' },
  { name: 'scanner', id: 'scanner', icon: ShieldAlert, category: 'CORE', badge: 'LIVE' },
  { name: 'phishing', id: 'phishing', icon: Mail, category: 'CORE', badge: 'DoH' },
  { name: 'alerts', id: 'alerts', icon: Bell, category: 'CORE', badge: '3' },
  
  // AI INTELLIGENCE
  { name: 'voice', id: 'voice', icon: Mic, category: 'AI_INTEL', badge: 'AI' },
  { name: 'wave', id: 'wave', icon: Waves, category: 'AI_INTEL' },
  { name: 'graph', id: 'graph', icon: Network, category: 'AI_INTEL' },
  { name: 'copilot', id: 'copilot', icon: Bot, category: 'AI_INTEL' },
  
  // PLATFORM & SETTINGS
  { name: 'api', id: 'api', icon: Terminal, category: 'PLATFORM' },
  { name: 'settings', id: 'settings', icon: Settings, category: 'PLATFORM' },
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
  const [showCopilot, setShowCopilot] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showLangDropdown, setShowLangDropdown] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const { language, setLanguage, t } = useLanguage();

  const handleNavClick = (id: string) => {
    setActiveTab(id);
    setIsMobileMenuOpen(false);
    setShowNotifications(false);
    setShowLangDropdown(false);
  };

  const activeItem = navItems.find(n => n.id === activeTab) || navItems[0];

  return (
    <div className="flex h-screen w-full bg-[#050811] text-white overflow-hidden relative selection:bg-cyber-blue selection:text-black">
      {/* Background Cyber Grid */}
      <div className="bg-grid absolute inset-0 opacity-40 pointer-events-none" />
      <div className="absolute top-0 right-1/4 w-96 h-96 bg-cyber-blue/5 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-0 left-1/4 w-96 h-96 bg-cyber-purple/5 rounded-full blur-[120px] pointer-events-none" />

      {/* ========================================================
          1. DESKTOP SIDEBAR (Visible on lg and above)
         ======================================================== */}
      <aside className="hidden lg:flex w-64 xl:w-72 h-full flex-shrink-0 border-r border-cyber-border/40 bg-[#070b14]/90 backdrop-blur-2xl z-30 flex-col py-6 px-4 box-border shadow-[10px_0_30px_rgba(0,0,0,0.6)]">
        {/* Brand Header */}
        <div className="flex items-center gap-3.5 mb-8 px-2 relative">
          <div className="relative w-10 h-10 flex items-center justify-center shrink-0">
            {/* Hexagon Cyber Shield Logo */}
            <svg viewBox="0 0 100 100" className="w-full h-full text-cyber-blue drop-shadow-[0_0_10px_rgba(0,243,255,0.8)] fill-current transition-all duration-300 hover:scale-105">
              <polygon points="50 3 93 25 93 75 50 97 7 75 7 25" fill="none" stroke="currentColor" strokeWidth="4" />
              <polygon points="50 15 80 32 80 68 50 85 20 68 20 32" fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray="5 5" className="animate-[spin_12s_linear_infinite_reverse]" />
              <circle cx="50" cy="50" r="12" className="animate-pulse fill-cyber-blue/80" />
            </svg>
            <div className="absolute inset-0 rounded-full shadow-[0_0_20px_var(--color-cyber-blue-glow)] opacity-70 mix-blend-screen pointer-events-none" />
          </div>
          <div className="leading-none flex flex-col justify-center">
            <div className="font-extrabold text-base tracking-[0.2em] text-white font-sans flex items-center gap-1.5">
              NEUROSHIELD
            </div>
            <div className="text-[9px] text-cyber-blue tracking-[0.3em] font-mono mt-1 uppercase font-bold drop-shadow-[0_0_5px_var(--color-cyber-blue-glow)]">
              AI SOC GATEWAY
            </div>
          </div>
        </div>

        {/* Navigation List */}
        <div className="flex-1 overflow-y-auto space-y-6 custom-scrollbar pr-1">
          {/* Section: Core Defense */}
          <div className="space-y-1">
            <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#5e738c] mb-2 px-3 flex items-center gap-2 font-mono">
              <span>{t('operations')}</span>
              <div className="flex-1 h-[1px] bg-gradient-to-r from-cyber-border/40 to-transparent" />
            </div>
            {navItems.filter(i => i.category === 'CORE').map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleNavClick(item.id)}
                  className={cn(
                    "w-full flex items-center justify-between px-3.5 py-2.5 text-xs rounded-xl transition-all duration-200 group relative font-medium",
                    isActive 
                      ? "bg-gradient-to-r from-cyber-blue/20 to-cyber-blue/5 text-white border border-cyber-blue/40 shadow-[0_0_20px_rgba(0,243,255,0.15)]" 
                      : "text-gray-400 hover:bg-white/5 hover:text-white border border-transparent"
                  )}
                >
                  <div className="flex items-center gap-3">
                    <Icon className={cn(
                      "h-4 w-4 transition-colors",
                      isActive ? "text-cyber-blue drop-shadow-[0_0_6px_var(--color-cyber-blue-glow)]" : "text-gray-400 group-hover:text-cyber-blue"
                    )} />
                    <span className="uppercase text-[11px] font-mono tracking-wider">{t(item.name)}</span>
                  </div>
                  {item.badge && (
                    <span className={cn(
                      "text-[9px] font-mono px-1.5 py-0.5 rounded-full font-bold",
                      isActive ? "bg-cyber-blue text-black" : "bg-white/10 text-gray-400 group-hover:text-white"
                    )}>
                      {item.badge}
                    </span>
                  )}
                  {isActive && (
                    <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-5 bg-cyber-blue rounded-r shadow-[0_0_10px_var(--color-cyber-blue-glow)]" />
                  )}
                </button>
              );
            })}
          </div>

          {/* Section: AI Intelligence */}
          <div className="space-y-1">
            <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#5e738c] mb-2 px-3 flex items-center gap-2 font-mono">
              <span>AI INTELLIGENCE</span>
              <div className="flex-1 h-[1px] bg-gradient-to-r from-cyber-border/40 to-transparent" />
            </div>
            {navItems.filter(i => i.category === 'AI_INTEL').map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleNavClick(item.id)}
                  className={cn(
                    "w-full flex items-center justify-between px-3.5 py-2.5 text-xs rounded-xl transition-all duration-200 group relative font-medium",
                    isActive 
                      ? "bg-gradient-to-r from-cyber-blue/20 to-cyber-blue/5 text-white border border-cyber-blue/40 shadow-[0_0_20px_rgba(0,243,255,0.15)]" 
                      : "text-gray-400 hover:bg-white/5 hover:text-white border border-transparent"
                  )}
                >
                  <div className="flex items-center gap-3">
                    <Icon className={cn(
                      "h-4 w-4 transition-colors",
                      isActive ? "text-cyber-blue drop-shadow-[0_0_6px_var(--color-cyber-blue-glow)]" : "text-gray-400 group-hover:text-cyber-blue"
                    )} />
                    <span className="uppercase text-[11px] font-mono tracking-wider">{t(item.name)}</span>
                  </div>
                  {item.badge && (
                    <span className={cn(
                      "text-[9px] font-mono px-1.5 py-0.5 rounded-full font-bold",
                      isActive ? "bg-cyber-blue text-black" : "bg-white/10 text-gray-400 group-hover:text-white"
                    )}>
                      {item.badge}
                    </span>
                  )}
                  {isActive && (
                    <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-5 bg-cyber-blue rounded-r shadow-[0_0_10px_var(--color-cyber-blue-glow)]" />
                  )}
                </button>
              );
            })}
          </div>

          {/* Section: Platform */}
          <div className="space-y-1">
            <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#5e738c] mb-2 px-3 flex items-center gap-2 font-mono">
              <span>SYSTEM &amp; API</span>
              <div className="flex-1 h-[1px] bg-gradient-to-r from-cyber-border/40 to-transparent" />
            </div>
            {navItems.filter(i => i.category === 'PLATFORM').map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleNavClick(item.id)}
                  className={cn(
                    "w-full flex items-center justify-between px-3.5 py-2.5 text-xs rounded-xl transition-all duration-200 group relative font-medium",
                    isActive 
                      ? "bg-gradient-to-r from-cyber-blue/20 to-cyber-blue/5 text-white border border-cyber-blue/40 shadow-[0_0_20px_rgba(0,243,255,0.15)]" 
                      : "text-gray-400 hover:bg-white/5 hover:text-white border border-transparent"
                  )}
                >
                  <div className="flex items-center gap-3">
                    <Icon className={cn(
                      "h-4 w-4 transition-colors",
                      isActive ? "text-cyber-blue drop-shadow-[0_0_6px_var(--color-cyber-blue-glow)]" : "text-gray-400 group-hover:text-cyber-blue"
                    )} />
                    <span className="uppercase text-[11px] font-mono tracking-wider">{t(item.name)}</span>
                  </div>
                  {isActive && (
                    <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-5 bg-cyber-blue rounded-r shadow-[0_0_10px_var(--color-cyber-blue-glow)]" />
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* System Health Status Footer */}
        <div className="mt-4 p-3.5 bg-[#090e1c] rounded-2xl border border-cyber-border/50 relative overflow-hidden group">
          <div className="text-[10px] text-cyber-blue font-mono flex items-center justify-between uppercase font-bold mb-2">
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
              {t('ai_status')}
            </span>
            <span className="text-cyber-green text-[10px] font-mono">99.98%</span>
          </div>
          <div className="flex items-center justify-between text-xs text-gray-300 font-mono">
            <span>SOC Core v2.4</span>
            <span className="text-[10px] text-cyber-muted">LATENCY 18ms</span>
          </div>
        </div>
      </aside>

      {/* ========================================================
          2. MAIN CONTENT WRAPPER & TOP HEADER
         ======================================================== */}
      <div className="flex-1 flex flex-col z-10 h-full overflow-hidden relative min-w-0">
        {/* Top Header */}
        <header className="h-16 flex-shrink-0 border-b border-cyber-border/40 bg-[#070b14]/80 backdrop-blur-xl flex items-center justify-between px-3 sm:px-6 z-20 shadow-md">
          {/* Left: Mobile menu toggle + Active Tab Title */}
          <div className="flex items-center gap-3 min-w-0">
            {/* Mobile Hamburger Toggle Button */}
            <button
              onClick={() => setIsMobileMenuOpen(true)}
              className="lg:hidden w-10 h-10 rounded-xl bg-white/5 border border-cyber-border/60 flex items-center justify-center text-cyber-blue hover:bg-cyber-blue/15 transition-all shrink-0 active:scale-95"
              aria-label="Open Navigation Menu"
            >
              <Menu className="w-5 h-5" />
            </button>

            {/* Mobile Brand Logo */}
            <div className="lg:hidden flex items-center gap-2 shrink-0 mr-1">
              <div className="w-6 h-6 rounded-lg bg-cyber-blue/15 border border-cyber-blue/40 flex items-center justify-center text-cyber-blue">
                <ShieldAlert className="w-3.5 h-3.5" />
              </div>
            </div>

            {/* Active Tab Title with glowing accent */}
            <div className="flex items-center gap-2.5 truncate">
              <span className="hidden sm:block w-2 h-5 bg-cyber-blue rounded shadow-[0_0_8px_var(--color-cyber-blue-glow)]" />
              <h1 className="text-sm sm:text-lg font-bold font-sans tracking-wide uppercase text-white truncate drop-shadow-[0_0_8px_rgba(255,255,255,0.2)]">
                {t(activeItem.name)}
              </h1>
            </div>
          </div>

          {/* Right Controls: Security Status, Search, Language, Notifications, User */}
          <div className="flex items-center gap-2 sm:gap-4 shrink-0">
            {/* Security Status Badges (Hidden on mobile) */}
            <div className="hidden xl:flex items-center gap-2.5">
              <div className="text-[10px] uppercase font-bold font-mono text-cyber-green flex items-center gap-1.5 border border-cyber-green/30 bg-cyber-green/10 px-2.5 py-1 rounded-full shadow-[0_0_8px_var(--color-cyber-green-glow)]">
                <div className="w-1.5 h-1.5 bg-cyber-green rounded-full animate-pulse" />
                {t('system_secure')}
              </div>
              <div className="text-[10px] uppercase font-bold font-mono text-cyber-blue flex items-center gap-1.5 border border-cyber-blue/30 bg-cyber-blue/10 px-2.5 py-1 rounded-full shadow-[0_0_8px_var(--color-cyber-blue-glow)]">
                <Activity className="w-3 h-3" />
                {t('ai_models_active')}
              </div>
            </div>

            {/* Global Search Bar (Hidden on small mobile) */}
            <div className="hidden md:flex items-center gap-2 bg-[#0a0f1c] px-3 py-1.5 rounded-xl border border-cyber-border/60 text-gray-400 focus-within:border-cyber-blue focus-within:text-white transition-all w-48 lg:w-64">
              <Search className="w-3.5 h-3.5 text-gray-500 shrink-0" />
              <input 
                type="text" 
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={t('search_placeholder')} 
                className="bg-transparent text-xs focus:outline-none text-white w-full placeholder:text-gray-600 font-mono"
              />
              {searchQuery && (
                <button onClick={() => setSearchQuery('')} className="text-gray-500 hover:text-white">
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>

            {/* Language Switcher Dropdown */}
            <div className="relative">
              <button 
                onClick={() => {
                  setShowLangDropdown(!showLangDropdown);
                  setShowNotifications(false);
                }}
                className="h-9 px-2.5 rounded-xl bg-white/5 border border-cyber-border/60 text-gray-300 hover:text-white hover:border-cyber-blue/50 transition-all flex items-center gap-1.5 text-xs font-mono"
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
                    className={cn("w-full text-left px-3 py-2 text-xs rounded-xl flex items-center justify-between transition-colors", language === 'en' ? "bg-cyber-blue/15 text-cyber-blue font-bold" : "text-gray-300 hover:bg-white/5")}
                  >
                    <span>English (EN)</span>
                    {language === 'en' && <Check className="w-3.5 h-3.5" />}
                  </button>
                  <button 
                    onClick={() => { setLanguage('hi'); setShowLangDropdown(false); }}
                    className={cn("w-full text-left px-3 py-2 text-xs rounded-xl flex items-center justify-between transition-colors", language === 'hi' ? "bg-cyber-blue/15 text-cyber-blue font-bold" : "text-gray-300 hover:bg-white/5")}
                  >
                    <span>Hindi (हिन्दी)</span>
                    {language === 'hi' && <Check className="w-3.5 h-3.5" />}
                  </button>
                  <button 
                    onClick={() => { setLanguage('te'); setShowLangDropdown(false); }}
                    className={cn("w-full text-left px-3 py-2 text-xs rounded-xl flex items-center justify-between transition-colors", language === 'te' ? "bg-cyber-blue/15 text-cyber-blue font-bold" : "text-gray-300 hover:bg-white/5")}
                  >
                    <span>Telugu (తెలుగు)</span>
                    {language === 'te' && <Check className="w-3.5 h-3.5" />}
                  </button>
                </div>
              )}
            </div>

            {/* Notification Bell with Popover */}
            <div className="relative">
              <button 
                onClick={() => {
                  setShowNotifications(!showNotifications);
                  setShowLangDropdown(false);
                }}
                className="w-9 h-9 rounded-xl bg-white/5 border border-cyber-border/60 text-gray-300 hover:text-white hover:border-cyber-blue/50 transition-all flex items-center justify-center relative"
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
                      className="text-[10px] font-mono text-cyber-blue hover:underline"
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
              <div className="hidden sm:flex flex-col text-right justify-center leading-none">
                <span className="text-xs font-bold text-white font-mono">{t('soc_admin')}</span>
                <span className="text-[9px] text-cyber-green font-mono flex items-center justify-end gap-1 mt-0.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyber-green" />
                  {t('online')}
                </span>
              </div>
              <div className="w-9 h-9 rounded-xl border border-cyber-border/60 bg-white/5 flex items-center justify-center text-cyber-blue shadow-sm">
                <User className="w-4 h-4" />
              </div>
            </div>
          </div>
        </header>

        {/* Page Content Viewport */}
        <div className={cn(
          "flex-1 overflow-y-auto overflow-x-hidden flex flex-col min-h-0",
          (activeTab === 'wave' || activeTab === 'scanner') ? "p-0 pb-20 lg:pb-0" : "p-3.5 sm:p-5 md:p-6 pb-24 lg:pb-6"
        )}>
          {children}
        </div>
      </div>

      {/* ========================================================
          3. MOBILE SLIDE-OUT DRAWER (Full navigation on phone/tablet)
         ======================================================== */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsMobileMenuOpen(false)}
              className="fixed inset-0 bg-black/80 backdrop-blur-md z-[90] lg:hidden"
            />

            {/* Drawer */}
            <motion.aside
              initial={{ x: '-100%' }}
              animate={{ x: 0 }}
              exit={{ x: '-100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 280 }}
              className="fixed top-0 bottom-0 left-0 w-80 max-w-[85vw] bg-[#070b14] border-r border-cyber-border/60 z-[100] flex flex-col p-5 shadow-2xl lg:hidden"
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
                  className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-gray-400 hover:text-white"
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
                          "w-full min-h-[44px] flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-mono uppercase tracking-wider transition-all",
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
                          "w-full min-h-[44px] flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-mono uppercase tracking-wider transition-all",
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
                          "w-full min-h-[44px] flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-mono uppercase tracking-wider transition-all",
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

              {/* Drawer Footer: Language quick switch */}
              <div className="pt-4 border-t border-white/10 space-y-3 mt-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-gray-400">LANGUAGE</span>
                  <div className="flex gap-1.5">
                    <button
                      onClick={() => setLanguage('en')}
                      className={cn("px-2 py-1 rounded text-[10px] font-mono font-bold", language === 'en' ? "bg-cyber-blue text-black" : "bg-white/5 text-gray-400")}
                    >
                      EN
                    </button>
                    <button
                      onClick={() => setLanguage('hi')}
                      className={cn("px-2 py-1 rounded text-[10px] font-mono font-bold", language === 'hi' ? "bg-cyber-blue text-black" : "bg-white/5 text-gray-400")}
                    >
                      HI
                    </button>
                    <button
                      onClick={() => setLanguage('te')}
                      className={cn("px-2 py-1 rounded text-[10px] font-mono font-bold", language === 'te' ? "bg-cyber-blue text-black" : "bg-white/5 text-gray-400")}
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
          4. MOBILE DOCKED BOTTOM NAVIGATION BAR (lg:hidden)
         ======================================================== */}
      <nav className="lg:hidden fixed bottom-0 left-0 right-0 z-40 bg-[#070b14]/95 backdrop-blur-2xl border-t border-cyber-border/60 px-2 py-1.5 shadow-[0_-10px_25px_rgba(0,0,0,0.8)] safe-bottom">
        <div className="flex items-center justify-around">
          {/* 1. Dashboard */}
          <button
            onClick={() => handleNavClick('dashboard')}
            className={cn(
              "flex flex-col items-center justify-center py-1 px-3 rounded-xl transition-all min-w-[56px] min-h-[44px]",
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
              "flex flex-col items-center justify-center py-1 px-3 rounded-xl transition-all min-w-[56px] min-h-[44px]",
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
              "flex flex-col items-center justify-center py-1 px-3 rounded-xl transition-all min-w-[56px] min-h-[44px]",
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
              "flex flex-col items-center justify-center py-1 px-3 rounded-xl transition-all min-w-[56px] min-h-[44px] relative",
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
            className="flex flex-col items-center justify-center py-1 px-3 rounded-xl transition-all min-w-[56px] min-h-[44px] text-gray-400 hover:text-cyber-blue"
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
            className="fixed bottom-20 lg:bottom-6 right-4 sm:right-6 z-[80]"
          >
            <button 
              onClick={() => setShowCopilot(true)}
              className="w-12 h-12 rounded-full bg-cyber-blue/15 border border-cyber-blue text-cyber-blue shadow-[0_0_20px_var(--color-cyber-blue-glow)] flex items-center justify-center hover:bg-cyber-blue/30 transition-all hover:scale-105 active:scale-95 group"
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
            className="fixed bottom-20 lg:bottom-6 right-4 sm:right-6 w-[calc(100vw-2rem)] sm:w-[340px] z-[100] bg-[#090e1c] border border-cyber-blue/50 rounded-2xl flex flex-col shadow-2xl overflow-hidden"
          >
            <div className="p-3 px-4 border-b border-cyber-border/60 flex items-center justify-between bg-cyber-blue/10 font-mono font-bold text-xs">
              <div className="flex items-center gap-2 text-cyber-blue">
                <Bot className="w-4 h-4" />
                <span>NEUROSHIELD AI COPILOT</span>
              </div>
              <button 
                onClick={() => setShowCopilot(false)} 
                className="text-gray-400 hover:text-white transition-colors p-1"
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
                  className="flex-1 bg-black/40 border border-cyber-border/80 rounded-xl px-3 py-2 text-xs text-white placeholder:text-gray-600 focus:outline-none focus:border-cyber-blue font-mono"
                />
                <button 
                  onClick={() => handleNavClick('copilot')}
                  className="px-3 bg-cyber-blue text-black rounded-xl font-bold font-mono text-xs flex items-center justify-center hover:bg-cyber-blue/90"
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
