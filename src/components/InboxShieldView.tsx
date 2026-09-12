import React, { useState, useMemo } from 'react';
import { 
  Laptop, Mail, Search, RefreshCw, ChevronDown, Check, 
  MoreVertical, ArrowRight, ShieldCheck, ShieldAlert, 
  ExternalLink, Terminal, Globe, Filter, LogIn
} from 'lucide-react';
import { InboxEmailItem } from '@/data/inboxEmails';
import { useLanguage } from '@/contexts/LanguageContext';

interface InboxShieldViewProps {
  emails: InboxEmailItem[];
  isLoading?: boolean;
  onRefresh?: () => void;
  onSelectEmailForAnalysis: (email: InboxEmailItem, initialTab?: 'forensics' | 'neural') => void;
  onOpenRfcLab?: () => void;
  onOpenDnsLookup?: () => void;
  onConnectGmail?: () => void;
  isAuthenticated?: boolean;
  userEmail?: string | null;
  hasMore?: boolean;
  isLoadingMore?: boolean;
  onLoadMore?: () => void;
}

export function InboxShieldView({
  emails,
  isLoading = false,
  onRefresh,
  onSelectEmailForAnalysis,
  onOpenRfcLab,
  onOpenDnsLookup,
  onConnectGmail,
  isAuthenticated = false,
  userEmail,
  hasMore = false,
  isLoadingMore = false,
  onLoadMore
}: InboxShieldViewProps) {
  const { t } = useLanguage();
  const [filterTab, setFilterTab] = useState<'all' | 'high' | 'suspicious' | 'safe'>('all');
  const [sortBy, setSortBy] = useState<'newest' | 'highest' | 'lowest' | 'oldest'>('newest');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [openMenuId, setOpenMenuId] = useState<string | null>(null);

  // Counts strictly from real emails received via Gmail API
  const highRiskCount = useMemo(() => emails.filter(e => e.score >= 71).length, [emails]);
  const suspiciousCount = useMemo(() => emails.filter(e => e.score >= 31 && e.score <= 70).length, [emails]);
  const safeCount = useMemo(() => emails.filter(e => e.score <= 30).length, [emails]);

  const displayTotal = emails.length;
  const displayHigh = highRiskCount;
  const displaySuspicious = suspiciousCount;
  const displaySafe = safeCount;

  // Filter and Sort logic
  const filteredEmails = useMemo(() => {
    let result = [...emails];

    // Filter tab
    if (filterTab === 'high') {
      result = result.filter(e => e.score >= 71);
    } else if (filterTab === 'suspicious') {
      result = result.filter(e => e.score >= 31 && e.score <= 70);
    } else if (filterTab === 'safe') {
      result = result.filter(e => e.score <= 30);
    }

    // Search
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(e => 
        e.senderName.toLowerCase().includes(q) ||
        e.senderEmail.toLowerCase().includes(q) ||
        e.subject.toLowerCase().includes(q) ||
        e.snippet.toLowerCase().includes(q) ||
        e.tags.some(t => t.text.toLowerCase().includes(q))
      );
    }

    // Sort
    if (sortBy === 'highest') {
      result.sort((a, b) => b.score - a.score);
    } else if (sortBy === 'lowest') {
      result.sort((a, b) => a.score - b.score);
    } else if (sortBy === 'oldest') {
      // reverse current order
      result.reverse();
    }
    // newest keeps default order

    return result;
  }, [emails, filterTab, searchQuery, sortBy]);

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => 
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  return (
    <div className="space-y-6">
      {/* 1. TOP HEADER (INBOX SHIELD + GMAIL SCANNER PIPELINE) */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-5 pb-1">
        {/* Left: Title & Subtitle */}
        <div className="flex items-center gap-4">
          <div className="w-13 h-13 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_25px_rgba(6,182,212,0.15)] shrink-0">
            <Laptop className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight font-mono">
              {t('inbox_shield_title')}
            </h1>
            <p className="text-xs sm:text-sm text-cyan-400/80 font-sans mt-0.5">
              {t('inbox_shield_subtitle')}
            </p>
          </div>
        </div>

        {/* Right: Gmail Scanner Pipeline Card matching screenshot */}
        <div className="bg-[#070d1e]/80 border border-cyber-border/40 rounded-2xl p-4 sm:p-5 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4 backdrop-blur-xl">
          <div className="flex items-center gap-3.5">
            {/* Google Gmail Icon */}
            <div className="w-11 h-11 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center shrink-0">
              <svg className="w-6 h-6" viewBox="0 0 24 24">
                <path fill="#EA4335" d="M24 5.457v13.909c0 .904-.732 1.636-1.636 1.636h-3.819V11.73L12 16.64l-6.545-4.91v9.272H1.636A1.636 1.636 0 0 1 0 19.366V5.457c0-2.023 2.309-3.178 3.927-1.964L12 9.545l8.073-6.052C21.69 2.28 24 3.434 24 5.457z"/>
              </svg>
            </div>
            <div className="space-y-0.5">
              <div className="flex items-center gap-2">
                <h3 className="text-xs sm:text-sm font-bold text-white font-mono">
                  {t('gmail_scanner_pipeline')}
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyber-blue/10 border border-cyber-blue/40 text-cyber-blue font-bold tracking-wider flex items-center gap-1.5 animate-pulse">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyber-blue" />
                  {t('analysis_active_badge')}
                </span>
              </div>
              <p className="text-[11px] text-gray-400 font-sans">
                {t('pipeline_desc')}
              </p>
              <div className="text-[11px] font-mono text-cyan-300/90 flex items-center gap-2 pt-0.5">
                <span className="text-emerald-400">✓</span> Context & Intent
                <span className="text-gray-500">+</span>
                <span className="text-amber-400">✓</span> Sensitive Data
                <span className="text-gray-500">+</span>
                <span className="text-cyan-400">✓</span> Action Protection
              </div>
            </div>
          </div>

          {/* Vertical Divider on md+ screens */}
          <div className="hidden md:block w-px h-12 bg-white/10" />

          {/* 4 Stat Metrics */}
          <div className="grid grid-cols-4 gap-3 sm:gap-5 shrink-0 text-center font-mono pt-2 md:pt-0 border-t md:border-t-0 border-white/5">
            <div>
              <div className="text-base sm:text-lg font-black text-white leading-tight">{displayTotal}</div>
              <div className="text-[10px] text-gray-400 uppercase tracking-wider">{t('stat_total_emails')}</div>
            </div>
            <div>
              <div className="text-base sm:text-lg font-black text-cyber-red leading-tight">{displayHigh}</div>
              <div className="text-[10px] text-cyber-red/80 uppercase tracking-wider font-bold">{t('stat_high_risk')}</div>
            </div>
            <div>
              <div className="text-base sm:text-lg font-black text-amber-400 leading-tight">{displaySuspicious}</div>
              <div className="text-[10px] text-amber-400/80 uppercase tracking-wider font-bold">{t('stat_suspicious')}</div>
            </div>
            <div>
              <div className="text-base sm:text-lg font-black text-cyber-green leading-tight">{displaySafe}</div>
              <div className="text-[10px] text-cyber-green/80 uppercase tracking-wider font-bold">{t('stat_safe')}</div>
            </div>
          </div>
        </div>
      </div>

      {/* 2. FILTER TABS & TOOLBAR */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pt-1">
        {/* Left: Filter Tabs matching screenshot */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 lg:pb-0 scrollbar-none font-mono text-xs font-bold">
          {/* All Emails */}
          <button
            onClick={() => setFilterTab('all')}
            className={`px-3.5 py-2 rounded-xl flex items-center gap-2 transition-all cursor-pointer whitespace-nowrap ${
              filterTab === 'all'
                ? 'bg-cyber-blue/15 text-cyber-blue border border-cyber-blue/50 shadow-[0_0_12px_rgba(0,240,255,0.25)]'
                : 'bg-white/5 text-gray-400 hover:text-white border border-white/5'
            }`}
          >
            <Mail className="w-3.5 h-3.5 text-cyber-blue" />
            <span>{t('all_emails_tab')} ({displayTotal})</span>
          </button>

          {/* High Risk */}
          <button
            onClick={() => setFilterTab('high')}
            className={`px-3.5 py-2 rounded-xl flex items-center gap-2 transition-all cursor-pointer whitespace-nowrap ${
              filterTab === 'high'
                ? 'bg-cyber-red/20 text-cyber-red border border-cyber-red/50 shadow-[0_0_12px_rgba(244,63,94,0.25)]'
                : 'bg-white/5 text-gray-400 hover:text-cyber-red border border-white/5'
            }`}
          >
            <span>{t('high_risk_tab')} ({displayHigh})</span>
          </button>

          {/* Suspicious */}
          <button
            onClick={() => setFilterTab('suspicious')}
            className={`px-3.5 py-2 rounded-xl flex items-center gap-2 transition-all cursor-pointer whitespace-nowrap ${
              filterTab === 'suspicious'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50 shadow-[0_0_12px_rgba(245,158,11,0.25)]'
                : 'bg-white/5 text-gray-400 hover:text-amber-300 border border-white/5'
            }`}
          >
            <span>{t('suspicious_tab')} ({displaySuspicious})</span>
          </button>

          {/* Safe */}
          <button
            onClick={() => setFilterTab('safe')}
            className={`px-3.5 py-2 rounded-xl flex items-center gap-2 transition-all cursor-pointer whitespace-nowrap ${
              filterTab === 'safe'
                ? 'bg-cyber-green/20 text-cyber-green border border-cyber-green/50 shadow-[0_0_12px_rgba(16,185,129,0.25)]'
                : 'bg-white/5 text-gray-400 hover:text-cyber-green border border-white/5'
            }`}
          >
            <span>{t('safe_tab')} ({displaySafe})</span>
          </button>
        </div>

        {/* Right: Search, Sort & Refresh */}
        <div className="flex flex-wrap items-center gap-2.5">

          {/* Search Bar */}
          <div className="relative flex-1 sm:w-60">
            <Search className="w-3.5 h-3.5 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={t('search_emails_placeholder')}
              className="w-full bg-[#070d1e] border border-white/10 rounded-xl pl-8 pr-3 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyber-blue/50 font-mono"
            />
          </div>

          {/* Sort Dropdown */}
          <div className="relative">
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="bg-[#080d1a] border border-white/10 rounded-xl px-3 py-1.5 text-xs text-gray-300 font-mono focus:outline-none focus:border-cyan-500/50 cursor-pointer appearance-none pr-7"
            >
              <option value="newest">{t('sort_newest')}</option>
              <option value="highest">{t('sort_highest')}</option>
              <option value="lowest">{t('sort_lowest')}</option>
              <option value="oldest">{t('sort_oldest')}</option>
            </select>
            <ChevronDown className="w-3.5 h-3.5 text-gray-400 absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          </div>

          {/* Refresh Button */}
          <button
            onClick={onRefresh}
            className="p-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-gray-300 hover:text-cyan-400 transition-all cursor-pointer"
            title={t('refresh_inbox_title')}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Connect Real Gmail Banner if not authenticated */}
      {!isAuthenticated && (
        <div className="bg-[#09101d] border border-cyan-500/30 rounded-2xl p-4 sm:p-5 shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0">
              <Mail className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-sm font-bold text-white font-mono">
                {t('connect_real_gmail_title')}
              </h4>
              <p className="text-xs text-gray-400 font-sans mt-0.5">
                {t('connect_real_gmail_desc')}
              </p>
            </div>
          </div>
          <button
            onClick={onConnectGmail}
            className="min-h-[44px] px-5 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-black font-mono text-xs font-bold uppercase tracking-wider flex items-center gap-2 cursor-pointer shadow-[0_0_15px_rgba(6,182,212,0.3)] transition-all active:scale-95 whitespace-nowrap"
          >
            <LogIn className="w-4 h-4" />
            <span>{t('connect_gmail_btn')}</span>
          </button>
        </div>
      )}

      {/* 3. EMAIL CARDS LIST */}
      {isLoading ? (
        <div className="bg-[#09101d] border border-white/5 rounded-2xl p-12 text-center space-y-3">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
          <h4 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
            {t('scanning_inbox_title')}
          </h4>
          <p className="text-xs text-gray-400 font-sans max-w-md mx-auto">
            {t('scanning_inbox_desc')}
          </p>
        </div>
      ) : filteredEmails.length === 0 ? (
        <div className="bg-[#09101d] border border-white/5 rounded-2xl p-10 text-center space-y-3">
          <Mail className="w-8 h-8 text-gray-500 mx-auto" />
          {!isAuthenticated ? (
            <>
              <h4 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                {t('gmail_not_connected_title')}
              </h4>
              <p className="text-xs text-gray-400 font-sans max-w-md mx-auto">
                {t('gmail_not_connected_desc')}
              </p>
              <button
                onClick={onConnectGmail}
                className="min-h-[44px] px-5 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-black font-mono text-xs font-bold uppercase tracking-wider inline-flex items-center gap-2 cursor-pointer shadow-md transition-all active:scale-95"
              >
                <LogIn className="w-4 h-4" />
                <span>{t('connect_gmail_btn')}</span>
              </button>
            </>
          ) : emails.length === 0 ? (
            <>
              <h4 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                {t('no_messages_gmail_title')}
              </h4>
              <p className="text-xs text-gray-400 font-sans max-w-md mx-auto">
                {t('connected_as')} <span className="text-white font-mono">{userEmail || 'Active User'}</span>. {t('click_to_fetch_gmail')}
              </p>
              <button
                onClick={onRefresh}
                className="min-h-[44px] px-5 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-black font-mono text-xs font-bold uppercase tracking-wider inline-flex items-center gap-2 cursor-pointer shadow-md transition-all active:scale-95"
              >
                <RefreshCw className="w-4 h-4" />
                <span>{t('fetch_gmail_btn')}</span>
              </button>
            </>
          ) : (
            <>
              <h4 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                {t('no_messages_match_filter')}
              </h4>
              <p className="text-xs text-gray-400 font-sans max-w-md mx-auto">
                {t('no_messages_match_desc')}
              </p>
              <button
                onClick={() => { setFilterTab('all'); setSearchQuery(''); }}
                className="min-h-[44px] px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-mono text-cyan-300 cursor-pointer"
              >
                {t('reset_filters_btn')}
              </button>
            </>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {filteredEmails.map((item) => {
            const isSelected = selectedIds.includes(item.id);
            const isHigh = item.score >= 71;
            const isSuspicious = item.score >= 31 && item.score <= 70;
            const isSafe = item.score <= 30;

            return (
              <div
                key={item.id}
                className="bg-[#070d1e]/80 hover:bg-[#0c142b]/90 border border-cyber-border/40 hover:border-cyber-blue/40 rounded-2xl p-4 sm:p-5 transition-all shadow-lg flex flex-col md:flex-row items-start md:items-center justify-between gap-4 group backdrop-blur-xl"
              >
                {/* Left: Checkbox + Status Dot + Avatar + Sender Info */}
                <div className="flex items-center gap-3.5 w-full md:w-60 lg:w-72 shrink-0">
                  {/* Selection Checkbox */}
                  <button 
                    onClick={() => toggleSelect(item.id)}
                    className="w-4 h-4 rounded border border-white/20 hover:border-cyber-blue flex items-center justify-center cursor-pointer shrink-0 transition-colors"
                  >
                    {isSelected && <Check className="w-3 h-3 text-cyber-blue" />}
                  </button>

                  {/* Status Indicator Dot */}
                  <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${
                    isHigh 
                      ? 'bg-cyber-red shadow-[0_0_8px_#f43f5e]' 
                      : isSuspicious 
                        ? 'bg-amber-400 shadow-[0_0_8px_#f59e0b]' 
                        : 'bg-cyber-green shadow-[0_0_8px_#10b981]'
                  }`} />

                  {/* Circular Avatar */}
                  <div className="w-9 h-9 rounded-full bg-white/5 border border-white/10 flex items-center justify-center font-mono font-bold text-white text-xs shrink-0 shadow-inner">
                    {item.avatarLetter}
                  </div>

                  {/* Sender Details */}
                  <div className="min-w-0 flex-1 space-y-0.5">
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs sm:text-sm font-bold text-white truncate group-hover:text-cyber-blue transition-colors font-sans">
                        {item.senderName}
                      </span>
                      {item.isVerified && (
                        <span className="w-3.5 h-3.5 rounded-full bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40 flex items-center justify-center text-[9px] shrink-0 font-bold" title={t('verified_sender_tooltip')}>
                          ✓
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-gray-400 font-mono truncate" title={item.senderEmail}>
                      {item.senderEmail}
                    </p>
                  </div>
                </div>

                {/* Middle: Subject + Preview Snippet + Threat Tags */}
                <div className="flex-1 min-w-0 space-y-1.5 w-full md:w-auto">
                  <h3 className="text-xs sm:text-sm font-semibold text-white tracking-tight truncate group-hover:text-white transition-colors" title={item.subject}>
                    {item.subject}
                  </h3>
                  <p className="text-xs text-gray-400 font-sans line-clamp-1">
                    {item.snippet}
                  </p>
                  
                  {/* Threat Tags / Pills matching screenshot */}
                  <div className="flex items-center gap-1.5 flex-wrap pt-0.5">
                    {item.tags.map((tag, idx) => (
                      <span
                        key={idx}
                        className={`text-[10px] font-mono px-2 py-0.5 rounded-md font-semibold tracking-wider ${
                          tag.type === 'red'
                            ? 'bg-cyber-red/15 text-cyber-red border border-cyber-red/30'
                            : tag.type === 'amber'
                              ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                              : 'bg-cyber-green/15 text-cyber-green border border-cyber-green/30'
                        }`}
                      >
                        {tag.text}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Right-Middle: Timestamp */}
                <div className="shrink-0 font-mono text-[11px] text-gray-400 whitespace-nowrap hidden lg:block pr-2">
                  {item.timeString}
                </div>

                {/* Right: Prominent Threat Score Box + View Analysis + Options Menu */}
                <div className="flex items-center justify-between sm:justify-end gap-3 w-full md:w-auto shrink-0 pt-2 md:pt-0 border-t md:border-t-0 border-white/5">
                  {/* Score Hero Box with vertical left border matching screenshot */}
                  <div className={`px-3.5 py-1.5 rounded-xl border-l-4 min-w-[110px] text-right font-mono ${
                    isHigh 
                      ? 'border-l-cyber-red bg-cyber-red/10 text-cyber-red' 
                      : isSuspicious 
                        ? 'border-l-amber-400 bg-amber-500/10 text-amber-400' 
                        : 'border-l-cyber-green bg-cyber-green/10 text-cyber-green'
                  }`}>
                    <div className="leading-none">
                      <span className="text-lg sm:text-xl font-black">{item.score}</span>
                      <span className="text-[11px] text-gray-400 font-normal"> / 100</span>
                    </div>
                    <div className="text-[10px] font-black tracking-widest uppercase mt-0.5">
                      {isHigh ? t('risk_label_high') : isSuspicious ? t('risk_label_suspicious') : t('risk_label_low')}
                    </div>
                  </div>

                  {/* View Analysis Button */}
                  <button
                    onClick={() => onSelectEmailForAnalysis(item, 'neural')}
                    className="min-h-[40px] px-3.5 py-2 rounded-xl text-xs font-mono font-bold bg-[#0a1128] hover:bg-cyber-blue/20 text-white hover:text-cyber-blue border border-white/10 hover:border-cyber-blue/40 transition-all flex items-center gap-1.5 cursor-pointer shadow-sm active:scale-95 whitespace-nowrap"
                  >
                    <span>{t('view_analysis_btn')}</span>
                    <ArrowRight className="w-3.5 h-3.5 text-gray-400 group-hover:text-cyber-blue transition-colors" />
                  </button>

                  {/* Options Menu Button (⋮) */}
                  <div className="relative">
                    <button
                      onClick={() => setOpenMenuId(openMenuId === item.id ? null : item.id)}
                      className="w-8 h-8 rounded-lg bg-white/5 hover:bg-white/10 border border-white/5 text-gray-400 hover:text-white flex items-center justify-center cursor-pointer transition-colors"
                      title={t('more_options_title')}
                    >
                      <MoreVertical className="w-3.5 h-3.5" />
                    </button>
                    
                    {openMenuId === item.id && (
                      <div className="absolute right-0 top-9 z-30 w-48 bg-[#070d1e] border border-cyber-border/60 rounded-xl p-1 shadow-2xl space-y-0.5 text-xs font-mono backdrop-blur-xl">
                        <button
                          onClick={() => { setOpenMenuId(null); }}
                          className="w-full text-left px-2.5 py-1.5 rounded-lg text-gray-300 hover:text-white hover:bg-white/5 cursor-pointer"
                        >
                          {t('mark_as_read')}
                        </button>
                        <button
                          onClick={() => { setOpenMenuId(null); }}
                          className="w-full text-left px-2.5 py-1.5 rounded-lg text-gray-300 hover:text-white hover:bg-white/5 cursor-pointer"
                        >
                          {t('move_to_quarantine')}
                        </button>
                        <button
                          onClick={() => { 
                            setOpenMenuId(null); 
                            navigator.clipboard.writeText(item.rawHeaders);
                          }}
                          className="w-full text-left px-2.5 py-1.5 rounded-lg text-cyber-blue hover:bg-white/5 cursor-pointer"
                        >
                          {t('copy_rfc_headers')}
                        </button>
                        <button
                          onClick={() => { 
                            setOpenMenuId(null); 
                            onSelectEmailForAnalysis(item, 'neural');
                          }}
                          className="w-full text-left px-2.5 py-1.5 rounded-lg text-purple-400 hover:bg-white/5 cursor-pointer"
                        >
                          {t('inspect_neuro_profile')}
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* 4. BOTTOM PAGINATION & LOAD MORE BAR */}
      {filteredEmails.length > 0 && (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 border-t border-white/5 font-mono text-xs text-gray-400">
          <div>
            {t('showing_label')} <span className="text-white font-bold">1–{filteredEmails.length}</span> {t('of_label')} <span className="text-white font-bold">{displayTotal}</span> {t('scanned_emails_label')}
          </div>

          <div className="flex items-center gap-2">
            {hasMore && onLoadMore && (
              <button
                onClick={onLoadMore}
                disabled={isLoadingMore}
                className="min-h-[36px] px-3.5 py-1.5 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-mono text-xs font-bold flex items-center gap-1.5 cursor-pointer transition-all disabled:opacity-50"
              >
                {isLoadingMore ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                    <span>{t('loading_more_emails')}</span>
                  </>
                ) : (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
                    <span>{t('load_more_btn')}</span>
                  </>
                )}
              </button>
            )}

            <div className="flex items-center gap-1.5">
              <button className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center hover:text-white cursor-pointer transition-colors" disabled>
                &lt;
              </button>
              <button className="w-8 h-8 rounded-lg bg-cyan-500 text-black font-bold flex items-center justify-center shadow-[0_0_10px_rgba(6,182,212,0.4)]">
                1
              </button>
              {displayTotal > 30 && (
                <button 
                  onClick={onLoadMore}
                  disabled={isLoadingMore}
                  className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center hover:text-white cursor-pointer transition-colors"
                >
                  2
                </button>
              )}
              <button 
                onClick={onLoadMore}
                disabled={!hasMore || isLoadingMore}
                className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center hover:text-white cursor-pointer transition-colors disabled:opacity-30"
              >
                &gt;
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
