import React, { useMemo } from 'react';
import { DomainAuthLookup } from '../components/DomainAuthLookup';
import { ShieldCheck } from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';

export function DomainOSINT() {
  const { t } = useLanguage();
  // Read any initial domain passed via query string or hash (e.g. #osint?domain=github.com)
  const initialDomain = useMemo(() => {
    if (typeof window !== 'undefined') {
      const hash = window.location.hash;
      const match = hash.match(/[?&]domain=([^&]+)/i);
      if (match && match[1]) {
        try {
          return decodeURIComponent(match[1]);
        } catch {
          return match[1];
        }
      }
    }
    return 'github.com';
  }, []);

  return (
    <main className="p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto w-full space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/5 pb-5">
        <div>
          <div className="text-[11px] font-mono tracking-widest text-cyber-blue uppercase font-bold flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-cyber-blue animate-pulse" />
            {t('osint_eyebrow') || 'INFRASTRUCTURE INTELLIGENCE & OSINT'}
          </div>
          <h1 className="text-2xl sm:text-3xl font-black font-mono text-white tracking-tight flex items-center gap-2">
            {t('osint_title') || 'Domain OSINT & Auth Inspector'}<span className="text-cyber-blue">.</span>
          </h1>
          <p className="text-xs sm:text-sm text-gray-400 mt-1 max-w-3xl font-sans leading-relaxed">
            {t('osint_desc') || 'Unified infrastructure investigation: inspect live DNS cryptographic records (SPF, DKIM, DMARC), DoH resolution, RDAP registry longevity, network ASN routing, and public hosting relationships.'}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-3 py-1.5 rounded-xl flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5" />
            {t('passive_doh_badge') || 'Passive DoH / Non-Intrusive'}
          </span>
        </div>
      </div>

      {/* Unified Domain OSINT & Authentication Module */}
      <DomainAuthLookup initialDomain={initialDomain} />
    </main>
  );
}

