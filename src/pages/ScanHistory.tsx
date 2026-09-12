import React, { useState, useEffect } from 'react';
import { 
  History, 
  Search, 
  Download, 
  Filter, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  ArrowRight, 
  ChevronRight, 
  Copy, 
  Check, 
  FileText, 
  Clock,
  ExternalLink
} from 'lucide-react';
import { getScanHistory, ScanHistoryItem } from '@/lib/history';

interface ScanHistoryProps {
  onSelectScan?: (item: ScanHistoryItem) => void;
}

export function ScanHistory({ onSelectScan }: ScanHistoryProps) {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterVerdict, setFilterVerdict] = useState<'ALL' | 'CRITICAL' | 'SUSPICIOUS' | 'SAFE'>('ALL');
  const [selectedScan, setSelectedScan] = useState<ScanHistoryItem | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    setHistory(getScanHistory());
  }, []);

  const filteredHistory = history.filter(item => {
    const q = searchQuery.toLowerCase();
    const matchSearch = 
      item.threatName?.toLowerCase().includes(q) ||
      item.source?.toLowerCase().includes(q) ||
      item.payloadDescription?.toLowerCase().includes(q) ||
      item.id.toLowerCase().includes(q);

    if (!matchSearch) return false;

    if (filterVerdict === 'CRITICAL' && item.riskScore < 75) return false;
    if (filterVerdict === 'SUSPICIOUS' && (item.riskScore < 40 || item.riskScore >= 75)) return false;
    if (filterVerdict === 'SAFE' && item.riskScore >= 40) return false;

    return true;
  });

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(history, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kitsih-scan-audit-trail-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6 font-sans text-slate-100">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-white/[0.08]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-8 h-8 rounded-xl bg-[#10151D] border border-[#00F0FF]/30 flex items-center justify-center text-[#00F0FF]">
              <History className="w-4 h-4" />
            </div>
            <h1 className="text-xl sm:text-2xl font-bold font-mono tracking-tight text-white uppercase">
              Scan Audit History & Threat Logs
            </h1>
          </div>
          <p className="text-xs sm:text-sm text-[#8995A5] font-mono">
            Chronological forensic ledger of all processed emails, reverse tunnels, and containment actions
          </p>
        </div>

        <button
          onClick={handleExportJson}
          className="px-4 py-2 rounded-xl bg-[#10151D] hover:bg-[#161D27] text-white border border-white/[0.1] transition-all flex items-center gap-2 font-mono text-xs cursor-pointer shadow-lg self-start sm:self-auto"
        >
          <Download className="w-3.5 h-3.5 text-[#00F0FF]" />
          <span>Export Audit History</span>
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 rounded-2xl bg-[#10151D] border border-white/[0.08] flex flex-col sm:flex-row items-center justify-between gap-4 font-mono text-xs">
        <div className="relative w-full sm:w-80">
          <Search className="w-3.5 h-3.5 text-[#8995A5] absolute left-3 top-3" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by ID, sender, or threat name..."
            className="w-full bg-[#080B10] border border-white/[0.1] rounded-xl pl-9 pr-3 py-2 text-white focus:outline-none focus:border-[#00F0FF]"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto overflow-x-auto">
          {(['ALL', 'CRITICAL', 'SUSPICIOUS', 'SAFE'] as const).map((v) => (
            <button
              key={v}
              onClick={() => setFilterVerdict(v)}
              className={`px-3 py-1.5 rounded-lg font-bold transition-all border cursor-pointer ${
                filterVerdict === v
                  ? 'bg-[#00F0FF]/15 text-[#00F0FF] border-[#00F0FF]/40 shadow-[0_0_12px_rgba(0,240,255,0.2)]'
                  : 'bg-[#080B10] text-[#8995A5] border-white/[0.08] hover:text-white'
              }`}
            >
              {v}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="rounded-2xl bg-[#10151D] border border-white/[0.08] overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-white/[0.08] bg-[#080B10] text-[11px] text-[#8995A5] uppercase tracking-wider">
                <th className="py-3.5 px-4">Audit ID</th>
                <th className="py-3.5 px-4">Timestamp</th>
                <th className="py-3.5 px-4">Threat Name / Description</th>
                <th className="py-3.5 px-4">Sender / Origin</th>
                <th className="py-3.5 px-4">Risk Quotient</th>
                <th className="py-3.5 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06]">
              {filteredHistory.map((item) => {
                const isCrit = item.riskScore >= 75;
                const isWarn = item.riskScore >= 40 && item.riskScore < 75;

                return (
                  <tr 
                    key={item.id}
                    onClick={() => setSelectedScan(item)}
                    className="hover:bg-white/[0.03] transition-colors cursor-pointer group"
                  >
                    <td className="py-3.5 px-4 font-bold text-white">
                      {item.id}
                    </td>

                    <td className="py-3.5 px-4 text-[#8995A5] whitespace-nowrap">
                      {new Date(item.timestamp).toLocaleDateString()} {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>

                    <td className="py-3.5 px-4 max-w-xs">
                      <div className="font-bold text-white group-hover:text-[#00F0FF] transition-colors truncate">
                        {item.threatName || item.payloadDescription}
                      </div>
                      <div className="text-[10px] text-[#8995A5] truncate mt-0.5">
                        {item.payloadDescription}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 text-[#8995A5] max-w-xs truncate">
                      {item.source}
                    </td>

                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[10px] font-bold border ${
                        isCrit 
                          ? 'bg-[#F43F5E]/15 text-[#F43F5E] border-[#F43F5E]/40' 
                          : isWarn 
                          ? 'bg-[#F59E0B]/15 text-[#F59E0B] border-[#F59E0B]/40' 
                          : 'bg-[#10B981]/15 text-[#10B981] border-[#10B981]/40'
                      }`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          isCrit ? 'bg-[#F43F5E] animate-pulse' : isWarn ? 'bg-[#F59E0B]' : 'bg-[#10B981]'
                        }`} />
                        <span>{item.riskScore}/100</span>
                      </span>
                    </td>

                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <button className="px-2.5 py-1 rounded-lg bg-[#080B10] hover:bg-[#161D27] border border-white/[0.08] text-[#8995A5] hover:text-white transition-all text-[11px] flex items-center gap-1 ml-auto cursor-pointer">
                        <span>Inspect</span>
                        <ChevronRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Modal */}
      {selectedScan && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-[#10151D] border border-white/[0.1] rounded-2xl max-w-2xl w-full p-6 space-y-5 shadow-2xl font-mono text-xs">
            <div className="flex items-center justify-between pb-3 border-b border-white/[0.08]">
              <div className="flex items-center gap-2">
                <span className="font-bold text-white text-sm">
                  AUDIT RECORD: {selectedScan.id}
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                  selectedScan.riskScore >= 75 ? 'bg-[#F43F5E]/20 text-[#F43F5E]' : 'bg-[#10B981]/20 text-[#10B981]'
                }`}>
                  {selectedScan.riskScore}/100
                </span>
              </div>
              <button
                onClick={() => setSelectedScan(null)}
                className="text-[#8995A5] hover:text-white px-2.5 py-1 rounded-lg bg-[#080B10]"
              >
                ✕ Close
              </button>
            </div>

            <div className="space-y-2">
              <span className="text-[10px] text-[#8995A5] uppercase font-bold">Threat Name & Description:</span>
              <div className="text-white font-bold text-sm">{selectedScan.threatName || selectedScan.payloadDescription}</div>
              <p className="text-[#8995A5] text-xs">{selectedScan.aiExplanation || selectedScan.payloadDescription}</p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 bg-[#080B10] rounded-xl border border-white/[0.06]">
                <div className="text-[10px] text-[#8995A5]">Origin / Ingress:</div>
                <div className="text-white font-bold truncate mt-0.5">{selectedScan.source}</div>
              </div>
              <div className="p-3 bg-[#080B10] rounded-xl border border-white/[0.06]">
                <div className="text-[10px] text-[#8995A5]">Target Destination:</div>
                <div className="text-white font-bold truncate mt-0.5">{selectedScan.target || 'Corporate Mail Gateway'}</div>
              </div>
            </div>

            {selectedScan.signals && (
              <div>
                <span className="text-[10px] text-[#8995A5] uppercase font-bold block mb-1.5">Identified Signals:</span>
                <div className="flex flex-wrap gap-1.5">
                  {selectedScan.signals.map((s, idx) => (
                    <span key={idx} className="px-2 py-0.5 rounded bg-[#F43F5E]/10 border border-[#F43F5E]/30 text-[#F43F5E] text-[10px]">
                      {s}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

    </div>
  );
}
