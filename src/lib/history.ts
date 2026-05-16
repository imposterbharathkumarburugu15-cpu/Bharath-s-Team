import { ScanResult } from "@/services/geminiService";

export interface ScanHistoryItem extends ScanResult {
  id: string;
  timestamp: string;
}

export const getScanHistory = (): ScanHistoryItem[] => {
  try {
    const raw = localStorage.getItem('sentinel_scan_history');
    if (raw) return JSON.parse(raw);
  } catch (e) {}
  return [];
};

export const addScanToHistory = (scan: ScanResult) => {
  try {
    const history = getScanHistory();
    const item: ScanHistoryItem = {
      ...scan,
      id: "TR-" + Math.floor(1000 + Math.random() * 9000),
      timestamp: new Date().toISOString()
    };
    const newHistory = [item, ...history].slice(0, 100); 
    localStorage.setItem('sentinel_scan_history', JSON.stringify(newHistory));
  } catch (e) {}
};
