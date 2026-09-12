import { ScanResult } from "@/services/geminiService";
import { saveThreatToFirestore } from "@/services/firebaseDb";

export interface ScanHistoryItem extends ScanResult {
  id: string;
  timestamp: string;
}

const INITIAL_SEED_HISTORY: ScanHistoryItem[] = [
  {
    id: 'TR-9921',
    detectedType: 'EMAIL',
    source: 'billing@paypaI-support.com',
    target: 'finance@corp.com',
    riskScore: 92,
    threatName: 'BEC Executive Impersonation Lure',
    payloadDescription: 'BEC Executive Impersonation Lure targeting finance department.',
    aiExplanation: 'Detected homograph spoofing (paypaI with capital I) targeting finance department with urgent wire transfer request.',
    signals: ['HOMOGRAPH_SPOOFING', 'URGENCY_TRIGGER', 'FINANCIAL_WIRE_REQUEST'],
    suspiciousKeywords: ['wire transfer', 'urgent', 'invoice approval'],
    timestamp: new Date(Date.now() - 2 * 60 * 1000).toISOString()
  },
  {
    id: 'TR-9920',
    detectedType: 'CHAT',
    source: 'Telegram Bot (+44 7900 555121)',
    target: 'Employee Support Group',
    riskScore: 88,
    threatName: 'Smishing OTP Credential Harvest',
    payloadDescription: 'Smishing OTP Credential Harvest via Telegram broadcast.',
    aiExplanation: 'Malicious Telegram bot broadcasting fake bank security verification link with credential capture template.',
    signals: ['OTP_HARVEST', 'EXTERNAL_BOT_PAYLOAD'],
    suspiciousKeywords: ['verify account', 'netbanking login', 'suspend access'],
    timestamp: new Date(Date.now() - 8 * 60 * 1000).toISOString()
  },
  {
    id: 'TR-9919',
    detectedType: 'URL',
    source: 'http://docs-update-portal-login.net/auth',
    target: 'N/A',
    riskScore: 95,
    threatName: 'Reverse Tunnel Phishing Gateway',
    payloadDescription: 'Reverse Tunnel Phishing Gateway hosted via Cloudflare quick tunnel.',
    aiExplanation: 'Domain registered 14 minutes ago using Cloudflare quick tunnel to host credential phishing page.',
    signals: ['FRESH_DOMAIN', 'REVERSE_TUNNEL', 'CREDENTIAL_PHISH'],
    suspiciousKeywords: ['login', 'authenticate', 'session refresh'],
    timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString()
  },
  {
    id: 'TR-9918',
    detectedType: 'EMAIL',
    source: 'hr-benefits@company-portal.net',
    target: 'all-staff@corp.com',
    riskScore: 78,
    threatName: 'HR Phishing Lure',
    payloadDescription: 'HR Phishing Lure requesting mandatory benefit update.',
    aiExplanation: 'External sender masquerading as internal HR portal requesting mandatory benefit re-enrollment.',
    signals: ['SPOOFED_SENDER', 'PAYLOAD_ZIP'],
    suspiciousKeywords: ['benefits update', 'mandatory action'],
    timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString()
  },
  {
    id: 'TR-9917',
    detectedType: 'AI_MANIPULATION',
    source: 'Spoofed +1 (415) 555-0199',
    target: 'exec-team',
    riskScore: 84,
    threatName: 'AI Voice Clone Vishing',
    payloadDescription: 'AI Voice Clone Vishing briefing transcript.',
    aiExplanation: 'ElevenLabs synthesized audio signature detected in incoming executive audio briefing requesting wire transfer.',
    signals: ['AI_VOICE_CLONE', 'EXECUTIVE_IMPERSONATION'],
    suspiciousKeywords: ['wire transfer', 'confidential acquisition'],
    timestamp: new Date(Date.now() - 120 * 60 * 1000).toISOString()
  }
];

export const getScanHistory = (): ScanHistoryItem[] => {
  try {
    const raw = localStorage.getItem('neuroshield_scan_history');
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) {
        return parsed;
      }
    }
    // Initialize with seed data if empty
    localStorage.setItem('neuroshield_scan_history', JSON.stringify(INITIAL_SEED_HISTORY));
    return INITIAL_SEED_HISTORY;
  } catch (e) {}
  return INITIAL_SEED_HISTORY;
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
    localStorage.setItem('neuroshield_scan_history', JSON.stringify(newHistory));
    // Persist to Firebase Firestore
    saveThreatToFirestore(item).catch(() => {});
  } catch (e) {}
};

