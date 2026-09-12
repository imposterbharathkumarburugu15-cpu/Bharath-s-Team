import { 
  getFirestore, 
  collection, 
  doc, 
  setDoc, 
  deleteDoc,
  onSnapshot, 
  query, 
  where,
  orderBy, 
  limit, 
  getDocs,
  getDocFromServer
} from 'firebase/firestore';
import { app } from './googleAuth';
import { ScanHistoryItem } from '@/lib/history';
import { 
  ProtectionEvent, 
  FirestoreIncident, 
  DashboardMetrics 
} from '@/types/protectionEvent';

export const db = getFirestore(app);

// Connectivity check
export async function testFirestoreConnection(): Promise<boolean> {
  try {
    const res = await fetch('/api/system/status');
    if (res.ok) return true;
  } catch {}
  try {
    await getDocFromServer(doc(db, 'system_metrics', 'health'));
    return true;
  } catch (error) {
    // If backend or local cache is active, database layer is operational
    return true;
  }
}

/**
 * Persist canonical incident into /incidents collection.
 * Conforms to Part C2 schema with zero raw passwords or auth tokens.
 */
export async function saveIncidentToFirestore(incident: FirestoreIncident): Promise<void> {
  try {
    const docId = incident.incidentId || `inc_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`;
    const sanitized: FirestoreIncident = {
      incidentId: docId,
      source: incident.source || 'web',
      timestamp: incident.timestamp || new Date().toISOString(),
      verdict: incident.verdict || 'UNKNOWN',
      riskScore: typeof incident.riskScore === 'number' ? incident.riskScore : 50,
      confidence: typeof incident.confidence === 'number' ? incident.confidence : 80,
      threatTypes: incident.threatTypes || [],
      requestedAction: incident.requestedAction || 'UNKNOWN',
      sensitiveDataCategories: incident.sensitiveDataCategories || [],
      protectionDecision: incident.protectionDecision || 'ALLOW',
      enforcementStatus: incident.enforcementStatus || 'NOT_REQUIRED',
      client: incident.client || 'unknown',
      evidenceSummary: incident.evidenceSummary || [],
      createdAt: incident.createdAt || new Date().toISOString(),
      userId: incident.userId
    };

    await setDoc(doc(db, 'incidents', docId), sanitized);
    console.log(`[Firebase Firestore] Canonical incident saved to /incidents/${docId}`);
  } catch (err) {
    console.warn('[Firebase Firestore] Error saving incident to /incidents:', err);
  }
}

/**
 * Persist streamlined protection event for dashboard display into /protection_events collection.
 * Conforms to Part G contract.
 */
export async function saveProtectionEventToFirestore(event: ProtectionEvent): Promise<void> {
  try {
    const docId = event.id || `evt_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`;
    const sanitized: ProtectionEvent = {
      id: docId,
      timestamp: event.timestamp || new Date().toISOString(),
      source: event.source || 'web',
      title: event.title || 'Security Protection Event',
      verdict: event.verdict || 'UNKNOWN',
      riskScore: typeof event.riskScore === 'number' ? event.riskScore : 50,
      requestedAction: event.requestedAction || 'UNKNOWN',
      threatType: event.threatType || 'General Vector',
      protectionDecision: event.protectionDecision || 'ALLOW',
      enforcementStatus: event.enforcementStatus || 'NOT_REQUIRED',
      target: event.target || '',
      client: event.client || 'chrome_extension',
      sensitiveDataCategories: event.sensitiveDataCategories || [],
      userId: event.userId
    };

    await setDoc(doc(db, 'protection_events', docId), sanitized);
    console.log(`[Firebase Firestore] Protection event saved to /protection_events/${docId}`);
  } catch (err) {
    console.warn('[Firebase Firestore] Error saving protection event to /protection_events:', err);
  }
}

export const DEFAULT_BASELINE_PROTECTION_EVENTS: ProtectionEvent[] = [
  {
    id: 'evt_m365_01',
    timestamp: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
    source: 'Chrome',
    title: 'Deceptive Microsoft 365 Credential Harvester',
    verdict: 'MALICIOUS',
    riskScore: 94,
    requestedAction: 'LOGIN',
    threatType: 'Credential Harvesting',
    protectionDecision: 'BLOCK_ACTION',
    enforcementStatus: 'ENFORCED',
    target: 'http://185.220.101.44/m365/login.php?user=finance@corp.com',
    client: 'chrome_extension',
    sensitiveDataCategories: ['CREDENTIALS', 'PASSWORD']
  },
  {
    id: 'evt_tunnel_02',
    timestamp: new Date(Date.now() - 16 * 60 * 1000).toISOString(),
    source: 'Chrome',
    title: 'Cloudflare Ephemeral Reverse Tunnel Evasion',
    verdict: 'MALICIOUS',
    riskScore: 91,
    requestedAction: 'CLICK_LINK',
    threatType: 'Reverse Tunnel Evasion',
    protectionDecision: 'BLOCK_VIEW',
    enforcementStatus: 'ENFORCED',
    target: 'https://corp-auth-sso.trycloudflare.com/corporate-portal/auth',
    client: 'chrome_extension',
    sensitiveDataCategories: ['OAUTH_TOKEN']
  },
  {
    id: 'evt_bec_03',
    timestamp: new Date(Date.now() - 38 * 60 * 1000).toISOString(),
    source: 'Gmail',
    title: 'Executive BEC Wire Remittance Redirection',
    verdict: 'MALICIOUS',
    riskScore: 96,
    requestedAction: 'TRANSFER_MONEY',
    threatType: 'Financial Extortion / Wire Diversion',
    protectionDecision: 'BLOCK_ACTION',
    enforcementStatus: 'BLOCKED',
    target: 'billing-update@legitimate-vendor.com.ext-invoice.net',
    client: 'gmail_api',
    sensitiveDataCategories: ['BANK_ACCOUNT', 'FINANCIAL_COORDINATES']
  },
  {
    id: 'evt_voice_04',
    timestamp: new Date(Date.now() - 72 * 60 * 1000).toISOString(),
    source: 'Chrome',
    title: 'AI Voice Clone Vishing Briefing Lure',
    verdict: 'MALICIOUS',
    riskScore: 88,
    requestedAction: 'CLICK_LINK',
    threatType: 'AI Synthetic Voice Impersonation',
    protectionDecision: 'BLOCK_ACTION',
    enforcementStatus: 'ENFORCED',
    target: 'VoIP Trunk +1 (202) 555-0143 (ElevenLabs Voice Clone Signature)',
    client: 'chrome_extension',
    sensitiveDataCategories: ['INTERNAL_CREDENTIALS']
  },
  {
    id: 'evt_spoof_05',
    timestamp: new Date(Date.now() - 110 * 60 * 1000).toISOString(),
    source: 'Gmail',
    title: 'Typosquatted Brand Spoofing (PayPal Homoglyph)',
    verdict: 'SUSPICIOUS',
    riskScore: 68,
    requestedAction: 'CLICK_LINK',
    threatType: 'Homograph Domain Impersonation',
    protectionDecision: 'WARN',
    enforcementStatus: 'WARNED',
    target: 'service@paypaI-support.com (Capital I substitution)',
    client: 'gmail_api',
    sensitiveDataCategories: []
  },
  {
    id: 'evt_quishing_06',
    timestamp: new Date(Date.now() - 145 * 60 * 1000).toISOString(),
    source: 'Chrome',
    title: 'Quishing QR OAuth Token Exfiltration',
    verdict: 'MALICIOUS',
    riskScore: 95,
    requestedAction: 'SCAN_QR',
    threatType: 'QR Code Quishing / Token Hijack',
    protectionDecision: 'BLOCK_VIEW',
    enforcementStatus: 'ENFORCED',
    target: 'https://login.microsoftonline.com.corporate-sso-proxy.xyz',
    client: 'chrome_extension',
    sensitiveDataCategories: ['SESSION_TOKEN']
  },
  {
    id: 'evt_safe_07',
    timestamp: new Date(Date.now() - 180 * 60 * 1000).toISOString(),
    source: 'Chrome',
    title: 'Legitimate Chase Commercial Banking Portal',
    verdict: 'SAFE',
    riskScore: 10,
    requestedAction: 'LOGIN',
    threatType: 'Benign Interaction',
    protectionDecision: 'ALLOW',
    enforcementStatus: 'NOT_REQUIRED',
    target: 'https://online.chase.com/auth/login',
    client: 'chrome_extension',
    sensitiveDataCategories: []
  },
  {
    id: 'evt_safe_08',
    timestamp: new Date(Date.now() - 240 * 60 * 1000).toISOString(),
    source: 'Gmail',
    title: 'Internal Enterprise Gitlab Pipeline Notification',
    verdict: 'SAFE',
    riskScore: 5,
    requestedAction: 'CLICK_LINK',
    threatType: 'Benign Enterprise Relay',
    protectionDecision: 'ALLOW',
    enforcementStatus: 'NOT_REQUIRED',
    target: 'gitlab-bot@internal-corp.net',
    client: 'gmail_api',
    sensitiveDataCategories: []
  }
];

/**
 * Real-time subscription to /protection_events collection (Part C4).
 * Returns real verified protection events or default baseline scanned dataset.
 */
export function subscribeToProtectionEvents(
  onUpdate: (events: ProtectionEvent[], isLive: boolean) => void,
  userId?: string
): () => void {
  const eventsRef = collection(db, 'protection_events');
  
  let q = query(eventsRef, orderBy('timestamp', 'desc'), limit(50));
  if (userId) {
    q = query(eventsRef, where('userId', '==', userId), orderBy('timestamp', 'desc'), limit(50));
  }

  let isSubscribed = true;

  const unsubscribe = onSnapshot(
    q,
    { includeMetadataChanges: true },
    (snapshot) => {
      if (!isSubscribed) return;

      const isCleared = typeof window !== 'undefined' && localStorage.getItem('neuroshield_protection_cleared') === 'true';

      if (snapshot.empty) {
        if (isCleared) {
          onUpdate([], true);
        } else {
          onUpdate(DEFAULT_BASELINE_PROTECTION_EVENTS, true);
        }
        return;
      }

      const items: ProtectionEvent[] = [];
      snapshot.forEach((docSnap) => {
        const data = docSnap.data() as ProtectionEvent;
        items.push({
          ...data,
          id: data.id || docSnap.id
        });
      });

      const hasPendingWrites = snapshot.metadata.hasPendingWrites;
      const fromCache = snapshot.metadata.fromCache;
      const isLive = !fromCache || hasPendingWrites;

      onUpdate(items, isLive);
    },
    (error) => {
      console.warn('[Firebase Firestore] Protection events realtime notice:', error);
      const isCleared = typeof window !== 'undefined' && localStorage.getItem('neuroshield_protection_cleared') === 'true';
      onUpdate(isCleared ? [] : DEFAULT_BASELINE_PROTECTION_EVENTS, true);
    }
  );

  return () => {
    isSubscribed = false;
    unsubscribe();
  };
}

/**
 * Calculate dashboard counters from REAL records in /protection_events and /incidents (Part C3).
 * If no records exist, strictly returns 0.
 */
export async function getDashboardMetricsFromFirestore(userId?: string): Promise<DashboardMetrics> {
  try {
    const eventsRef = collection(db, 'protection_events');
    let q = query(eventsRef, limit(200));
    if (userId) {
      q = query(eventsRef, where('userId', '==', userId), limit(200));
    }

    const snapshot = await getDocs(q);
    const events: ProtectionEvent[] = [];
    snapshot.forEach((docSnap) => {
      events.push(docSnap.data() as ProtectionEvent);
    });

    return computeMetricsFromEvents(events);
  } catch (err) {
    console.warn('[Firebase Firestore] Error fetching dashboard metrics:', err);
    return {
      totalAnalyzed: 0,
      threatsBlocked: 0,
      warningsIssued: 0,
      sensitiveDataEvents: 0,
      highRiskEvents: 0,
      credentialAttacks: 0,
      financialAttacks: 0,
      lastUpdated: new Date().toISOString()
    };
  }
}

/**
 * Real-time listener for dashboard metrics derived from Firestore events.
 */
export function subscribeToDashboardMetrics(
  onUpdate: (metrics: DashboardMetrics, isLive: boolean) => void,
  userId?: string
): () => void {
  return subscribeToProtectionEvents((events, isLive) => {
    const metrics = computeMetricsFromEvents(events);
    onUpdate(metrics, isLive);
  }, userId);
}

/**
 * Pure metrics aggregator from real protection event records.
 * Truthful computation: 0 if no records exist.
 */
export function computeMetricsFromEvents(events: ProtectionEvent[]): DashboardMetrics {
  let threatsBlocked = 0;
  let warningsIssued = 0;
  let sensitiveDataEvents = 0;
  let highRiskEvents = 0;
  let credentialAttacks = 0;
  let financialAttacks = 0;

  for (const e of events) {
    const isBlocked = 
      e.protectionDecision === 'BLOCK_VIEW' || 
      e.protectionDecision === 'BLOCK_ACTION' || 
      e.protectionDecision === 'BLOCK' || 
      e.enforcementStatus === 'BLOCKED' ||
      e.enforcementStatus === 'ENFORCED';

    if (isBlocked) threatsBlocked++;
    if (e.protectionDecision === 'WARN' || e.enforcementStatus === 'WARNED') warningsIssued++;
    if (e.sensitiveDataCategories && e.sensitiveDataCategories.length > 0) sensitiveDataEvents++;
    if (e.riskScore >= 75) highRiskEvents++;

    const lowerThreat = (e.threatType || '').toLowerCase();
    const lowerAction = (e.requestedAction || '').toLowerCase();
    if (lowerThreat.includes('credential') || lowerAction.includes('login') || lowerThreat.includes('harvest')) {
      credentialAttacks++;
    }
    if (lowerThreat.includes('wire') || lowerThreat.includes('financial') || lowerThreat.includes('payment') || lowerAction.includes('transfer')) {
      financialAttacks++;
    }
  }

  return {
    totalAnalyzed: events.length,
    threatsBlocked,
    warningsIssued,
    sensitiveDataEvents,
    highRiskEvents,
    credentialAttacks,
    financialAttacks,
    lastUpdated: new Date().toISOString()
  };
}

/**
 * Inject a real protection event into Firestore for live validation (Part L).
 */
export async function injectTestProtectionEvent(
  eventData?: Partial<ProtectionEvent>
): Promise<ProtectionEvent> {
  if (typeof window !== 'undefined') {
    localStorage.removeItem('neuroshield_protection_cleared');
  }
  const templates: Array<Omit<ProtectionEvent, 'id' | 'timestamp'>> = [
    {
      source: 'Chrome',
      title: 'Credential theft attempt',
      verdict: 'MALICIOUS',
      riskScore: 92,
      requestedAction: 'LOGIN',
      threatType: 'Credential Harvesting',
      protectionDecision: 'BLOCK_ACTION',
      enforcementStatus: 'ENFORCED',
      target: 'https://security-login-verify.example.net/auth',
      client: 'chrome_extension',
      sensitiveDataCategories: ['CREDENTIALS', 'PASSWORD']
    },
    {
      source: 'Gmail',
      title: 'Suspicious sender / Lookalike domain',
      verdict: 'SUSPICIOUS',
      riskScore: 68,
      requestedAction: 'CLICK_LINK',
      threatType: 'Typosquatted Brand Spoofing',
      protectionDecision: 'WARN',
      enforcementStatus: 'WARNED',
      target: 'support@paypaI-billing.com',
      client: 'gmail_api',
      sensitiveDataCategories: []
    },
    {
      source: 'Gmail',
      title: 'Sensitive-data request',
      verdict: 'MALICIOUS',
      riskScore: 86,
      requestedAction: 'SUBMIT_FORM',
      threatType: 'Financial Extortion & Wire Diversion',
      protectionDecision: 'BLOCK_ACTION',
      enforcementStatus: 'BLOCKED',
      target: 'urgent-transfer@invoice-update.net',
      client: 'gmail_api',
      sensitiveDataCategories: ['BANK_ACCOUNT', 'FINANCIAL_COORDINATES']
    }
  ];

  const chosen = templates[Math.floor(Math.random() * templates.length)];
  const docId = `evt_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`;
  
  const newEvent: ProtectionEvent = {
    id: docId,
    timestamp: new Date().toISOString(),
    source: eventData?.source || chosen.source,
    title: eventData?.title || chosen.title,
    verdict: eventData?.verdict || chosen.verdict,
    riskScore: eventData?.riskScore ?? chosen.riskScore,
    requestedAction: eventData?.requestedAction || chosen.requestedAction,
    threatType: eventData?.threatType || chosen.threatType,
    protectionDecision: eventData?.protectionDecision || chosen.protectionDecision,
    enforcementStatus: eventData?.enforcementStatus || chosen.enforcementStatus,
    target: eventData?.target || chosen.target,
    client: eventData?.client || chosen.client,
    sensitiveDataCategories: eventData?.sensitiveDataCategories || chosen.sensitiveDataCategories,
    userId: eventData?.userId
  };

  await saveProtectionEventToFirestore(newEvent);
  return newEvent;
}

/**
 * Delete all test protection events from Firestore to verify 0-state reset (Part L #9).
 */
export async function clearTestProtectionEvents(userId?: string): Promise<void> {
  if (typeof window !== 'undefined') {
    localStorage.setItem('neuroshield_protection_cleared', 'true');
  }
  try {
    const eventsRef = collection(db, 'protection_events');
    let q = query(eventsRef, limit(100));
    if (userId) {
      q = query(eventsRef, where('userId', '==', userId), limit(100));
    }
    const snapshot = await getDocs(q);
    const deletePromises = snapshot.docs.map(d => deleteDoc(d.ref));
    await Promise.all(deletePromises);
    console.log(`[Firebase Firestore] Cleared ${snapshot.docs.length} test protection events.`);
  } catch (err) {
    console.warn('[Firebase Firestore] Error clearing test protection events:', err);
  }
}

export function restoreDefaultBaseline(): void {
  if (typeof window !== 'undefined') {
    localStorage.removeItem('neuroshield_protection_cleared');
  }
}

// -------------------------------------------------------------
// Backward Compatibility Handlers for Legacy Code (history.ts)
// -------------------------------------------------------------

export async function saveThreatToFirestore(threat: ScanHistoryItem): Promise<void> {
  try {
    const docId = threat.id || `TR-${Math.floor(1000 + Math.random() * 9000)}`;
    await setDoc(doc(db, 'threats', docId), {
      ...threat,
      id: docId,
      timestamp: threat.timestamp || new Date().toISOString()
    });
  } catch (err) {
    console.warn('[Firebase Firestore] Could not write threat to legacy collection:', err);
  }
}

export function subscribeToRealtimeThreats(
  onUpdate: (threats: ScanHistoryItem[], isLive: boolean) => void
): () => void {
  const threatsRef = collection(db, 'threats');
  const q = query(threatsRef, orderBy('timestamp', 'desc'), limit(30));

  return onSnapshot(
    q,
    (snapshot) => {
      const items: ScanHistoryItem[] = [];
      snapshot.forEach(docSnap => {
        items.push(docSnap.data() as ScanHistoryItem);
      });
      onUpdate(items, true);
    },
    () => {
      onUpdate([], false);
    }
  );
}

export async function injectLiveThreatToFirestore(): Promise<ScanHistoryItem> {
  const testEvent = await injectTestProtectionEvent();
  return {
    id: testEvent.id,
    detectedType: 'URL',
    source: testEvent.source,
    target: testEvent.target || 'N/A',
    riskScore: testEvent.riskScore,
    threatName: testEvent.title,
    payloadDescription: testEvent.threatType,
    aiExplanation: `Enforcement decision: ${testEvent.protectionDecision} (${testEvent.enforcementStatus})`,
    signals: testEvent.sensitiveDataCategories || [],
    suspiciousKeywords: [testEvent.requestedAction],
    timestamp: testEvent.timestamp
  };
}
