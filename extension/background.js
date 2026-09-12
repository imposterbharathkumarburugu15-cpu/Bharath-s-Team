/**
 * NeuroShield Guard — Background Service Worker (Manifest V3)
 * Phase 4 Authoritative Automatic Protection & Client-Side Enforcement
 */

const DEFAULT_API_URL = 'http://localhost:3000';

// Known suspicious patterns for Level 1 Local Preflight Analysis
const SUSPICIOUS_TUNNELS = [
  'ngrok.io', 'ngrok-free.app', 'trycloudflare.com', 'loclx.io', 
  'pagekite.me', 'serveo.net', 'localtunnel.me', 'portmap.io'
];

const SENSITIVE_KEYWORDS = [
  'login', 'signin', 'verify', 'account', 'banking', 'otp', 
  'password', 'credential', 'update-billing', 'security-alert', 'wallet'
];

// Decision Cache with 5-minute TTL to ensure fast browsing without redundant network roundtrips
const decisionCache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000;

function getCachedDecision(url, action) {
  const key = `${action}:${url}`;
  const entry = decisionCache.get(key);
  if (entry && Date.now() - entry.timestamp < CACHE_TTL_MS) {
    return entry.decision;
  }
  if (entry) decisionCache.delete(key);
  return null;
}

function setCachedDecision(url, action, decision) {
  const key = `${action}:${url}`;
  // Limit cache size to 500 entries
  if (decisionCache.size > 500) {
    const firstKey = decisionCache.keys().next().value;
    decisionCache.delete(firstKey);
  }
  decisionCache.set(key, { decision, timestamp: Date.now() });
}

// Initialize Context Menus and Storage
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'neuroshield-inspect-link',
    title: '🛡️ Check Link with NeuroShield Guard',
    contexts: ['link']
  });

  chrome.contextMenus.create({
    id: 'neuroshield-inspect-selection',
    title: '🛡️ Analyze Text with NeuroShield Guard',
    contexts: ['selection']
  });

  // Default settings
  chrome.storage.local.get(['apiUrl', 'privacyMode', 'autoCheckUrls'], (res) => {
    if (!res.apiUrl) chrome.storage.local.set({ apiUrl: DEFAULT_API_URL });
    if (!res.privacyMode) chrome.storage.local.set({ privacyMode: 'STANDARD' });
    if (res.autoCheckUrls === undefined) chrome.storage.local.set({ autoCheckUrls: true });
  });

  console.log('[NeuroShield Guard] Background worker initialized (Phase 4 Enforcement Active).');
});

// Real-Time Navigation Interception (BLOCK_VIEW)
if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
  chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only inspect main frame navigation (frameId === 0)
    if (details.frameId !== 0) return;

    const url = details.url;
    if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) {
      return;
    }

    try {
      // 1. Fast preflight check
      const localCheck = runLocalUrlHeuristics(url);

      // Check cache first
      let evaluation = getCachedDecision(url, 'VISIT_WEBSITE');
      if (!evaluation) {
        evaluation = await evaluatePolicyWithCore(url, 'VISIT_WEBSITE', localCheck);
        setCachedDecision(url, 'VISIT_WEBSITE', evaluation);
      }

      // If protection decision is BLOCK_VIEW or risk is CRITICAL/HIGH on malicious site
      if (
        evaluation.protectionDecision === 'BLOCK_VIEW' ||
        (evaluation.riskScore >= 75 && evaluation.verdict === 'MALICIOUS')
      ) {
        console.warn(`[NeuroShield Guard] Navigation blocked to malicious destination: ${url}`);

        // Record enforcement event to backend
        recordEnforcementEvent({
          incidentId: evaluation.incidentId || `nav-block-${Date.now()}`,
          requestedAction: 'VISIT_WEBSITE',
          risk: evaluation.riskScore,
          decision: 'BLOCK_VIEW',
          enforcementStatus: 'ENFORCED',
          client: 'chrome_extension',
          url,
          failureReason: undefined
        });

        // Redirect tab to authoritative blocked screen
        const blockedPageUrl = chrome.runtime.getURL(
          `blocked.html?url=${encodeURIComponent(url)}` +
          `&risk=${encodeURIComponent(evaluation.riskScore >= 85 ? 'CRITICAL' : 'HIGH')}` +
          `&threat=${encodeURIComponent(evaluation.threatTypes?.[0] || 'Malicious Destination')}` +
          `&action=VISIT_WEBSITE` +
          `&incidentId=${encodeURIComponent(evaluation.incidentId || '')}` +
          `&evidence=${encodeURIComponent(JSON.stringify(evaluation.evidence || ['Malicious destination blocked']))}`
        );

        chrome.tabs.update(details.tabId, { url: blockedPageUrl });
      }
    } catch (err) {
      console.warn('[NeuroShield Guard] Navigation inspection error:', err);
    }
  });
}

// Handle Context Menu clicks
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'neuroshield-inspect-link' && info.linkUrl) {
    const analysis = await analyzeUrl(info.linkUrl, 'CLICK_LINK');
    if (tab && tab.id) {
      chrome.tabs.sendMessage(tab.id, {
        type: 'NEUROSHIELD_INSPECT_RESULT',
        targetUrl: info.linkUrl,
        analysis
      }).catch(() => {});
    }
  } else if (info.menuItemId === 'neuroshield-inspect-selection' && info.selectionText) {
    const analysis = await analyzeText(info.selectionText);
    if (tab && tab.id) {
      chrome.tabs.sendMessage(tab.id, {
        type: 'NEUROSHIELD_INSPECT_RESULT',
        targetText: info.selectionText,
        analysis
      }).catch(() => {});
    }
  }
});

// Policy Check via NeuroShield Core API (/api/guard/policy-check)
async function evaluatePolicyWithCore(urlStr, userAction = 'VISIT_WEBSITE', localCheck = null) {
  const settings = await chrome.storage.local.get(['apiUrl']);
  const apiUrl = settings.apiUrl || DEFAULT_API_URL;
  const preflight = localCheck || runLocalUrlHeuristics(urlStr);

  try {
    const response = await fetch(`${apiUrl}/api/guard/policy-check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: urlStr,
        source: 'web',
        requestedAction: userAction,
        client: 'chrome_extension',
        clientCapabilities: {
          canBlockNavigation: true,
          canBlockFormSubmit: true,
          canDisarmLinks: true,
        },
      })
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} from Core API`);
    }

    const data = await response.json();
    return data;
  } catch (err) {
    console.warn('[NeuroShield Guard] Core policy-check unavailable, failing safe with UNKNOWN:', err);

    // Fail-Safe: DO NOT say SAFE. Instead: UNKNOWN
    return {
      incidentId: `offline-${Date.now()}`,
      verdict: preflight.suspicious ? 'SUSPICIOUS' : 'UNKNOWN',
      riskScore: preflight.suspicious ? 70 : 45,
      confidence: 25,
      requestedAction: userAction,
      threatTypes: preflight.signals.length > 0 ? preflight.signals : ['UNVERIFIED_SOURCE'],
      protectionDecision: preflight.suspicious ? 'WARN' : 'WARN',
      enforcementLevel: 'FAIL_SAFE_OFFLINE_CAUTION',
      enforcementStatus: 'UNKNOWN',
      evidence: [
        'Central verification offline or unreachable.',
        'Local heuristic flags: ' + (preflight.signals.join(', ') || 'No critical offline flags'),
      ],
      warning_card: {
        state: preflight.suspicious ? 'HIGH_RISK' : 'SUSPICIOUS',
        title: 'NeuroShield Offline — Caution Advised',
        summary: 'Cloud threat correlation unavailable. Local heuristic scanner active.',
        risk_detected: preflight.signals.join('; ') || 'Server unreachable; cannot verify destination.',
        required_action: 'EXERCISE CAUTION BEFORE ENTERING CREDENTIALS',
        safe_alternative: {
          title: 'Verify Manually',
          action_label: 'Open Official Site',
          guidance: 'Open the verified site directly via your address bar.',
          requires_independent_verification: true
        },
        primary_button_label: 'Go Back',
        secondary_button_label: 'Dismiss'
      }
    };
  }
}

// Staged URL Inspection (Level 1 Local -> Level 2 Core API)
async function analyzeUrl(urlStr, userAction = 'CLICK_LINK') {
  const startTime = Date.now();
  const cached = getCachedDecision(urlStr, userAction);
  if (cached) {
    return {
      success: true,
      cached: true,
      ...cached,
      latencyMs: Date.now() - startTime
    };
  }

  const localCheck = runLocalUrlHeuristics(urlStr);
  const evaluation = await evaluatePolicyWithCore(urlStr, userAction, localCheck);
  setCachedDecision(urlStr, userAction, evaluation);

  return {
    success: true,
    ...evaluation,
    local_check: localCheck,
    latencyMs: Date.now() - startTime
  };
}

// Staged Text / SMS Inspection
async function analyzeText(text, source = 'sms', userAction = 'UNKNOWN') {
  const settings = await chrome.storage.local.get(['apiUrl']);
  const apiUrl = settings.apiUrl || DEFAULT_API_URL;

  try {
    const response = await fetch(`${apiUrl}/api/neuroshield/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source,
        content: text,
        user_action: userAction,
        metadata: { client: 'chrome_extension' }
      })
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const incident = await response.json();
    return {
      success: true,
      incident,
      verdict: incident.verdict,
      risk_level: incident.risk_level,
      risk_score: incident.risk_score,
      protection: incident.protection,
      protectionDecision: incident.protectionDecision || incident.protection?.decision,
      enforcementStatus: incident.enforcementStatus || 'NOT_REQUIRED',
    };
  } catch (err) {
    return {
      success: false,
      api_available: false,
      api_error: err.message,
      verdict: 'UNKNOWN',
      risk_level: 'MEDIUM',
      risk_score: 50,
      protection: {
        decision: 'WARN',
        recommended_action: 'NeuroShield deep analysis is offline. Do not disclose OTPs or passwords.',
        steps: ['Server offline. Exercise caution.'],
        interventions: ['Never share OTPs or passwords.'],
        circuit_breakers: []
      },
      protectionDecision: 'WARN',
      enforcementStatus: 'UNKNOWN',
    };
  }
}

// Record Enforcement Event to Central Backend
async function recordEnforcementEvent(record) {
  try {
    const settings = await chrome.storage.local.get(['apiUrl']);
    const apiUrl = settings.apiUrl || DEFAULT_API_URL;

    await fetch(`${apiUrl}/api/guard/enforce-event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(record)
    });
  } catch (err) {
    console.warn('[NeuroShield Guard] Failed to record enforcement event to server:', err);
  }
}

// Local Heuristics
function runLocalUrlHeuristics(urlStr) {
  const signals = [];
  let suspicious = false;

  try {
    const parsed = new URL(urlStr);
    const hostname = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname.toLowerCase();

    // Check IP address hostname
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
      signals.push('IP_HOST_ADDRESS');
      suspicious = true;
    }

    // Check reverse tunnels
    for (const tunnel of SUSPICIOUS_TUNNELS) {
      if (hostname.endsWith(tunnel)) {
        signals.push('REVERSE_PROXY_TUNNEL_HOST');
        suspicious = true;
        break;
      }
    }

    // Check subdomains depth
    const parts = hostname.split('.');
    if (parts.length > 4) {
      signals.push('EXCESSIVE_SUBDOMAIN_NESTING');
      suspicious = true;
    }

    // Check sensitive path keywords
    for (const kw of SENSITIVE_KEYWORDS) {
      if (pathname.includes(kw) || parsed.search.toLowerCase().includes(kw)) {
        signals.push(`SENSITIVE_ENDPOINT_${kw.toUpperCase()}`);
      }
    }

    // Check Punycode / IDN homograph
    if (hostname.includes('xn--')) {
      signals.push('PUNYCODE_IDN_HOMOGRAPH');
      suspicious = true;
    }
  } catch (e) {
    signals.push('MALFORMED_URL_STRUCTURE');
  }

  return { suspicious, signals };
}

// Dedicated In-Page Gmail Message Inspector (Phase 4.5 Real-Time Protection)
async function analyzeGmailMessage(data) {
  const settings = await chrome.storage.local.get(['apiUrl']);
  const apiUrl = settings.apiUrl || DEFAULT_API_URL;

  // Prioritize most suspicious link if multiple links exist
  let targetUrl = undefined;
  if (data.links && data.links.length > 0) {
    const suspiciousCandidate = data.links.find(l => 
      /(trycloudflare|ngrok|loclx|serveo|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|login|verify|security|update|account|auth|claim|invoice|banking|password)/i.test(l)
    );
    targetUrl = suspiciousCandidate || data.links[0];
  }

  try {
    const response = await fetch(`${apiUrl}/api/guard/policy-check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: targetUrl,
        content: data.content ? data.content.substring(0, 2000) : '',
        source: 'email',
        requestedAction: targetUrl ? 'CLICK_LINK' : 'READ_EMAIL',
        client: 'chrome_extension',
        metadata: {
          sender: data.sender,
          subject: data.subject,
          externalLinks: data.links || [],
          isInSpamFolder: Boolean(data.isInSpamFolder),
          client: 'chrome_extension_gmail_hud'
        }
      })
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const evaluation = await response.json();

    if (data.isInSpamFolder) {
      evaluation.verdict = evaluation.verdict === 'MALICIOUS' ? 'MALICIOUS' : 'SUSPICIOUS';
      evaluation.riskScore = Math.max(evaluation.riskScore || 0, 85);
      evaluation.protectionDecision = 'BLOCK_VIEW';
      if (!evaluation.threatTypes || evaluation.threatTypes.length === 0) {
        evaluation.threatTypes = ['Untrusted Spam / Suspicious Inbound Email'];
      }
    }

    return {
      success: true,
      ...evaluation
    };
  } catch (err) {
    console.warn('[NeuroShield Guard] analyzeGmailMessage error:', err);
    // Local fallback heuristic if backend offline
    const isObviousPhish = Boolean(data.isInSpamFolder) || /(verify your account|password expired|suspended|security alert|urgent action|wire transfer|gift card)/i.test(data.content || '');
    return {
      success: false,
      riskScore: isObviousPhish ? 85 : 30,
      verdict: isObviousPhish ? 'SUSPICIOUS' : 'SAFE',
      threatTypes: isObviousPhish ? ['Untrusted Spam / Suspicious Inbound Email'] : [],
      protectionDecision: isObviousPhish ? 'BLOCK_VIEW' : 'ALLOW',
      evidence: [isObviousPhish ? 'Local heuristic: Suspicious urgency/spam markers detected' : 'Normal communication']
    };
  }
}

// Message Dispatcher
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'ANALYZE_URL') {
    analyzeUrl(request.url, request.userAction).then(sendResponse);
    return true; // async
  }
  if (request.type === 'ANALYZE_TEXT') {
    analyzeText(request.text, request.source, request.userAction).then(sendResponse);
    return true; // async
  }
  if (request.type === 'ANALYZE_GMAIL_MESSAGE') {
    analyzeGmailMessage(request.data).then(sendResponse);
    return true; // async
  }
  if (request.type === 'SET_GMAIL_THREAT') {
    chrome.storage.local.set({ activeGmailThreat: request.threat }).then(() => {
      sendResponse({ success: true });
    });
    return true;
  }
  if (request.type === 'CLEAR_GMAIL_THREAT') {
    chrome.storage.local.remove(['activeGmailThreat']).then(() => {
      sendResponse({ success: true });
    });
    return true;
  }
  if (request.type === 'RECORD_ENFORCEMENT') {
    recordEnforcementEvent(request.record).then(() => sendResponse({ success: true }));
    return true; // async
  }
  if (request.type === 'SUBMIT_FEEDBACK') {
    chrome.storage.local.get(['apiUrl'], async (res) => {
      const apiUrl = res.apiUrl || DEFAULT_API_URL;
      try {
        const resp = await fetch(`${apiUrl}/api/feedback`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(request.feedback)
        });
        const data = await resp.json();
        sendResponse({ success: true, data });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    });
    return true; // async
  }
});
