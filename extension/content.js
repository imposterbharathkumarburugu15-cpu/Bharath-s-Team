/**
 * NeuroShield Guard — Content Script (Manifest V3)
 * Real-Time Before-Action Interception & Enforcement Engine
 */

(function () {
  'use strict';

  // Prevent multiple injections
  if (window.__neuroshield_guard_injected__) return;
  window.__neuroshield_guard_injected__ = true;

  const IS_GMAIL = window.location.hostname === 'mail.google.com';

  function unwrapTargetUrl(href) {
    if (!href) return '';
    try {
      const u = new URL(href);
      if ((u.hostname.endsWith('google.com') || u.hostname.endsWith('googleusercontent.com')) && (u.pathname === '/url' || u.pathname.endsWith('/url') || u.searchParams.has('q'))) {
        const q = u.searchParams.get('q');
        if (q) return q;
      }
      return href;
    } catch {
      return href;
    }
  }

  // ──────────────────────────────────────────────────────────────────────────
  // 1. UI: Authoritative Block Screen & Warning Overlay
  // ──────────────────────────────────────────────────────────────────────────

  function showBlockOverlay(details) {
    const existing = document.getElementById('neuroshield-guard-overlay');
    if (existing) existing.remove();

    const risk = details.riskScore >= 85 ? 'CRITICAL' : details.riskScore >= 65 ? 'HIGH' : 'SUSPICIOUS';
    const threat = details.threatTypes?.[0] || details.threat || 'Malicious Interaction';
    const action = details.requestedAction || 'UNKNOWN';
    const evidenceItems = details.evidence || ['Suspicious destination', 'Credential harvesting indicators'];

    const overlay = document.createElement('div');
    overlay.id = 'neuroshield-guard-overlay';
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      background: rgba(9, 13, 22, 0.96);
      backdrop-filter: blur(8px);
      z-index: 2147483647;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      color: #f8fafc;
      box-sizing: border-box;
      animation: nsFadeIn 0.2s ease-out;
    `;

    const card = document.createElement('div');
    card.style.cssText = `
      background: #0f172a;
      border: 2px solid #ef4444;
      border-radius: 14px;
      box-shadow: 0 25px 50px -12px rgba(239, 68, 68, 0.35);
      max-width: 580px;
      width: 100%;
      padding: 28px;
    `;

    card.innerHTML = `
      <style>
        @keyframes nsFadeIn { from { opacity: 0; } to { opacity: 1; } }
        .ns-badge {
          display: inline-block;
          padding: 3px 8px;
          border-radius: 9999px;
          font-size: 11px;
          font-weight: 700;
          background: rgba(239, 68, 68, 0.2);
          color: #f87171;
          border: 1px solid rgba(239, 68, 68, 0.4);
        }
        .ns-btn {
          padding: 10px 18px;
          border-radius: 8px;
          font-weight: 600;
          font-size: 13px;
          cursor: pointer;
          border: none;
          transition: opacity 0.15s;
        }
        .ns-btn:hover { opacity: 0.9; }
        .ns-btn-primary { background: #3b82f6; color: #ffffff; }
        .ns-btn-secondary { background: #1e293b; color: #94a3b8; border: 1px solid #334155; }
        .ns-fb-btn {
          padding: 5px 10px;
          font-size: 11px;
          border-radius: 4px;
          background: #1e293b;
          color: #94a3b8;
          border: 1px solid #334155;
          cursor: pointer;
        }
        .ns-fb-btn:hover { background: #334155; color: #ffffff; }
      </style>

      <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 20px; border-bottom: 1px solid rgba(239, 68, 68, 0.2); padding-bottom: 14px;">
        <span style="font-size: 20px;">🚫</span>
        <h2 style="font-size: 18px; font-weight: 800; color: #f87171; margin: 0; letter-spacing: 0.5px;">
          NEUROSHIELD BLOCKED THIS ACTION
        </h2>
      </div>

      <div style="margin-bottom: 14px;">
        <div style="font-size: 10px; font-weight: 700; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.5px;">Risk</div>
        <div style="margin-top: 2px;"><span class="ns-badge">${risk}</span></div>
      </div>

      <div style="margin-bottom: 14px;">
        <div style="font-size: 10px; font-weight: 700; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.5px;">Threat</div>
        <div style="font-size: 15px; font-weight: 700; color: #f87171; margin-top: 2px;">${escapeHtml(threat)}</div>
      </div>

      <div style="margin-bottom: 14px;">
        <div style="font-size: 10px; font-weight: 700; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.5px;">Requested Action</div>
        <div style="font-size: 14px; font-weight: 600; color: #ffffff; margin-top: 2px;">${escapeHtml(action)}</div>
      </div>

      <div style="margin-bottom: 20px;">
        <div style="font-size: 10px; font-weight: 700; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.5px;">Evidence</div>
        <div style="background: #020617; border-left: 3px solid #ef4444; border-radius: 6px; padding: 10px 14px; margin-top: 4px; font-size: 12px; color: #cbd5e1; line-height: 1.6;">
          ${evidenceItems.slice(0, 4).map(e => `<div>• ${escapeHtml(typeof e === 'string' ? e : e.evidence || e.signal || JSON.stringify(e))}</div>`).join('')}
        </div>
      </div>

      <div style="background: #020617; border: 1px solid #1e293b; border-radius: 6px; padding: 10px 12px; margin-bottom: 20px;">
        <div style="font-size: 10px; font-weight: 700; text-transform: uppercase; color: #94a3b8; margin-bottom: 6px;">Report to SOC / Calibrate Engine</div>
        <div style="display: flex; gap: 6px;">
          <button id="ns-fb-tp" class="ns-fb-btn">Threat Confirmed</button>
          <button id="ns-fb-fp" class="ns-fb-btn">False Alarm</button>
          <button id="ns-fb-fn" class="ns-fb-btn">Missed Threat</button>
        </div>
        <div id="ns-fb-msg" style="font-size: 11px; color: #10b981; margin-top: 6px; display: none;">✓ Feedback recorded.</div>
      </div>

      <div style="display: flex; justify-content: flex-end; gap: 10px;">
        <button id="ns-close-overlay" class="ns-btn ns-btn-secondary">Dismiss</button>
        <button id="ns-go-back" class="ns-btn ns-btn-primary">← Go Back</button>
      </div>
    `;

    overlay.appendChild(card);
    document.body.appendChild(overlay);

    document.getElementById('ns-close-overlay')?.addEventListener('click', () => overlay.remove());
    document.getElementById('ns-go-back')?.addEventListener('click', () => {
      overlay.remove();
      window.history.back();
    });

    // Feedback handlers
    const sendFeedback = (type) => {
      chrome.runtime.sendMessage({
        type: 'SUBMIT_FEEDBACK',
        feedback: {
          incident_id: details.incidentId || `fb-modal-${Date.now()}`,
          feedback: type,
          user_comment: `Reported from in-page block modal on ${window.location.hostname}`,
          source: 'web'
        }
      });
      const msg = document.getElementById('ns-fb-msg');
      if (msg) msg.style.display = 'block';
    };

    document.getElementById('ns-fb-tp')?.addEventListener('click', () => sendFeedback('TRUE_POSITIVE'));
    document.getElementById('ns-fb-fp')?.addEventListener('click', () => sendFeedback('FALSE_POSITIVE'));
    document.getElementById('ns-fb-fn')?.addEventListener('click', () => sendFeedback('MISSED_THREAT'));
  }

  // ──────────────────────────────────────────────────────────────────────────
  // 2. Real-Time Link Click Interception (CLICK_LINK / BLOCK_VIEW)
  // ──────────────────────────────────────────────────────────────────────────

  document.addEventListener('click', async (e) => {
    // Find closest anchor tag
    const anchor = e.target.closest ? e.target.closest('a') : null;
    if (!anchor || !anchor.href) return;

    const rawHref = anchor.href;
    const targetUrl = unwrapTargetUrl(rawHref);
    // Ignore internal or same-page hashes
    if (!targetUrl || targetUrl.startsWith('javascript:') || targetUrl.startsWith('#') || targetUrl === window.location.href + '#') {
      return;
    }

    // 1. If link was already disarmed by NeuroShield in Gmail:
    const isDisarmed = anchor.getAttribute('data-ns-disarmed') === 'true';
    if (isDisarmed) {
      e.preventDefault();
      e.stopImmediatePropagation();
      showBlockOverlay({
        riskScore: 92,
        threat: 'Disarmed Phishing Link in Email',
        requestedAction: 'CLICK_LINK',
        threatTypes: ['PHISHING', 'MALICIOUS_LINK'],
        evidence: [
          'Email contains unverified external credential-harvesting link',
          `Target: ${targetUrl}`,
          'Link was pre-emptively disarmed by NeuroShield Guard'
        ]
      });
      return;
    }

    // 2. Fast heuristic check or Gmail external link
    const isSuspiciousTunnel = /(ngrok-free\.app|trycloudflare\.com|loclx\.io|serveo\.net)/i.test(targetUrl);
    const isIpHost = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(targetUrl);
    const isPunycode = targetUrl.includes('xn--');
    let isGmailExternalLink = false;
    if (IS_GMAIL) {
      try {
        const u = new URL(targetUrl);
        isGmailExternalLink = !u.hostname.endsWith('google.com') && !u.hostname.endsWith('googleusercontent.com') && !targetUrl.startsWith('mailto:');
      } catch {
        isGmailExternalLink = false;
      }
    }

    if (isSuspiciousTunnel || isIpHost || isPunycode || isGmailExternalLink) {
      // Synchronously halt event in capture phase to prevent navigation / tab open
      e.preventDefault();
      e.stopImmediatePropagation();

      // Query central core for authoritative policy decision
      chrome.runtime.sendMessage({
        type: 'ANALYZE_URL',
        url: targetUrl,
        userAction: 'CLICK_LINK'
      }, (response) => {
        if (response && (response.protectionDecision === 'BLOCK_VIEW' || response.protectionDecision === 'BLOCK_ACTION' || response.riskScore >= 65 || response.verdict === 'MALICIOUS')) {
          // Record enforcement
          chrome.runtime.sendMessage({
            type: 'RECORD_ENFORCEMENT',
            record: {
              incidentId: response.incidentId,
              requestedAction: 'CLICK_LINK',
              risk: response.riskScore,
              decision: 'BLOCK_VIEW',
              enforcementStatus: 'ENFORCED',
              client: 'chrome_extension',
              url: targetUrl
            }
          });

          showBlockOverlay(response);
        } else {
          // Allowed: proceed with safe navigation
          window.open(targetUrl, '_blank', 'noopener,noreferrer');
        }
      });
    }
  }, true); // Capture phase ensures execution before inline click handlers

  // ──────────────────────────────────────────────────────────────────────────
  // 3. Credential & Sensitive Form Interception (LOGIN / ENTER_PASSWORD / OTP)
  // ──────────────────────────────────────────────────────────────────────────

  document.addEventListener('submit', (e) => {
    const form = e.target;
    if (!form || !(form instanceof HTMLFormElement)) return;

    // Check if form was already verified safe by NeuroShield in this session
    if (form.getAttribute('data-neuroshield-verified') === 'true') {
      return;
    }

    const hasPassword = Boolean(form.querySelector('input[type="password"]'));
    const hasOtp = Boolean(
      form.querySelector('input[autocomplete="one-time-code"]') ||
      form.querySelector('input[name*="otp" i], input[name*="2fa" i], input[id*="otp" i], input[id*="2fa" i]')
    );
    const hasCreditCard = Boolean(
      form.querySelector('input[autocomplete="cc-number"]') ||
      form.querySelector('input[name*="card" i], input[id*="card" i]')
    );

    if (hasPassword || hasOtp || hasCreditCard) {
      const requestedAction = hasOtp ? 'SHARE_OTP' : hasPassword ? 'ENTER_PASSWORD' : 'SHARE_SENSITIVE_DATA';

      // Synchronously halt submission in capture phase
      e.preventDefault();
      e.stopImmediatePropagation();

      const currentUrl = window.location.href;

      chrome.runtime.sendMessage({
        type: 'ANALYZE_URL',
        url: currentUrl,
        userAction: requestedAction
      }, (response) => {
        const isHighRisk = response && (response.riskScore >= 65 || response.verdict === 'MALICIOUS');
        const isBlock = response && (response.protectionDecision === 'BLOCK_ACTION' || response.protectionDecision === 'BLOCK_VIEW');

        if (isBlock || isHighRisk) {
          console.warn(`[NeuroShield Guard] Form submission blocked: ${requestedAction} on ${currentUrl}`);

          // Record actual enforcement
          chrome.runtime.sendMessage({
            type: 'RECORD_ENFORCEMENT',
            record: {
              incidentId: response?.incidentId,
              requestedAction,
              risk: response?.riskScore || 85,
              decision: 'BLOCK_ACTION',
              enforcementStatus: 'ENFORCED',
              client: 'chrome_extension',
              url: currentUrl
            }
          });

          showBlockOverlay(response || {
            riskScore: 90,
            threat: hasPassword ? 'Credential Harvesting' : hasOtp ? 'OTP Interception' : 'Sensitive Data Exfiltration',
            requestedAction,
            evidence: ['Untrusted origin attempting to collect credentials/secrets']
          });
        } else {
          // Genuine / verified login: allow submission
          form.setAttribute('data-neuroshield-verified', 'true');
          form.submit();
        }
      });
    }
  }, true); // Capture phase ensures interception before malicious submit listeners

  // ──────────────────────────────────────────────────────────────────────────
  // 4. Gmail Automatic Zero-Click Content Protection
  // ──────────────────────────────────────────────────────────────────────────

  if (IS_GMAIL) {
    // Helper to extract visible Gmail message bodies across all Gmail layout variants
    const findGmailBodies = () => {
      const elements = document.querySelectorAll('.a3s, .ii.gt, div[data-message-id], div.adn');
      const bodies = [];
      const seen = new Set();
      elements.forEach(el => {
        const bodyEl = el.matches('.a3s') ? el : (el.querySelector('.a3s') || el);
        if (!seen.has(bodyEl)) {
          seen.add(bodyEl);
          const text = (bodyEl.innerText || '').trim();
          if (text.length > 5 && (bodyEl.offsetParent !== null || bodyEl.clientHeight > 0 || (window.getComputedStyle && window.getComputedStyle(bodyEl).display !== 'none'))) {
            bodies.push(bodyEl);
          }
        }
      });
      return bodies;
    };

    const observeGmailMessages = () => {
      const visibleContainers = findGmailBodies();

      if (visibleContainers.length === 0) {
        // Not currently inside an opened email (e.g. browsing inbox list)
        chrome.runtime.sendMessage({ type: 'CLEAR_GMAIL_THREAT' }).catch(() => {});
        return;
      }

      const hash = window.location.hash.toLowerCase();
      const isSpamHash = hash.includes('spam') || hash.includes('trash');
      const pageText = document.body ? document.body.innerText : '';
      const hasNativeSpamWarning = /why\s+is\s+this\s+message\s+in\s+spam|be\s+careful\s+with\s+this\s+message|marked\s+as\s+spam|phishing\s+scam/i.test(pageText);
      const isSpamFolder = isSpamHash || hasNativeSpamWarning;

      visibleContainers.forEach((container) => {
        const text = container.innerText || '';

        // Extract sender and subject from Gmail DOM
        const senderElem = document.querySelector('span.gD') || document.querySelector('span[email]') || container.closest('.gs')?.querySelector('span.gD');
        const sender = senderElem ? (senderElem.getAttribute('email') || senderElem.innerText || '') : '';
        const subjectElem = document.querySelector('h2.hP') || document.querySelector('.ha h2');
        const subject = subjectElem ? subjectElem.innerText || '' : '';

        // Signature so navigating between emails re-evaluates instantly
        const scanSig = `${subject}::${text.substring(0, 100)}`;
        if (container.getAttribute('data-ns-scanned') === scanSig) return;
        container.setAttribute('data-ns-scanned', scanSig);

        // Find insertion anchor: prefer conversation item or container itself
        const bannerTarget = container.closest('.gs') || container.closest('.adn') || container;
        const oldBanner = bannerTarget.querySelector('.neuroshield-gmail-banner');
        if (oldBanner) oldBanner.remove();

        // Extract all external links in this message (unwrapping google.com/url?q=)
        const externalLinks = Array.from(container.querySelectorAll('a[href]'))
          .map((a) => unwrapTargetUrl(a.href))
          .filter((href) => {
            if (!href || href.startsWith('javascript:') || href.startsWith('#') || href.startsWith('mailto:')) return false;
            try {
              const u = new URL(href);
              return !u.hostname.endsWith('google.com') && !u.hostname.endsWith('googleusercontent.com');
            } catch {
              return false;
            }
          });

        // Instant heuristics for phishing / scam emails
        const hasFinancialCoercion = /(transfer\s+(?:funds|money|₹|\$)|send\s+(?:₹|\$|\d+\s*lakh)|wire\s+to\s+this\s+new\s+account)/i.test(text);
        const hasUrgentMeeting = /(in\s+a\s+meeting|don't\s+call\s+me|changed\s+my\s+number)/i.test(text);
        const hasCredentialLure = /(verify\s+your\s+account|password\s+expired|account\s+suspended|unauthorized\s+login|security\s+alert|confirm\s+identity|action\s+required|click\s+here\s+to\s+claim|billing\s+failed|update\s+payment)/i.test(text + ' ' + subject);
        const hasTunnelLink = externalLinks.some((l) => /(trycloudflare\.com|ngrok(-free)?\.(app|io)|loclx\.io|serveo\.net)/i.test(l));

        const isImmediateThreat = isSpamFolder || hasTunnelLink || (hasFinancialCoercion && hasUrgentMeeting) || (hasCredentialLure && externalLinks.length > 0);

        // Helper to disarm links and inject warning banner
        const enforceGmailThreat = (threatTitle, riskScore) => {
          container.setAttribute('data-ns-threat', 'true');

          if (!bannerTarget.querySelector('.neuroshield-gmail-banner')) {
            const banner = document.createElement('div');
            banner.className = 'neuroshield-gmail-banner';
            banner.style.cssText = `
              background: linear-gradient(135deg, rgba(239, 68, 68, 0.18) 0%, rgba(15, 23, 42, 0.96) 100%);
              border: 2px solid #ef4444;
              border-radius: 10px;
              padding: 14px 18px;
              margin: 12px 0 20px 0;
              color: #f87171;
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
              box-shadow: 0 10px 25px -5px rgba(239, 68, 68, 0.3);
              display: block;
              z-index: 100;
            `;
            banner.innerHTML = `
              <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                <div style="display: flex; align-items: center; gap: 8px;">
                  <span style="font-size: 20px;">🛡️</span>
                  <strong style="font-size: 14px; font-weight: 800; letter-spacing: 0.5px; color: #f87171;">
                    NEUROSHIELD AUTOMATIC DEFENSE: THREAT DETECTED
                  </strong>
                </div>
                <span style="background: #ef4444; color: #ffffff; padding: 4px 12px; border-radius: 6px; font-size: 11px; font-weight: 800; letter-spacing: 0.5px;">
                  RISK ${riskScore}/100 • BLOCKED
                </span>
              </div>
              <div style="font-size: 13px; color: #fca5a5; line-height: 1.5; margin-bottom: 10px;">
                <strong>Classification:</strong> ${escapeHtml(threatTitle)}<br>
                <span style="color: #cbd5e1; font-size: 12px;">
                  NeuroShield automatically analyzed this message. All ${externalLinks.length} external link(s) have been <strong>pre-emptively disarmed</strong> to prevent credential harvesting and malicious redirects.
                </span>
              </div>
              <div style="display: flex; flex-wrap: wrap; gap: 8px; font-size: 11px; color: #94a3b8;">
                <span style="background: rgba(15, 23, 42, 0.85); padding: 4px 10px; border-radius: 4px; border: 1px solid #334155;">
                  Sender: <strong style="color: #e2e8f0;">${escapeHtml(sender || 'Unverified External Sender')}</strong>
                </span>
                <span style="background: rgba(15, 23, 42, 0.85); padding: 4px 10px; border-radius: 4px; border: 1px solid #334155;">
                  Neutralized Links: <strong style="color: #f87171;">${externalLinks.length}</strong>
                </span>
                <span style="background: rgba(15, 23, 42, 0.85); padding: 4px 10px; border-radius: 4px; border: 1px solid #334155;">
                  Status: <strong style="color: #34d399;">Active Auto-Protection</strong>
                </span>
              </div>
            `;
            if (bannerTarget.firstChild) {
              bannerTarget.insertBefore(banner, bannerTarget.firstChild);
            } else {
              bannerTarget.appendChild(banner);
            }
          }

          // Disarm all links inside message body
          container.querySelectorAll('a').forEach((link) => {
            const rawHref = link.href;
            const target = unwrapTargetUrl(rawHref);
            if (!target || target.startsWith('javascript:') || target.startsWith('#') || target.startsWith('mailto:')) return;
            try {
              const u = new URL(target);
              if (u.hostname.endsWith('google.com') || u.hostname.endsWith('googleusercontent.com')) return;
            } catch { return; }

            link.setAttribute('data-ns-disarmed', 'true');
            link.style.border = '2px dashed #ef4444';
            link.style.backgroundColor = 'rgba(239, 68, 68, 0.12)';
            link.style.color = '#f87171';
            link.style.padding = '2px 6px';
            link.style.borderRadius = '4px';
            link.style.fontWeight = 'bold';
            link.title = `⛔ Disarmed by NeuroShield: Malicious destination neutralized (${target})`;
          });

          // Sync with popup HUD immediately
          chrome.runtime.sendMessage({
            type: 'SET_GMAIL_THREAT',
            threat: {
              detected: true,
              riskScore,
              threatName: threatTitle,
              sender,
              subject,
              linkCount: externalLinks.length,
              firstLink: externalLinks[0] || null
            }
          }).catch(() => {});
        };

        // 1. Instant zero-latency enforcement for known spam folder or dangerous markers
        if (isImmediateThreat) {
          const instantTitle = isSpamFolder
            ? 'Untrusted Spam / Suspicious Inbound Email'
            : hasTunnelLink
            ? 'Cloudflare Quick Tunnel / Reverse Proxy Evasion'
            : hasCredentialLure
            ? 'Credential Harvesting & Account Takeover Lure'
            : 'Executive Smishing & Wire Fraud Attempt';
          const instantScore = isSpamFolder ? 88 : 82;
          enforceGmailThreat(instantTitle, instantScore);
        }

        // 2. Asynchronous deep analysis with NeuroShield Core & Sandbox
        if (isSpamFolder || hasFinancialCoercion || hasCredentialLure || hasTunnelLink || externalLinks.length > 0) {
          chrome.runtime.sendMessage({
            type: 'ANALYZE_GMAIL_MESSAGE',
            data: {
              content: text.substring(0, 2000),
              sender,
              subject,
              links: externalLinks,
              isInSpamFolder: isSpamFolder
            }
          }, (response) => {
            const isThreat = isSpamFolder || hasTunnelLink || (response && (
              response.protectionDecision === 'BLOCK_VIEW' ||
              response.protectionDecision === 'BLOCK_ACTION' ||
              response.verdict === 'MALICIOUS' ||
              response.verdict === 'SUSPICIOUS' ||
              (response.riskScore && response.riskScore >= 50)
            ));

            if (isThreat) {
              const finalTitle = (response?.threatTypes?.[0]) || (isSpamFolder ? 'Untrusted Spam / Suspicious Inbound Email' : 'Phishing / Deceptive Email');
              const finalScore = response?.riskScore || (isSpamFolder ? 88 : 75);
              enforceGmailThreat(finalTitle, finalScore);
            }
          });
        }
      });
    };

    // Zero-latency instant detection via MutationObserver + fast poll fallback
    let scanTimeout = null;
    const triggerScan = () => {
      if (scanTimeout) clearTimeout(scanTimeout);
      scanTimeout = setTimeout(observeGmailMessages, 60);
    };

    // Listen to DOM mutations in Gmail SPA
    const observer = new MutationObserver(triggerScan);
    observer.observe(document.body || document.documentElement, {
      childList: true,
      subtree: true
    });

    // Listen to route/hash changes
    window.addEventListener('hashchange', triggerScan);
    window.addEventListener('popstate', triggerScan);

    // Listen to clicks on email rows in the list
    document.addEventListener('click', (e) => {
      const isRow = e.target.closest && e.target.closest('tr, [role="row"], .zA');
      if (isRow) {
        triggerScan();
        setTimeout(triggerScan, 250);
        setTimeout(triggerScan, 600);
      }
    }, true);

    // Fallback heartbeat
    setInterval(observeGmailMessages, 1200);
  }

  // Helper
  function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

})();
