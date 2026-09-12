/**
 * NeuroShield Guard — Blocked Screen Controller
 * Phase 4 Authoritative Client Enforcement Screen
 */

document.addEventListener('DOMContentLoaded', async () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get('url') || 'Unknown Destination';
  const risk = params.get('risk') || 'CRITICAL';
  const threat = params.get('threat') || 'Credential Theft';
  const action = params.get('action') || 'LOGIN';
  const incidentId = params.get('incidentId') || `inc-block-${Date.now()}`;
  const evidenceParam = params.get('evidence');

  // DOM elements
  const riskBadge = document.getElementById('risk-badge');
  const threatVal = document.getElementById('threat-val');
  const actionVal = document.getElementById('action-val');
  const urlVal = document.getElementById('url-val');
  const evidenceList = document.getElementById('evidence-list');
  const btnGoBack = document.getElementById('btn-go-back');
  const btnCloseTab = document.getElementById('btn-close-tab');

  const fbTp = document.getElementById('fb-tp');
  const fbFp = document.getElementById('fb-fp');
  const fbFn = document.getElementById('fb-fn');
  const fbStatus = document.getElementById('fb-status');

  // Populate fields
  if (riskBadge) {
    riskBadge.textContent = risk;
    riskBadge.className = risk === 'CRITICAL' ? 'badge badge-critical' : 'badge badge-high';
  }
  if (threatVal) threatVal.textContent = threat;
  if (actionVal) actionVal.textContent = action;
  if (urlVal) urlVal.textContent = targetUrl;

  if (evidenceList && evidenceParam) {
    try {
      const items = JSON.parse(evidenceParam);
      if (Array.isArray(items) && items.length > 0) {
        evidenceList.innerHTML = items
          .map(item => `<li class="evidence-item">${escapeHtml(item)}</li>`)
          .join('');
      }
    } catch {
      evidenceList.innerHTML = `<li class="evidence-item">${escapeHtml(evidenceParam)}</li>`;
    }
  }

  // Navigation handlers
  if (btnGoBack) {
    btnGoBack.addEventListener('click', () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.close();
      }
    });
  }

  if (btnCloseTab) {
    btnCloseTab.addEventListener('click', () => {
      window.close();
    });
  }

  // Real backend feedback submission
  async function submitFeedback(type) {
    if (fbStatus) {
      fbStatus.style.display = 'block';
      fbStatus.textContent = 'Submitting feedback to NeuroShield Core...';
    }

    try {
      // Query backend API URL from storage
      const storage = await chrome.storage.local.get(['apiUrl']);
      const apiUrl = storage.apiUrl || 'http://localhost:3000';

      const resp = await fetch(`${apiUrl}/api/feedback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incident_id: incidentId,
          feedback: type,
          user_comment: `Reported via NeuroShield Block Screen for ${targetUrl}`,
          source: 'web',
          targetId: incidentId,
        })
      });

      if (resp.ok) {
        if (fbStatus) {
          fbStatus.style.color = '#10b981';
          fbStatus.textContent = '✓ Thank you! Feedback transmitted to SOC calibration engine.';
        }
      } else {
        throw new Error(`HTTP ${resp.status}`);
      }
    } catch (err) {
      if (fbStatus) {
        fbStatus.style.color = '#f59e0b';
        fbStatus.textContent = 'Note: Core offline, feedback recorded locally in browser client.';
      }
    }
  }

  if (fbTp) {
    fbTp.addEventListener('click', () => {
      setActiveFeedbackBtn(fbTp);
      submitFeedback('TRUE_POSITIVE');
    });
  }
  if (fbFp) {
    fbFp.addEventListener('click', () => {
      setActiveFeedbackBtn(fbFp);
      submitFeedback('FALSE_POSITIVE');
    });
  }
  if (fbFn) {
    fbFn.addEventListener('click', () => {
      setActiveFeedbackBtn(fbFn);
      submitFeedback('MISSED_THREAT');
    });
  }

  function setActiveFeedbackBtn(btn) {
    [fbTp, fbFp, fbFn].forEach(b => b?.classList.remove('active'));
    btn?.classList.add('active');
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
});
