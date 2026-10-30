/**
 * AuthDrift Frontend Application
 * Interacts with AuthDrift FastAPI backend to render:
 * A. Authentication Overview Metrics
 * B. Authentication Journey Timelines
 * C. Explainable Security Intelligence (Balaa Engine)
 * D. Filtering, Scenario Switching & Raw Log Ingestion
 */

let allJourneys = [];
let allAlerts = [];
let selectedJourneyIndex = 0;

// Method assurance helper aligned with NIST SP 800-63B
function getAssuranceLevel(method) {
  if (!method) return 'LOW';
  const m = method.toLowerCase();
  if (['passkey', 'fido2', 'webauthn', 'hardware_token', 'client_cert'].includes(m)) return 'HIGH';
  if (['totp', 'authenticator_app', 'otp', 'sms_otp', 'sms', 'email_otp', 'push_notification'].includes(m)) return 'MEDIUM';
  return 'LOW';
}

function formatDate(isoStr) {
  if (!isoStr) return 'N/A';
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch (e) {
    return isoStr;
  }
}

// 1. Fetch & Initialize Data
async function loadData() {
  try {
    const [overviewRes, journeysRes, alertsRes] = await Promise.all([
      fetch('/api/overview'),
      fetch('/api/journeys'),
      fetch('/api/alerts')
    ]);

    if (!overviewRes.ok || !journeysRes.ok || !alertsRes.ok) {
      throw new Error('Failed to load data from AuthDrift API.');
    }

    const overview = await overviewRes.json();
    const journeysData = await journeysRes.json();
    const alertsData = await alertsRes.json();

    allJourneys = journeysData.journeys || [];
    allAlerts = alertsData.alerts || [];

    renderOverview(overview);
    applyFilters();
  } catch (err) {
    console.error('Data loading error:', err);
    document.getElementById('journeys-container').innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">⚠️</div>
        <h3>Backend Disconnected</h3>
        <p>Ensure the AuthDrift backend is running on <code>http://localhost:8000</code>.</p>
      </div>
    `;
  }
}

// 2. Render Overview Metrics (Section A)
function renderOverview(data) {
  const m = data.metrics || {};
  document.getElementById('val-events').textContent = m.processed_events ?? 0;
  document.getElementById('val-raw-events').textContent = `From ${data.total_raw_events ?? 0} raw logs`;
  document.getElementById('val-journeys').textContent = m.reconstructed_journeys ?? 0;
  document.getElementById('val-alerts').textContent = m.detected_drift_alerts ?? 0;
  document.getElementById('val-drift-rate').textContent = `${m.drift_rate_percentage ?? 0}% drift rate`;

  document.getElementById('current-provider-name').textContent = data.provider ?? 'Keycloak';

  const sev = m.severity_distribution || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  document.getElementById('pill-crit').textContent = `CRIT: ${sev.CRITICAL ?? 0}`;
  document.getElementById('pill-high').textContent = `HIGH: ${sev.HIGH ?? 0}`;
  document.getElementById('pill-med').textContent = `MED: ${sev.MEDIUM ?? 0}`;
  document.getElementById('pill-low').textContent = `LOW: ${sev.LOW ?? 0}`;
}

// 3. Render Journey Timelines (Section B)
function renderJourneys(filteredJourneys) {
  const container = document.getElementById('journeys-container');
  document.getElementById('journey-count-badge').textContent = `${filteredJourneys.length} Journeys`;

  if (!filteredJourneys || filteredJourneys.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🔍</div>
        <h3>No Authentication Journeys Found</h3>
        <p>No journeys matched the selected filters. Try clearing the search or changing scenario.</p>
      </div>
    `;
    renderAlertDetails(null);
    return;
  }

  container.innerHTML = '';

  filteredJourneys.forEach((journey, idx) => {
    // Find matching alert from Balaa's engine
    const matchedAlert = allAlerts.find(a => 
      a.user_id === journey.user_id && (a.session_id === journey.session_id || !journey.session_id)
    ) || allAlerts[idx];

    const hasDrift = matchedAlert ? matchedAlert.drift_detected : false;
    const isSelected = idx === selectedJourneyIndex;

    const card = document.createElement('div');
    card.className = `journey-card ${hasDrift ? 'has-drift' : ''} ${isSelected ? 'selected' : ''}`;
    card.onclick = () => {
      selectedJourneyIndex = idx;
      document.querySelectorAll('.journey-card').forEach(c => c.classList.remove('selected'));
      card.classList.add('selected');
      renderAlertDetails(matchedAlert, journey);
    };

    const firstTime = journey.events[0]?.timestamp;
    const lastTime = journey.events[journey.events.length - 1]?.timestamp;

    let stepsHtml = '';
    journey.events.forEach(ev => {
      const assurance = getAssuranceLevel(ev.authentication_method);
      const isSuccess = ev.outcome === 'SUCCESS';

      let contextTagsHtml = '';
      if (ev.device_id) {
        contextTagsHtml += `<span class="context-tag" title="Device">💻 ${ev.device_id}</span>`;
      }
      if (ev.location) {
        contextTagsHtml += `<span class="context-tag" title="Location">📍 ${ev.location}</span>`;
      }
      if (ev.authenticator_id) {
        contextTagsHtml += `<span class="context-tag" title="Authenticator">🔑 ${ev.authenticator_id}</span>`;
      }
      if (!contextTagsHtml) {
        contextTagsHtml = `<span class="context-tag" style="opacity: 0.5;">Context Unavailable</span>`;
      }

      stepsHtml += `
        <div class="timeline-step ${isSuccess ? 'step-success' : 'step-failure'}">
          <div class="step-left">
            <span class="badge-assurance assurance-${assurance.toLowerCase()}">${assurance}</span>
            <span class="step-method">${ev.authentication_method}</span>
            <span class="badge-outcome outcome-${isSuccess ? 'success' : 'failure'}">${ev.outcome}</span>
            <div class="step-context">${contextTagsHtml}</div>
          </div>
          <span class="step-time">${formatDate(ev.timestamp)}</span>
        </div>
      `;
    });

    let driftBanner = '';
    if (hasDrift && matchedAlert?.drift_result) {
      const prev = matchedAlert.drift_result.previous_assurance || 'HIGH';
      const curr = matchedAlert.drift_result.current_assurance || 'LOW';
      driftBanner = `
        <div class="drift-transition-banner">
          <span>⚠️ <strong>Assurance Drift:</strong> ${prev} ➔ ${curr} (${matchedAlert.drift_result.transition_type || 'DOWNGRADE'})</span>
        </div>
      `;
    }

    card.innerHTML = `
      <div class="journey-header">
        <div class="user-badge">
          <span class="icon">👤</span>
          <span>${journey.user_id}</span>
          ${journey.session_id ? `<span class="badge" style="font-size: 0.65rem;">${journey.session_id}</span>` : ''}
        </div>
        <div class="time-range">${formatDate(firstTime)} - ${formatDate(lastTime)} (${journey.event_count} events)</div>
      </div>
      <div class="timeline-steps">
        ${stepsHtml}
      </div>
      ${driftBanner}
    `;

    container.appendChild(card);
  });

  // Render the selected journey details
  const initialSelectedAlert = allAlerts.find(a => 
    a.user_id === filteredJourneys[selectedJourneyIndex]?.user_id
  ) || allAlerts[0];

  renderAlertDetails(initialSelectedAlert, filteredJourneys[selectedJourneyIndex]);
}

// 4. Render Explainable Alert Details (Section C)
function renderAlertDetails(alert, journey) {
  const panel = document.getElementById('details-panel');

  if (!alert) {
    panel.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">👈</div>
        <h3>No Journey Selected</h3>
        <p>Select a journey from the timeline to view explainable risk intelligence.</p>
      </div>
    `;
    return;
  }

  const risk = alert.risk_assessment || { score: 0, severity: 'LOW', triggered_factors: [], factor_breakdown: {} };
  const sevClass = `risk-${risk.severity ? risk.severity.toLowerCase() : 'low'}`;
  const evidence = alert.context_evidence || {};

  const formatFlag = (val) => {
    if (val === true) return '<span class="evidence-val flagged">⚠️ Confirmed New</span>';
    if (val === false) return '<span class="evidence-val">✅ Known / Baseline</span>';
    return '<span class="evidence-val" style="color: var(--text-muted);">Unavailable</span>';
  };

  let factorListHtml = '';
  if (risk.factor_breakdown && Object.keys(risk.factor_breakdown).length > 0) {
    for (const [factor, pts] of Object.entries(risk.factor_breakdown)) {
      factorListHtml += `
        <li class="factor-item">
          <span class="factor-name">${factor}</span>
          <span class="factor-pts">+${pts} pts</span>
        </li>
      `;
    }
  } else {
    factorListHtml = `<li class="factor-item" style="color: var(--text-muted);">No elevated risk factors triggered.</li>`;
  }

  panel.innerHTML = `
    <div class="alert-header">
      <div>
        <h3 style="color: #ffffff; font-size: 1.1rem; font-weight: 700;">Journey: ${alert.user_id}</h3>
        <p style="color: var(--text-muted); font-size: 0.75rem; font-family: var(--font-mono);">
          Alert ID: ${alert.alert_id} &bull; Actionable: ${alert.is_actionable ? '🚨 Yes' : 'ℹ️ Informational'}
        </p>
      </div>
      <div class="risk-badge ${sevClass}">
        ${risk.severity} RISK (${risk.score}/100)
      </div>
    </div>

    <div>
      <h4 class="section-title">Detection Explanation (Balaa Engine)</h4>
      <div class="explanation-box">
        ${alert.explanation}
      </div>
    </div>

    <div>
      <h4 class="section-title">Contextual Evidence Signals</h4>
      <div class="context-evidence-grid">
        <div class="evidence-item">
          <div class="evidence-key">Device Anomaly</div>
          ${formatFlag(evidence.is_new_device)}
          ${evidence.device_id ? `<div style="font-size: 0.7rem; color: var(--text-secondary); margin-top: 2px;">${evidence.device_id}</div>` : ''}
        </div>
        <div class="evidence-item">
          <div class="evidence-key">Location Anomaly</div>
          ${formatFlag(evidence.is_location_changed)}
          ${evidence.location ? `<div style="font-size: 0.7rem; color: var(--text-secondary); margin-top: 2px;">${evidence.location}</div>` : ''}
        </div>
        <div class="evidence-item">
          <div class="evidence-key">Rogue Authenticator Registered</div>
          ${evidence.authenticator_registered ? '<span class="evidence-val flagged">⚠️ Persistence Flag</span>' : '<span class="evidence-val">None</span>'}
        </div>
        <div class="evidence-item">
          <div class="evidence-key">Prior Failures Count</div>
          <span class="evidence-val ${evidence.prior_failures_count > 0 ? 'flagged' : ''}">
            ${evidence.prior_failures_count} attempt(s)
          </span>
        </div>
      </div>
    </div>

    <div>
      <h4 class="section-title">Risk Scoring Breakdown</h4>
      <ul class="factor-breakdown-list">
        ${factorListHtml}
      </ul>
    </div>
  `;
}

// 5. Filter Logic (Section D)
function applyFilters() {
  const userQuery = document.getElementById('filter-user').value.trim().toLowerCase();
  const outcomeFilter = document.getElementById('filter-outcome').value;
  const severityFilter = document.getElementById('filter-severity').value;
  const driftOnly = document.getElementById('filter-drift-only').checked;

  const filtered = allJourneys.filter((journey, idx) => {
    // User filter
    if (userQuery && !journey.user_id.toLowerCase().includes(userQuery)) {
      return false;
    }

    // Outcome filter
    if (outcomeFilter) {
      const hasOutcome = journey.events.some(e => e.outcome === outcomeFilter);
      if (!hasOutcome) return false;
    }

    // Match alert
    const matchedAlert = allAlerts.find(a => 
      a.user_id === journey.user_id && (a.session_id === journey.session_id || !journey.session_id)
    ) || allAlerts[idx];

    // Severity filter
    if (severityFilter && matchedAlert?.risk_assessment?.severity !== severityFilter) {
      return false;
    }

    // Drift only
    if (driftOnly && !matchedAlert?.drift_detected) {
      return false;
    }

    return true;
  });

  selectedJourneyIndex = 0;
  renderJourneys(filtered);
}

// 6. Scenario Switcher
document.getElementById('btn-load-scenario').addEventListener('click', async () => {
  const scenario = document.getElementById('scenario-dropdown').value;
  try {
    const res = await fetch(`/api/scenarios/${scenario}/load`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to load scenario.');
    await loadData();
  } catch (err) {
    alert('Error loading scenario: ' + err.message);
  }
});

// 7. Filters Event Listeners
document.getElementById('filter-user').addEventListener('input', applyFilters);
document.getElementById('filter-outcome').addEventListener('change', applyFilters);
document.getElementById('filter-severity').addEventListener('change', applyFilters);
document.getElementById('filter-drift-only').addEventListener('change', applyFilters);

document.getElementById('btn-reset-filters').addEventListener('click', () => {
  document.getElementById('filter-user').value = '';
  document.getElementById('filter-outcome').value = '';
  document.getElementById('filter-severity').value = '';
  document.getElementById('filter-drift-only').checked = false;
  applyFilters();
});

// 8. Ingestion Modal Logic
const modal = document.getElementById('modal-ingest');
document.getElementById('btn-open-ingest').addEventListener('click', () => modal.classList.add('active'));
document.getElementById('btn-close-modal').addEventListener('click', () => modal.classList.remove('active'));

document.getElementById('btn-sample-kc').addEventListener('click', () => {
  document.getElementById('ingest-provider').value = 'keycloak';
  document.getElementById('raw-json-input').value = JSON.stringify([
    {
      "id": "kc-demo-01",
      "time": Date.now() - 30000,
      "type": "LOGIN_ERROR",
      "details": { "username": "rohan_demo", "auth_method": "passkey", "error": "user_cancelled" }
    },
    {
      "id": "kc-demo-02",
      "time": Date.now() - 10000,
      "type": "LOGIN",
      "details": { "username": "rohan_demo", "auth_method": "password" }
    }
  ], null, 2);
});

document.getElementById('btn-sample-okta').addEventListener('click', () => {
  document.getElementById('ingest-provider').value = 'okta';
  document.getElementById('raw-json-input').value = JSON.stringify([
    {
      "uuid": "okta-demo-01",
      "published": new Date(Date.now() - 40000).toISOString(),
      "eventType": "user.authentication.auth_via_mfa",
      "outcome": { "result": "FAILURE" },
      "actor": { "alternateId": "rohan_okta@company.com" },
      "authenticationContext": { "credentialProvider": "FIDO2 (WebAuthn)" }
    },
    {
      "uuid": "okta-demo-02",
      "published": new Date(Date.now() - 15000).toISOString(),
      "eventType": "user.authentication.authenticate",
      "outcome": { "result": "SUCCESS" },
      "actor": { "alternateId": "rohan_okta@company.com" },
      "authenticationContext": { "credentialProvider": "PASSWORD" }
    }
  ], null, 2);
});

document.getElementById('btn-submit-ingest').addEventListener('click', async () => {
  const provider = document.getElementById('ingest-provider').value;
  const rawText = document.getElementById('raw-json-input').value.trim();

  try {
    const parsed = JSON.parse(rawText);
    const events = Array.isArray(parsed) ? parsed : [parsed];

    const res = await fetch('/api/pipeline/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider, events, deduplicate: true })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Failed to process logs');
    }

    modal.classList.remove('active');
    await loadData();
  } catch (err) {
    alert('Invalid JSON or Pipeline Error: ' + err.message);
  }
});

// Initial boot
loadData();

