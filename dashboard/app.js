/**
 * AuthDrift Frontend Application
 * Interacts with AuthDrift FastAPI backend to render:
 * A. Authentication Overview Metrics
 * B. Authentication Journey Timelines with IP & Context separation
 * C. Explainable Security Intelligence & Alerts (Drift vs. Contextual Anomaly)
 * D. Filtering, Scenario Switching & Raw Log Ingestion
 */

let allJourneys = [];
let allAlerts = [];
let selectedJourneyIndex = 0;

// Method assurance helper aligned with NIST SP 800-63B relative model
function getAssuranceLevel(method) {
  if (!method) return 'LOW';
  const m = method.toLowerCase();
  if (['passkey', 'fido2', 'webauthn', 'hardware_token', 'client_cert', 'security_key', 'u2f'].includes(m)) return 'HIGH';
  if (['totp', 'authenticator_app', 'otp', 'sms_otp', 'sms', 'email_otp', 'push_notification', 'push'].includes(m)) return 'MEDIUM';
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
    // Find matching alert from detection engine
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
        contextTagsHtml += `<span class="context-tag" title="Geographic Location">📍 ${ev.location}</span>`;
      }
      if (ev.ip_address) {
        contextTagsHtml += `<span class="context-tag" title="IP Address">🌐 ${ev.ip_address}</span>`;
      }
      if (ev.authenticator_id) {
        contextTagsHtml += `<span class="context-tag" title="Authenticator ID">🔑 ${ev.authenticator_id}</span>`;
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

    const alertType = matchedAlert?.alert_type || (hasDrift ? 'ASSURANCE_DRIFT' : 'INFORMATIONAL');
    let alertTypeClass = 'alert-type-info';
    if (alertType === 'ASSURANCE_DRIFT') alertTypeClass = 'alert-type-drift';
    else if (alertType === 'CONTEXTUAL_ANOMALY') alertTypeClass = 'alert-type-context';

    card.innerHTML = `
      <div class="journey-header">
        <div class="user-badge">
          <span class="icon">👤</span>
          <span>${journey.user_id}</span>
          <span class="badge-alert-type ${alertTypeClass}">${alertType.replace('_', ' ')}</span>
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
  const drift = alert.drift_result || {};

  const formatFlag = (val) => {
    if (val === true) return '<span class="evidence-val flagged">⚠️ Confirmed New</span>';
    if (val === false) return '<span class="evidence-val">✅ Known / Baseline</span>';
    return '<span class="evidence-val" style="color: var(--text-muted);">Unavailable / Unconfigured</span>';
  };

  const formatLocStatus = (status) => {
    if (status === 'KNOWN') return '<span class="loc-status-badge loc-status-known">✅ KNOWN</span>';
    if (status === 'NEW') return '<span class="loc-status-badge loc-status-new">⚠️ NEW</span>';
    return '<span class="loc-status-badge loc-status-unknown">ℹ️ UNKNOWN (Insufficient History)</span>';
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

  const alertType = alert.alert_type || (alert.drift_detected ? 'ASSURANCE_DRIFT' : 'INFORMATIONAL');
  let alertTypeClass = 'alert-type-info';
  if (alertType === 'ASSURANCE_DRIFT') alertTypeClass = 'alert-type-drift';
  else if (alertType === 'CONTEXTUAL_ANOMALY') alertTypeClass = 'alert-type-context';

  panel.innerHTML = `
    <div class="alert-header">
      <div>
        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
          <h3 style="color: #ffffff; font-size: 1.15rem; font-weight: 700;">User: ${alert.user_id}</h3>
          <span class="badge-alert-type ${alertTypeClass}">${alertType.replace('_', ' ')}</span>
        </div>
        <p style="color: var(--text-muted); font-size: 0.75rem; font-family: var(--font-mono);">
          Alert ID: ${alert.alert_id} &bull; Priority: ${alert.priority || 'INFORMATIONAL'} &bull; Actionable: ${alert.is_actionable ? '🚨 Yes' : 'ℹ️ No'}
        </p>
      </div>
      <div class="risk-badge ${sevClass}">
        ${risk.severity} RISK (${risk.score}/100)
      </div>
    </div>

    <div>
      <h4 class="section-title">Assurance Transition & Drift Analysis</h4>
      <div class="transition-grid">
        <div class="transition-node">
          <span class="transition-node-label">Prior Method & Assurance</span>
          <span class="transition-node-val">
            ${drift.previous_method || 'None'}
            ${drift.previous_assurance ? `(${drift.previous_assurance})` : ''}
          </span>
        </div>
        <div class="transition-arrow">➔</div>
        <div class="transition-node">
          <span class="transition-node-label">Subsequent Method & Assurance</span>
          <span class="transition-node-val">
            ${drift.current_method || 'None'}
            ${drift.current_assurance ? `(${drift.current_assurance})` : ''}
          </span>
        </div>
      </div>
      <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.25rem;">
        <strong>Detection Rule:</strong> <code>${drift.transition_type || 'NORMAL_JOURNEY'}</code> &bull;
        <strong>Status:</strong> ${alert.drift_detected ? '<span style="color: #fda4af; font-weight: 700;">DRIFT DETECTED</span>' : '<span style="color: #34d399; font-weight: 700;">NO DRIFT</span>'}
      </div>
    </div>

    <div>
      <h4 class="section-title">Detection Explanation</h4>
      <div class="explanation-box">
        ${alert.explanation}
      </div>
    </div>

    <div>
      <h4 class="section-title">Contextual Evidence & Baselines</h4>
      <div class="context-evidence-grid">
        <div class="evidence-item">
          <div class="evidence-key">Device Status</div>
          ${formatFlag(evidence.is_new_device)}
          ${evidence.device_id ? `<div style="font-size: 0.7rem; color: var(--text-secondary); margin-top: 2px;">ID: ${evidence.device_id}</div>` : ''}
        </div>

        <div class="evidence-item">
          <div class="evidence-key">Location Status & Baseline</div>
          ${formatLocStatus(evidence.location_status)}
          <div style="font-size: 0.7rem; color: var(--text-secondary); margin-top: 4px;">
            Observed: <strong>${evidence.location || 'Unavailable'}</strong><br>
            Primary Baseline: <strong>${evidence.primary_location || 'Not Established'}</strong>
          </div>
        </div>

        <div class="evidence-item">
          <div class="evidence-key">IP Address</div>
          <div class="evidence-val" style="font-family: var(--font-mono); font-size: 0.8rem;">
            ${evidence.ip_address ? `🌐 ${evidence.ip_address}` : '<span style="color: var(--text-muted); font-weight: normal;">Unavailable</span>'}
          </div>
        </div>

        <div class="evidence-item">
          <div class="evidence-key">Authenticator Registration</div>
          ${evidence.authenticator_registered ? '<span class="evidence-val flagged">⚠️ Explicitly Registered</span>' : '<span class="evidence-val">None (Usage Only)</span>'}
          ${evidence.authenticator_id ? `<div style="font-size: 0.7rem; color: var(--text-secondary); margin-top: 2px;">Key ID: ${evidence.authenticator_id}</div>` : ''}
        </div>

        <div class="evidence-item" style="grid-column: span 2;">
          <div class="evidence-key">Prior Failures Count</div>
          <span class="evidence-val ${evidence.prior_failures_count > 0 ? 'flagged' : ''}">
            ${evidence.prior_failures_count} attempt(s) observed in journey
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
  const alertTypeFilter = document.getElementById('filter-alert-type') ? document.getElementById('filter-alert-type').value : '';
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

    // Alert Type filter
    if (alertTypeFilter && matchedAlert?.alert_type !== alertTypeFilter) {
      return false;
    }

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
if (document.getElementById('filter-alert-type')) {
  document.getElementById('filter-alert-type').addEventListener('change', applyFilters);
}
document.getElementById('filter-outcome').addEventListener('change', applyFilters);
document.getElementById('filter-severity').addEventListener('change', applyFilters);
document.getElementById('filter-drift-only').addEventListener('change', applyFilters);

document.getElementById('btn-reset-filters').addEventListener('click', () => {
  document.getElementById('filter-user').value = '';
  if (document.getElementById('filter-alert-type')) {
    document.getElementById('filter-alert-type').value = '';
  }
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
      "ipAddress": "192.168.1.100",
      "details": { "username": "demo_user", "auth_method": "passkey", "error": "user_cancelled", "location": "Bangalore, IN" }
    },
    {
      "id": "kc-demo-02",
      "time": Date.now() - 10000,
      "type": "LOGIN",
      "ipAddress": "192.168.1.100",
      "details": { "username": "demo_user", "auth_method": "password", "location": "Bangalore, IN" }
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
      "actor": { "alternateId": "demo_user@company.com" },
      "client": { "ipAddress": "203.0.113.19", "geographicalContext": { "city": "San Francisco", "country": "United States" } },
      "authenticationContext": { "credentialProvider": "FIDO2 (WebAuthn)" }
    },
    {
      "uuid": "okta-demo-02",
      "published": new Date(Date.now() - 15000).toISOString(),
      "eventType": "user.authentication.authenticate",
      "outcome": { "result": "SUCCESS" },
      "actor": { "alternateId": "demo_user@company.com" },
      "client": { "ipAddress": "203.0.113.19", "geographicalContext": { "city": "San Francisco", "country": "United States" } },
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
