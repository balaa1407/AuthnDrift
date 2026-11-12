/**
 * AuthDrift Frontend Application
 * Interacts with AuthDrift FastAPI backend to render:
 * A. Authentication Overview Metrics
 * B. Authentication Journey Timelines with IP, Context, and Lifecycle Stage separation
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

// Match a journey to its own alert. The API links them via alert_id; fall back to
// user + session only for older payloads. Never match on user alone: a user can have
// several journeys (e.g. Bengaluru then Berlin) that each carry different location context.
function findAlertForJourney(journey) {
  if (!journey) return null;
  if (journey.alert_id) {
    return allAlerts.find(a => a.alert_id === journey.alert_id) || null;
  }
  return allAlerts.find(a =>
    a.user_id === journey.user_id && a.session_id === journey.session_id
  ) || null;
}

function escapeHtml(val) {
  if (val === null || val === undefined) return '';
  return String(val)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatThreatIntelStatus(rep) {
  if (!rep || rep.status === 'UNKNOWN') return '<span style="color: var(--text-muted);">UNKNOWN / Unchecked</span>';
  if (rep.status === 'KNOWN_MALICIOUS') return '<span class="loc-status-badge" style="background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); padding: 2px 6px; border-radius: 4px; font-weight: 700;">🚨 KNOWN MALICIOUS</span>';
  if (rep.status === 'SUSPICIOUS') return '<span class="loc-status-badge" style="background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); padding: 2px 6px; border-radius: 4px; font-weight: 600;">⚠️ SUSPICIOUS</span>';
  if (rep.status === 'CLEAN') return '<span class="loc-status-badge" style="background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); padding: 2px 6px; border-radius: 4px; font-weight: 600;">✅ CLEAN</span>';
  if (rep.status === 'PRIVATE') return '<span class="loc-status-badge" style="background: rgba(148, 163, 184, 0.2); color: #94a3b8; padding: 2px 6px; border-radius: 4px;">🏠 PRIVATE / LOCAL</span>';
  return escapeHtml(rep.status);
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

// Live UTC Telemetry Clock
function updateLiveClock() {
  const el = document.getElementById('live-clock');
  if (el) {
    const now = new Date();
    el.textContent = now.toUTCString().slice(17, 25) + ' UTC';
  }
}
setInterval(updateLiveClock, 1000);
setTimeout(updateLiveClock, 50);

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
    const matchedAlert = findAlertForJourney(journey);

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
      const isSuccess = ev.outcome === 'SUCCESS';
      const category = ev.event_category || 'AUTHENTICATION';

      // Domain-restricted assurance representation
      let assuranceBadge = '';
      if (ev.effective_assurance) {
        assuranceBadge = `<span class="badge-assurance assurance-${ev.effective_assurance.toLowerCase()}">${ev.effective_assurance}</span>`;
      } else if (ev.attempted_assurance) {
        assuranceBadge = `<span class="badge-assurance assurance-${ev.attempted_assurance.toLowerCase()}" title="Attempted (Failed)">${ev.attempted_assurance} (Att)</span>`;
      } else if (category === 'SESSION_LIFECYCLE') {
        assuranceBadge = `<span class="badge-assurance" style="background: rgba(148, 163, 184, 0.2); color: #94a3b8;" title="Non-interactive session lifecycle">SESSION</span>`;
      } else if (category === 'ACCOUNT_LIFECYCLE') {
        assuranceBadge = `<span class="badge-assurance" style="background: rgba(148, 163, 184, 0.2); color: #94a3b8;" title="Account factor mutation">ACCOUNT</span>`;
      } else {
        const rawAssurance = getAssuranceLevel(ev.authentication_method);
        assuranceBadge = `<span class="badge-assurance assurance-${rawAssurance.toLowerCase()}">${rawAssurance}</span>`;
      }

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
            <span class="badge-category" style="font-size: 0.65rem; background: rgba(255, 255, 255, 0.08); padding: 2px 6px; border-radius: 4px; color: var(--text-muted);">${category}</span>
            ${assuranceBadge}
            <span class="step-method">${ev.authentication_method}</span>
            <span class="badge-outcome outcome-${isSuccess ? 'success' : 'failure'}">${ev.outcome}</span>
            <div class="step-context">${contextTagsHtml}</div>
          </div>
          <span class="step-time">${formatDate(ev.timestamp)}</span>
        </div>
      `;
    });

    let driftBanner = '';
    if (matchedAlert?.is_recovery_candidate) {
      driftBanner = `
        <div class="drift-transition-banner" style="background: rgba(16, 185, 129, 0.12); border-color: rgba(16, 185, 129, 0.35); color: #34d399;">
          <span>✅ <strong>Legitimate Recovery Candidate:</strong> Hardware &amp; IP continuity verified (Fallback exempt from drift alert per autonomous client continuity policy)</span>
        </div>
      `;
    } else if (hasDrift && matchedAlert?.drift_result) {
      const prev = matchedAlert.drift_result.previous_assurance || 'HIGH';
      const curr = matchedAlert.drift_result.current_assurance || 'LOW';
      const transitionCitation = (matchedAlert.source_event_id && matchedAlert.target_event_id)
        ? ` &bull; <code>${matchedAlert.source_event_id} ➔ ${matchedAlert.target_event_id}</code>`
        : '';
      driftBanner = `
        <div class="drift-transition-banner">
          <span>⚠️ <strong>Assurance Drift:</strong> ${prev} ➔ ${curr} (${matchedAlert.drift_result.transition_type || 'DOWNGRADE'})${transitionCitation}</span>
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
          ${matchedAlert?.is_recovery_candidate ? '<span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #34d399; font-size: 0.65rem; font-weight: 700; border: 1px solid rgba(16, 185, 129, 0.4);">RECOVERY CANDIDATE</span>' : ''}
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
  const selectedJourney = filteredJourneys[selectedJourneyIndex];
  renderAlertDetails(findAlertForJourney(selectedJourney), selectedJourney);
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

  // Structured Contextual Anomalies rendering
  let anomaliesHtml = '';
  const anomalies = alert.context_anomalies || evidence.context_anomalies || [];
  if (anomalies.length > 0) {
    anomaliesHtml = `
      <div>
        <h4 class="section-title">Contextual Anomalies & Telemetry Deltas (${anomalies.length})</h4>
        <div class="anomalies-list" style="display: flex; flex-direction: column; gap: 0.5rem;">
          ${anomalies.map(a => `
            <div class="anomaly-card" style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 6px; padding: 0.6rem;">
              <div style="display: flex; justify-content: space-between; font-size: 0.75rem; font-weight: 600; color: #f87171;">
                <span>⚠️ ${escapeHtml(a.anomaly_type.replace('_', ' '))}</span>
                <span style="color: var(--text-muted); font-size: 0.7rem;">${escapeHtml(a.lifecycle_stage)}</span>
              </div>
              <div style="font-size: 0.8rem; margin-top: 0.25rem; color: #e2e8f0;">
                <code>${escapeHtml(a.previous_value || 'BASELINE')}</code> ➔ <strong><code>${escapeHtml(a.current_value)}</code></strong>
              </div>
              ${a.target_event_id ? `<div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.25rem;">Events: ${a.source_event_id ? '<code>' + escapeHtml(a.source_event_id) + '</code> ➔ ' : ''}<code>${escapeHtml(a.target_event_id)}</code></div>` : ''}
              ${a.is_impossible_travel ? `
                <div style="background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.5); border-radius: 4px; padding: 0.35rem 0.5rem; margin-top: 0.35rem; font-size: 0.72rem; color: #fca5a5; display: flex; align-items: center; justify-content: space-between;">
                  <span>🚀 <strong>GEODESIC VELOCITY VIOLATION:</strong> Physical travel impossibility (&gt;900 km/h)</span>
                  <span style="font-family: var(--font-mono); font-weight: 700; color: #ef4444;">${a.velocity_kmh ? Math.round(a.velocity_kmh).toLocaleString() + ' km/h' : 'SUPERSONIC'}</span>
                </div>
              ` : ''}
              ${a.subnet_continuity !== undefined && a.subnet_continuity !== null ? `
                <div style="font-size: 0.7rem; margin-top: 0.25rem;">
                  Subnet Continuity: ${a.subnet_continuity ? '<span style="color: #34d399; font-weight: 600;">✅ Verified Same Subnet (/24 lease continuity)</span>' : '<span style="color: #f87171; font-weight: 600;">⚠️ Disparate Subnet Hop</span>'}
                </div>
              ` : ''}
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  // Structured Failed Authentications rendering
  let failedAuthHtml = '';
  const failedAuths = alert.failed_authentications || [];
  if (failedAuths.length > 0) {
    failedAuthHtml = `
      <div>
        <h4 class="section-title">Failed Authentication Attempts (${failedAuths.length})</h4>
        <div class="failed-auths-list" style="display: flex; flex-direction: column; gap: 0.4rem;">
          ${failedAuths.map(f => `
            <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 6px; padding: 0.5rem; font-size: 0.75rem;">
              <div style="display: flex; justify-content: space-between;">
                <span style="font-weight: 600; color: #fbbf24;">❌ ${escapeHtml(f.authentication_method || 'Unknown Method')}</span>
                <span style="color: var(--text-muted);">${formatDate(f.timestamp)}</span>
              </div>
              <div style="color: var(--text-secondary); margin-top: 0.2rem; font-size: 0.7rem;">
                ${f.location ? `📍 ${escapeHtml(f.location)}` : ''} ${f.ip_address ? `🌐 ${escapeHtml(f.ip_address)}` : ''} ${f.event_id ? `<code>${escapeHtml(f.event_id)}</code>` : ''}
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  const alertType = alert.alert_type || (alert.drift_detected ? 'ASSURANCE_DRIFT' : 'INFORMATIONAL');
  let alertTypeClass = 'alert-type-info';
  if (alertType === 'ASSURANCE_DRIFT') alertTypeClass = 'alert-type-drift';
  else if (alertType === 'CONTEXTUAL_ANOMALY') alertTypeClass = 'alert-type-context';

  const riskScore = Math.min(100, Math.max(0, risk.score || 0));
  const scoreColor = riskScore >= 75 ? '#ef4444' : riskScore >= 50 ? '#f97316' : riskScore >= 25 ? '#fbbf24' : '#10b981';
  const scoreGlow = riskScore >= 75 ? 'rgba(239, 68, 68, 0.5)' : riskScore >= 50 ? 'rgba(249, 115, 22, 0.4)' : riskScore >= 25 ? 'rgba(251, 191, 36, 0.3)' : 'rgba(16, 185, 129, 0.35)';

  const caseCategory = alert.case_category || evidence.case_category || null;
  const recovClass = alert.recovery_classification || evidence.recovery_classification || null;

  const formatPrimaryMatch = (val) => {
    if (val === true) return '<span style="color: #34d399; font-weight: 700;">✅ Matched Baseline</span>';
    if (val === false) return '<span style="color: #f87171; font-weight: 700;">⚠️ Mismatch / Novel</span>';
    return '<span style="color: var(--text-muted);">Unestablished / Unavailable</span>';
  };

  panel.innerHTML = `
    <div class="alert-header">
      <div>
        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem; flex-wrap: wrap;">
          <h3 style="color: #ffffff; font-size: 1.15rem; font-weight: 700;">User: ${escapeHtml(alert.user_id)}</h3>
          <span class="badge-alert-type ${alertTypeClass}">${alertType.replace('_', ' ')}</span>
          ${caseCategory ? `<span class="badge" style="background: rgba(99, 102, 241, 0.16); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.35); font-size: 0.65rem; font-family: var(--font-mono);">${escapeHtml(caseCategory)}</span>` : ''}
        </div>
        <p style="color: var(--text-muted); font-size: 0.75rem; font-family: var(--font-mono);">
          Alert ID: ${escapeHtml(alert.alert_id)} &bull; Priority: ${escapeHtml(alert.priority || 'INFORMATIONAL')} &bull; Actionable: ${alert.is_actionable ? '🚨 Yes' : 'ℹ️ No'}${recovClass ? ` &bull; Calibration: ${escapeHtml(recovClass)}` : ''}
        </p>
      </div>
      <div class="risk-badge ${sevClass}">
        ${risk.severity} RISK (${risk.score}/100)
      </div>
    </div>

    <div style="background: rgba(13, 20, 36, 0.85); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: var(--radius-sm); padding: 0.9rem 1.15rem; margin-bottom: 0.25rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; font-family: var(--font-mono); font-size: 0.75rem;">
        <span style="color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.06em; font-weight: 700;">Deterministic Risk Exposure Gauge</span>
        <span style="font-weight: 800; color: ${scoreColor}; font-size: 0.9rem;">${riskScore} / 100 PTS</span>
      </div>
      <div style="width: 100%; height: 8px; background: rgba(255, 255, 255, 0.06); border-radius: 9999px; overflow: hidden; position: relative;">
        <div style="width: ${riskScore}%; height: 100%; background: linear-gradient(90deg, #10b981 0%, ${scoreColor} 100%); border-radius: 9999px; box-shadow: 0 0 12px ${scoreGlow}; transition: width 0.4s ease;"></div>
      </div>
      <div style="display: flex; justify-content: space-between; font-size: 0.65rem; color: var(--text-dim); margin-top: 0.35rem; font-family: var(--font-mono);">
        <span>0 LOW (NOMINAL)</span>
        <span>25 MEDIUM</span>
        <span>50 HIGH</span>
        <span>75+ CRITICAL</span>
      </div>
    </div>

    ${alert.is_recovery_candidate ? `
      <div style="background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.35); border-radius: 8px; padding: 0.8rem; margin-bottom: 1rem;">
        <div style="display: flex; align-items: center; gap: 0.5rem; color: #34d399; font-weight: 700; font-size: 0.85rem;">
          <span>🛡️ CLIENT CONTINUITY POLICY: RECOVERY EXEMPTION</span>
          <span style="font-size: 0.7rem; font-weight: 500; background: rgba(16, 185, 129, 0.2); padding: 2px 6px; border-radius: 4px;">Zero False Positive Protection</span>
        </div>
        <p style="font-size: 0.75rem; color: #cbd5e1; margin-top: 0.35rem; line-height: 1.4;">
          The user completed authentication fallback on their <strong>verified primary device and matching network subnet</strong>. Consistent with empirical authentication continuity studies (Wiefling et al., ACM ASIACCS), genuine recovery actions on verified client parameters are classified as legitimate recovery behavior rather than an active attack, preventing spurious security alerts.
        </p>
      </div>
    ` : ''}

    <div>
      <h4 class="section-title">Assurance Transition & Drift Analysis</h4>
      <div class="transition-grid">
        <div class="transition-node">
          <span class="transition-node-label">Prior Method & Assurance</span>
          <span class="transition-node-val">
            ${drift.previous_method || 'None'}
            ${drift.previous_assurance ? `(${drift.previous_assurance})` : ''}
          </span>
          ${alert.source_event_id ? `<span style="font-size: 0.65rem; color: var(--text-muted); margin-top: 2px;">Event: <code>${alert.source_event_id}</code></span>` : ''}
        </div>
        <div class="transition-arrow">➔</div>
        <div class="transition-node">
          <span class="transition-node-label">Subsequent Method & Assurance</span>
          <span class="transition-node-val">
            ${drift.current_method || 'None'}
            ${drift.current_assurance ? `(${drift.current_assurance})` : ''}
          </span>
          ${alert.target_event_id ? `<span style="font-size: 0.65rem; color: var(--text-muted); margin-top: 2px;">Event: <code>${alert.target_event_id}</code></span>` : ''}
        </div>
      </div>
      <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.25rem;">
        <strong>Detection Rule:</strong> <code>${drift.transition_type || 'NORMAL_JOURNEY'}</code> &bull;
        <strong>Status:</strong> ${alert.drift_detected ? '<span style="color: #fda4af; font-weight: 700;">DRIFT DETECTED</span>' : '<span style="color: #34d399; font-weight: 700;">NO DRIFT DETECTED</span>'}
      </div>
      ${alert.cryptographic_boundary ? `
        <div style="background: rgba(99, 102, 241, 0.08); border: 1px solid rgba(99, 102, 241, 0.3); border-radius: 6px; padding: 0.6rem 0.85rem; margin-top: 0.5rem;">
          <div style="font-size: 0.68rem; font-weight: 700; color: #a5b4fc; text-transform: uppercase; letter-spacing: 0.05em; font-family: var(--font-mono);">
            NIST SP 800-63B Cryptographic Boundary Transition
          </div>
          <div style="font-size: 0.8rem; color: #ffffff; font-weight: 600; margin-top: 0.2rem; font-family: var(--font-mono);">
            ${escapeHtml(alert.cryptographic_boundary)}
          </div>
        </div>
      ` : ''}
    </div>

    <div>
      <h4 class="section-title">Detection Explanation</h4>
      <div class="explanation-box">
        ${alert.explanation}
      </div>
    </div>

    ${anomaliesHtml}

    ${failedAuthHtml}

    <div>
      <h4 class="section-title">Contextual Evidence & Baselines</h4>
      <div class="context-evidence-grid">
        <div class="evidence-item">
          <div class="evidence-key">Device Status</div>
          ${formatFlag(evidence.is_new_device)}
          ${evidence.device_id ? `<div style="font-size: 0.7rem; color: var(--text-secondary); margin-top: 2px;">ID: ${evidence.device_id}</div>` : ''}
        </div>

        ${AuthDriftLocationView.buildLocationFieldsHtml({
          primary_location: evidence.primary_location,
          location: evidence.location,
          location_status: evidence.location_status,
          ip_address: evidence.ip_address
        })}

        <div class="evidence-item">
          <div class="evidence-key">Primary Hardware Continuity</div>
          <div class="evidence-val">${formatPrimaryMatch(evidence.is_primary_device_matched)}</div>
          ${evidence.primary_device ? `<div style="font-size: 0.7rem; color: var(--text-secondary); margin-top: 2px;">Baseline: <code>${escapeHtml(evidence.primary_device)}</code></div>` : ''}
        </div>

        <div class="evidence-item">
          <div class="evidence-key">Primary Network / IP Continuity</div>
          <div class="evidence-val">${formatPrimaryMatch(evidence.is_primary_ip_matched)}</div>
          ${evidence.primary_ip ? `<div style="font-size: 0.7rem; color: var(--text-secondary); margin-top: 2px;">Baseline: <code>${escapeHtml(evidence.primary_ip)}</code></div>` : ''}
        </div>

        <div class="evidence-item">
          <div class="evidence-key">Authenticator Registration</div>
          ${evidence.authenticator_registered ? '<span class="evidence-val flagged">⚠️ Explicitly Registered</span>' : '<span class="evidence-val">None (Usage Only)</span>'}
          ${evidence.authenticator_id ? `<div style="font-size: 0.7rem; color: var(--text-secondary); margin-top: 2px;">Key ID: ${evidence.authenticator_id}</div>` : ''}
        </div>

        <div class="evidence-item">
          <div class="evidence-key">Prior Failures Count</div>
          <span class="evidence-val ${evidence.prior_failures_count > 0 ? 'flagged' : ''}">
            ${evidence.prior_failures_count} attempt(s) observed in journey
          </span>
        </div>

        <div class="evidence-item">
          <div class="evidence-key">IP Threat Intelligence (${escapeHtml(evidence.ip_reputation?.provider || alert.ip_reputation?.provider || 'AbuseIPDB')})</div>
          <div class="evidence-val">
            ${formatThreatIntelStatus(evidence.ip_reputation || alert.ip_reputation)}
          </div>
          ${(evidence.ip_reputation || alert.ip_reputation)?.abuse_confidence_score !== undefined && (evidence.ip_reputation || alert.ip_reputation)?.abuse_confidence_score !== null ? `<div style="font-size: 0.7rem; color: var(--text-secondary); margin-top: 2px;">Abuse Score: <strong>${(evidence.ip_reputation || alert.ip_reputation).abuse_confidence_score}%</strong> &bull; Reports: ${(evidence.ip_reputation || alert.ip_reputation).total_reports ?? 0}</div>` : ''}
        </div>
      </div>
    </div>

    <div>
      <h4 class="section-title">Risk Scoring Breakdown</h4>
      <ul class="factor-breakdown-list">
        ${factorListHtml}
      </ul>
    </div>

    ${alert.actionable_remediation && alert.actionable_remediation.length > 0 ? `
      <div>
        <h4 class="section-title">Actionable SOC Remediation Guidance</h4>
        <div style="background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(59, 130, 246, 0.35); border-radius: 8px; padding: 0.85rem 1rem;">
          <ul style="margin: 0; padding-left: 1.2rem; display: flex; flex-direction: column; gap: 0.4rem; font-size: 0.78rem; color: #e2e8f0; line-height: 1.45;">
            ${alert.actionable_remediation.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
          </ul>
        </div>
      </div>
    ` : ''}

    <div style="margin-top: 0.5rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
        <h4 class="section-title" style="margin: 0;">Research &amp; Calibration Inference</h4>
        <button id="btn-run-calibration" class="btn btn-secondary" style="padding: 0.35rem 0.75rem; font-size: 0.72rem;">
          Run Calibration Audit
        </button>
      </div>
      <div id="calibration-result-box" style="background: rgba(13, 20, 36, 0.75); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; padding: 0.75rem 1rem; font-size: 0.78rem; color: var(--text-secondary);">
        Click <strong>Run Calibration Audit</strong> to verify confidence scoring, academic citation, and fallback memory alignment for this journey.
      </div>
    </div>
  `;

  const btnCalib = document.getElementById('btn-run-calibration');
  if (btnCalib) {
    btnCalib.addEventListener('click', async () => {
      const box = document.getElementById('calibration-result-box');
      box.innerHTML = '<span style="color: var(--text-muted);">Running calibration audit...</span>';
      try {
        const res = await fetch('/api/llm/calibrate-journey', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ user_id: alert.user_id, session_id: alert.session_id || journey?.session_id || null })
        });
        if (!res.ok) throw new Error('Calibration endpoint failed');
        const c = await res.json();
        const confPct = Math.round((c.confidence_score || 0) * 100);
        box.innerHTML = `
          <div style="display: flex; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.4rem;">
            <span><strong>Classification:</strong> <code>${escapeHtml(c.classification)}</code> (${escapeHtml(c.case_category)})</span>
            <span><strong>Confidence:</strong> <span style="color: #38bdf8; font-weight: 700;">${confPct}%</span> &bull; <strong>Action:</strong> <code>${escapeHtml(c.recommended_action)}</code></span>
          </div>
          <p style="margin: 0.25rem 0; color: #e2e8f0; line-height: 1.45;">${escapeHtml(c.reasoning)}</p>
          <div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.35rem;">Citation: ${escapeHtml(c.research_citation)}</div>
        `;
      } catch (err) {
        box.innerHTML = `<span style="color: #f87171;">Calibration failed: ${escapeHtml(err.message)}</span>`;
      }
    });
  }
}

// 5. Filter Logic (Section D)
function applyFilters() {
  const userQuery = document.getElementById('filter-user').value.trim().toLowerCase();
  const alertTypeFilter = document.getElementById('filter-alert-type') ? document.getElementById('filter-alert-type').value : '';
  const outcomeFilter = document.getElementById('filter-outcome').value;
  const severityFilter = document.getElementById('filter-severity').value;
  const driftOnly = document.getElementById('filter-drift-only').checked;

  const filtered = allJourneys.filter((journey) => {
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
    const matchedAlert = findAlertForJourney(journey);

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

// Fallback Memory Modal Controls
const memoryModal = document.getElementById('modal-memory');
const btnOpenMemory = document.getElementById('btn-open-memory');
const btnCloseMemory = document.getElementById('btn-close-memory-modal');
const btnSaveBaseline = document.getElementById('btn-save-baseline');

async function loadFallbackMemory() {
  const listEl = document.getElementById('memory-profiles-list');
  if (!listEl) return;
  try {
    const res = await fetch('/api/llm/fallback-memory');
    if (!res.ok) throw new Error('Failed to load fallback memory');
    const data = await res.json();
    const entries = Object.values(data.profiles || {});
    if (entries.length === 0) {
      listEl.innerHTML = '<p style="font-size: 0.78rem; color: var(--text-muted);">No baselines explicitly registered yet. Register a primary device and IP above to track continuity history.</p>';
      return;
    }
    listEl.innerHTML = entries.map(p => `
      <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 6px; padding: 0.6rem 0.8rem; font-size: 0.75rem;">
        <div style="display: flex; justify-content: space-between; font-weight: 700; color: #f8fafc;">
          <span>👤 ${escapeHtml(p.user_id)}</span>
          <span style="color: #34d399; font-family: var(--font-mono);">Recoveries: ${p.verified_recovery_count || 0}</span>
        </div>
        <div style="color: var(--text-secondary); margin-top: 0.25rem; font-family: var(--font-mono); font-size: 0.7rem;">
          Device: <code>${escapeHtml(p.primary_device || 'None')}</code> &bull; IP: <code>${escapeHtml(p.primary_ip || 'None')}</code>
        </div>
      </div>
    `).join('');
  } catch (err) {
    listEl.innerHTML = `<p style="font-size: 0.78rem; color: #f87171;">Error loading memory: ${escapeHtml(err.message)}</p>`;
  }
}

if (btnOpenMemory && memoryModal) {
  btnOpenMemory.addEventListener('click', () => {
    memoryModal.classList.add('active');
    loadFallbackMemory();
  });
}

if (btnCloseMemory && memoryModal) {
  btnCloseMemory.addEventListener('click', () => memoryModal.classList.remove('active'));
}

if (btnSaveBaseline) {
  btnSaveBaseline.addEventListener('click', async () => {
    const userId = document.getElementById('mem-user-id').value.trim();
    const primaryDevice = document.getElementById('mem-primary-device').value.trim();
    const primaryIp = document.getElementById('mem-primary-ip').value.trim();
    if (!userId) {
      alert('Please specify a User Identifier.');
      return;
    }
    try {
      const res = await fetch('/api/llm/register-baseline', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          primary_device: primaryDevice || null,
          primary_ip: primaryIp || null
        })
      });
      if (!res.ok) throw new Error('Registration failed');
      await loadFallbackMemory();
    } catch (err) {
      alert('Error registering baseline: ' + err.message);
    }
  });
}

// Initial boot
loadData();
