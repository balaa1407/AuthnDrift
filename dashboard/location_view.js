/**
 * AuthDrift: Location evidence view helpers.
 * Pure functions (no DOM access) so they can be unit-tested under Node.
 * Primary location, observed location, status and IP address are rendered as
 * separate, labeled fields. Missing values render as "Not available".
 */
(function (root) {
  const NOT_AVAILABLE = 'Not available';

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function textOrNotAvailable(value) {
    if (value === null || value === undefined) return NOT_AVAILABLE;
    const text = String(value).trim();
    return text ? escapeHtml(text) : NOT_AVAILABLE;
  }

  function normalizeStatus(status) {
    return ['KNOWN', 'NEW', 'UNKNOWN'].includes(status) ? status : 'UNKNOWN';
  }

  function formatLocationStatus(status) {
    const s = normalizeStatus(status);
    if (s === 'KNOWN') return '<span class="loc-status-badge loc-status-known" data-field="status">KNOWN</span>';
    if (s === 'NEW') return '<span class="loc-status-badge loc-status-new" data-field="status">NEW</span>';
    return '<span class="loc-status-badge loc-status-unknown" data-field="status">UNKNOWN</span>';
  }

  /**
   * @param {{primary_location?: string|null, location?: string|null,
   *          location_status?: string, ip_address?: string|null}} ctx
   * @returns {string} HTML for the four location evidence fields.
   */
  function buildLocationFieldsHtml(ctx) {
    const c = ctx || {};
    const item = (label, field, valueHtml) => `
        <div class="evidence-item">
          <div class="evidence-key">${label}</div>
          <div class="evidence-val" data-field="${field}">${valueHtml}</div>
        </div>`;
    return [
      item('Primary Location', 'primary_location', textOrNotAvailable(c.primary_location)),
      item('Observed Location', 'location', textOrNotAvailable(c.location)),
      item('Location Status', 'location_status', formatLocationStatus(c.location_status)),
      item('IP Address', 'ip_address',
        `<span style="font-family: var(--font-mono); font-size: 0.8rem;">${textOrNotAvailable(c.ip_address)}</span>`)
    ].join('');
  }

  const api = { NOT_AVAILABLE, escapeHtml, textOrNotAvailable, formatLocationStatus, buildLocationFieldsHtml };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.AuthDriftLocationView = api;
})(typeof window !== 'undefined' ? window : globalThis);
