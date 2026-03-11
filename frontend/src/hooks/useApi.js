/**
 * DarkShield API Hook - Centralized API calls and WebSocket management.
 */
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const WS_BASE = API_BASE.replace('http', 'ws');

export async function startAudit(url, scenarios = null) {
  const body = { url };
  if (scenarios) body.scenarios = scenarios;

  const res = await fetch(`${API_BASE}/api/v1/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }

  return res.json();
}

export async function getAudit(auditId) {
  const res = await fetch(`${API_BASE}/api/v1/audit/${auditId}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function getAuditPatterns(auditId) {
  const res = await fetch(`${API_BASE}/api/v1/audit/${auditId}/patterns`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function listAudits() {
  const res = await fetch(`${API_BASE}/api/v1/audits`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/**
 * Returns the report PDF download URL (synchronous -- no async needed).
 */
export function getReportUrl(auditId) {
  return `${API_BASE}/api/v1/audit/${auditId}/report`;
}

/**
 * Connect to the audit WebSocket for real-time events.
 * Returns { ws, close } where ws is the WebSocket instance.
 */
export function connectAuditWebSocket(auditId, onMessage, onError) {
  const ws = new WebSocket(`${WS_BASE}/api/v1/ws/audit/${auditId}`);

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      // Backend sends 'keepalive' (not 'heartbeat') — filter it out
      if (data.type !== 'keepalive') {
        onMessage(data);
      }
    } catch (e) {
      console.error('WS parse error:', e);
    }
  };

  ws.onerror = (event) => {
    console.error('WS error:', event);
    if (onError) onError(event);
  };

  ws.onclose = () => {
    console.log('WS closed for audit:', auditId);
  };

  return {
    ws,
    close: () => ws.close(),
  };
}

// Severity colors and labels for consistent UI
export const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

export const SEVERITY_LABELS = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

// Each entry must be { label, icon } — consumed by AuditForm, AuditStatus,
// PatternDetail, and SeverityHeatmap via destructuring / .label / .icon access.
export const SCENARIO_LABELS = {
  cookie_consent:      { label: 'Cookie Consent',      icon: '🍪' },
  subscription_cancel: { label: 'Subscription Cancel',  icon: '📋' },
  checkout_flow:       { label: 'Checkout Flow',         icon: '🛒' },
  account_deletion:    { label: 'Account Deletion',      icon: '🗑️' },
};
