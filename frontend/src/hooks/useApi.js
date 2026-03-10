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
    throw new Error(err.detail || 'Failed to start audit');
  }
  return res.json();
}

export async function getAudit(auditId) {
  const res = await fetch(`${API_BASE}/api/v1/audit/${auditId}`);
  if (!res.ok) throw new Error('Audit not found');
  return res.json();
}

export async function getAuditPatterns(auditId) {
  const res = await fetch(`${API_BASE}/api/v1/audit/${auditId}/patterns`);
  if (!res.ok) throw new Error('Patterns not found');
  return res.json();
}

export async function listAudits() {
  const res = await fetch(`${API_BASE}/api/v1/audits`);
  if (!res.ok) throw new Error('Failed to list audits');
  return res.json();
}

export async function deleteAudit(auditId) {
  const res = await fetch(`${API_BASE}/api/v1/audit/${auditId}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to delete audit');
  return res.json();
}

export async function getReportUrl(auditId) {
  return `${API_BASE}/api/v1/audit/${auditId}/report`;
}

export async function healthCheck() {
  const res = await fetch(`${API_BASE}/api/v1/health`);
  return res.json();
}

export function connectAuditWebSocket(auditId, onEvent) {
  const ws = new WebSocket(`${WS_BASE}/api/v1/ws/audit/${auditId}`);
  let pingInterval;

  ws.onopen = () => {
    console.log(`[WS] Connected to audit ${auditId}`);
    pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send('ping');
    }, 25000);
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type !== 'keepalive') {
        onEvent(data);
      }
    } catch {
      // ignore non-JSON (like pong)
    }
  };

  ws.onerror = (err) => console.error('[WS] Error:', err);

  ws.onclose = () => {
    console.log(`[WS] Disconnected from audit ${auditId}`);
    clearInterval(pingInterval);
  };

  return {
    close: () => {
      clearInterval(pingInterval);
      ws.close();
    },
    ws,
  };
}

export const SCENARIO_LABELS = {
  cookie_consent: { label: 'Cookie Consent', icon: '🍪', color: '#f59e0b' },
  subscription_cancel: { label: 'Subscription Cancel', icon: '💳', color: '#ef4444' },
  checkout_flow: { label: 'Checkout Flow', icon: '🛒', color: '#8b5cf6' },
  account_deletion: { label: 'Account Deletion', icon: '🗑️', color: '#ec4899' },
};

export const SEVERITY_COLORS = {
  low: '#22c55e',
  medium: '#f59e0b',
  high: '#ef4444',
  critical: '#dc2626',
};

export const SEVERITY_LABELS = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
};
