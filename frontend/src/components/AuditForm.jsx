import { useState } from 'react';
import { startAudit, SCENARIO_LABELS } from '../hooks/useApi';

const PRESET_URLS = [
  { label: 'Amazon', url: 'https://www.amazon.com' },
  { label: 'Facebook', url: 'https://www.facebook.com/settings' },
  { label: 'LinkedIn', url: 'https://www.linkedin.com/premium' },
];

export default function AuditForm({ onAuditStarted }) {
  const [url, setUrl] = useState('');
  const [selectedScenarios, setSelectedScenarios] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const toggleScenario = (key) => {
    setSelectedScenarios((prev) =>
      prev.includes(key) ? prev.filter((s) => s !== key) : [...prev, key]
    );
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    setLoading(true);
    setError('');

    try {
      let targetUrl = url.trim();
      if (!targetUrl.startsWith('http')) targetUrl = `https://${targetUrl}`;

      const scenarios = selectedScenarios.length > 0 ? selectedScenarios : null;
      const result = await startAudit(targetUrl, scenarios);
      onAuditStarted(result.audit_id, targetUrl);
    } catch (err) {
      setError(err.message || 'Failed to start audit');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="audit-form">
      <div className="form-header">
        <h2>Scan a Website</h2>
        <p>Enter a URL to detect dark patterns in its UI</p>
      </div>

      <form onSubmit={handleSubmit}>
        <div className="url-input-group">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            disabled={loading}
            className="url-input"
          />
          <button type="submit" disabled={loading} className="scan-button">
            {loading ? (
              <span className="loading-spinner">Launching Agent...</span>
            ) : (
              'Scan'
            )}
          </button>
        </div>

        {error && <div className="error-message">{error}</div>}

        <div className="preset-urls">
          {PRESET_URLS.map((preset) => (
            <button
              key={preset.url}
              type="button"
              onClick={() => setUrl(preset.url)}
              className="preset-button"
              disabled={loading}
            >
              {preset.label}
            </button>
          ))}
        </div>

        <div className="scenario-selector">
          <p className="scenario-label">Scenarios (leave empty for all):</p>
          <div className="scenario-chips">
            {Object.entries(SCENARIO_LABELS).map(([key, { label, icon }]) => (
              <button
                key={key}
                type="button"
                onClick={() => toggleScenario(key)}
                className={`scenario-chip ${selectedScenarios.includes(key) ? 'active' : ''}`}
                disabled={loading}
              >
                <span role="img" aria-hidden="true">{icon}</span> {label}
              </button>
            ))}
          </div>
        </div>
      </form>
    </div>
  );
}
