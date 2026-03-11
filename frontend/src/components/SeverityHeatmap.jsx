import { SEVERITY_COLORS, SEVERITY_LABELS, SCENARIO_LABELS } from '../hooks/useApi';

export default function SeverityHeatmap({ scenarios }) {
  if (!scenarios || scenarios.length === 0) return null;

  const severityOrder = ['critical', 'high', 'medium', 'low'];

  // Build matrix: scenario x severity -> count
  const matrix = {};
  scenarios.forEach((s) => {
    matrix[s.scenario_name] = { critical: 0, high: 0, medium: 0, low: 0 };
    (s.patterns_found || []).forEach((p) => {
      const sev = p.severity || 'medium';
      if (matrix[s.scenario_name][sev] !== undefined) {
        matrix[s.scenario_name][sev]++;
      }
    });
  });

  const maxCount = Math.max(
    1,
    ...Object.values(matrix).flatMap((row) => Object.values(row))
  );

  return (
    <div className="severity-heatmap">
      <h3>Severity Heatmap</h3>
      <div className="heatmap-grid">
        {/* Header row */}
        <div className="heatmap-cell heatmap-corner" />
        {severityOrder.map((sev) => (
          <div
            key={sev}
            className="heatmap-cell heatmap-header"
            style={{ color: SEVERITY_COLORS[sev] }}
          >
            {SEVERITY_LABELS[sev]}
          </div>
        ))}

        {/* Data rows */}
        {scenarios.map((s) => (
          <div key={s.scenario_name} className="heatmap-row">
            <div className="heatmap-cell heatmap-label">
              <span role="img" aria-hidden="true">{SCENARIO_LABELS[s.scenario_name]?.icon || '>'}</span>
              {SCENARIO_LABELS[s.scenario_name]?.label || s.scenario_name}
            </div>
            {severityOrder.map((sev) => {
              const count = matrix[s.scenario_name]?.[sev] || 0;
              const opacity = count > 0 ? 0.3 + (count / maxCount) * 0.7 : 0.05;
              return (
                <div
                  key={sev}
                  className="heatmap-cell heatmap-value"
                  style={{
                    backgroundColor: SEVERITY_COLORS[sev],
                    opacity,
                  }}
                >
                  {count > 0 ? count : '-'}
                </div>
              );
            })}
          </div>
        ))}
      </div>

      {/* Summary stats */}
      <div className="heatmap-summary">
        {severityOrder.map((sev) => {
          const total = Object.values(matrix).reduce((sum, row) => sum + row[sev], 0);
          return (
            <div key={sev} className="summary-stat">
              <span
                className="summary-dot"
                style={{ backgroundColor: SEVERITY_COLORS[sev] }}
              />
              <span className="summary-label">{SEVERITY_LABELS[sev]}</span>
              <span className="summary-count">{total}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
