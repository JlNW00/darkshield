import { useState, useEffect } from 'react';
import { getAudit, getAuditPatterns, getReportUrl } from '../hooks/useApi';
import SeverityHeatmap from './SeverityHeatmap';
import PatternDetail from './PatternDetail';

export default function ReportView({ auditId, onBack }) {
  const [audit, setAudit] = useState(null);
  const [patterns, setPatterns] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [expandedPattern, setExpandedPattern] = useState(null);

  useEffect(() => {
    async function loadData() {
      try {
        const [auditData, patternData] = await Promise.all([
          getAudit(auditId),
          getAuditPatterns(auditId),
        ]);
        setAudit(auditData);
        setPatterns(patternData);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [auditId]);

  if (loading) return <div className="loading">Loading audit results...</div>;
  if (error) return <div className="error-message">{error}</div>;
  if (!audit) return null;

  const riskLevel =
    audit.risk_score >= 7 ? 'critical' :
    audit.risk_score >= 4 ? 'high' :
    audit.risk_score >= 2 ? 'medium' : 'low';

  const riskColors = {
    critical: '#dc2626',
    high: '#ef4444',
    medium: '#f59e0b',
    low: '#22c55e',
  };

  // Map classifications by pattern_id
  const classMap = {};
  (patterns?.classifications || []).forEach((c) => {
    classMap[c.pattern_id] = c;
  });

  const allPatterns = patterns?.patterns || [];

  return (
    <div className="report-view">
      <div className="report-header">
        <button onClick={onBack} className="back-button">
          Back
        </button>
        <h2>Audit Report</h2>
        <a
          href={`${getReportUrl(auditId)}`}
          target="_blank"
          rel="noopener"
          className="download-button"
        >
          Download PDF
        </a>
      </div>

      {/* Risk Score */}
      <div className="risk-score-card">
        <div className="risk-score-circle" style={{ borderColor: riskColors[riskLevel] }}>
          <span className="risk-number">{audit.risk_score}</span>
          <span className="risk-max">/10</span>
        </div>
        <div className="risk-info">
          <h3 style={{ color: riskColors[riskLevel] }}>
            {riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1)} Risk
          </h3>
          <p>{audit.total_patterns} dark patterns detected across {audit.scenarios?.length || 0} scenarios</p>
          <p className="risk-url">{audit.target_url}</p>
          <p className="risk-time">
            Completed: {audit.completed_at ? new Date(audit.completed_at).toLocaleString() : 'In progress'}
          </p>
        </div>
      </div>

      {/* Severity Heatmap */}
      <SeverityHeatmap scenarios={audit.scenarios || []} />

      {/* Scenario Breakdown */}
      <div className="scenario-breakdown">
        <h3>Scenario Results</h3>
        {(audit.scenarios || []).map((scenario) => (
          <div key={scenario.scenario_name} className="scenario-section">
            <div className="scenario-header">
              <h4>{scenario.scenario_name.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())}</h4>
              <span className="scenario-stats">
                {scenario.patterns_found?.length || 0} patterns | {scenario.steps_taken} steps | {scenario.duration_seconds}s
              </span>
            </div>

            {(scenario.patterns_found || []).length === 0 ? (
              <p className="no-patterns">No dark patterns detected in this scenario.</p>
            ) : (
              <div className="patterns-list">
                {(scenario.patterns_found || []).map((pattern) => (
                  <div
                    key={pattern.pattern_id}
                    className={`pattern-card ${expandedPattern === pattern.pattern_id ? 'expanded' : ''}`}
                    onClick={() =>
                      setExpandedPattern(
                        expandedPattern === pattern.pattern_id ? null : pattern.pattern_id
                      )
                    }
                  >
                    <PatternDetail
                      pattern={pattern}
                      classification={classMap[pattern.pattern_id]}
                    />
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
