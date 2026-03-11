import { SEVERITY_COLORS, SEVERITY_LABELS, SCENARIO_LABELS } from '../hooks/useApi';

export default function PatternDetail({ pattern, classification }) {
  // classification is a plain dict returned directly from the backend classify() call.
  // Field names match what classifier.py returns: category, confidence, explanation,
  // oecdreference (string), remediation (string).
  const sev = classification?.severity || pattern?.severity || 'medium';
  const category = classification?.category || pattern?.category || 'unknown';
  const confidence = classification?.confidence || pattern?.confidence || 0;

  // Backend taxonomy keys from classifier.py TAXONOMY dict
  const categoryLabels = {
    asymmetric_choice:     'Asymmetric Choice',
    confirmshaming:        'Confirmshaming',
    forced_consent:        'Forced Consent',
    hidden_costs:          'Hidden Costs',
    interface_interference:'Interface Interference',
    misdirection:          'Misdirection',
    nagging:               'Nagging',
    obstruction:           'Obstruction',
    sneaking:              'Sneaking',
    urgency:               'Urgency',
  };

  const scenarioInfo = SCENARIO_LABELS[pattern?.scenario] || {};

  return (
    <div className="pattern-detail">
      <div className="pattern-header">
        <div
          className="severity-badge"
          style={{ backgroundColor: SEVERITY_COLORS[sev] }}
        >
          {SEVERITY_LABELS[sev]}
        </div>
        <span className="pattern-category">
          {categoryLabels[category] || category}
        </span>
        <span className="pattern-scenario">
          <span role="img" aria-hidden="true">{scenarioInfo.icon}</span> {scenarioInfo.label || pattern?.scenario}
        </span>
      </div>

      <div className="pattern-body">
        <p className="pattern-description">
          {classification?.description || pattern?.description}
        </p>

        {confidence > 0 && (
          <div className="confidence-bar">
            <span className="confidence-label">
              AI Confidence: {Math.round(confidence * 100)}%
            </span>
            <div className="confidence-track">
              <div
                className="confidence-fill"
                style={{
                  width: `${confidence * 100}%`,
                  backgroundColor:
                    confidence > 0.8
                      ? '#22c55e'
                      : confidence > 0.6
                      ? '#f59e0b'
                      : '#ef4444',
                }}
              />
            </div>
          </div>
        )}

        {classification?.explanation && (
          <div className="pattern-reasoning">
            <strong>AI Reasoning:</strong>
            <p>{classification.explanation}</p>
          </div>
        )}

        {classification?.oecdreference && (
          <div className="oecd-reference">
            <strong>Regulatory Reference:</strong>
            <p>{classification.oecdreference}</p>
          </div>
        )}

        {classification?.remediation && (
          <div className="pattern-remediation">
            <strong>Remediation:</strong>
            <p>{classification.remediation}</p>
          </div>
        )}
      </div>
    </div>
  );
}
