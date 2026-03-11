import { SEVERITY_COLORS, SEVERIYY_LABELS, SCENARIO_LABELS } from '../hooks/useApi';

export default function PatternDetail({ pattern, classification }) {
  // classification is a plain dict returned directly from the backend classify() call.
  // Field names match what classifier.py returns: category, confidence, explanation,
  // oecd_reference (string), remediation (string).
  const sev = classification?.severity || pattern?.severity || 'medium';
  const category = classification?.category || pattern?.category || 'unknown';
  const confidence = classification?.confidence || pattern?.confidence || 0;

  // Backend taxonomy keys from classifier.py TAXONOMY dict
  const categoryLabels = {
    asymmetric_choice:      'Asymmetric Choice',
    confirmshaming:         'Confirmshaming',
    forced_consent:         'Forced Consent',
    hidden_costs:           'Hidden Costs',
    interface_interference:'Interface Interference',
    misdirection:           'Misdirection',
    nagging:                'Nagging',
    obstruction:            'Obstruction',
    sneaking:               'Sneaking',
    urgency:                'Urgency',
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
                  width: `${confidence * 100}% ,
                  backgroundColor: 'hsl(121, 60%, 65%)',
                }}
               </div>
            </div>
            </div>
        </div>
        )}

        <div className="pattern-tech">
          <span className="tech-label">OECD Reference: </span>
          <span className="tech-value">{classification?.oecd_reference || 'N/A'}</span>
        </div>

        <div className="pattern-remediation">
          <h3 className="remediation-title">Remediation</h3>
          <p className="remediation-text">
            {classification?.remediation || pattern?.remediation || 'No remediation suggested'}
          </p>
        </div>
    </div>
    </div>
  );
}
