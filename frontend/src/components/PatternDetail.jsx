import { SEVERITY_COLORS, SEVERITY_LABELS, SCENARIO_LABELS } from '../hooks/useApi';

export default function PatternDetail({ pattern, classification }) {
  const sev = classification?.severity || pattern.severity || 'medium';
  const category = classification?.ai_category || pattern.category || 'unknown';
  const confidence = classification?.ai_confidence || pattern.confidence || 0;

  const categoryLabels = {
    confirmshaming: 'Confirmshaming',
    misdirection: 'Misdirection',
    roach_motel: 'Roach Motel',
    forced_continuity: 'Forced Continuity',
    hidden_costs: 'Hidden Costs',
    trick_questions: 'Trick Questions',
    disguised_ads: 'Disguised Ads',
    friend_spam: 'Friend Spam',
    privacy_zuckering: 'Privacy Zuckering',
    bait_and_switch: 'Bait & Switch',
  };

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
          {SCENARIO_LABELS[pattern.scenario]?.icon}{' '}
          {SCENARIO_LABELS[pattern.scenario]?.label || pattern.scenario}
        </span>
      </div>

      <div className="pattern-body">
        <p className="pattern-description">
          {classification?.description || pattern.description}
        </p>

        <div className="pattern-evidence">
          <strong>Evidence:</strong>
          <p>{classification?.evidence_summary || pattern.evidence}</p>
        </div>

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

        {classification?.ai_reasoning && (
          <div className="pattern-reasoning">
            <strong>AI Reasoning:</strong>
            <p>{classification.ai_reasoning}</p>
          </div>
        )}

        {classification?.oecd_reference && Object.keys(classification.oecd_reference).length > 0 && (
          <div className="oecd-reference">
            <strong>Regulatory Reference:</strong>
            <div className="oecd-details">
              <div><em>Guideline:</em> {classification.oecd_reference.guideline}</div>
              <div><em>Principle:</em> {classification.oecd_reference.principle}</div>
              <div><em>Regulation:</em> {classification.oecd_reference.regulation}</div>
            </div>
          </div>
        )}

        {classification?.remediation && classification.remediation.length > 0 && (
          <div className="remediation">
            <strong>Remediation:</strong>
            <ul>
              {classification.remediation.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
