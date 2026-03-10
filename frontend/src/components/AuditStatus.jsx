import { useState, useEffect, useRef } from 'react';
import { connectAuditWebSocket, SCENARIO_LABELS } from '../hooks/useApi';

export default function AuditStatus({ auditId, url, onComplete }) {
  const [events, setEvents] = useState([]);
  const [status, setStatus] = useState('connecting');
  const [currentScenario, setCurrentScenario] = useState(null);
  const [patternsFound, setPatternsFound] = useState(0);
  const wsRef = useRef(null);
  const feedRef = useRef(null);

  useEffect(() => {
    if (!auditId) return;

    const connection = connectAuditWebSocket(auditId, (event) => {
      setEvents((prev) => [...prev, event]);

      switch (event.type) {
        case 'pipeline_started':
          setStatus('scanning');
          break;
        case 'scenario_started':
          setCurrentScenario(event.scenario);
          break;
        case 'scenario_completed':
          setPatternsFound((prev) => prev + (event.patterns_found || 0));
          break;
        case 'classification_started':
          setStatus('classifying');
          setCurrentScenario(null);
          break;
        case 'pipeline_completed':
          setStatus('completed');
          setPatternsFound(event.total_patterns || 0);
          setTimeout(() => onComplete?.(auditId), 1500);
          break;
        case 'pipeline_error':
          setStatus('error');
          break;
      }
    });

    wsRef.current = connection;
    return () => connection.close();
  }, [auditId]);

  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [events]);

  const getEventMessage = (event) => {
    switch (event.type) {
      case 'pipeline_started':
        return `Initializing agent for ${event.url}`;
      case 'audit_started':
        return `Starting ${event.scenarios?.length || 4} detection scenarios`;
      case 'scenario_started': {
        const info = SCENARIO_LABELS[event.scenario] || {};
        return `${info.icon || '>'} Running: ${info.label || event.scenario}`;
      }
      case 'agent_action':
        return `  Step ${event.step}: ${event.action}`;
      case 'agent_observation':
        return `  Observation: ${event.observation}`;
      case 'scenario_completed':
        return `  Found ${event.patterns_found} pattern(s) in ${event.scenario}`;
      case 'classification_started':
        return `Classifying ${event.message?.match(/\d+/)?.[0] || ''} findings with AI...`;
      case 'classification_completed':
        return `Classified ${event.classified} patterns`;
      case 'pipeline_completed':
        return `Audit complete: ${event.total_patterns} patterns, risk score ${event.risk_score}/10`;
      case 'pipeline_error':
        return `Error: ${event.error}`;
      default:
        return event.message || event.type;
    }
  };

  const statusConfig = {
    connecting: { label: 'Connecting...', color: '#6366f1' },
    scanning: { label: 'Scanning Website', color: '#f59e0b' },
    classifying: { label: 'AI Classification', color: '#8b5cf6' },
    completed: { label: 'Complete', color: '#22c55e' },
    error: { label: 'Failed', color: '#ef4444' },
  };

  const config = statusConfig[status] || statusConfig.connecting;

  return (
    <div className="audit-status">
      <div className="status-header">
        <div className="status-badge" style={{ backgroundColor: config.color }}>
          {config.label}
        </div>
        <span className="status-url">{url}</span>
        {patternsFound > 0 && (
          <span className="patterns-count">{patternsFound} patterns found</span>
        )}
      </div>

      {currentScenario && (
        <div className="current-scenario">
          <span className="scenario-icon">
            {SCENARIO_LABELS[currentScenario]?.icon || '>'}
          </span>
          <span>{SCENARIO_LABELS[currentScenario]?.label || currentScenario}</span>
          <span className="pulse-dot" />
        </div>
      )}

      <div className="event-feed" ref={feedRef}>
        {events.filter((e) => e.type !== 'keepalive').map((event, i) => (
          <div key={i} className={`event-line event-${event.type}`}>
            <span className="event-time">
              {new Date(event.timestamp).toLocaleTimeString()}
            </span>
            <span className="event-msg">{getEventMessage(event)}</span>
          </div>
        ))}
        {status === 'scanning' && (
          <div className="event-line event-pending">
            <span className="typing-indicator">...</span>
          </div>
        )}
      </div>
    </div>
  );
}
