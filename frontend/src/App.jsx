import { useState } from 'react';
import AuditForm from './components/AuditForm';
import AuditStatus from './components/AuditStatus';
import ReportView from './components/ReportView';
import './App.css';

function App() {
  const [view, setView] = useState('form'); // form | scanning | report
  const [auditId, setAuditId] = useState(null);
  const [auditUrl, setAuditUrl] = useState('');

  const handleAuditStarted = (id, url) => {
    setAuditId(id);
    setAuditUrl(url);
    setView('scanning');
  };

  const handleAuditComplete = (id) => {
    setView('report');
  };

  const handleBack = () => {
    setView('form');
    setAuditId(null);
    setAuditUrl('');
  };

  return (
    <div className="app">
      <header className="app-header">
        <div className="logo" onClick={handleBack} style={{ cursor: 'pointer' }}>
          <span className="logo-icon">&#x1F6E1;</span>
          <h1>DarkShield</h1>
        </div>
        <p className="tagline">AI-Powered Dark Pattern Detection</p>
      </header>

      <main className="app-main">
        {view === 'form' && (
          <AuditForm onAuditStarted={handleAuditStarted} />
        )}

        {view === 'scanning' && (
          <AuditStatus
            auditId={auditId}
            url={auditUrl}
            onComplete={handleAuditComplete}
          />
        )}

        {view === 'report' && (
          <ReportView auditId={auditId} onBack={handleBack} />
        )}
      </main>

      <footer className="app-footer">
        <p>DarkShield -- Nova Hackathon 2026</p>
      </footer>
    </div>
  );
}

export default App;
