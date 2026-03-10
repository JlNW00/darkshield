import { useState } from 'react'
import AuditForm from './components/AuditForm'
import AuditStatus from './components/AuditStatus'
import ReportView from './components/ReportView'

export default function App() {
  const [currentAudit, setCurrentAudit] = useState(null)
  const [view, setView] = useState('home') // home, auditing, report

  return (
    <div className="min-h-screen bg-dark-900">
      {/* Header */}
      <header className="border-b border-dark-700 px-6 py-4">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-shield-500 flex items-center justify-center">
              <span className="text-white font-bold text-sm">DS</span>
            </div>
            <h1 className="text-xl font-bold">DarkShield</h1>
            <span className="text-xs text-gray-500 bg-dark-700 px-2 py-0.5 rounded">v0.1</span>
          </div>
          <nav className="flex gap-4 text-sm text-gray-400">
            <button onClick={() => setView('home')} className="hover:text-white">New Audit</button>
            <button className="hover:text-white">History</button>
            <button className="hover:text-white">Docs</button>
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-6xl mx-auto p-6">
        {view === 'home' && (
          <AuditForm onStart={(audit) => { setCurrentAudit(audit); setView('auditing') }} />
        )}
        {view === 'auditing' && (
          <AuditStatus audit={currentAudit} onComplete={() => setView('report')} />
        )}
        {view === 'report' && (
          <ReportView audit={currentAudit} />
        )}
      </main>
    </div>
  )
}