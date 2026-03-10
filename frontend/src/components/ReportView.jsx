export default function ReportView({ audit }) {
  // TODO: Fetch full report data from API
  const mockPatterns = [
    { type: 'confirmshaming', severity: 'high', element: '.cancel-btn', desc: 'Guilt-trip language on cancellation button' },
    { type: 'misdirection', severity: 'medium', element: '.cookie-accept', desc: 'Accept button 3x larger than reject' },
    { type: 'hidden_costs', severity: 'critical', element: '.checkout-total', desc: 'Service fee added at final checkout step' },
  ]

  const severityColor = {
    low: 'text-gray-400 bg-gray-400/10',
    medium: 'text-warn-400 bg-warn-400/10',
    high: 'text-orange-400 bg-orange-400/10',
    critical: 'text-danger-400 bg-danger-400/10',
  }

  return (
    <div className="max-w-4xl mx-auto mt-10">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-bold">Audit Report</h2>
          <p className="text-gray-400 mt-1">{audit?.url}</p>
        </div>
        <div className="text-right">
          <div className="text-3xl font-bold text-danger-400">{mockPatterns.length}</div>
          <div className="text-sm text-gray-400">patterns found</div>
        </div>
      </div>

      {/* Severity Summary */}
      <div className="grid grid-cols-4 gap-3 mb-8">
        {['critical', 'high', 'medium', 'low'].map(sev => (
          <div key={sev} className="bg-dark-800 border border-dark-700 rounded-lg p-4 text-center">
            <div className={`text-2xl font-bold ${severityColor[sev].split(' ')[0]}`}>
              {mockPatterns.filter(p => p.severity === sev).length}
            </div>
            <div className="text-xs text-gray-400 capitalize mt-1">{sev}</div>
          </div>
        ))}
      </div>

      {/* Findings Table */}
      <div className="bg-dark-800 rounded-lg border border-dark-700 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-dark-700 text-gray-400 text-left">
              <th className="px-4 py-3">Pattern</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Element</th>
              <th className="px-4 py-3">Description</th>
            </tr>
          </thead>
          <tbody>
            {mockPatterns.map((p, i) => (
              <tr key={i} className="border-b border-dark-700/50 hover:bg-dark-700/30">
                <td className="px-4 py-3 font-medium">{p.type.replace('_', ' ')}</td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${severityColor[p.severity]}`}>
                    {p.severity}
                  </span>
                </td>
                <td className="px-4 py-3 font-mono text-xs text-gray-400">{p.element}</td>
                <td className="px-4 py-3 text-gray-300">{p.desc}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}