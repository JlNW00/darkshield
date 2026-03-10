import { useState, useEffect } from 'react'
import axios from 'axios'

export default function AuditStatus({ audit, onComplete }) {
  const [status, setStatus] = useState(audit)
  const [logs, setLogs] = useState([
    { time: new Date().toISOString(), msg: 'Audit queued...', type: 'info' },
  ])

  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const { data } = await axios.get(`/api/v1/audit/${audit.audit_id}`)
        setStatus(data)
        if (data.status === 'completed' || data.status === 'failed') {
          clearInterval(interval)
          if (data.status === 'completed') {
            setTimeout(() => onComplete(), 1500)
          }
        }
      } catch (err) {
        console.error(err)
      }
    }, 2000)
    return () => clearInterval(interval)
  }, [audit.audit_id])

  return (
    <div className="max-w-3xl mx-auto mt-10">
      <div className="flex items-center gap-4 mb-8">
        <div className={`w-3 h-3 rounded-full ${
          status.status === 'running' ? 'bg-shield-400 animate-pulse' :
          status.status === 'completed' ? 'bg-green-400' : 'bg-yellow-400'
        }`} />
        <h2 className="text-2xl font-bold">Auditing: {status.url}</h2>
      </div>

      {/* Agent Activity Feed */}
      <div className="bg-dark-800 rounded-lg border border-dark-700 p-4 font-mono text-sm">
        <div className="text-gray-500 mb-2">Agent Activity</div>
        {logs.map((log, i) => (
          <div key={i} className="flex gap-3 py-1">
            <span className="text-gray-600 text-xs">{new Date(log.time).toLocaleTimeString()}</span>
            <span className={log.type === 'finding' ? 'text-danger-400' : 'text-gray-300'}>
              {log.msg}
            </span>
          </div>
        ))}
        {status.status === 'running' && (
          <div className="flex gap-3 py-1 animate-pulse">
            <span className="text-gray-600 text-xs">{new Date().toLocaleTimeString()}</span>
            <span className="text-shield-300">Agent analyzing page...</span>
          </div>
        )}
      </div>
    </div>
  )
}