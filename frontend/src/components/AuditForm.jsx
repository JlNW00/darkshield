import { useState } from 'react'
import axios from 'axios'

const SCENARIOS = [
  { id: 'cookie_consent', label: 'Cookie Consent', icon: '🍪' },
  { id: 'subscription_cancel', label: 'Subscription Cancel', icon: '❌' },
  { id: 'checkout_flow', label: 'Checkout Flow', icon: '🛒' },
  { id: 'account_deletion', label: 'Account Deletion', icon: '🗑️' },
]

export default function AuditForm({ onStart }) {
  const [url, setUrl] = useState('')
  const [selected, setSelected] = useState(SCENARIOS.map(s => s.id))
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    try {
      const { data } = await axios.post('/api/v1/audit', {
        url,
        check_categories: selected,
      })
      onStart(data)
    } catch (err) {
      console.error('Audit failed:', err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-2xl mx-auto mt-20">
      <div className="text-center mb-10">
        <h2 className="text-4xl font-bold mb-3">Detect Dark Patterns</h2>
        <p className="text-gray-400">Enter a URL and our AI agent will audit it for manipulative design patterns</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="flex gap-3">
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="flex-1 bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-shield-500"
            required
          />
          <button
            type="submit"
            disabled={loading}
            className="bg-shield-500 hover:bg-shield-400 px-6 py-3 rounded-lg font-medium transition disabled:opacity-50"
          >
            {loading ? 'Starting...' : 'Audit'}
          </button>
        </div>

        <div className="grid grid-cols-2 gap-3">
          {SCENARIOS.map(s => (
            <label
              key={s.id}
              className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition ${
                selected.includes(s.id) ? 'border-shield-500 bg-dark-800' : 'border-dark-700 bg-dark-900'
              }`}
            >
              <input
                type="checkbox"
                checked={selected.includes(s.id)}
                onChange={() => setSelected(prev =>
                  prev.includes(s.id) ? prev.filter(x => x !== s.id) : [...prev, s.id]
                )}
                className="sr-only"
              />
              <span>{s.icon}</span>
              <span className="text-sm">{s.label}</span>
            </label>
          ))}
        </div>
      </form>
    </div>
  )
}