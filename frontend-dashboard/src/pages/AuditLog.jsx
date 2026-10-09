import { useState, useEffect } from 'react'
import { API, describeFailure } from '../api.js'

const SEVERITY_CLASS = { critical: 'sev-high', warning: 'sev-medium', info: 'sev-low' }

export default function AuditLog() {
  const [events, setEvents] = useState([])
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('')

  async function fetchEvents() {
    try {
      const res = await fetch(`${API}/audit/?limit=200`)
      if (!res.ok) throw new Error(await describeFailure(res))
      setEvents(await res.json())
      setError(null)
    } catch (err) {
      setError(err.message)
    }
  }

  useEffect(() => {
    fetchEvents()
    const interval = setInterval(fetchEvents, 3000)
    return () => clearInterval(interval)
  }, [])

  const eventTypes = [...new Set(events.map((e) => e.event_type))].sort()
  const visible = filter ? events.filter((e) => e.event_type === filter) : events

  return (
    <div>
      <h2>Audit log</h2>
      {error && <p className="error-state">Couldn't load the audit log: {error}</p>}
      <p>
        <select value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="">All event types</option>
          {eventTypes.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>
      </p>
      {visible.length === 0 && !error && (
        <p className="empty-state">
          No audit events yet. Start the monitor (monitor-service/monitor_service.py) and
          container activity appears here.
        </p>
      )}
      {visible.map((e) => (
        <div key={e.id} className={`incident-card ${SEVERITY_CLASS[e.severity] || 'sev-low'}`}>
          <div className="incident-meta">
            <span>{e.event_type}</span>
            <span>{e.container_name || e.container_id || 'host'}</span>
            {e.image_name && <span>{e.image_name}</span>}
            <span>{new Date(e.occurred_at || e.created_at).toLocaleString()}</span>
          </div>
          {Object.keys(e.detail).length > 0 && (
            <pre className="rule-yaml">{JSON.stringify(e.detail, null, 2)}</pre>
          )}
        </div>
      ))}
    </div>
  )
}
