import {
  Badge,
  EmptyState,
  Loading,
  PageHeader,
  Notice,
} from '../components/ui.jsx'
import { useState, useEffect } from 'react'
import { API, apiFetch, describeFailure } from '../api.js'

const SEVERITY_CLASS = {
  critical: 'sev-critical',
  warning: 'sev-medium',
  info: 'sev-low',
}

export default function AuditLog() {
  const [events, setEvents] = useState([])
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')

  async function fetchEvents() {
    try {
      const res = await apiFetch(`${API}/audit/?limit=200`)
      if (!res.ok) throw new Error(await describeFailure(res))
      setEvents(await res.json())
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchEvents()
    const interval = setInterval(fetchEvents, 3000)
    return () => clearInterval(interval)
  }, [])

  const eventTypes = [...new Set(events.map((e) => e.event_type))].sort()
  const visible = filter
    ? events.filter((e) => e.event_type === filter)
    : events

  return (
    <div>
      <PageHeader title="Audit log">
        A traceable record of container activity and security decisions.
      </PageHeader>
      {loading && <Loading />}
      {error && (
        <p className="error-state" role="alert">
          Couldn't load the audit log: {error}
        </p>
      )}
      <p>
        <select
          aria-label="Filter audit events by type"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        >
          <option value="">All event types</option>
          {eventTypes.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>
      </p>
      {visible.length === 0 && !error && !loading && (
        <EmptyState
          title={filter ? 'No matching events' : 'No audit events yet'}
        >
          {filter
            ? 'Choose another event type to explore the audit trail.'
            : 'Container activity will appear when the monitor reports events.'}
        </EmptyState>
      )}
      {visible.map((e) => (
        <div
          key={e.id}
          className={`incident-card ${SEVERITY_CLASS[e.severity] || 'sev-low'}`}
        >
          <div className="incident-meta">
            <Badge
              tone={
                e.severity === 'critical'
                  ? 'critical'
                  : e.severity === 'warning'
                    ? 'medium'
                    : 'accent'
              }
            >
              {e.severity}
            </Badge>
            <span>{e.event_type}</span>
            <span>{e.container_name || e.container_id || 'host'}</span>
            {e.image_name && <span>{e.image_name}</span>}
            <span>
              {new Date(e.occurred_at || e.created_at).toLocaleString()}
            </span>
          </div>
          {Object.keys(e.detail).length > 0 && (
            <pre className="rule-yaml">{JSON.stringify(e.detail, null, 2)}</pre>
          )}
        </div>
      ))}
    </div>
  )
}
