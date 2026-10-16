import {
  Badge,
  EmptyState,
  Loading,
  PageHeader,
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

  const [eventId, setEventId] = useState('')
  const [beforeId, setBeforeId] = useState(null)
  const [knownTypes, setKnownTypes] = useState([
    'CONTAINER_RESUMED', 'CONTAINER_RESUME_REQUESTED',
    'CONTAINER_RESUME_RECHECK', 'RULE_NATIVE_REFIRE',
  ])

  useEffect(() => {
    let active = true
    let pending = false
    const controller = new AbortController()
    setLoading(true)
    setEvents([])
    async function fetchEvents() {
      if (pending) return
      if (eventId && !/^[1-9][0-9]*$/.test(eventId)) {
        setError('Enter a positive whole-number audit ID.')
        setLoading(false)
        return
      }
      pending = true
      try {
        const params = new URLSearchParams({ limit: '200' })
        if (filter) params.set('event_type', filter)
        if (eventId) params.set('event_id', eventId)
        if (beforeId) params.set('before_id', String(beforeId))
        const res = await apiFetch(`${API}/audit/?${params}`, {
          signal: controller.signal,
        })
        if (!res.ok) throw new Error(await describeFailure(res))
        const items = await res.json()
        if (active) {
          setEvents(items)
          setKnownTypes((old) => [...new Set([...old, ...items.map((e) => e.event_type)])])
          setError(null)
        }
      } catch (err) {
        if (active) setError(err.message)
      } finally {
        pending = false
        if (active) setLoading(false)
      }
    }
    fetchEvents()
    const interval = setInterval(fetchEvents, 3000)
    return () => {
      active = false
      controller.abort()
      clearInterval(interval)
    }
  }, [filter, eventId, beforeId])

  const eventTypes = [...knownTypes].sort()
  const visible = events

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
          onChange={(e) => { setFilter(e.target.value); setBeforeId(null) }}
        >
          <option value="">All event types</option>
          {eventTypes.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>{' '}
        <input
          type="number"
          min="1"
          step="1"
          aria-label="Find audit ID"
          placeholder="Audit ID (e.g. 829)"
          value={eventId}
          onChange={(e) => { setEventId(e.target.value); setBeforeId(null) }}
        />
      </p>
      <p>
        {eventId ? `Audit ID ${eventId}` : 'Up to 200 records per page, newest first.'}{' '}
        Filters search the stored audit history.
      </p>
      <p>
        <button type="button" disabled={!beforeId} onClick={() => setBeforeId(null)}>
          Latest records
        </button>{' '}
        <button
          type="button"
          disabled={loading || !!error || !!eventId || events.length < 200}
          onClick={() => setBeforeId(events[events.length - 1].id)}
        >
          Older records
        </button>
      </p>
      {visible.length === 0 && !error && !loading && (
        <EmptyState
          title={filter || eventId || beforeId ? 'No matching events' : 'No audit events yet'}
        >
          {filter || eventId || beforeId
            ? 'Clear the audit ID or choose another event type to explore the audit trail.'
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
            <span>Audit #{e.id}</span>
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
