import { useEffect, useState } from 'react'
import { Radio } from 'lucide-react'
import { useMonitor } from '../hooks/useMonitor.jsx'
import { monitorState, eventAge } from './status.js'
export default function StatusBar() {
  const { status, error } = useMonitor()
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [])
  const state = monitorState(status, error)
  return (
    <div className="status-bar" aria-label="Live system status">
      <span className={`status-label tone-${state.tone}`}>
        <span className="status-dot" />
        Monitor: {state.label}
      </span>
      <span>
        <b>{error ? '—' : (status?.containers?.tracked ?? '—')}</b> containers
      </span>
      <span>
        <b>{error ? '—' : (status?.unconfirmed_incidents ?? '—')}</b> pending
        incidents
      </span>
      <span>
        Last event: <b>{eventAge(status?.last_event_at, now)}</b>
        {error && status ? ' (cached)' : ''}
      </span>
      <span className="api-status">
        <Radio size={13} />
        {error ? 'API unavailable' : status ? 'API connected' : 'Connecting…'}
      </span>
    </div>
  )
}
