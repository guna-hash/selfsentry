import { isSampleMode, dashboardNow } from '../utils/demoMode.js'
import { useEffect, useState } from 'react'
import { Radio, Menu } from 'lucide-react'
import { useMonitor } from '../hooks/useMonitor.jsx'
import { monitorState, eventAge, isolationState } from './status.js'
import ThemeToggle from './ThemeToggle.jsx'
export default function StatusBar({ navigationOpen, onToggleNavigation }) {
  const { status, error } = useMonitor()
  const [now, setNow] = useState(dashboardNow())
  useEffect(() => {
    const timer = setInterval(() => setNow(dashboardNow()), 1000)
    return () => clearInterval(timer)
  }, [])
  const state = monitorState(status, error)
  const isolation = isolationState(status, error)
  return (
    <header className="status-bar" aria-label={isSampleMode() ? "Sample system status" : "Live system status"}>
      <button type="button" className="shell-button" onClick={onToggleNavigation}
        aria-label="Toggle navigation" aria-controls="workspace-navigation" aria-expanded={navigationOpen}>
        <Menu size={18} aria-hidden="true" />
      </button>
      <span className={`status-label tone-${state.tone}`}>
        <span className="status-dot" />
        {isSampleMode() ? 'Sample monitor' : 'Monitor'}: {state.label}
      </span>
      <span title="Watcher inventory includes stopped containers until they are removed; see Containers for current Docker state.">
        <b>{error ? '—' : (status?.containers?.tracked ?? '—')}</b> tracked containers
      </span>
      <span>
        <b>{error ? '—' : (status?.unconfirmed_incidents ?? '—')}</b> pending
        incidents
      </span>
      <span title={status?.last_event_at || 'No recorded event'}>
        Last event: <b>{eventAge(status?.last_event_at, now)}</b>
        {error && status ? ' (cached)' : ''}
      </span>
      <span className={`status-label tone-${isolation.tone}`}>{isolation.label}</span>
      <span className="api-status">
        <Radio size={13} />
        {isSampleMode() ? 'Local sample · no API connection' : error ? 'API unavailable' : status ? 'API connected' : 'Connecting…'}
      </span>
      <ThemeToggle />
    </header>
  )
}
