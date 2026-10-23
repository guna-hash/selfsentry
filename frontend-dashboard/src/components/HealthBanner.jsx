import { Link } from 'react-router-dom'
import { useMonitor } from '../hooks/useMonitor.jsx'
import { monitorState, isolationState } from './status.js'

export function HealthNotice({ status, error }) {
  const state = monitorState(status, error)
  const isolation = isolationState(status, error)
  const unhealthy = ['Stopped', 'Degraded', 'Unavailable'].includes(state.label)
  return (
    <>
      {unhealthy && <section className={`health-banner tone-${state.tone}`} role="status">
        <div><strong>Monitor {state.label.toLowerCase()}</strong>
          <p>{error ? 'Live health could not be checked. Displayed data may be stale.'
            : status?.health_reason || status?.reason || 'Continuous detection may be interrupted. Check monitor components and recent errors.'}</p>
        </div>
        <Link to="/monitor">View monitor health</Link>
      </section>}
      {isolation.enabled && <section className="health-banner tone-medium" role="status">
        <div><strong>Auto-isolation enabled{error ? ' (last reported)' : ''}</strong>
          <p>Eligible incidents can automatically pause containers and disconnect their networks.
            {error ? ' The current setting could not be verified.' : ''}</p>
        </div>
        <Link to="/containers">View containers</Link>
      </section>}
    </>
  )
}
export default function HealthBanner() {
  const { status, error } = useMonitor()
  return <HealthNotice status={status} error={error} />
}
