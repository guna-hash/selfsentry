export function monitorState(status, error) {
  if (error) return { label: 'Unavailable', tone: 'critical' }
  if (!status) return { label: 'Connecting', tone: 'neutral' }
  if (!status.running) return { label: 'Stopped', tone: 'critical' }
  const degraded = Object.values(status.components || {}).some(
    (item) => !['ok', 'connected', 'disabled'].includes(item.state),
  )
  if (!status.healthy || degraded) return { label: 'Degraded', tone: 'medium' }
  return { label: 'Running', tone: 'low' }
}
export function eventAge(timestamp, now = Date.now()) {
  if (!timestamp) return 'No events yet'
  const time = Date.parse(timestamp)
  if (!Number.isFinite(time)) return 'Unknown'
  const seconds = Math.floor((now - time) / 1000)
  if (seconds < 0) return 'Clock ahead'
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

export function isolationState(status, error) {
  const enabled = status?.configuration?.auto_isolation_enabled
  if (error || typeof enabled !== 'boolean') {
    return { label: 'Isolation: unknown', enabled: enabled === true, tone: 'neutral' }
  }
  return enabled
    ? { label: 'Isolation: on', enabled: true, tone: 'medium' }
    : { label: 'Isolation: off (default)', enabled: false, tone: 'neutral' }
}
