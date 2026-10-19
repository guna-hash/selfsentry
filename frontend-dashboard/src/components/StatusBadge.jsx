const tones = {
  running: 'low', healthy: 'low', approved: 'low', deployed: 'low', allowed: 'low',
  pending: 'medium', learning: 'medium', degraded: 'medium', overridden: 'medium',
  stopped: 'critical', rejected: 'critical', blocked: 'critical', invalid: 'critical',
  disabled: 'neutral', unavailable: 'neutral', unknown: 'neutral',
}
export default function StatusBadge({ status, children, tone }) {
  const label = children ?? status ?? 'Unknown'
  const semanticTone = tone ?? tones[String(status).toLowerCase()] ?? 'neutral'
  return <span className={`badge tone-${semanticTone}`}>{label}</span>
}
