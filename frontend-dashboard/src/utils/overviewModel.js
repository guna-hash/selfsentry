import { finiteNumber } from './format.js'

export const DAY = 86400000
export const RANGE_MS = { '24h': DAY, '7d': 7 * DAY }

// Backend DateTime columns use naive UTC. Never interpret those strings in browser local time.
export function utcEpoch(value) {
  if (typeof value !== 'string' || !value.trim()) return null
  const text = value.trim()
  const normalized = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/.test(text)
    ? `${text.replace(' ', 'T')}Z` : text
  const time = Date.parse(normalized)
  return Number.isFinite(time) ? time : null
}

export function effectiveRisk(incident) {
  const effective = finiteNumber(incident.monitor_evidence?.effective_score)
  const score = effective ?? finiteNumber(incident.risk_score)
  return score !== null && score >= 0 && score <= 100 ? score : null
}
export function layersFired(incident) {
  const alert = incident.falco_alert
  const falco = !!alert?.rule && !String(alert.rule).startsWith('Baseline ')
  // Model availability/assessment alone is NOT a contribution to the correlated incident.
  const anomaly = finiteNumber(incident.anomaly_features?.anomaly_score)
  const ml = anomaly !== null && anomaly >= 0 && anomaly <= 1
  return falco && ml ? 'Both' : falco ? 'Falco only' : ml ? 'ML only' : 'Not recorded'
}
export function incidentState(incident) {
  if (incident.monitor_workflow?.disposition?.status === 'benign') return 'Benign'
  if (!incident.confirmation) return 'Unconfirmed'
  return incident.confirmation.confirmed_by === 'selfsentry-auto' ? 'Auto-confirmed' : 'Human-confirmed'
}
export function lookupContainer(identifier, containers = []) {
  if (typeof identifier !== 'string' || !Array.isArray(containers)) return null
  const exact = containers.find((c) => c.id === identifier || c.full_id === identifier)
  if (exact) return exact
  if (!/^[0-9a-f]{12,64}$/i.test(identifier)) return null
  const matches = containers.filter((c) => {
    const id = c.full_id || c.id
    return typeof id === 'string' && /^[0-9a-f]{12,64}$/i.test(id) && (id.startsWith(identifier) || identifier.startsWith(id))
  })
  return matches.length === 1 ? matches[0] : null
}
export function normalizeIncidents(incidents, containers) {
  return incidents?.map((incident) => {
    const container = lookupContainer(incident.container_id, containers)
    return { ...incident, time: utcEpoch(incident.created_at), score: effectiveRisk(incident),
      layer: layersFired(incident), state: incidentState(incident),
      containerKey: container?.full_id || container?.id || incident.container_id,
      containerName: container?.name || incident.container_id || 'Not recorded' }
  }) ?? null
}
const highest = (rows) => {
  const scores = rows.map((r) => r.score).filter((s) => s !== null)
  return scores.length ? scores.reduce((maximum, value) => Math.max(maximum, value), 0) : null
}
const countOpen = (rows) => rows.filter((row) => row.state === 'Unconfirmed').length

export function periodSummary(rows, range = '24h', now = Date.now(), container = '') {
  if (rows === null) return { current: null, previous: null, trend: null, open: null, previousOpen: null, highest: null, previousHighest: null, excluded: 0 }
  const duration = RANGE_MS[range] || DAY
  const end = now, start = end - duration, priorStart = start - duration
  const scoped = rows.filter((row) => !container || row.containerKey === container)
  const current = scoped.filter((row) => row.time !== null && row.time >= start && row.time <= end)
  const previous = scoped.filter((row) => row.time !== null && row.time >= priorStart && row.time < start)
  const bins = range === '7d' ? 7 : 24
  const width = duration / bins
  const trend = Array.from({ length: bins }, (_, index) => ({
    start: start + index * width, end: start + (index + 1) * width,
    previousStart: priorStart + index * width, previousEnd: priorStart + (index + 1) * width,
    current: 0, previous: 0, open: 0,
  }))
  for (const row of current) {
    const bin = trend[Math.min(bins - 1, Math.floor((row.time - start) / width))]
    bin.current++
    if (row.state === 'Unconfirmed') bin.open++
  }
  for (const row of previous) trend[Math.min(bins - 1, Math.floor((row.time - priorStart) / width))].previous++
  return { current, previous, trend, open: countOpen(current), previousOpen: countOpen(previous),
    highest: highest(current), previousHighest: highest(previous),
    excluded: scoped.filter((row) => row.time === null || row.time > end).length }
}

export function learningLoop(incidents, rules) {
  const ids = new Set((incidents || []).map((row) => String(row.id)))
  const cohort = rules?.filter((rule) => ids.has(String(rule.incident_id))) ?? null
  const hasEvent = (rule, type) => Array.isArray(rule.lifecycle_events) && rule.lifecycle_events.some((event) => event.event_type === type)
  const stages = [
    { key: 'incidents', label: 'Incidents', unit: 'incidents', value: incidents === null ? null : incidents.length },
    { key: 'confirmed', label: 'Confirmed', unit: 'incidents', value: incidents === null ? null : incidents.filter((row) => !!row.confirmation).length },
    { key: 'candidates', label: 'Candidates', unit: 'rules', value: incidents === null || cohort === null ? null : cohort.length },
    { key: 'approved', label: 'Approved', unit: 'rules', value: incidents === null || cohort === null ? null : cohort.filter((r) => hasEvent(r, 'RULE_APPROVED') || ['approved', 'deployed'].includes(r.status)).length },
    { key: 'deployed', label: 'Deployed', unit: 'rules', value: incidents === null || cohort === null ? null : cohort.filter((r) => hasEvent(r, 'RULE_DEPLOYED') || r.status === 'deployed').length },
    { key: 'refired', label: 'Re-fired', unit: 'rules', value: incidents === null || cohort === null || cohort.some((r) => !Array.isArray(r.native_refires) && !Array.isArray(r.lifecycle_events)) ? null
      : cohort.filter((r) => r.native_refires?.length > 0 || hasEvent(r, 'RULE_NATIVE_REFIRE')).length },
  ]
  return { stages, limited: (rules?.length ?? 0) >= 100,
    unlinked: rules?.filter((r) => r.incident_id == null).length ?? 0 }
}
