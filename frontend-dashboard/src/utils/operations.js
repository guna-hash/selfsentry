import { isSampleMode } from './demoMode.js'
import { formatDate } from './format.js'
import { utcEpoch } from './overviewModel.js'
export const options = values => [...new Set(values.filter(v => v != null && v !== ''))].sort().map(value => ({ value: String(value), label: String(value) }))
export function auditActor(row) {
  const detail = row.detail || {}
  return ['actor', 'resumed_by', 'isolated_by', 'reviewed_by', 'confirmed_by', 'requested_by', 'deployed_by'].map(k => detail[k]).find(v => typeof v === 'string' && v.trim()) || 'Not recorded'
}
export function auditInRange(row, from, to) {
  const time = utcEpoch(row.occurred_at || row.created_at)
  if (!from && !to) return true
  if (!Number.isFinite(time)) return false
  return (!from || time >= Date.parse(from + 'T00:00:00Z')) && (!to || time < Date.parse(to + 'T00:00:00Z') + 86400000)
}
export function csvText(rows, columns) {
  const escape = value => {
    let text = String(value ?? '')
    if (/^[\s]*[=+@-]|^[\t\r\n]/.test(text)) text = "'" + text
    return '"' + text.replaceAll('"', '""') + '"'
  }
  return '\uFEFF' + [columns.map(c => escape(c.label)).join(','), ...rows.map(row => columns.map(c => escape(c.value(row))).join(','))].join('\r\n')
}
export function auditExport(rows, columns) {
  const sample = isSampleMode()
  const exportColumns = sample ? [{label:'Data provenance',value:()=> 'Synthetic sample data; not evaluation evidence'}, ...columns] : columns
  return {text:csvText(rows, exportColumns),filename:sample ? 'selfsentry-sample-audit.csv' : 'selfsentry-audit.csv'}
}
export function downloadCsv(rows, columns) {
  const file = auditExport(rows,columns)
  const url = URL.createObjectURL(new Blob([file.text], { type: 'text/csv;charset=utf-8' }))
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = file.filename; anchor.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
export function modelLabel(state) {
  return ({ NO_BASELINE: 'No baseline', LEARNING: 'Learning', BASELINE_READY: 'Baseline ready', MODEL_TRAINING: 'Model training', MODEL_READY: 'Model ready', MODEL_UNAVAILABLE: 'Model invalid / unavailable', MODEL_INVALID: 'Model invalid / unavailable' })[state] || 'Unknown'
}
export async function containerAction(container, action, actor, reason, request, requireToken) {
  if (!actor.trim() || (action === 'isolate' && !reason.trim())) throw new Error('Record an operator and an isolation reason.')
  if (container.containment_state === 'record_unavailable') throw new Error('Isolation recovery record is unavailable. Operator repair is required before another action.')
  if (action === 'isolate' && container.protected !== false) throw new Error('Isolation requires a confirmed unprotected container.')
  if (action === 'resume' && !container.isolated) throw new Error('Resume requires an active isolation record.')
  if (!['isolate', 'resume'].includes(action)) throw new Error('Unknown action.')
  requireToken()
  const params = new URLSearchParams(action === 'resume' ? { resumed_by: actor.trim(), recheck: 'true' } : { isolated_by: actor.trim(), reason: reason.trim() })
  return request(`/containers/${encodeURIComponent(container.full_id || container.id)}/${action}?${params}`, { method: 'POST' })
}

export const operationDate = value => formatDate(typeof value === 'number' ? value : utcEpoch(value))
export function auditVerification(row) {
  if (row.source !== 'backend') return 'Verification not recorded'
  if (row.event_type === 'CONTAINER_RESUMED') return 'Backend recorded verified running state and restored saved networks'
  if (row.event_type === 'CONTAINER_ISOLATED') return 'Backend recorded verified pause and network disconnection'
  if (/CONTAINER_(RESUME|ISOLATION|ISOLATE)_FAILED/.test(row.event_type)) return 'Action failed; outcome not verified'
  return 'Verification not recorded'
}
