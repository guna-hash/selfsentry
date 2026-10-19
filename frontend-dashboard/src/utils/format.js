import { dashboardNow } from './demoMode.js'
// Null, missing and non-finite values remain unavailable, never measured zero.
export const NOT_RECORDED = 'Not recorded'
export function finiteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}
export function formatNumber(value, options = {}, locale) {
  return finiteNumber(value) === null ? '—' : new Intl.NumberFormat(locale, options).format(value)
}
export function recordedDate(value) {
  if (value == null || value === '') return null
  const date = new Date(value)
  return Number.isFinite(date.getTime()) ? date : null
}
export function formatDate(value, options = {}, locale) {
  const date = recordedDate(value)
  return date ? new Intl.DateTimeFormat(locale, {
    dateStyle: 'medium', timeStyle: 'medium', ...options,
  }).format(date) : NOT_RECORDED
}
export function relativeTime(value, now = dashboardNow(), locale) {
  const date = recordedDate(value)
  if (!date) return NOT_RECORDED
  const seconds = (date.getTime() - now) / 1000
  if (seconds > 0) return 'Clock ahead'
  for (const [unit, size] of [['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]]) {
    if (Math.abs(seconds) >= size || unit === 'second')
      return new Intl.RelativeTimeFormat(locale, { numeric: 'auto' }).format(Math.trunc(seconds / size), unit)
  }
}
export function comparison(current, previous) {
  if (finiteNumber(current) === null || finiteNumber(previous) === null)
    return { label: 'Comparison unavailable', direction: 'unknown' }
  const difference = current - previous
  const direction = difference > 0 ? 'up' : difference < 0 ? 'down' : 'flat'
  if (previous === 0 && difference !== 0)
    return { label: 'Previous period was zero; percentage unavailable', direction }
  const percent = previous === 0 ? 0 : Math.abs(difference / previous) * 100
  return { label: `${formatNumber(percent, { maximumFractionDigits: 1 })}% ${direction === 'flat' ? 'unchanged' : direction} vs previous period`, direction }
}
