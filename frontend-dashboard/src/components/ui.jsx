import { Activity, LoaderCircle, X } from 'lucide-react'

export function MetricCard({
  label,
  value,
  detail,
  tone = 'accent',
  icon: Icon = Activity,
}) {
  return (
    <div className={`metric-card tone-${tone}`}>
      <div className="metric-label">
        {label}
        <Icon size={17} aria-hidden="true" />
      </div>
      <div className="metric-value">{value ?? '—'}</div>
      <div className="metric-detail">{detail || ' '}</div>
    </div>
  )
}
// Compatibility exports preserve existing pages while later steps migrate them.
export { default as Badge } from './StatusBadge.jsx'
export { default as EmptyState } from './EmptyState.jsx'
export { default as KpiCard } from './KpiCard.jsx'
export { default as StatusBadge } from './StatusBadge.jsx'
export { default as DataTable } from './DataTable.jsx'
export { default as FilterChips } from './FilterChips.jsx'
export { default as ErrorState } from './ErrorState.jsx'
export { default as Skeleton } from './Skeleton.jsx'
export { default as Drawer } from './Drawer.jsx'
export function Loading() {
  return (
    <div className="loading-state" role="status">
      <LoaderCircle size={18} className="spin" />
      Loading live data…
    </div>
  )
}
export function PageHeader({
  eyebrow = 'SECURITY OPERATIONS',
  title,
  children,
}) {
  return (
    <header className="page-header">
      <span className="eyebrow">{eyebrow}</span>
      <h2>{title}</h2>
      <p>{children}</p>
    </header>
  )
}
export function Notice({ notice, onDismiss }) {
  if (!notice) return null
  return (
    <div
      className={`notice tone-${notice.kind === 'error' ? 'critical' : 'low'}`}
      role={notice.kind === 'error' ? 'alert' : 'status'}
    >
      <span>{notice.text}</span>
      <button
        className="icon-button"
        aria-label="Dismiss notice"
        onClick={onDismiss}
      >
        <X size={16} />
      </button>
    </div>
  )
}
