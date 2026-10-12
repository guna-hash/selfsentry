import { Activity, Inbox, LoaderCircle, X } from 'lucide-react'

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
export function Badge({ children, tone = 'neutral' }) {
  return <span className={`badge tone-${tone}`}>{children}</span>
}
export function EmptyState({
  title = 'Nothing here yet',
  children,
  waiting = false,
}) {
  return (
    <div className="empty-state">
      <Inbox size={28} aria-hidden="true" />
      <h3>{title}</h3>
      <p>{children}</p>
      {waiting && (
        <span className="waiting">
          <span className="status-dot" />
          Waiting for first event…
        </span>
      )}
    </div>
  )
}
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
