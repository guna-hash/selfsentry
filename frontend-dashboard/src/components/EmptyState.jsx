import { Inbox } from 'lucide-react'
export default function EmptyState({ title = 'Nothing here yet', children, waiting = false, action }) {
  return <div className="empty-state">
    <Inbox size={24} aria-hidden="true" />
    <h3>{title}</h3>
    {children && <div className="empty-description">{children}</div>}
    {waiting && <span className="waiting"><span className="status-dot" />Waiting for first event…</span>}
    {action}
  </div>
}
