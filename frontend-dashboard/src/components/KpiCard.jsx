import { ArrowDown, ArrowUp, Minus } from 'lucide-react'
import { comparison, formatNumber } from '../utils/format.js'

export default function KpiCard({ label, value, previous, detail, tone = 'neutral', icon: Icon, prominent = false, comparisonLabel, children }) {
  const change = comparison(value, previous)
  const Direction = change.direction === 'up' ? ArrowUp : change.direction === 'down' ? ArrowDown : Minus
  return (
    <section className={`metric-card tone-${tone}${prominent ? ' kpi-prominent' : ''}`} aria-label={label}>
      <div className="metric-label">{label}{Icon && <Icon size={16} aria-hidden="true" />}</div>
      <div className="metric-value">{typeof value === 'string' ? value : formatNumber(value)}</div>
      <div className="kpi-comparison"><Direction size={16} aria-hidden="true" />{comparisonLabel ?? change.label}</div>
      {children}
      {detail && <div className="metric-detail">{detail}</div>}
    </section>
  )
}
