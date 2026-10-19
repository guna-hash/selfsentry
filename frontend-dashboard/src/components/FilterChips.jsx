import { X } from 'lucide-react'
export default function FilterChips({ filters = [], onRemove, onClear }) {
  if (!filters.length) return null
  return <div className="filter-chips" aria-label="Active filters">
    {filters.map(({ id, label }) => <button key={id} type="button" className="filter-chip"
      onClick={() => onRemove(id)} aria-label={`Remove ${label} filter`}>
      {label}<X size={12} aria-hidden="true" />
    </button>)}
    <button type="button" className="shell-button" onClick={onClear}>Clear all</button>
  </div>
}
