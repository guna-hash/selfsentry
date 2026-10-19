export default function Skeleton({ label = 'Loading data…', rows = 3 }) {
  return <div className="skeleton-group" role="status" aria-label={label}>
    <span className="sr-only">{label}</span>
    {Array.from({ length: Math.min(20, Math.max(1, rows)) }, (_, index) =>
      <div key={index} className="skeleton-line" aria-hidden="true" />)}
  </div>
}
