import { useId, useMemo, useState } from 'react'
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react'
import FilterChips from './FilterChips.jsx'
import EmptyState from './EmptyState.jsx'
import ErrorState from './ErrorState.jsx'
import Skeleton from './Skeleton.jsx'
import { cellValue, selectRows } from './tableModel.js'
import { formatNumber } from '../utils/format.js'

// Columns: key, label, accessor?, render?, compare?, sortable?, searchable?, filterOptions?.
// filterOptions: [{ value: string, label: string }]. Row ids must be stable and unique.
export default function DataTable({
  rows = [], columns, caption = 'Records', rowKey = 'id', initialSort = {}, pageSize = 10,
  loading = false, error = null, errorStatus, onRetry, onRowOpen, onExport,
}) {
  const id = useId()
  const [query, setQuery] = useState('')
  const [filters, setFilters] = useState({})
  const [sort, setSort] = useState(initialSort)
  const [page, setPage] = useState(1)
  const selected = useMemo(() => selectRows(rows, columns, { query, filters, sort }), [rows, columns, query, filters, sort])
  const size = Number.isInteger(pageSize) && pageSize > 0 ? pageSize : 10
  const pages = Math.max(1, Math.ceil(selected.length / size))
  const current = Math.min(page, pages)
  const visible = selected.slice((current - 1) * size, current * size)
  const chips = Object.entries(filters).map(([key, value]) => {
    const column = columns.find((item) => item.key === key)
    const label = column?.filterOptions?.find((item) => item.value === value)?.label ?? value
    return { id: key, label: `${column?.label ?? key}: ${label}` }
  })
  if (query) chips.unshift({ id: '__search', label: `Search: ${query}` })
  function removeFilter(key) {
    if (key === '__search') setQuery('')
    else setFilters((old) => { const next = { ...old }; delete next[key]; return next })
    setPage(1)
  }
  function clear() { setQuery(''); setFilters({}); setPage(1) }
  return <section className="data-table" aria-label={caption} aria-busy={loading}>
    <div className="table-toolbar">
      <label htmlFor={`${id}-search`}>Search {caption.toLowerCase()}
        <input id={`${id}-search`} type="search" value={query} placeholder="Search records"
          onChange={(event) => { setQuery(event.target.value); setPage(1) }} />
      </label>
      {columns.filter((column) => column.filterOptions).map((column) => <label key={column.key} htmlFor={`${id}-${column.key}`}>
        {column.label}
        <select id={`${id}-${column.key}`} value={filters[column.key] ?? ''} onChange={(event) => {
          const value = event.target.value
          if (value === '') removeFilter(column.key)
          else { setFilters((old) => ({ ...old, [column.key]: value })); setPage(1) }
        }}><option value="">All</option>{column.filterOptions.map((option) =>
          <option key={option.value} value={option.value}>{option.label}</option>)}</select>
      </label>)}
    </div>
    {onExport && <button className="shell-button" disabled={loading || !!error || !selected.length} onClick={() => onExport(selected)}>Export filtered CSV</button>}
    <FilterChips filters={chips} onRemove={removeFilter} onClear={clear} />
    {loading ? <Skeleton label={`Loading ${caption.toLowerCase()}…`} />
      : error ? <ErrorState error={error} status={errorStatus} onRetry={onRetry} />
        : !selected.length ? <EmptyState title={rows.length ? 'No matching records' : 'No records yet'}>
          {rows.length ? 'Adjust your search or clear the filters.' : 'No recorded data is available.'}
        </EmptyState> : <>
          <div className="table-scroll" tabIndex={0} role="region" aria-label={`${caption} table`}>
            <table><caption className="sr-only">{caption}</caption><thead><tr>
              {columns.map((column) => <th key={column.key} scope="col" aria-sort={sort.key === column.key ? sort.direction === 'desc' ? 'descending' : 'ascending' : 'none'}>
                {column.sortable === false ? column.label : <button type="button" className="sort-button"
                  onClick={() => { setSort({ key: column.key, direction: sort.key === column.key && sort.direction === 'asc' ? 'desc' : 'asc' }); setPage(1) }}>
                  {column.label}{sort.key !== column.key ? <ArrowUpDown size={12} aria-hidden="true" />
                    : sort.direction === 'desc' ? <ArrowDown size={12} aria-hidden="true" /> : <ArrowUp size={12} aria-hidden="true" />}
                </button>}
              </th>)}
              {onRowOpen && <th scope="col">Details</th>}
            </tr></thead><tbody>
              {visible.map((row) => {
                const key = typeof rowKey === 'function' ? rowKey(row) : row[rowKey]
                return <tr key={key}>{columns.map((column) => <td key={column.key}>
                  {column.render ? column.render(cellValue(row, column), row) : cellValue(row, column) ?? 'Not recorded'}
                </td>)}{onRowOpen && <td><button type="button" className="shell-button" onClick={() => onRowOpen(row)} aria-label={`View record ${key}`}>View</button></td>}</tr>
              })}
            </tbody></table>
          </div>
          <nav className="table-pagination" aria-label={`${caption} pagination`}>
            <span role="status">{formatNumber(selected.length)} records · Page {current} of {pages}</span>
            <button type="button" className="shell-button" disabled={current === 1} onClick={() => setPage(current - 1)}>Previous</button>
            <button type="button" className="shell-button" disabled={current === pages} onClick={() => setPage(current + 1)}>Next</button>
          </nav>
        </>}
  </section>
}
