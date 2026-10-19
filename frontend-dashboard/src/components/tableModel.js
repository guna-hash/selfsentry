export const cellValue = (row, column) => column.accessor ? column.accessor(row) : row[column.key]
const missing = (value) => value == null || value === '' || (typeof value === 'number' && !Number.isFinite(value))
const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' })
export function selectRows(rows, columns, { query = '', filters = {}, sort = {} } = {}) {
  const needle = query.trim().toLocaleLowerCase()
  const filtered = rows.filter((row) => {
    if (needle && !columns.some((column) => column.searchable !== false &&
      String(cellValue(row, column) ?? '').toLocaleLowerCase().includes(needle))) return false
    return columns.every((column) => !Object.hasOwn(filters, column.key) ||
      String(cellValue(row, column) ?? '') === filters[column.key])
  })
  const column = columns.find((item) => item.key === sort.key)
  if (!column || column.sortable === false) return filtered
  return filtered.map((row, index) => ({ row, index })).sort((a, b) => {
    const left = cellValue(a.row, column), right = cellValue(b.row, column)
    // Missing evidence stays last in either direction. Input rows are never mutated.
    if (missing(left) || missing(right)) return missing(left) === missing(right) ? a.index - b.index : missing(left) ? 1 : -1
    const result = column.compare ? column.compare(left, right)
      : typeof left === 'number' && typeof right === 'number' ? left - right
        : collator.compare(String(left), String(right))
    return (sort.direction === 'desc' ? -result : result) || a.index - b.index
  }).map(({ row }) => row)
}
