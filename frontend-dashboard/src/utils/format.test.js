import { expect, it } from 'vitest'
import { comparison, formatNumber, formatDate, relativeTime } from './format.js'
it('preserves missing and invalid values instead of coercing to zero', () => {
  for (const value of [null, undefined, NaN, Infinity, '', '12']) expect(formatNumber(value)).toBe('—')
  expect(formatNumber(0)).toBe('0')
  expect(formatDate(null)).toBe('Not recorded')
  expect(formatDate('invalid')).toBe('Not recorded')
})
it('reports honest comparisons including zero denominators', () => {
  expect(comparison(10,null).direction).toBe('unknown')
  expect(comparison(10,0).label).toContain('percentage unavailable')
  expect(comparison(0,0).label).toBe('0% unchanged vs previous period')
  expect(comparison(5,10).label).toBe('50% down vs previous period')
})
it('formats recorded times and clock skew explicitly', () => {
  const now=Date.parse('2026-10-16T09:00:00Z')
  expect(relativeTime(null,now)).toBe('Not recorded')
  expect(relativeTime('2026-10-16T09:01:00Z',now)).toBe('Clock ahead')
  expect(relativeTime('2026-10-16T08:59:00Z',now,'en')).toBe('1 minute ago')
  expect(formatDate('2026-10-16T09:00:00Z',{timeZone:'UTC'},'en')).toContain('2026')
})
