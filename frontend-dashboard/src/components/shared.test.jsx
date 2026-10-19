import { renderToStaticMarkup } from 'react-dom/server'
import { expect, it } from 'vitest'
import KpiCard from './KpiCard.jsx'
import StatusBadge from './StatusBadge.jsx'
import { errorMessage } from './ErrorState.jsx'
it('does not invent missing KPI comparisons or values', () => {
  const html=renderToStaticMarkup(<KpiCard label="Open incidents" value={null} />)
  expect(html).toContain('—'); expect(html).toContain('Comparison unavailable')
})
it('uses neutral status for unknown states and text as well as color', () => {
  expect(renderToStaticMarkup(<StatusBadge status="unknown" />)).toContain('tone-neutral')
  expect(renderToStaticMarkup(<StatusBadge status="blocked" />)).toContain('blocked')
})
it('distinguishes authentication, authorization, missing record and server errors', () => {
  expect(new Set([401,403,404,500].map(errorMessage)).size).toBe(4)
})
it('allows snapshot cards to explain missing historical comparisons explicitly', () => {
  const html=renderToStaticMarkup(<KpiCard label="Models ready" value={2} comparisonLabel="No historical snapshot" />)
  expect(html).toContain('No historical snapshot')
})
