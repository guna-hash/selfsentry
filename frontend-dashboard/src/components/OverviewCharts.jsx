import { memo } from 'react'
import { ResponsiveContainer, LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts'
import EmptyState from './EmptyState.jsx'
import { formatDate, formatNumber } from '../utils/format.js'

const tooltipStyle = { background: 'var(--panel)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 8 }
const utc = (time) => `${formatDate(time, { timeZone: 'UTC' })} UTC`
export const OpenSparkline = memo(function OpenSparkline({ data }) {
  if (!data?.some((row) => row.open > 0)) return null
  return <div className="overview-sparkline" role="img" aria-label="Unconfirmed incidents by creation time; not historical backlog">
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={data}><Line dataKey="open" stroke="var(--accent)" dot={false} strokeWidth={2} isAnimationActive={false} /></LineChart>
    </ResponsiveContainer>
  </div>
})

export default memo(function OverviewCharts({ trend, stages, limited, unlinked }) {
  const hasTrend = trend?.some((row) => row.current > 0 || row.previous > 0)
  const hasLoop = stages.some((stage) => stage.value !== null && stage.value > 0)
  return <div className="overview-charts">
    <section className="chart-panel" aria-labelledby="incident-trend-title">
      <div className="section-heading"><h3 id="incident-trend-title">Incident trend</h3><span>Created incidents</span></div>
      <p className="overview-caption">Selected period vs the preceding equal period. Buckets use UTC; this is recorded volume, not detection accuracy.</p>
      {hasTrend ? <>
        <div className="overview-chart" role="img" aria-label="Incident counts in selected and previous periods">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={trend} margin={{ top: 12, right: 16, left: -16, bottom: 4 }}>
              <CartesianGrid stroke="var(--border-subtle)" vertical={false} />
              <XAxis dataKey="start" tickFormatter={(time) => new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', timeZone: 'UTC' }).format(time)}
                stroke="var(--text-muted)" tickLine={false} axisLine={false} fontSize={11} minTickGap={32} />
              <YAxis allowDecimals={false} stroke="var(--text-muted)" tickLine={false} axisLine={false} fontSize={11} />
              <Tooltip contentStyle={tooltipStyle} labelFormatter={(value) => utc(value)} />
              <Line dataKey="current" name="Selected period" stroke="var(--accent)" strokeWidth={2} dot={false} isAnimationActive={false} />
              <Line dataKey="previous" name="Previous period (aligned)" stroke="var(--text-muted)" strokeDasharray="4 4" dot={false} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="overview-legend"><span>Solid: selected period</span><span>Dashed: preceding period, aligned by bucket</span></div>
        <details className="chart-data"><summary>Read trend counts</summary><ol>
          {trend.map((row) => <li key={row.start}>{utc(row.start)}–{utc(row.end)}: {row.current} incidents.
            {' '}Preceding bucket {utc(row.previousStart)}–{utc(row.previousEnd)}: {row.previous} incidents.</li>)}
        </ol></details>
      </> : <EmptyState title={trend ? 'No incidents in these periods' : 'Incident data unavailable'}>
        {trend ? 'The selected and previous periods contain no timestamped incident records.' : 'Retry the incident request to load this chart.'}
      </EmptyState>}
    </section>
    <section className="chart-panel" aria-labelledby="learning-loop-title">
      <div className="section-heading"><h3 id="learning-loop-title">Learning loop</h3><span>Observed cohort</span></div>
      <p className="overview-caption">Incidents created in the selected period, with their current confirmation and rule lifecycle evidence. First two stages count incidents; later stages count rules. These are not conversion rates.</p>
      {limited && <p className="overview-limit" role="note">Only the latest 100 rule records are exposed by the API. Earlier candidates and their lifecycle evidence may be missing.</p>}
      {unlinked > 0 && <p className="overview-caption">{unlinked} rule records have no source-incident link and are excluded.</p>}
      {hasLoop ? <>
        <div className="overview-chart" role="img" aria-label="Recorded incident-to-rule lifecycle counts">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={stages} layout="vertical" margin={{ top: 0, right: 16, left: 0, bottom: 0 }}>
              <XAxis type="number" allowDecimals={false} stroke="var(--text-muted)" fontSize={11} tickLine={false} axisLine={false} />
              <YAxis type="category" dataKey="label" width={88} stroke="var(--text-muted)" fontSize={11} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={tooltipStyle} formatter={(value, name, item) => [`${formatNumber(value)} ${item.payload.unit}`, 'Recorded']} />
              <Bar dataKey="value" name="Recorded" fill="var(--accent)" radius={[0, 4, 4, 0]} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div>
        <ol className="loop-counts">{stages.map((stage) => <li key={stage.key}>
          <span>{stage.label}</span><strong>{stage.value === null ? 'No data' : `${formatNumber(stage.value)} ${stage.unit}`}</strong>
        </li>)}</ol>
      </> : <EmptyState title="No learning-loop data in this period">Select a broader period, or review an incident and its candidate evidence. Missing evidence is not a measured zero.</EmptyState>}
      <p className="overview-caption">Every rule deployment requires human approval. Re-fired means a recorded native Falco match, not a validated true positive.</p>
    </section>
  </div>
})
