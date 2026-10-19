import { dashboardNow } from '../utils/demoMode.js'
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Activity, Bell, BrainCircuit, Gauge, ListChecks, Pause, Play, RefreshCw } from 'lucide-react'
import PresentationFocus from '../components/PresentationFocus.jsx'
import useOverviewData from '../hooks/useOverviewData.js'
import { useMonitor } from '../hooks/useMonitor.jsx'
import { DataTable, ErrorState, FilterChips, KpiCard, PageHeader, Skeleton, StatusBadge } from '../components/ui.jsx'
import OverviewCharts, { OpenSparkline } from '../components/OverviewCharts.jsx'
import { monitorState, eventAge } from '../components/status.js'
import { learningLoop, normalizeIncidents, periodSummary, utcEpoch } from '../utils/overviewModel.js'
import { formatDate, formatNumber, relativeTime } from '../utils/format.js'
import './overview.css'

const SOURCE_LABELS = { incidents: 'Incidents', containers: 'Container inventory', rules: 'Rule lifecycle', pending: 'Pending rule queue' }
const snapshotComparison = 'Comparison unavailable: no historical snapshots'
const riskTone = (risk) => risk == null ? 'neutral' : risk >= 90 ? 'critical' : risk >= 70 ? 'high' : risk >= 40 ? 'medium' : 'low'
const columns = [
  { key: 'id', label: 'Incident', render: (value) => <Link to={`/alerts?incident=${encodeURIComponent(value)}`}>#{value}</Link> },
  { key: 'score', label: 'Effective risk', render: (value) => <StatusBadge tone={riskTone(value)}>{formatNumber(value)} / 100</StatusBadge> },
  { key: 'containerName', label: 'Container', render: (value, row) => <span title={row.container_id}>{value}</span> },
  { key: 'layer', label: 'Layers fired', filterOptions: ['Both', 'Falco only', 'ML only', 'Not recorded'].map((value) => ({ value, label: value })),
    render: (value) => <StatusBadge tone={value === 'Both' ? 'accent' : 'neutral'}>{value === 'Both' ? 'Both · dual layer' : value}</StatusBadge> },
  { key: 'source', label: 'Detection source', accessor: (row) => row.layer === 'Both' ? 'Falco-backed; ML contributed'
    : row.layer === 'Falco only' ? 'Falco-backed' : row.layer === 'ML only' ? 'ML contributed' : 'Not recorded' },
  { key: 'state', label: 'Confirmation', render: (value) => <StatusBadge tone={value === 'Unconfirmed' ? 'medium' : 'neutral'}>{value}</StatusBadge> },
  { key: 'time', label: 'Created', render: (value) => <time dateTime={value === null ? undefined : new Date(value).toISOString()} title={formatDate(value)}>{relativeTime(value)}</time> },
]

export default function Overview() {
  const { data, errors, loading, refreshing, updatedAt, asOf, paused, togglePaused, refresh } = useOverviewData()
  const { status, error: monitorError } = useMonitor()
  const [range, setRange] = useState('24h')
  const [container, setContainer] = useState('')
  const normalized = useMemo(() => normalizeIncidents(data.incidents, data.containers), [data.incidents, data.containers])
  const summary = useMemo(() => periodSummary(normalized, range, asOf, container), [normalized, range, asOf, container])
  const loop = useMemo(() => learningLoop(summary.current, data.rules), [summary.current, data.rules])
  const choices = useMemo(() => {
    const entries = new Map()
    for (const row of normalized || []) entries.set(row.containerKey, row.containerName)
    // Preserve a selected container through transient inventory/incident failures.
    if (container && !entries.has(container)) entries.set(container, container)
    return [...entries].sort((a, b) => a[1].localeCompare(b[1]))
  }, [normalized, container])
  const health = monitorState(status, monitorError)
  const pendingCount = data.pending?.filter((rule) => rule.status === 'pending_review').length ?? null
  const waitingDeploy = data.pending?.filter((rule) => rule.status === 'approved').length ?? null
  const modelsReady = monitorError || !status?.healthy ? null : status?.models_ready
  const protectedCount = data.containers?.filter((row) => row.protected === true).length ?? null
  const active = [
    ...(range === '7d' ? [{ id: 'range', label: 'Period: Last 7 days' }] : []),
    ...(container ? [{ id: 'container', label: `Container: ${choices.find(([id]) => id === container)?.[1] || container}` }] : []),
  ]
  const issueEntries = Object.entries(errors)
  return <div className="overview-page">
    <div className="overview-heading">
      <PageHeader title="Security overview">Is the system healthy, and what needs attention right now?</PageHeader>
      <div className="overview-refresh">
        <span title={formatDate(updatedAt)}>Last complete refresh: {updatedAt ? relativeTime(updatedAt) : 'Not recorded'}</span>
        <div>
          <button type="button" className="shell-button" aria-pressed={paused} onClick={togglePaused}>
            {paused ? <Play size={16} aria-hidden="true" /> : <Pause size={16} aria-hidden="true" />}
            {paused ? 'Resume overview refresh' : 'Pause overview refresh'}
          </button>
          <button type="button" className="shell-button" disabled={refreshing} onClick={refresh} aria-label="Refresh overview now">
            <RefreshCw size={16} className={refreshing ? 'spin' : ''} aria-hidden="true" />{refreshing ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>
    </div>
    <div className="overview-controls">
      <label htmlFor="overview-range">Creation period<select id="overview-range" value={range} onChange={(event) => setRange(event.target.value)}>
        <option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option>
      </select></label>
      <label htmlFor="overview-container">Container<select id="overview-container" value={container} onChange={(event) => setContainer(event.target.value)}>
        <option value="">All containers</option>{choices.map(([value, name]) => <option key={value} value={value}>{name} · {value.slice(0, 12)}</option>)}
      </select></label>
      <p>Period and container filters apply to incidents and the learning-loop cohort. Health, queue and models show live host-wide snapshots.</p>
    </div>
    <FilterChips filters={active} onRemove={(id) => id === 'range' ? setRange('24h') : setContainer('')} onClear={() => { setRange('24h'); setContainer('') }} />
    {paused && <p className="overview-limit" role="status">Overview refresh paused. Monitor health in the header continues updating; security monitoring continues.</p>}
    {issueEntries.map(([source, issue]) => <section key={source} aria-label={`${SOURCE_LABELS[source]} error`}>
      <ErrorState status={issue.status} error={`${SOURCE_LABELS[source]} unavailable: ${issue.message}`} onRetry={refresh} retrying={refreshing} />
    </section>)}
    {loading ? <Skeleton label="Loading overview metrics…" rows={5} /> : <div className="overview-kpis">
      <KpiCard label="Open incidents" value={summary.open} previous={summary.previousOpen} prominent tone={summary.open ? 'medium' : 'neutral'} icon={Bell}
        detail={<><p>Unconfirmed records created in the selected period; benign dispositions excluded. Both periods use current confirmation state, not historical backlog.</p><Link to="/alerts">Investigate incidents</Link></>}>
        <OpenSparkline data={summary.trend} />
      </KpiCard>
      <KpiCard label="Highest risk score" value={summary.highest} previous={summary.previousHighest} tone={riskTone(summary.highest)} icon={Gauge}
        detail="Effective risk / 100 in the selected creation period. No records means unavailable." />
      <KpiCard label="Pending rule reviews" value={pendingCount} comparisonLabel={snapshotComparison} tone={pendingCount ? 'medium' : 'neutral'} icon={ListChecks}
        detail={<><p>Host-wide queue · {formatNumber(waitingDeploy)} approved rules awaiting deployment.</p><Link to="/rules">Review queue</Link></>} />
      <KpiCard label="Monitor health" value={health.label} comparisonLabel={snapshotComparison} tone={health.tone} icon={Activity}
        detail={<><p title={formatDate(utcEpoch(status?.last_event_at))}>Last event: {eventAge(status?.last_event_at, dashboardNow())}{monitorError && status ? ' (cached)' : ''}</p><Link to="/monitor">Check monitor</Link></>} />
      <KpiCard label="Models ready" value={modelsReady} comparisonLabel={snapshotComparison} icon={BrainCircuit}
        detail={<><p>{formatNumber(protectedCount)} protected containers in current inventory (excluded from automatic isolation). Falco alerts still create incidents without a valid model. Model readiness does not imply complete detection coverage.</p><Link to="/monitor">Baselines and models</Link></>} />
    </div>}
    {!loading && <PresentationFocus rows={summary.current} unavailable={!!errors.incidents} />}
    {summary.excluded > 0 && <p className="overview-caption">{summary.excluded} incident records have missing, invalid or future creation timestamps and are excluded from time comparisons.</p>}
    {loading ? <Skeleton label="Loading incident trend and learning loop…" rows={6} />
      : <OverviewCharts trend={summary.trend} stages={loop.stages} limited={loop.limited} unlinked={loop.unlinked} />}
    <section className="overview-incidents" aria-labelledby="recent-incidents-title">
      <div className="section-heading"><h3 id="recent-incidents-title">Recent incidents</h3><Link to="/alerts">View all incidents</Link></div>
      <p className="overview-caption">Selected period · highest effective risk first. Layer and source labels reflect recorded evidence; AI text is advisory and is not a detection source.</p>
      <DataTable rows={summary.current || []} columns={columns} caption="Recent incidents" initialSort={{ key: 'score', direction: 'desc' }}
        loading={loading} error={errors.incidents?.message} errorStatus={errors.incidents?.status} onRetry={refresh} pageSize={10} />
    </section>
  </div>
}
