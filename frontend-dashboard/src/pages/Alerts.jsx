import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Pause, Play, RefreshCw } from 'lucide-react'
import { DataTable, FilterChips, Notice, PageHeader, StatusBadge } from '../components/ui.jsx'
import IncidentDrawer from '../components/IncidentDrawer.jsx'
import { useIncidents } from '../hooks/useIncidents.js'
import { incidentSeverity } from '../api.js'
import { normalizeIncidents, RANGE_MS } from '../utils/overviewModel.js'
import { formatDate, formatNumber, relativeTime } from '../utils/format.js'
import './alerts.css'

const columns = [
  { key: 'id', label: 'Incident ID', render: (value) => `#${value}` },
  { key: 'score', label: 'Risk', render: (value) => `${formatNumber(value)} / 100` },
  { key: 'severity', label: 'Severity', accessor: (row) => incidentSeverity(row), render: (value) => <StatusBadge tone={value}>{value}</StatusBadge> },
  { key: 'containerName', label: 'Container', render: (value,row) => <span title={row.container_id}>{value}</span> },
  { key: 'layer', label: 'Layers fired', filterOptions: ['Both','Falco only','ML only','Not recorded'].map((value)=>({value,label:value})), render:(value)=><StatusBadge tone={value==='Both'?'accent':'neutral'}>{value==='Both'?'Both · dual layer':value}</StatusBadge> },
  { key: 'state', label: 'Confirmation', filterOptions: ['Unconfirmed','Auto-confirmed','Human-confirmed','Benign'].map((value)=>({value,label:value})), render:(value)=><StatusBadge tone={value==='Unconfirmed'?'medium':'neutral'}>{value}</StatusBadge> },
  { key: 'time', label: 'Created', render:(value)=><time title={formatDate(value)} dateTime={value===null?undefined:new Date(value).toISOString()}>{relativeTime(value)}</time> },
]
export default function Alerts() {
  const { incidents, containers, error, inventoryError, loading, refreshing, updatedAt, paused, refresh, togglePaused, hasOlder, hasNewer, older, newer, latest, pageNumber = 1, pageSize = 200 } = useIncidents()
  const [search,setSearch] = useSearchParams()
  const selected = search.get('incident')
  const validId = selected && /^\d+$/.test(selected) && Number(selected)>0
  const [period,setPeriod] = useState('all')
  const [notice,setNotice] = useState(null)
  const normalized = useMemo(()=>normalizeIncidents(incidents,containers),[incidents,containers])
  const rows = useMemo(()=>{
    if (!normalized) return []
    if (period==='all') return normalized
    const end=updatedAt ?? Date.now(), start=end-RANGE_MS[period]
    return normalized.filter((row)=>row.time!==null && row.time>=start && row.time<=end)
  },[normalized,period,updatedAt])
  function open(incident) { const next=new URLSearchParams(search);next.set('incident',incident.id);setSearch(next) }
  function close() { const next=new URLSearchParams(search);next.delete('incident');setSearch(next) }
  return <div className="alerts-page">
    <div className="alerts-heading"><PageHeader title="Alerts & incidents">Find the incidents that need review, then inspect their recorded evidence.</PageHeader>
      <div className="alerts-refresh"><span title={formatDate(updatedAt)}>Last incident update: {updatedAt?relativeTime(updatedAt):'Not recorded'}</span>
        <div><button type="button" className="shell-button" onClick={togglePaused} aria-pressed={paused}>{paused?<Play size={16} aria-hidden="true"/>:<Pause size={16} aria-hidden="true"/>}{paused?'Resume incident refresh':'Pause incident refresh'}</button>
          <button type="button" className="shell-button" disabled={refreshing} onClick={refresh} aria-label="Refresh incidents now"><RefreshCw size={16} className={refreshing?'spin':''} aria-hidden="true"/>Refresh</button></div>
      </div>
    </div>
    <Notice notice={notice} onDismiss={()=>setNotice(null)} />
    <div className="alerts-controls"><label htmlFor="incident-period">Creation period<select id="incident-period" value={period} onChange={(event)=>setPeriod(event.target.value)}><option value="all">All time in this batch</option><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option></select></label>
      <p>Risk uses effective score when recorded, otherwise base risk. Model availability and advisory AI text do not establish which layers fired.</p></div>
    <FilterChips filters={period==='all'?[]:[{id:'period',label:`Creation period: ${period}`}]} onRemove={()=>setPeriod('all')} onClear={()=>setPeriod('all')}/>
    {paused && <p role="status" className="incident-caption">Incident refresh paused. Header health updates and security monitoring continue.</p>}
    {inventoryError && <p role="status" className="incident-caption">Container names unavailable; recorded IDs are shown. <button type="button" className="shell-button" disabled={refreshing} onClick={refresh}>Retry inventory</button></p>}
    {selected && !validId && <p role="alert" className="error-state">The incident link has an invalid ID. <button type="button" className="shell-button" onClick={close}>Clear incident selection</button></p>}
    <nav aria-label="Incident history" className="alerts-controls">
      <button type="button" className="shell-button" disabled={!hasNewer || loading || refreshing} onClick={latest}>Latest incidents</button>
      <button type="button" className="shell-button" disabled={!hasNewer || loading || refreshing} onClick={newer}>Newer batch</button>
      <button type="button" className="shell-button" disabled={!hasOlder || loading || refreshing || !!error} onClick={older}>Older batch</button>
      <p role="status">History batch {pageNumber} · up to {pageSize} incidents. Search, sorting and creation-period filters apply to this batch.</p>
    </nav>
    <DataTable rows={rows} columns={columns} caption="Incidents" initialSort={{key:'score',direction:'desc'}} pageSize={10}
      loading={loading} error={error?.message} errorStatus={error?.status} onRetry={refresh} onRowOpen={open}/>
    {validId && <IncidentDrawer key={selected} id={selected} paused={paused} onClose={close} onChanged={refresh} onNotice={setNotice}/>}
  </div>
}
