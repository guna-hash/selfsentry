import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { DataTable, Drawer, PageHeader, StatusBadge, FilterChips } from '../components/ui.jsx'
import RefreshControls from '../components/RefreshControls.jsx'
import useCollection from '../hooks/useCollection.js'
import { operationDate, auditVerification, auditActor, auditInRange, downloadCsv, options } from '../utils/operations.js'
import { formatDate } from '../utils/format.js'
export default function AuditLog() {
  const [search,setSearch] = useSearchParams()
  const [type,setType] = useState(''), [eventId,setEventId] = useState(''), [before,setBefore] = useState(null)
  const [from,setFrom] = useState(''), [to,setTo] = useState(''), [selected,setSelected] = useState(null)
  const params = new URLSearchParams({limit:'200'})
  if (type) params.set('event_type',type)
  if (eventId) params.set('event_id',eventId)
  if (before) params.set('before_id',String(before))
  if (search.get('container_id')) params.set('container_id',search.get('container_id'))
  const data = useCollection('/audit/?' + params)
  const rows = data.rows.filter(r => auditInRange(r,from,to))
  const columns = [
    {key:'id',label:'Audit ID'}, {key:'occurred_at',label:'Time (local display)',accessor:r => r.occurred_at || r.created_at,render:v => operationDate(v)},
    {key:'event_type',label:'Event type'}, {key:'actor',label:'Actor',accessor:auditActor,filterOptions:options(data.rows.map(auditActor))},
    {key:'verification',label:'Verification evidence',accessor:auditVerification},
    {key:'severity',label:'Severity',filterOptions:options(data.rows.map(r => r.severity)),render:v => <StatusBadge status={v} tone={v === 'critical' ? 'critical' : v === 'warning' ? 'medium' : 'neutral'} />},
    {key:'container_name',label:'Container',accessor:r => r.container_name || r.container_id || 'Host'},
    {key:'detail',label:'Recorded outcome / detail',accessor:r => JSON.stringify(r.detail || {}),render:v => <span className="audit-preview">{v}</span>},
  ]
  const clearScope = () => {setFrom('');setTo('');setType('');setEventId('');setBefore(null)}
  const scopes = [{id:'type',value:type,label:'Stored event type'},{id:'eventId',value:eventId,label:'Exact ID'},{id:'from',value:from,label:'From UTC'},{id:'to',value:to,label:'Through UTC'}].filter(x => x.value).map(x => ({id:x.id,label:`${x.label}: ${x.value}`}))
  function removeScope(id) { if (id === 'type') {setType('');setBefore(null)}; if (id === 'eventId') {setEventId('');setBefore(null)}; if (id === 'from') setFrom(''); if (id === 'to') setTo('') }
  return <><PageHeader title="Audit log">Read-only recorded evidence. Type and exact ID query stored history; actor, UTC dates, search, and export apply to the loaded 200-record window.</PageHeader>
    <div className="table-toolbar">
      <label>Stored event type<input value={type} placeholder="e.g. CONTAINER_RESUMED" onChange={e => {setType(e.target.value);setBefore(null)}} /></label>
      <label>Exact audit ID<input type="number" min="1" step="1" value={eventId} onChange={e => {setEventId(e.target.value);setBefore(null)}} /></label>
      <label>From date (UTC)<input type="date" value={from} onChange={e => setFrom(e.target.value)} /></label>
      <label>Through date (UTC)<input type="date" value={to} onChange={e => setTo(e.target.value)} /></label>
      <button className="shell-button" onClick={clearScope}>Clear scope filters</button>
    </div>
    <FilterChips filters={scopes} onRemove={removeScope} onClear={clearScope} />
    {search.get('container_id') && <p>History for container {search.get('container_id')}. <Link to="/audit">All containers</Link>{search.get('legacy_container_id') && search.get('legacy_container_id') !== search.get('container_id') && <button className="shell-button" onClick={() => {const next = new URLSearchParams(search);next.set('container_id',search.get('legacy_container_id'));next.set('legacy_container_id',search.get('container_id'));setBefore(null);setSearch(next)}}>Switch recorded short / full ID</button>} Older records may use either Docker ID; inspect both histories.</p>}
    {from && to && from > to && <p role="alert">From date must be on or before through date.</p>}
    <RefreshControls {...data} />
    <div className="table-toolbar"><button className="shell-button" disabled={!before} onClick={() => setBefore(null)}>Latest records</button>
      <button className="shell-button" disabled={data.loading || !!data.error || !!eventId || data.rows.length < 200} onClick={() => setBefore(data.rows.at(-1).id)}>Older records</button>
      <span>{before ? `Records before audit #${before}` : 'Latest matching records'}</span></div>
    <DataTable {...data} rows={rows} error={data.error?.message} errorStatus={data.error?.status} onRetry={data.refresh} columns={columns} initialSort={{key:'id',direction:'desc'}} caption="Audit events" onRowOpen={setSelected}
      onExport={filtered => downloadCsv(filtered, columns.map(c => ({label:c.label,value:r => c.accessor ? c.accessor(r) : r[c.key]})))} />
    <Drawer open={!!selected} title="Audit evidence" onClose={() => setSelected(null)}>{selected && <><p>Audit #{selected.id} · {selected.event_type} · {auditActor(selected)}</p><pre className="rule-yaml">{JSON.stringify(selected,null,2)}</pre></>}</Drawer>
  </>
}
