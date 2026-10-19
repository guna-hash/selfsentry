import { isSampleMode, dashboardNow } from '../utils/demoMode.js'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { DataTable, KpiCard, PageHeader, StatusBadge, Notice, ErrorState, Skeleton } from '../components/ui.jsx'
import RefreshControls from '../components/RefreshControls.jsx'
import { useMonitorSnapshot } from '../hooks/useMonitor.jsx'
import { monitorState, eventAge } from '../components/status.js'
import { formatDate, formatNumber } from '../utils/format.js'
import { operationDate, options } from '../utils/operations.js'
export default function Monitor() {
  const data = useMonitorSnapshot(), {status,error,loading} = data
  const [token,setToken] = useState(''), [notice,setNotice] = useState(null)
  const state = monitorState(status,error)
  const components = Object.entries(status?.components || {}).map(([id,item]) => ({id,...item}))
  const matching = status?.configuration?.rule_matching ?? status?.rule_matching
  const queueRows = [
    ['incident_outbox_size','Incident delivery outbox'],['audit_spool_size','Audit delivery spool'],
    ['event_queue_depth','Event queue'],['rule_queue_depth','Rule queue'],
  ].map(([key,name]) => ({id:key,name,value:status?.[key]}))
  function saveToken() {
    if (isSampleMode()) return
    try {
      if (token.trim()) sessionStorage.setItem('selfsentry-api-token',token.trim())
      else sessionStorage.removeItem('selfsentry-api-token')
      setToken('');setNotice({kind:'success',text:'Session credentials updated.'});data.refresh()
    } catch {setNotice({kind:'error',text:'Browser session storage is unavailable; credentials were not saved.'})}
  }
  return <><PageHeader title="Monitor">Service health and recorded pipeline telemetry. Global safety indicators continue updating when this page snapshot is paused.</PageHeader>
    <RefreshControls {...data} />{loading && <Skeleton label="Loading monitor…" />}{error && <ErrorState error={error} onRetry={data.refresh} />}
    <section className="health-panel"><div><h3><StatusBadge tone={state.tone}>{state.label}</StatusBadge></h3><p>{status?.reason || 'No additional service reason recorded'}</p></div>
      <div>Last event: {eventAge(status?.last_event_at,dashboardNow())}<br />Snapshot: {formatDate(status?.updated_at)}<br />Heartbeat age: {formatNumber(status?.status_age_seconds, {maximumFractionDigits:0})} seconds</div></section>
    <div className="metrics-grid">{[['Failed responses',status?.failed_response_actions],['Pending incidents',status?.unconfirmed_incidents],['Containers tracked',status?.containers?.tracked],['Models ready',status?.models_ready]].map(([label,value]) => <KpiCard key={label} label={label} value={value} comparisonLabel="Historical comparison unavailable" />)}</div>
    <p>Rule matching: {matching ?? 'Not exposed by this API'}.</p>{matching != null && matching !== 'all' && <p className="error-state" role="alert">Rule matching is not “all”; multiple matching detections may be suppressed. Review Falco configuration.</p>}
    <p>Last error: {status?.last_error || 'Not exposed; inspect recorded connection details below.'}</p>
    <DataTable rows={components} caption="Connections" loading={loading} error={error} onRetry={data.refresh} columns={[
      {key:'id',label:'Service'}, {key:'state',label:'State',filterOptions:options(components.map(r => r.state)),render:v => <StatusBadge status={v} tone={['ok','connected'].includes(v) ? 'low' : v === 'disabled' ? 'neutral' : 'critical'} />},
      {key:'detail',label:'Recorded detail / last error'}, {key:'since',label:'Since',render:v => operationDate(v)},
    ]} />
    <p>Only services reported by the backend are listed. Missing Falco journal, backend, or database status is unavailable, rather than proof of health.</p>
    <DataTable rows={queueRows} caption="Queue depths" loading={loading} error={error} onRetry={data.refresh} columns={[{key:'name',label:'Queue'},{key:'value',label:'Reported depth'}]} />
    <p><Link to="/models">View container baselines and models</Link></p>
    {isSampleMode() ? <p>Sample mode is read-only; session credentials are not used or changed.</p> : <details className="credentials"><summary>Session credentials</summary><p>Operator token for this browser tab. Blank clears the saved token.</p>
      <label htmlFor="operator-token">Operator token</label><div className="token-form"><input id="operator-token" type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} /><button className="shell-button" onClick={saveToken}>Save token</button></div>
      <Notice notice={notice} onDismiss={() => setNotice(null)} /></details>}
  </>
}
