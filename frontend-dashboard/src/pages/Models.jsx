import { DataTable, PageHeader, StatusBadge } from '../components/ui.jsx'
import RefreshControls from '../components/RefreshControls.jsx'
import { useMonitorSnapshot } from '../hooks/useMonitor.jsx'
import useCollection from '../hooks/useCollection.js'
import { modelLabel, options } from '../utils/operations.js'
export default function Models() {
  const data = useMonitorSnapshot(), inventory = useCollection('/containers/')
  const baselines = data.status?.baselines || {}
  const ids = [...new Set([...inventory.rows.map(r => r.id), ...Object.keys(baselines)])]
  const rows = ids.map(id => {
    const container = inventory.rows.find(r => r.id === id)
    const item = baselines[id]
    return {id,name:container?.name || id,...item,label:item ? modelLabel(item.state) : 'Unknown',reason:item?.reason || (item ? 'Not recorded' : 'No lifecycle evidence reported')}
  })
  const columns = [
    {key:'name',label:'Container'}, {key:'id',label:'Container ID'},
    {key:'label',label:'Model state',filterOptions:options(rows.map(r => r.label)),render:(v,r) => <StatusBadge tone={r.state === 'MODEL_READY' ? 'low' : r.state?.includes('INVALID') || r.state === 'MODEL_UNAVAILABLE' ? 'critical' : 'medium'}>{v}</StatusBadge>},
    {key:'state',label:'Raw lifecycle'}, {key:'samples',label:'Samples'}, {key:'reason',label:'Recorded reason'},
    {key:'coverage',label:'Detection coverage',accessor:r => r.state === 'MODEL_READY' ? 'Behavioral model ready; inspect Monitor for live health' : 'Falco still produces incidents when ingestion is healthy; behavioral scoring has no valid model'},
  ]
  return <><PageHeader title="Models">Per-container baseline lifecycle. Missing evidence stays unknown. Model availability does not establish live detection health.</PageHeader>
    <p>Without a valid behavioral model, Falco still produces incidents when ingestion is healthy. Check Monitor for current ingestion status.</p>
    <RefreshControls {...data} /><p>Pausing freezes lifecycle telemetry only; inventory and global safety status continue updating.</p>
    {inventory.error && <p role="alert">Container inventory unavailable: {inventory.error.message}. Reported baselines may omit undiscovered containers.</p>}
    <DataTable rows={rows} columns={columns} caption="Models" loading={data.loading || inventory.loading} error={data.error} onRetry={data.refresh} />
  </>
}
