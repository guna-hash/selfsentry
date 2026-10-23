import { Link } from 'react-router-dom'
import { isSampleMode } from '../utils/demoMode.js'
import { useState } from 'react'
import { DataTable, Drawer, PageHeader, StatusBadge } from '../components/ui.jsx'
import RefreshControls from '../components/RefreshControls.jsx'
import ContainerActionDialog from '../components/ContainerActionDialog.jsx'
import useCollection from '../hooks/useCollection.js'
import { options } from '../utils/operations.js'
import { formatDate, formatNumber } from '../utils/format.js'
export default function Containers() {
  const data = useCollection('/containers/'), [selected, setSelected] = useState(null), [action, setAction] = useState(null)
  const columns = [
    { key: 'name', label: 'Container', render: (v,r) => <span>{v}<small className="muted"> {r.id}</small></span> },
    { key: 'id', label: 'Container ID', accessor: r => r.full_id || r.id, render: v => <span title={v}>{v?.slice(0,12)}</span> },
    { key: 'image', label: 'Image' },
    { key: 'status', label: 'Runtime', filterOptions: options(data.rows.map(r => r.status)), render: v => <StatusBadge status={v} /> },
    { key: 'protected', label: 'Protection', accessor: r => r.protected === true ? 'Protected' : r.protected === false ? 'Unprotected' : 'Unknown', filterOptions: options(['Protected','Unprotected','Unknown']) },
    { key: 'containment_label', label: 'Containment' },
    { key: 'monitoring', label: 'Monitoring', accessor: r => r.monitoring?.label },
    { key: 'latest_risk_score', label: 'Latest risk', render: v => formatNumber(v) },
  ]
  const live = selected && data.rows.find(r => r.id === selected.id)
  const current = live || selected
  const recoveryUnavailable = current?.containment_state === 'record_unavailable'
  return <><PageHeader title="Containers">Live Docker inventory. Network disconnection is verified only when the backend containment label explicitly reports it.</PageHeader>
    <RefreshControls {...data} />
    <DataTable {...data} error={data.error?.message} errorStatus={data.error?.status} onRetry={data.refresh} columns={columns} caption="Containers" onRowOpen={setSelected} />
    <Drawer open={!!current && !action} title="Container details" onClose={() => setSelected(null)}>
      {current && <><h3>{current.name}</h3><p>{current.full_id || current.id}</p><p>{current.containment_label || 'Containment verification not available'}</p>
        <p>Isolation recorded: {formatDate(current.isolated_at)} · Reason: {current.isolation_reason || 'Not recorded'}</p>
        <h3>Response error</h3><pre className="rule-yaml">{JSON.stringify(current.isolation_error ?? 'Not recorded', null, 2)}</pre><h3>Risk explanation</h3><pre className="rule-yaml">{JSON.stringify(current.risk_explanation ?? 'Not recorded', null, 2)}</pre>
        {/svm/i.test(current.isolation_reason || '') && <p>Experimental SVM response: review the recorded reason.</p>}
        <p>Response history records action, time, actor, and outcome in the read-only audit log.</p><Link to={`/audit?container_id=${encodeURIComponent(current.full_id || current.id)}&legacy_container_id=${encodeURIComponent(current.id)}`}>View response history</Link>
        <div className="table-toolbar"><button className="shell-button" disabled={isSampleMode() || !live || !!data.error || data.loading || recoveryUnavailable || current.isolated || current.protected !== false} onClick={() => setAction('isolate')}>Isolate</button>
        <button className="shell-button" disabled={isSampleMode() || !live || !!data.error || data.loading || recoveryUnavailable || !current.isolated} onClick={() => setAction('resume')}>Resume / restore networks</button></div>
        {!live && <p>Container is absent from the current inventory. Refresh before taking action.</p>}
        {current.protected && <p>Protected workload: manual isolation is disabled.</p>}</>}
    </Drawer>
    {action && current && <ContainerActionDialog container={current} action={action} onClose={() => setAction(null)} onComplete={data.refresh} />}
  </>
}
