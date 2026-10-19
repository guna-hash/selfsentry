import { useState } from 'react'
import { DataTable, Drawer, PageHeader, StatusBadge } from '../components/ui.jsx'
import RefreshControls from '../components/RefreshControls.jsx'
import useCollection from '../hooks/useCollection.js'
import { formatDate } from '../utils/format.js'
import { operationDate, options } from '../utils/operations.js'
export default function Deployments() {
  const data = useCollection('/deployments/?limit=500'), [selected,setSelected] = useState(null)
  const columns = [
    { key: 'id', label: 'ID' }, { key: 'created_at', label: 'Recorded', render: v => operationDate(v) },
    { key: 'container_name', label: 'Container' }, { key: 'image_name', label: 'Image' },
    { key: 'decision', label: 'Gate decision', filterOptions: options(['allowed','blocked','overridden']), render: v => <StatusBadge status={v} /> },
    ...[['critical','Critical'],['high','High'],['secrets_found','Secrets'],['misconfigurations_found','Misconfigurations']].map(([key,label]) => ({ key, label, accessor: r => r.scan?.[key] })),
    { key: 'requested_by', label: 'Recorded actor' }, { key: 'override_reason', label: 'Override reason' },
  ]
  return <><PageHeader title="Deployments">Recorded deployment gate decisions and Trivy evidence. Up to 500 latest records; filters apply to this loaded window.</PageHeader>
    <RefreshControls {...data} />{data.rows.length >= 500 && <p role="status">History limit reached. Earlier deployments are outside this view.</p>}
    <DataTable {...data} error={data.error?.message} errorStatus={data.error?.status} onRetry={data.refresh} columns={columns} initialSort={{key:'id',direction:'desc'}} caption="Deployments" onRowOpen={setSelected} />
    <Drawer open={!!selected} title="Deployment evidence" onClose={() => setSelected(null)}>{selected && <><p>Deployment #{selected.id} · {selected.decision}</p>
      <p>Recorded actor: {selected.requested_by || 'Not recorded'} · Override reason: {selected.override_reason || 'Not recorded'}</p>
      <h3>Policy violations</h3><pre className="rule-yaml">{JSON.stringify(selected.policy_violations || [], null, 2)}</pre>
      <h3>Policy summary</h3><pre className="rule-yaml">{JSON.stringify(selected.policy_summary ?? 'Not recorded', null, 2)}</pre>
      <h3>Trivy scan and findings</h3><pre className="rule-yaml">{JSON.stringify(selected.scan ?? 'Not recorded', null, 2)}</pre></>}</Drawer>
  </>
}
