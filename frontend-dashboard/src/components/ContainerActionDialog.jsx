import { isSampleMode } from '../utils/demoMode.js'
import { useRef, useState } from 'react'
import { Drawer, Notice } from './ui.jsx'
import { requestJson, requireWriteToken } from '../utils/requests.js'
import { containerAction } from '../utils/operations.js'
export default function ContainerActionDialog({ container, action, onClose, onComplete }) {
  const [actor, setActor] = useState(''), [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false), [notice, setNotice] = useState(null), [finished, setFinished] = useState(false)
  const [uncertain, setUncertain] = useState(false)
  const [result, setResult] = useState(null)
  const lock = useRef(false)
  const resume = action === 'resume'
  async function submit(event) {
    event.preventDefault(); if (isSampleMode() || lock.current || busy || finished || uncertain) return
    lock.current = true
    let retainLock = false
    setBusy(true); setNotice(null)
    try {
      const outcome = await containerAction(container, action, actor, reason, requestJson, requireWriteToken)
      retainLock = true
      setResult(outcome); setFinished(true)
      const verified = resume && typeof outcome?.container_id === 'string' && Array.isArray(outcome?.networks)
      setNotice({ kind: 'success', text: verified ? `Backend verified running state and restored saved network attachments: ${Array.isArray(outcome?.networks) ? outcome.networks.join(', ') || '(no saved attachments)' : 'network names not returned'}. Review the refreshed inventory and audit history.` : resume ? 'Resume returned without complete verification fields. Review refreshed inventory and audit evidence before assuming recovery.' : 'Backend accepted isolation. Check refreshed containment evidence and audit history.' })
      onComplete()
    } catch (error) {
      retainLock = !!error.uncertain
      setNotice({ kind: 'error', text: error.message }); setUncertain(!!error.uncertain); onComplete()
    } finally { lock.current = retainLock; setBusy(false) }
  }
  return <Drawer open title={resume ? 'Confirm resume / restore networks' : 'Confirm container isolation'} busy={busy} onClose={onClose}>
    <p>{container.name} · {container.id}</p>
    <p>{resume ? 'This unpauses the workload and reconnects its saved networks. Policy and behavior rechecks run after recovery; review their recorded outcomes.' : 'This pauses the workload and disconnects its networks. Protected workloads cannot be isolated.'}</p>
    <form onSubmit={submit}>
      <label>Operator<input required value={actor} onChange={e => setActor(e.target.value)} disabled={isSampleMode() || busy || finished || uncertain} /></label>
      {!resume && <label>Reason<textarea required value={reason} onChange={e => setReason(e.target.value)} disabled={isSampleMode() || busy || finished || uncertain} /></label>}
      <button className="shell-button" disabled={isSampleMode() || busy || finished || uncertain || !actor.trim() || (!resume && !reason.trim())}>{busy ? 'Submitting…' : resume ? 'Confirm restore networks' : 'Confirm isolate'}</button>
    </form>
    <Notice notice={notice} onDismiss={() => setNotice(null)} />
    {result && <><h3>Recorded response and rechecks</h3><pre className="rule-yaml">{JSON.stringify(result,null,2)}</pre></>}
    {uncertain && <p>Close this dialog and review refreshed inventory and audit evidence before attempting another action.</p>}
  </Drawer>
}
