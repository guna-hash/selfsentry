import { useEffect, useState } from 'react'
import { API, apiFetch, describeFailure } from '../api.js'

export default function Monitor() {
  const [status, setStatus] = useState(null)
  const [error, setError] = useState(null)
  const [token, setToken] = useState('')
  const [notice, setNotice] = useState('')
  useEffect(() => {
    let mounted = true
    async function refresh() {
      try {
        const response = await apiFetch(`${API}/monitor/status`)
        if (!response.ok) throw new Error(await describeFailure(response))
        const data = await response.json()
        if (mounted) { setStatus(data); setError(null) }
      } catch (err) { if (mounted) setError(err.message) }
    }
    refresh()
    const timer = setInterval(refresh, 3000)
    return () => { mounted = false; clearInterval(timer) }
  }, [])
  const components = status?.components || {}
  const baselines = status?.baselines || {}
  return (
    <div>
      <h2>Monitor</h2>
      <div className="incident-card">
        <label htmlFor="operator-token">Operator token for this browser session</label>
        <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
          <input id="operator-token" type="password" value={token} autoComplete="off"
            onChange={event => setToken(event.target.value)} />
          <button className="btn" onClick={() => {
            if (token.trim()) sessionStorage.setItem('selfsentry-api-token', token.trim())
            else sessionStorage.removeItem('selfsentry-api-token')
            setToken(''); setNotice('Session credentials updated.')
          }}>Save token</button>
        </div>
        {notice && <p role="status">{notice}</p>}
      </div>
      {error && <p className="error-state">Could not load monitor status: {error}</p>}
      {status && <>
        <div className="incident-card">
          <strong>{status.healthy ? 'Running' : 'Stopped or status stale'}</strong>
          <p>Last event: {status.last_event_at || 'none'}</p>
          <p>Containers tracked: {status.containers?.tracked ?? 0} · Learning: {status.containers_learning ?? 0} · Ready models: {status.models_ready ?? 0}</p>
          <p>Pending incidents: {status.incident_outbox_size ?? 0} · Failed responses: {status.failed_response_actions ?? 0}</p>
        </div>
        <h3>Connections</h3>
        {Object.entries(components).map(([name, item]) => <p key={name}>
          <strong>{name}</strong>: {item.state} {item.detail && `— ${item.detail}`}
        </p>)}
        <h3>Container baselines</h3>
        {Object.keys(baselines).length === 0 && <p className="empty-state">No containers discovered yet.</p>}
        {Object.entries(baselines).map(([cid, item]) => <div className="incident-card" key={cid}>
          <div className="incident-meta"><span>{cid}</span><strong>{item.state}</strong><span>{item.samples ?? 0} samples</span></div>
          {item.reason && <p>{item.reason}</p>}
        </div>)}
      </>}
    </div>
  )
}
