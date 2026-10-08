import { useState, useEffect } from 'react'
import { API, NOTICE_STYLES, describeFailure } from '../api.js'

function formatRisk(score) {
  return score === null || score === undefined ? 'no incidents yet' : `latest risk ${score}`
}

export default function Containers() {
  const [containers, setContainers] = useState([])
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [busyId, setBusyId] = useState(null)

  async function fetchContainers() {
    try {
      const res = await fetch(`${API}/containers/`)
      if (!res.ok) throw new Error(await describeFailure(res))
      setContainers(await res.json())
      setError(null)
    } catch (err) {
      setError(err.message)
    }
  }

  useEffect(() => {
    fetchContainers()
    const interval = setInterval(fetchContainers, 3000)
    return () => clearInterval(interval)
  }, [])

  async function runAction(container, url, successText) {
    setBusyId(container.id)
    try {
      const res = await fetch(url, { method: 'POST' })
      if (res.ok) {
        setNotice({ kind: 'success', text: successText })
      } else {
        setNotice({ kind: 'error', text: `${container.name}: ${await describeFailure(res)}` })
      }
    } catch (err) {
      setNotice({
        kind: 'error',
        text: `${container.name}: could not reach the backend (${err.message})`,
      })
    } finally {
      setBusyId(null)
      fetchContainers()
    }
  }

  function handleResume(container) {
    const resumedBy = prompt('Your name (for the audit record):')
    if (!resumedBy) return
    runAction(
      container,
      `${API}/containers/${container.id}/resume?resumed_by=${encodeURIComponent(resumedBy)}`,
      `${container.name} resumed: unpaused and network restored.`
    )
  }

  function handleIsolate(container) {
    const isolatedBy = prompt('Your name (for the audit record):')
    if (!isolatedBy) return
    const reason = prompt('Reason for isolating this container:')
    if (!reason) return
    runAction(
      container,
      `${API}/containers/${container.id}/isolate?isolated_by=${encodeURIComponent(isolatedBy)}` +
        `&reason=${encodeURIComponent(reason)}`,
      `${container.name} isolated: paused and disconnected from its networks.`
    )
  }

  return (
    <div>
      <h2>Containers</h2>
      {error && <p className="error-state">Couldn't load containers: {error}</p>}
      {notice && (
        <p
          style={{ padding: '10px 14px', borderRadius: 4, ...NOTICE_STYLES[notice.kind] }}
          onClick={() => setNotice(null)}
          title="Click to dismiss"
        >
          {notice.text}
        </p>
      )}
      {containers.length === 0 && !error && (
        <p className="empty-state">No containers found on this host.</p>
      )}
      {containers.map((container) => (
        <div
          key={container.id}
          className={`incident-card ${container.isolated ? 'sev-high' : 'sev-low'}`}
        >
          <div className="incident-meta">
            <span>{container.name}</span>
            <span>{container.image}</span>
            <span>
              {container.isolated ? 'ISOLATED (paused, network cut)' : container.status}
            </span>
            <span className="risk-score">{formatRisk(container.latest_risk_score)}</span>
          </div>
          {container.isolated && (
            <p>
              <strong>Isolated</strong>
              {container.isolation_reason} ({container.isolated_at})
            </p>
          )}
          {container.isolated && (
            <button
              className="btn btn-approve"
              disabled={busyId === container.id}
              onClick={() => handleResume(container)}
            >
              Resume
            </button>
          )}
          {!container.isolated && container.status === 'running' && (
            <button
              className="btn btn-reject"
              disabled={busyId === container.id}
              onClick={() => handleIsolate(container)}
            >
              Isolate
            </button>
          )}
        </div>
      ))}
    </div>
  )
}
