import RiskExplanation from '../components/RiskExplanation.jsx'
import {
  Badge,
  EmptyState,
  Loading,
  PageHeader,
  Notice,
} from '../components/ui.jsx'
import { useState, useEffect } from 'react'
import { API, apiFetch, describeFailure } from '../api.js'

function formatRisk(score) {
  return score === null || score === undefined
    ? 'no incidents yet'
    : `latest risk ${score}`
}

export default function Containers() {
  const [containers, setContainers] = useState([])
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [notice, setNotice] = useState(null)
  const [busyId, setBusyId] = useState(null)

  async function fetchContainers() {
    try {
      const res = await apiFetch(`${API}/containers/`)
      if (!res.ok) throw new Error(await describeFailure(res))
      setContainers(await res.json())
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
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
      const res = await apiFetch(url, { method: 'POST' })
      if (res.ok) {
        setNotice({ kind: 'success', text: successText })
      } else {
        setNotice({
          kind: 'error',
          text: `${container.name}: ${await describeFailure(res)}`,
        })
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
      `${API}/containers/${container.id}/resume?recheck=true&resumed_by=${encodeURIComponent(resumedBy)}`,
      `${container.name} resumed: unpaused and network restored.`,
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
      `${container.name} isolated: paused and disconnected from its networks.`,
    )
  }

  return (
    <div>
      <PageHeader title="Containers">
        Inspect runtime inventory and manage container isolation.
      </PageHeader>
      {loading && <Loading />}
      {error && (
        <p className="error-state" role="alert">
          Couldn't load containers: {error}
        </p>
      )}
      <Notice notice={notice} onDismiss={() => setNotice(null)} />
      {containers.length === 0 && !error && !loading && (
        <EmptyState title="No containers found">
          Discovered containers will appear here automatically.
        </EmptyState>
      )}
      {containers.map((container) => (
        <div
          key={container.id}
          className={`incident-card ${container.isolated ? 'sev-high' : 'sev-low'}`}
        >
          <div className="incident-meta">
            <span>{container.name}</span>
            <span>{container.image}</span>
            <Badge tone={container.isolated ? 'high' : 'neutral'}>
              {container.isolated
                ? container.containment_label
                : container.status}
            </Badge>
            <span className="risk-score">
              {formatRisk(container.latest_risk_score)}
            </span>
          </div>
          <p>
            <Badge tone={container.monitoring?.active ? 'low' : 'medium'}>
              {error ? 'Monitoring status unavailable' : container.monitoring?.label || 'Monitoring unknown'}
            </Badge>{' '}
            {container.protected && <Badge tone="accent">Protected from isolation</Badge>}
          </p>
          {container.risk_explanation && <RiskExplanation value={container.risk_explanation} />}
          {container.isolation_error && <p role="alert">Recovery needs attention: {JSON.stringify(container.isolation_error)}</p>}
          {container.isolated && (
            <p>
              <strong>Isolated</strong>
              {container.isolation_reason} ({container.isolated_at})
            </p>
          )}
          {container.isolated && (
            <button
              className="btn btn-approve"
              disabled={busyId !== null}
              onClick={() => handleResume(container)}
            >
              {busyId === container.id ? 'Resuming…' : 'Resume'}
            </button>
          )}
          {!container.isolated && !container.protected && container.status === 'running' && (
            <button
              className="btn btn-reject"
              disabled={busyId !== null}
              onClick={() => handleIsolate(container)}
            >
              {busyId === container.id ? 'Isolating…' : 'Isolate'}
            </button>
          )}
        </div>
      ))}
    </div>
  )
}
