import { useState, useEffect } from 'react'
import { API, describeFailure } from '../api.js'

const DECISION_CLASS = { blocked: 'sev-high', overridden: 'sev-medium', allowed: 'sev-low' }
const DECISION_LABEL = { blocked: 'BLOCKED', overridden: 'OVERRIDDEN', allowed: 'ALLOWED' }

export default function Deployments() {
  const [deployments, setDeployments] = useState([])
  const [error, setError] = useState(null)

  async function fetchDeployments() {
    try {
      const res = await fetch(`${API}/deployments/`)
      if (!res.ok) throw new Error(await describeFailure(res))
      setDeployments(await res.json())
      setError(null)
    } catch (err) {
      setError(err.message)
    }
  }

  useEffect(() => {
    fetchDeployments()
    const interval = setInterval(fetchDeployments, 3000)
    return () => clearInterval(interval)
  }, [])

  const blockedCount = deployments.filter((d) => d.decision === 'blocked').length

  return (
    <div>
      <h2>Deployments</h2>
      {error && <p className="error-state">Couldn't load deployments: {error}</p>}
      {deployments.length > 0 && (
        <p>
          {deployments.length} recorded, <strong>{blockedCount} blocked</strong>
        </p>
      )}
      {deployments.length === 0 && !error && (
        <p className="empty-state">
          No deployments recorded yet. Deploy through bin/selfsentry-run and every decision
          appears here.
        </p>
      )}
      {deployments.map((d) => (
        <div key={d.id} className={`incident-card ${DECISION_CLASS[d.decision] || 'sev-low'}`}>
          <div className="incident-meta">
            <span>{DECISION_LABEL[d.decision] || d.decision}</span>
            <span>{d.container_name}</span>
            <span>{d.image_name}</span>
            <span>{d.requested_by}</span>
            {d.created_at && <span>{new Date(d.created_at).toLocaleString()}</span>}
          </div>
          {d.scan ? (
            <p>
              <strong>Image scan</strong>
              critical {d.scan.critical}, high {d.scan.high}, secrets {d.scan.secrets_found}
            </p>
          ) : (
            <p>
              <strong>Image scan</strong>
              not available (the scan could not run)
            </p>
          )}
          {d.override_reason && (
            <p>
              <strong>Override reason</strong>
              {d.override_reason}
            </p>
          )}
          {d.policy_violations.length > 0 && (
            <div>
              <strong>Policy violations</strong>
              <ul>
                {d.policy_violations.map((v) => (
                  <li key={v.rule_id}>
                    [{v.severity}] {v.title}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {d.scan && d.scan.top_findings.length > 0 && (
            <div>
              <strong>Top critical findings</strong>
              <ul>
                {d.scan.top_findings.slice(0, 5).map((f) => (
                  <li key={`${f.id}-${f.package}`}>
                    {f.id} in {f.package}
                    {f.fixed ? ` (fixed in ${f.fixed})` : ''}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
