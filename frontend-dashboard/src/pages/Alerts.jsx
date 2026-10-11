import { apiFetch, incidentSeverity } from '../api.js'
import { useState, useEffect } from 'react'

export default function Alerts() {
  const [incidents, setIncidents] = useState([])
  const [error, setError] = useState(null)

  useEffect(() => {
    async function fetchIncidents() {
      try {
        const res = await apiFetch('http://localhost:8000/incidents/')
        if (!res.ok) throw new Error('Failed to fetch incidents')
        const data = await res.json()
        setIncidents(data)
        setError(null)
      } catch (err) {
        setError(err.message)
      }
    }

    fetchIncidents()
    const interval = setInterval(fetchIncidents, 3000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div>
      <h2>Alerts</h2>
      {error && <p className="error-state">Couldn't reach the backend: {error}</p>}
      {incidents.length === 0 && !error && (
        <p className="empty-state">No incidents yet. New detections will appear here automatically.</p>
      )}
      {incidents.map((incident) => {
        const severity = incidentSeverity(incident)
        const explanation = incident.monitor_workflow?.explanation
        const assessment = incident.monitor_evidence?.anomaly_assessment
        return (
          <div key={incident.id} className={`incident-card sev-${severity}`}>
            <div className="incident-meta">
              <span>{incident.container_id}</span>
              <span className="risk-score">risk {incident.risk_score}</span>
              <span>{incident.confidence}</span>
            </div>
            {incident.monitor_evidence && <p>
              Anomaly: {incident.monitor_evidence.anomaly_status} · Baseline: {incident.monitor_evidence.baseline_state} · Effective score: {incident.monitor_evidence.effective_score}
            </p>}
            {incident.confirmation && <p>Confirmed by {incident.confirmation.confirmed_by}</p>}
            {incident.monitor_workflow?.response && <p>Response: {incident.monitor_workflow.response.status}</p>}
            {incident.monitor_workflow?.candidate && <p>Rule candidate: {incident.monitor_workflow.candidate.status}</p>}
            {assessment && <p>
              Model score: {Number(assessment.anomaly_score).toFixed(4)} · Qualifies: {assessment.qualifies ? 'yes' : 'no'}
            </p>}
            <p>AI explanation: {explanation?.status || (incident.ai_summary ? 'ready' : 'not recorded')}</p>
            {explanation?.reason && <p>{explanation.reason}</p>}
            {explanation?.status === 'pending_retry' && Number.isFinite(explanation.next_retry_epoch) && <p>
              Next AI retry: {new Date(explanation.next_retry_epoch * 1000).toLocaleString()}
            </p>}
            {incident.ai_summary && (
              <div className="incident-summary">
                <p>
                  <strong>AI summary (advisory)</strong>
                  {incident.ai_summary.plain_summary}
                </p>
                <p>
                  <strong>Recommended action</strong>
                  {incident.ai_summary.recommended_action}
                </p>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
