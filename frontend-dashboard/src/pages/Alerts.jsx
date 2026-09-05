import { useState, useEffect } from 'react'

export default function Alerts() {
  const [incidents, setIncidents] = useState([])
  const [error, setError] = useState(null)

  useEffect(() => {
    async function fetchIncidents() {
      try {
        const res = await fetch('http://localhost:8000/incidents/')
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
        const severity = incident.ai_summary?.severity || 'low'
        return (
          <div key={incident.id} className={`incident-card sev-${severity}`}>
            <div className="incident-meta">
              <span>{incident.container_id}</span>
              <span className="risk-score">risk {incident.risk_score}</span>
              <span>{incident.confidence}</span>
            </div>
            {incident.ai_summary && (
              <div className="incident-summary">
                <p>
                  <strong>Summary</strong>
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
