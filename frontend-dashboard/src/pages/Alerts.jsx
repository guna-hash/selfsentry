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
    <div style={{ padding: '1rem' }}>
      <h1>Alerts</h1>
      {error && <p style={{ color: 'red' }}>Error: {error}</p>}
      {incidents.length === 0 && !error && <p>No incidents yet.</p>}
      {incidents.map((incident) => (
        <div
          key={incident.id}
          style={{ border: '1px solid #ccc', padding: '1rem', marginBottom: '1rem' }}
        >
          <strong>Container:</strong> {incident.container_id} |{' '}
          <strong>Risk Score:</strong> {incident.risk_score} |{' '}
          <strong>Confidence:</strong> {incident.confidence}
          {incident.ai_summary && (
            <div style={{ marginTop: '0.5rem' }}>
              <p><strong>Severity:</strong> {incident.ai_summary.severity}</p>
              <p><strong>Summary:</strong> {incident.ai_summary.plain_summary}</p>
              <p><strong>Recommended Action:</strong> {incident.ai_summary.recommended_action}</p>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}