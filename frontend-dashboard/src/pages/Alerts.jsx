import { useState, useEffect } from 'react'
import { AlertTriangle, Users, ListChecks, ShieldAlert } from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts'

const SEVERITIES = ['critical', 'high', 'medium', 'low']
const SEV_COLOR = {
  critical: '#EF4444',
  high: '#F5A524',
  medium: '#EAB308',
  low: '#3B82F6',
}

function Gauge({ value }) {
  const r = 34
  const c = 2 * Math.PI * r
  const pct = Math.max(0, Math.min(100, value))
  const color = pct >= 70 ? 'var(--sev-critical)' : pct >= 40 ? 'var(--sev-high)' : 'var(--sev-low)'
  return (
    <div className="gauge-wrap">
      <svg width="90" height="90">
        <circle cx="45" cy="45" r={r} stroke="var(--border)" strokeWidth="8" fill="none" />
        <circle
          cx="45" cy="45" r={r} stroke={color} strokeWidth="8" fill="none"
          strokeDasharray={c} strokeDashoffset={c - (pct / 100) * c}
          strokeLinecap="round" transform="rotate(-90 45 45)"
        />
      </svg>
      <div className="gauge-value">
        <span className="num">{value}</span>
        <span className="label">Risk Score</span>
      </div>
    </div>
  )
}

export default function Alerts() {
  const [incidents, setIncidents] = useState([])
  const [error, setError] = useState(null)
  const [selectedId, setSelectedId] = useState(null)
  const [showRaw, setShowRaw] = useState(false)

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

  const withSeverity = incidents
    .map((i) => ({ ...i, severity: i.ai_summary?.severity || 'low' }))
    .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))

  const criticalCount = withSeverity.filter((i) => i.severity === 'critical').length
  const highCount = withSeverity.filter((i) => i.severity === 'high').length
  const monitoredContainers = new Set(incidents.map((i) => i.container_id)).size
  const totalIncidents = incidents.length

  const distCounts = SEVERITIES.map((sev) => ({
    name: sev,
    value: withSeverity.filter((i) => i.severity === sev).length,
  })).filter((d) => d.value > 0)

  const chartData = withSeverity.map((i) => ({
    time: new Date(i.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    risk_score: i.risk_score,
  }))

  const selected = withSeverity.find((i) => i.id === selectedId) || withSeverity[withSeverity.length - 1] || null

  return (
    <>
      <h2>Security Alerts</h2>
      <p className="page-subtitle">Real-time threats and security events from your container environment</p>

      {error && <p className="error-state">Couldn't reach the backend: {error}</p>}

      <div className="stats-row-4">
        <div className="stat-card-icon">
          <div className="icon-circle critical"><AlertTriangle size={18} /></div>
          <div>
            <div className="stat-value">{criticalCount}</div>
            <div className="stat-label">Critical Alerts</div>
          </div>
        </div>
        <div className="stat-card-icon">
          <div className="icon-circle high"><ShieldAlert size={18} /></div>
          <div>
            <div className="stat-value">{highCount}</div>
            <div className="stat-label">High Risk</div>
          </div>
        </div>
        <div className="stat-card-icon">
          <div className="icon-circle accent"><Users size={18} /></div>
          <div>
            <div className="stat-value">{monitoredContainers}</div>
            <div className="stat-label">Monitored Containers</div>
          </div>
        </div>
        <div className="stat-card-icon">
          <div className="icon-circle neutral"><ListChecks size={18} /></div>
          <div>
            <div className="stat-value">{totalIncidents}</div>
            <div className="stat-label">Total Incidents</div>
          </div>
        </div>

        <div className="status-panel">
          <h4>Security Status</h4>
          {['Falco Engine', 'Policy Engine', 'Runtime Monitor', 'Audit Logger'].map((name) => (
            <div className="status-row" key={name}>
              <span className="status-label"><span className="dot dot-unknown" /> {name}</span>
              <span className="status-value unknown">Not connected</span>
            </div>
          ))}
        </div>
      </div>

      {incidents.length > 0 && (
        <div className="charts-row">
          <div className="chart-panel">
            <h3>Risk Score Over Time</h3>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={chartData}>
                <CartesianGrid stroke="#232C3D" strokeDasharray="3 3" />
                <XAxis dataKey="time" stroke="#8D97AC" fontSize={11} />
                <YAxis stroke="#8D97AC" fontSize={11} domain={[0, 100]} />
                <Tooltip contentStyle={{ background: '#121826', border: '1px solid #232C3D', fontSize: '0.8rem' }} />
                <Line type="monotone" dataKey="risk_score" stroke="#EF4444" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="chart-panel">
            <h3>Risk Distribution</h3>
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={distCounts} dataKey="value" nameKey="name" innerRadius={45} outerRadius={70} paddingAngle={2}>
                  {distCounts.map((d) => <Cell key={d.name} fill={SEV_COLOR[d.name]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#121826', border: '1px solid #232C3D', fontSize: '0.8rem' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {incidents.length === 0 && !error && (
        <p className="empty-state">No incidents yet. New detections will appear here automatically.</p>
      )}

      {incidents.length > 0 && (
        <div className="alerts-layout">
          <table className="alerts-table">
            <thead>
              <tr>
                <th className="row-checkbox"><input type="checkbox" disabled /></th>
                <th>Severity</th>
                <th>Alert</th>
                <th>Container</th>
                <th>Risk Score</th>
                <th>Time</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {withSeverity.map((incident) => (
                <tr
                  key={incident.id}
                  className={selected?.id === incident.id ? 'selected' : ''}
                  onClick={() => { setSelectedId(incident.id); setShowRaw(false) }}
                >
                  <td className="row-checkbox"><input type="checkbox" disabled /></td>
                  <td><span className={`sev-tag sev-${incident.severity}`}>{incident.severity}</span></td>
                  <td>{incident.falco_alert?.rule || 'Unnamed alert'}</td>
                  <td className="mono">{incident.container_id}</td>
                  <td>
                    <span className="mono">{incident.risk_score}</span>
                    <span className="risk-bar-track">
                      <span className="risk-bar-fill" style={{ width: `${incident.risk_score}%`, background: `var(--sev-${incident.severity})` }} />
                    </span>
                  </td>
                  <td className="mono">{new Date(incident.created_at).toLocaleTimeString()}</td>
                  <td><span className="status-tag">Open</span></td>
                </tr>
              ))}
            </tbody>
          </table>

          {selected && (
            <div className="detail-panel">
              <div className="detail-header-row">
                <div>
                  <span className={`sev-tag sev-${selected.severity} detail-sev`}>{selected.severity}</span>
                  <h3>{selected.falco_alert?.rule || 'Incident Detail'}</h3>
                </div>
                <Gauge value={Math.round(selected.risk_score)} />
              </div>

              <p>{selected.ai_summary?.plain_summary}</p>

              <div className="detail-meta-grid">
                <div><div className="label">CONTAINER</div><div className="mono">{selected.container_id}</div></div>
                <div><div className="label">CONFIDENCE</div><div>{selected.confidence}</div></div>
                <div><div className="label">RULE</div><div className="mono">{selected.falco_alert?.rule || '-'}</div></div>
                <div><div className="label">TIME</div><div className="mono">{new Date(selected.created_at).toLocaleString()}</div></div>
              </div>

              {selected.ai_summary?.recommended_action && (
                <>
                  <div className="label" style={{ marginBottom: '0.4rem' }}>RECOMMENDED ACTIONS</div>
                  <ul className="detail-actions-list">
                    {selected.ai_summary.recommended_action.split(/\d\)\s*/).filter(Boolean).map((step, idx) => (
                      <li key={idx}>{step.trim()}</li>
                    ))}
                  </ul>
                </>
              )}

              <div className="btn-row">
                <button className="btn btn-disabled" disabled title="Auto-isolation not yet implemented (Phase 11)">
                  Isolate Container
                </button>
                <button className="btn" onClick={() => setShowRaw((v) => !v)}>
                  {showRaw ? 'Hide raw alert' : 'Investigate'}
                </button>
              </div>

              {showRaw && (
                <pre className="raw-json">{JSON.stringify(selected.falco_alert, null, 2)}</pre>
              )}
            </div>
          )}
        </div>
      )}
    </>
  )
}
