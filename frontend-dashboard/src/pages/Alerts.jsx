import { API, apiFetch, incidentSeverity, describeFailure } from '../api.js'
import { useState, useEffect, useRef } from 'react'
import { ShieldAlert, Bell, ShieldCheck, Activity } from 'lucide-react'
import {
  MetricCard,
  Badge,
  EmptyState,
  Loading,
  PageHeader,
} from '../components/ui.jsx'
import TelemetryChart from '../components/TelemetryChart.jsx'

export default function Alerts() {
  const [incidents, setIncidents] = useState([])
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [newIds, setNewIds] = useState(new Set())
  const seen = useRef(null)
  useEffect(() => {
    let active = true
    let pending = false
    const controller = new AbortController()
    async function fetchIncidents() {
      if (pending) return
      pending = true
      try {
        const res = await apiFetch(`${API}/incidents/`, {
          signal: controller.signal,
        })
        if (!res.ok) throw new Error(await describeFailure(res))
        const data = await res.json()
        if (!active) return
        setNewIds(
          new Set(
            seen.current
              ? data.filter((i) => !seen.current.has(i.id)).map((i) => i.id)
              : [],
          ),
        )
        seen.current = new Set(data.map((i) => i.id))
        setIncidents(data)
        setError(null)
      } catch (err) {
        if (active) setError(err.message)
      } finally {
        pending = false
        if (active) setLoading(false)
      }
    }
    fetchIncidents()
    const interval = setInterval(fetchIncidents, 3000)
    return () => {
      active = false
      controller.abort()
      clearInterval(interval)
    }
  }, [])
  const chart = incidents
    .map((i) => ({
      time: Date.parse(i.created_at || i.falco_alert?.timestamp),
      value: i.risk_score,
    }))
    .filter((i) => Number.isFinite(i.time) && Number.isFinite(i.value))
    .sort((a, b) => a.time - b.time)
    .slice(-30)
    .map((i) => ({
      label: new Date(i.time).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
      }),
      fullLabel: new Date(i.time).toLocaleString(),
      value: i.value,
    }))
  const count = (predicate) =>
    loading || (error && !seen.current)
      ? null
      : incidents.filter(predicate).length
  return (
    <div>
      <PageHeader title="Alerts & incidents">
        Investigate runtime detections, review evidence, and track response
        decisions.
      </PageHeader>
      {error && (
        <p className="error-state" role="alert">
          Could not load incidents: {error}. Retrying every 3 seconds.
          {seen.current && ' Displayed incidents may be stale.'}
        </p>
      )}
      <div className="metrics-grid">
        <MetricCard
          label="Total incidents"
          value={count(() => true)}
          detail="Recorded detections"
          icon={Activity}
        />
        <MetricCard
          label="High / critical"
          value={count((i) =>
            ['high', 'critical'].includes(incidentSeverity(i)),
          )}
          detail="Recorded severity · not active threat count"
          tone="critical"
          icon={ShieldAlert}
        />
        <MetricCard
          label="Pending confirmation"
          value={count((i) => !i.confirmation)}
          detail="Not yet confirmed"
          tone="medium"
          icon={Bell}
        />
        <MetricCard
          label="Confirmed incidents"
          value={count((i) => !!i.confirmation)}
          detail="Confirmation recorded"
          tone="low"
          icon={ShieldCheck}
        />
      </div>
      {chart.length > 0 && <TelemetryChart data={chart} />}
      <div className="section-heading">
        <h3>Incident feed</h3>
        <span>Refreshes every 3 seconds</span>
      </div>
      {loading && <Loading />}
      {!loading && incidents.length === 0 && !error && (
        <EmptyState title="No incidents yet" waiting>
          New detections will appear here automatically.
        </EmptyState>
      )}
      {[...incidents].reverse().map((incident) => {
        const severity = incidentSeverity(incident)
        const evidence = incident.monitor_evidence
        const workflow = incident.monitor_workflow
        const explanation = workflow?.explanation
        const assessment = evidence?.anomaly_assessment
        return (
          <article
            key={incident.id}
            className={`incident-card sev-${severity} ${newIds.has(incident.id) && severity === 'critical' ? 'new-critical' : ''}`}
          >
            <div className="alert-header">
              <div>
                <div className="incident-meta">
                  <Badge tone={severity}>{severity}</Badge>
                  <span>INCIDENT #{incident.id}</span>
                  <span>{incident.confidence || 'Confidence unavailable'}</span>
                </div>
                <h3>{incident.falco_alert?.rule || 'Runtime detection'}</h3>
                <code className="container-id">{incident.container_id}</code>
              </div>
              <div className="risk-block">
                <strong>{incident.risk_score ?? '—'}</strong>
                <span>RISK / 100</span>
              </div>
            </div>
            <div className="incident-sections">
              <section>
                <h4>
                  AI summary <span>ADVISORY</span>
                </h4>
                <Badge
                  tone={
                    explanation?.status === 'ready' ||
                    incident.ai_summary?.plain_summary
                      ? 'accent'
                      : 'neutral'
                  }
                >
                  {explanation?.status ||
                    incident.ai_summary?.status ||
                    (incident.ai_summary ? 'ready' : 'not recorded')}
                </Badge>
                <p>
                  {incident.ai_summary?.plain_summary ||
                    'No AI explanation available for this incident.'}
                </p>
                {incident.ai_summary?.recommended_action && (
                  <p>
                    <strong>Recommended action</strong>
                    <br />
                    {incident.ai_summary.recommended_action}
                  </p>
                )}
                {explanation?.reason && <p>{explanation.reason}</p>}
                {explanation?.status === 'pending_retry' &&
                  Number.isFinite(explanation.next_retry_epoch) && (
                    <p>
                      Next AI retry:{' '}
                      {new Date(
                        explanation.next_retry_epoch * 1000,
                      ).toLocaleString()}
                    </p>
                  )}
              </section>
              <section>
                <h4>Anomaly assessment</h4>
                <dl>
                  <div>
                    <dt>Status</dt>
                    <dd>{evidence?.anomaly_status || 'Not recorded'}</dd>
                  </div>
                  <div>
                    <dt>Baseline</dt>
                    <dd>{evidence?.baseline_state || 'Unknown'}</dd>
                  </div>
                  <div>
                    <dt>Effective score</dt>
                    <dd>{evidence?.effective_score ?? '—'}</dd>
                  </div>
                  {assessment && (
                    <>
                      <div>
                        <dt>Model score</dt>
                        <dd>
                          {Number.isFinite(assessment.anomaly_score)
                            ? assessment.anomaly_score.toFixed(4)
                            : '—'}
                        </dd>
                      </div>
                      <div>
                        <dt>Qualifies</dt>
                        <dd>{assessment.qualifies ? 'Yes' : 'No'}</dd>
                      </div>
                    </>
                  )}
                </dl>
              </section>
            </div>
            <footer className="incident-footer">
              <div>
                <span>Confirmation</span>
                <strong>
                  {incident.confirmation
                    ? `Confirmed by ${incident.confirmation.confirmed_by}`
                    : 'Awaiting confirmation'}
                </strong>
              </div>
              <div>
                <span>Response</span>
                <strong>{workflow?.response?.status || 'Not recorded'}</strong>
              </div>
              <div>
                <span>Rule candidate</span>
                <strong>{workflow?.candidate?.status || 'Not recorded'}</strong>
              </div>
            </footer>
          </article>
        )
      })}
    </div>
  )
}
