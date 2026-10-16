import { useState } from 'react'
import { Boxes, BrainCircuit, Bell, Workflow, KeyRound } from 'lucide-react'
import { useMonitor } from '../hooks/useMonitor.jsx'
import {
  MetricCard,
  Badge,
  EmptyState,
  Loading,
  PageHeader,
  Notice,
} from '../components/ui.jsx'
import { monitorState, eventAge } from '../components/status.js'
import TelemetryChart from '../components/TelemetryChart.jsx'

export default function Monitor() {
  const { status, error, loading } = useMonitor()
  const [token, setToken] = useState('')
  const [notice, setNotice] = useState(null)
  const state = monitorState(status, error)
  const components = Object.entries(status?.components || {})
  const baselines = Object.entries(status?.baselines || {})
  const chart = baselines
    .filter(([, item]) => Number.isFinite(item.samples))
    .slice(0, 12)
    .map(([cid, item]) => ({
      label: cid.slice(0, 10),
      fullLabel: cid,
      value: item.samples,
    }))
  return (
    <div>
      <PageHeader title="Monitor">
        Live visibility into your containers, detection models, and response
        pipeline.
      </PageHeader>
      {loading && <Loading />}
      {error && (
        <p className="error-state" role="alert">
          Could not load monitor status: {error}.{' '}
          {status
            ? 'Showing the last received snapshot.'
            : 'Check the backend connection and session token.'}{' '}
          Retrying every 3 seconds.
        </p>
      )}
      <div className="metrics-grid">
        <MetricCard
          label="Containers tracked"
          value={status?.containers?.tracked}
          detail="Runtime inventory"
          icon={Boxes}
        />
        <MetricCard
          label="Models ready"
          value={status?.models_ready}
          detail={`${status?.containers_learning ?? '—'} containers learning`}
          icon={BrainCircuit}
        />
        <MetricCard
          label="Pending incidents"
          value={status?.unconfirmed_incidents}
          detail="Awaiting confirmation"
          tone="medium"
          icon={Bell}
        />
        <MetricCard
          label="Failed responses"
          value={status?.failed_response_actions}
          detail={`${status?.incident_outbox_size ?? '—'} incidents in delivery outbox`}
          tone="critical"
          icon={Workflow}
        />
      </div>
      {status && (
        <section className="health-panel">
          <div>
            <span className="eyebrow">MONITOR HEALTH</span>
            <h3>
              <Badge tone={state.tone}>{state.label}</Badge>
            </h3>
            <p>
              {status.reason ||
                (status.healthy
                  ? 'Monitor heartbeat is current.'
                  : 'Monitor is stopped or its heartbeat is stale.')}
            </p>
          </div>
          <div className="health-detail">
            <span>Last event</span>
            <strong>{eventAge(status.last_event_at)}</strong>
            <small>
              Heartbeat age:{' '}
              {status.status_age_seconds == null
                ? 'unknown'
                : `${Math.max(0, Math.floor(status.status_age_seconds))}s`}
            </small>
          </div>
        </section>
      )}
      <p>Automatic isolation: {status?.configuration ? (status.configuration.auto_isolation_enabled ? 'Enabled' : 'Disabled') : 'Unknown'}.
        Protected containers: {status?.configuration?.protected_containers?.join(', ') || 'None configured'}.</p>
      <div className="section-heading">
        <h3>Connections</h3>
        <span>{components.length} services</span>
      </div>
      {!loading && components.length === 0 && (
        <EmptyState title="No connection telemetry">
          Connection states will appear when the monitor reports them.
        </EmptyState>
      )}
      <div className="connection-grid">
        {components.map(([name, item]) => (
          <div className="connection-card" key={name}>
            <div>
              <strong>{name.replaceAll('_', ' ')}</strong>
              <Badge
                tone={
                  ['ok', 'connected'].includes(item.state)
                    ? 'low'
                    : item.state === 'disabled'
                      ? 'neutral'
                      : 'medium'
                }
              >
                {item.state}
              </Badge>
            </div>
            <p>
              {item.detail ||
                (['ok', 'connected'].includes(item.state)
                  ? 'Connection healthy'
                  : 'Reported by monitor')}
            </p>
          </div>
        ))}
      </div>
      <div className="section-heading">
        <h3>Container baselines</h3>
        <span>Behavioral learning</span>
      </div>
      {!loading && baselines.length === 0 && (
        <EmptyState
          title="No baselines yet"
          waiting={!error && status?.healthy}
        >
          Discovered containers and their learning state will appear here.
        </EmptyState>
      )}
      {chart.length > 0 && <TelemetryChart data={chart} kind="baseline" />}
      <div className="baseline-grid">
        {baselines.map(([cid, item]) => (
          <div className="incident-card baseline-card" key={cid}>
            <div className="incident-meta">
              <span title={cid}>{cid}</span>
              <Badge
                tone={
                  item.state === 'MODEL_READY'
                    ? 'low'
                    : item.state === 'MODEL_UNAVAILABLE'
                      ? 'critical'
                      : 'medium'
                }
              >
                {item.state}
              </Badge>
            </div>
            <div className="sample-count">
              {item.samples ?? '—'} <small>samples collected</small>
            </div>
            {item.reason && <p>{item.reason}</p>}
          </div>
        ))}
      </div>
      <details className="credentials">
        <summary>
          <KeyRound size={16} />
          Session credentials
        </summary>
        <p>Supply an operator token if this backend requires authentication.</p>
        <label htmlFor="operator-token">
          Operator token for this browser session
        </label>
        <div className="token-form">
          <input
            id="operator-token"
            type="password"
            value={token}
            autoComplete="off"
            placeholder="Enter token (blank clears it)"
            onChange={(event) => setToken(event.target.value)}
          />
          <button
            className="btn btn-primary"
            onClick={() => {
              if (token.trim())
                sessionStorage.setItem('selfsentry-api-token', token.trim())
              else sessionStorage.removeItem('selfsentry-api-token')
              setToken('')
              setNotice({
                kind: 'success',
                text: 'Session credentials updated. The next refresh will use them.',
              })
            }}
          >
            Save token
          </button>
        </div>
        <Notice notice={notice} onDismiss={() => setNotice(null)} />
      </details>
    </div>
  )
}
