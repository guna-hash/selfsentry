import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { API, apiFetch, describeFailure, incidentSeverity } from '../api.js'
import { useMonitor } from '../hooks/useMonitor.jsx'
import { Badge, MetricCard, PageHeader } from '../components/ui.jsx'
import { monitorState } from '../components/status.js'
import RiskExplanation from '../components/RiskExplanation.jsx'

const sources = { containers: '/containers/', incidents: '/incidents/',
  deployments: '/deployments/', rules: '/rules/history', audit: '/audit/?limit=5' }

export default function Overview() {
  const [data, setData] = useState({})
  const [errors, setErrors] = useState({})
  const { status, error } = useMonitor()
  const health = monitorState(status, error)
  useEffect(() => {
    let active = true
    let pending = false
    const controller = new AbortController()
    async function refresh() {
      if (pending) return
      pending = true
      const results = await Promise.allSettled(Object.entries(sources).map(async ([key, path]) => {
        const response = await apiFetch(API + path, { signal: controller.signal })
        if (!response.ok) throw new Error(`${key}: ${await describeFailure(response)}`)
        return [key, await response.json()]
      }))
      if (active) {
        const failures = {}
        const updates = {}
        results.forEach((result, i) => {
          const key = Object.keys(sources)[i]
          if (result.status === 'fulfilled') updates[key] = result.value[1]
          else failures[key] = result.reason.message
        })
        setData((old) => ({ ...old, ...updates }))
        setErrors(failures)
      }
      pending = false
    }
    refresh()
    const interval = setInterval(refresh, 5000)
    return () => { active = false; controller.abort(); clearInterval(interval) }
  }, [])
  const count = (key, fn) => errors[key] || !data[key] ? null : data[key].filter(fn).length
  return <div>
    <PageHeader title="Security overview">Deployment decisions, runtime coverage, response and supervised adaptation.</PageHeader>
    <p><Link to="/monitor"><Badge tone={health.tone}>Monitor: {health.label}</Badge></Link>{' '}
      Automatic isolation: {status?.configuration ? (status.configuration.auto_isolation_enabled ? 'Enabled' : 'Disabled') : 'Unknown'}</p>
    {Object.entries(errors).map(([key, value]) => <p className="error-state" key={key}>{value}. Displayed {key} may be stale.</p>)}
    <div className="metrics-grid">
      <MetricCard label="Running containers" value={count('containers', (c) => c.status === 'running')} detail={<Link to="/containers">Runtime inventory</Link>} />
      <MetricCard label="Isolation records active" value={count('containers', (c) => c.isolated)} detail={<Link to="/containers">Inspect / resume</Link>} tone="high" />
      <MetricCard label="Incidents recorded" value={count('incidents', () => true)} detail={<Link to="/alerts">All severities</Link>} />
      <MetricCard label="Rules awaiting action" value={count('rules', (r) => ['pending_review', 'approved'].includes(r.status))} detail={<Link to="/rules">Human review queue</Link>} tone="medium" />
    </div>
    <h3>Container coverage</h3>
    {(data.containers || []).map((c) => <p key={c.id}><Link to="/containers">{c.name}</Link>{' '}
      <Badge tone={c.isolated ? 'high' : 'neutral'}>{c.containment_label}</Badge>{' '}
      <Badge tone={c.monitoring?.active && !errors.containers ? 'low' : 'medium'}>{errors.containers ? 'Status unavailable' : c.monitoring?.label}</Badge>{' '}
      {c.protected && <Badge tone="accent">Protected</Badge>}</p>)}
    <h3>Recent incident risks <Link to="/alerts">View all</Link></h3>
    {[...(data.incidents || [])].reverse().slice(0, 4).map((i) => <article className={`incident-card sev-${incidentSeverity(i)}`} key={i.id}>
      <Badge tone={incidentSeverity(i)}>{incidentSeverity(i)}</Badge> #{i.id} · {i.container_id}
      <RiskExplanation value={i.risk_explanation} />
    </article>)}
    <h3>Recent deployment decisions <Link to="/deployments">View all</Link></h3>
    {(data.deployments || []).slice(0, 3).map((d) => <article className="incident-card" key={d.id}><RiskExplanation value={d.risk_explanation} /></article>)}
    <h3>Recent audit events <Link to="/audit">Full audit log</Link></h3>
    {(Array.isArray(data.audit) ? data.audit : []).map((e) => <p key={e.id}>{e.event_type} · {e.container_name || e.container_id || 'Platform'} · {new Date(e.created_at).toLocaleString()}</p>)}
  </div>
}
