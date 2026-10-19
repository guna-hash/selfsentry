import { isSampleMode } from '../utils/demoMode.js'
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Copy } from 'lucide-react'
import Drawer from './Drawer.jsx'
import StatusBadge from './StatusBadge.jsx'
import ErrorState from './ErrorState.jsx'
import Skeleton from './Skeleton.jsx'
import RiskExplanation from './RiskExplanation.jsx'
import { useIncidentDetail } from '../hooks/useIncidents.js'
import { confirmIncident, createCandidate } from '../utils/incidentActions.js'
import { writeTokenAvailable } from '../utils/requests.js'
import { formatDate, formatNumber } from '../utils/format.js'
import { incidentState, layersFired, utcEpoch } from '../utils/overviewModel.js'

const recorded = (value) => value == null || value === '' ? 'Not recorded' : typeof value === 'object' ? JSON.stringify(value) : String(value)
const bool = (value) => value === true ? 'Yes' : value === false ? 'No' : 'Not recorded'
function Time({ value }) {
  const time = utcEpoch(value)
  return <time title={typeof value === 'string' ? value : undefined} dateTime={time === null ? undefined : new Date(time).toISOString()}>{formatDate(time)}</time>
}
export default function IncidentDrawer({ id, paused, onClose, onChanged, onNotice }) {
  const { incident, loading, error, refresh } = useIncidentDetail(id, paused)
  const [form, setForm] = useState(null)
  const [actor, setActor] = useState('')
  const [yaml, setYaml] = useState('')
  const [fpPercent, setFpPercent] = useState('')
  const [busy, setBusy] = useState(false)
  const [issue, setIssue] = useState(null)
  const [message, setMessage] = useState(null)
  const locked = useRef(false), mounted = useRef(true)
  useEffect(() => { mounted.current = true; return () => { mounted.current = false } }, [])
  const tokenPresent = writeTokenAvailable()
  const benign = incident?.monitor_workflow?.disposition?.status === 'benign'
  const evidence = incident?.monitor_evidence || {}
  const workflow = incident?.monitor_workflow || {}
  const assessment = evidence.anomaly_assessment || {}
  const summary = incident?.ai_summary
  const explanation = workflow.explanation || {}
  const timeline = Array.isArray(evidence.observed_timeline) ? evidence.observed_timeline : []
  function report(kind, text) {
    if (mounted.current) setMessage({ kind, text })
    onNotice({ kind, text })
  }
  async function copy(value, label) {
    try { await navigator.clipboard.writeText(String(value)); report('success', `${label} copied.`) }
    catch { report('error', `Could not copy ${label.toLowerCase()}. Select and copy the displayed text.`) }
  }
  async function submit(event) {
    event.preventDefault()
    if (locked.current || !incident) return
    locked.current = true; setBusy(true); setIssue(null); setMessage(null)
    const selected = incident
    try {
      if (form === 'confirm') {
        const result = await confirmIncident(selected.id, actor)
        report('success', `Incident #${selected.id}: ${result.status === 'already_confirmed' ? 'confirmation already recorded' : 'confirmation recorded'} by ${recorded(result.confirmed_by)}.`)
      } else {
        const result = await createCandidate(selected, { actor, yaml, fpPercent })
        report('success', result.existing ? `Incident #${selected.id}: active candidate #${result.id} already exists (${result.status}).`
          : `Candidate #${result.id} queued for human review. No deployment was requested.`)
      }
      if (mounted.current) { setForm(null); setYaml(''); setFpPercent(''); refresh() }
      onChanged()
    } catch (failure) {
      if (mounted.current) setIssue(failure)
      if (failure.uncertain) { if (mounted.current) refresh(); onChanged() }
    } finally {
      locked.current = false
      if (mounted.current) setBusy(false)
    }
  }
  function openForm(kind) { setForm(kind); setIssue(null); setMessage(null) }
  return <Drawer open title={`Incident #${id}`} onClose={() => { if (!locked.current) onClose() }} busy={busy}>
    {message && <p className={`notice tone-${message.kind === 'error' ? 'critical' : 'low'}`} role={message.kind === 'error' ? 'alert' : 'status'}>{message.text}</p>}
    {loading ? <Skeleton label="Loading incident evidence…" /> : error ? <ErrorState error={error.message} status={error.status} onRetry={refresh} /> : incident && <>
      <div className="incident-drawer-heading">
        <h3>{recorded(incident.falco_alert?.rule || (incident.anomaly_features ? 'Behavioral anomaly' : null))}</h3>
        <button type="button" className="shell-button" onClick={() => copy(incident.id, 'Incident ID')} aria-label="Copy incident ID"><Copy size={16} aria-hidden="true" />Copy ID</button>
      </div>
      <p className="incident-identity">Container: {recorded(incident.container_id)}</p>
      <p><StatusBadge tone="neutral">{layersFired(incident)}</StatusBadge>{' '}<StatusBadge tone={incidentState(incident) === 'Unconfirmed' ? 'medium' : 'neutral'}>{incidentState(incident)}</StatusBadge></p>
      <section className="incident-detail-section" aria-label="Risk breakdown">
        <h3>Risk breakdown</h3>
        <dl>
          <div><dt>Recorded risk score</dt><dd>{formatNumber(incident.risk_score)} / 100</dd></div>
          <div><dt>Recorded effective score</dt><dd>{formatNumber(evidence.effective_score)} / 100</dd></div>
          <div><dt>Falco priority</dt><dd>{recorded(incident.falco_alert?.priority)}</dd></div>
          <div><dt>Correlated anomaly score</dt><dd>{formatNumber(incident.anomaly_features?.anomaly_score, { maximumFractionDigits: 4 })}</dd></div>
          <div><dt>Recorded cross-layer agreement</dt><dd>{bool(evidence.cross_layer_agreement)}</dd></div>
          <div><dt>Confidence</dt><dd>{recorded(incident.confidence)}</dd></div>
        </dl>
        <p>Recorded formula: {recorded(evidence.score_formula)}</p>
        <p>Detection source: {layersFired(incident) === 'Both' ? 'Falco-backed; ML contributed' : layersFired(incident) === 'Falco only' ? 'Falco-backed' : layersFired(incident) === 'ML only' ? 'ML contributed' : 'Not recorded'}.</p>
      </section>
      <section className="incident-detail-section" aria-label="Deterministic risk guidance"><h3>Risk guidance</h3><RiskExplanation value={incident.risk_explanation} /></section>
      <section className="incident-detail-section" aria-label="Observed timeline">
        <h3>Observed timeline</h3>
        <p className="incident-caption">Events appear in stored order. No additional events or attacker intent are inferred.</p>
        {timeline.length ? <ul className="observed-timeline">{timeline.map((entry, index) => entry && typeof entry === 'object' ? <li key={index}>
          <div><strong>Step {recorded(entry.step)}</strong> · <Time value={entry.timestamp} /></div>
          <p>{recorded(entry.source)} · {recorded(entry.description)}</p>
          {entry.output != null && <pre>{recorded(entry.output)}</pre>}
          {entry.anomaly_score != null && <p>Recorded anomaly score: {formatNumber(entry.anomaly_score, { maximumFractionDigits: 4 })}</p>}
          {entry.event_key != null && <p>Event key: {recorded(entry.event_key)}</p>}
        </li> : <li key={index}>Recorded entry: {recorded(entry)}</li>)}</ul> : <p>Observed timeline: not recorded.</p>}
      </section>
      <section className="incident-detail-section" aria-label="AI summary advisory">
        <h3>AI summary <StatusBadge tone="neutral">Advisory</StatusBadge></h3>
        <p className="incident-caption">Explanation only; AI output is not a detection source.</p>
        <p>Status: {recorded(explanation.status || summary?.status || (summary?.plain_summary ? 'ready' : 'unavailable'))}</p>
        <p>{typeof summary?.plain_summary === 'string' && summary.plain_summary ? summary.plain_summary : 'AI explanation unavailable. A provider limit or missing response does not change recorded detection evidence.'}</p>
        {summary?.recommended_action && <p>Recommendation: {recorded(summary.recommended_action)}</p>}
        {explanation.reason && <p>Reported reason: {recorded(explanation.reason)}</p>}
        {Number.isFinite(explanation.next_retry_epoch) && <p>Next reported retry: {formatDate(explanation.next_retry_epoch * 1000)}</p>}
      </section>
      <section className="incident-detail-section" aria-label="Model evidence">
        <h3>Model evidence {assessment.model_algorithm === 'one_class_svm' && <StatusBadge tone="medium">Experimental SVM</StatusBadge>}</h3><dl>
          <div><dt>Baseline state</dt><dd>{recorded(evidence.baseline_state)}</dd></div>
          <div><dt>Anomaly availability</dt><dd>{recorded(evidence.anomaly_status)}</dd></div>
          <div><dt>Model algorithm</dt><dd>{recorded(assessment.model_algorithm)}</dd></div>
          <div><dt>Assessed score</dt><dd>{formatNumber(assessment.anomaly_score, { maximumFractionDigits: 4 })}</dd></div>
          <div><dt>Assessment qualifies</dt><dd>{bool(assessment.qualifies)}</dd></div>
        </dl><p>{recorded(evidence.anomaly_reason)}</p>
        <p className="incident-caption">A model assessment alone does not mean ML contributed. Falco alerts still produce incidents without a valid model.</p>
      </section>
      <section className="incident-detail-section" aria-label="Workflow evidence">
        <h3>Confirmation and response</h3><dl>
          <div><dt>Confirmation</dt><dd>{incidentState(incident)}</dd></div>
          <div><dt>Confirmed by</dt><dd>{recorded(incident.confirmation?.confirmed_by)}</dd></div>
          <div><dt>Confirmed at</dt><dd><Time value={incident.confirmation?.confirmed_at} /></dd></div>
          <div><dt>Created at</dt><dd><Time value={incident.created_at} /></dd></div>
          <div><dt>Response status</dt><dd>{recorded(workflow.response?.status)}</dd></div>
          <div><dt>Response outcome verified</dt><dd>{bool(workflow.response?.verified)}</dd></div>
          <div><dt>Rule candidate</dt><dd>{recorded(workflow.candidate?.status)}</dd></div>
        </dl>
        <details><summary>Recorded response and candidate details</summary><pre>{JSON.stringify({ response: workflow.response ?? null, candidate: workflow.candidate ?? null }, null, 2)}</pre></details>
      </section>
      <section className="incident-detail-section" aria-label="Incident actions">
        <h3>Actions</h3>
        {isSampleMode() && <p role="status">Sample data mode is read-only; incident actions are disabled.</p>}
        {!isSampleMode() && !tokenPresent && <p role="status">Operator token missing. Configure it in <Link to="/monitor">Monitor → Session credentials</Link> to enable write actions.</p>}
        {benign && <p>This incident is marked benign. Confirmation and candidate actions are disabled.</p>}
        <div className="incident-actions">
          <button type="button" className="btn btn-primary" disabled={busy || !tokenPresent || benign || !!incident.confirmation} onClick={() => openForm('confirm')}>Confirm incident</button>
          <button type="button" className="btn" disabled={busy || !tokenPresent || benign || !incident.confirmation} onClick={() => openForm('candidate')}>Create candidate</button>
          <Link to="/rules">Review rule queue</Link>
        </div>
        {!incident.confirmation && <p className="incident-caption">Confirm the incident before creating a candidate.</p>}
        {issue && <ErrorState error={issue.message} status={issue.status} onRetry={() => { setIssue(null); refresh(); onChanged() }} />}
        {form && <form className="incident-action-form" onSubmit={submit} aria-label={form === 'confirm' ? 'Confirm incident form' : 'Create candidate form'}>
          <h4>{form === 'confirm' ? 'Record human confirmation' : 'Submit a generated candidate'}</h4>
          <label htmlFor="incident-operator">Operator name</label>
          <input id="incident-operator" value={actor} onChange={(event) => setActor(event.target.value)} required disabled={busy} autoComplete="off" autoFocus />
          {form === 'candidate' && <>
            <p>Automatic synthesis runs in the monitor/CLI. Paste its generated YAML and reported benign backtest rate here. The backend rechecks the configured benign corpus before accepting a candidate.</p>
            <label htmlFor="candidate-yaml">Template-generated rule YAML</label>
            <textarea id="candidate-yaml" value={yaml} onChange={(event) => setYaml(event.target.value)} required disabled={busy} rows={10} spellCheck={false} />
            <label htmlFor="candidate-fp">Reported false-positive rate (%)</label>
            <input id="candidate-fp" type="number" min="0" max="5" step="any" value={fpPercent} onChange={(event) => setFpPercent(event.target.value)} required disabled={busy} />
            <p className="incident-caption">No rate is prefilled. Submission queues review; every deployment still needs explicit human approval. Existing candidates are reconciled without creating duplicates.</p>
          </>}
          <button type="submit" className="btn btn-primary" disabled={busy || !tokenPresent || !actor.trim() || actor.trim().toLowerCase() === 'selfsentry-auto' || (form === 'candidate' && (!yaml.trim() || fpPercent.trim() === ''))}>{busy ? 'Submitting…' : form === 'confirm' ? 'Record confirmation' : 'Submit for human review'}</button>
          <button type="button" className="btn btn-ghost" disabled={busy} onClick={() => setForm(null)}>Cancel</button>
        </form>}
      </section>
      <details className="incident-detail-section"><summary>Recorded raw detection evidence</summary><pre>{JSON.stringify({ falco_alert: incident.falco_alert ?? null, anomaly_features: incident.anomaly_features ?? null, monitor_evidence: incident.monitor_evidence ?? null }, null, 2)}</pre></details>
    </>}
  </Drawer>
}
