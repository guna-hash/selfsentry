import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Copy } from 'lucide-react'
import Drawer from './Drawer.jsx'
import ErrorState from './ErrorState.jsx'
import StatusBadge from './StatusBadge.jsx'
import YamlCode from './YamlCode.jsx'
import { reviewRule } from '../utils/ruleActions.js'
import { writeTokenAvailable } from '../utils/requests.js'
import { actionableRule, backtestSummary, deploymentSummary, lifecycleEvents, recordedCondition, ruleStatus } from '../utils/ruleView.js'
import { formatDate, formatNumber } from '../utils/format.js'
import { utcEpoch } from '../utils/overviewModel.js'

const text=(value)=>value==null || value===''?'Not recorded':typeof value==='object'?JSON.stringify(value):String(value)
const snapshotKey=(rule)=>JSON.stringify(['id','status','rule_yaml','backtested_fp_rate','reviewed_by','reviewed_at','backtest'].map(key=>rule[key]??null))
export default function RuleReviewDialog({rule,onClose,onChanged,onNotice,writeUnavailable=false}) {
  const [decision,setDecision]=useState(null)
  const [reviewer,setReviewer]=useState('')
  const [reason,setReason]=useState('')
  const [busy,setBusy]=useState(false)
  const [issue,setIssue]=useState(null)
  const [message,setMessage]=useState(null)
  const locked=useRef(false),mounted=useRef(true)
  useEffect(()=>{mounted.current=true;return()=>{mounted.current=false}},[])
  const test=backtestSummary(rule), deployment=deploymentSummary(rule)
  const events=lifecycleEvents(rule)
  const token=writeTokenAvailable()
  const changed=decision && snapshotKey(decision.rule)!==snapshotKey(rule)
  const editable=actionableRule(rule) && token && !writeUnavailable
  const validName=reviewer.trim() && reviewer.trim().toLowerCase()!=='selfsentry-auto'
  const report=test.report
  async function copy(value,label){
    try{await navigator.clipboard.writeText(String(value));if(mounted.current)setMessage({kind:'success',text:`${label} copied.`})}
    catch{if(mounted.current)setMessage({kind:'error',text:`Could not copy ${label.toLowerCase()}. Select and copy the displayed text.`})}
  }
  function choose(action){setDecision({action,rule:{...rule}});setReason('');setIssue(null);setMessage(null)}
  async function submit(event){
    event.preventDefault()
    if(locked.current || !decision || changed || !editable || !validName)return
    if(decision.action==='reject' && !reason.trim())return
    if(decision.action==='approve' && test.blocked)return
    locked.current=true;setBusy(true);setIssue(null)
    try{
      const result=await reviewRule(decision.rule,{action:decision.action,reviewer,reason})
      const notice={kind:'success',text:result.status==='deployed'?`Rule #${rule.id}: backend confirmed deployment after Falco reload.`:`Rule #${rule.id} rejected; reason recorded.`}
      if(mounted.current){setMessage(notice);setDecision(null);setReason('')}
      onNotice(notice)
    }catch(error){
      if(mounted.current){setIssue(error);setDecision(null)}
      onNotice({kind:'error',text:`Rule #${rule.id}: ${error.message}`})
    }finally{
      locked.current=false
      if(mounted.current)setBusy(false)
      onChanged()
    }
  }
  return <Drawer open title={`Rule #${rule.id}`} onClose={()=>{if(!locked.current)onClose()}} busy={busy}>
    {message && <p className={`notice tone-${message.kind==='error'?'critical':'low'}`} role={message.kind==='error'?'alert':'status'}>{message.text}</p>}
    <div className="rule-detail-heading"><StatusBadge tone={rule.status==='deployed'?'low':['rejected','rejected_duplicate'].includes(rule.status)?'critical':'neutral'}>{ruleStatus(rule.status,rule)}</StatusBadge>
      <button type="button" className="shell-button" onClick={()=>copy(rule.id,'Rule ID')} aria-label="Copy rule ID"><Copy size={16} aria-hidden="true"/>Copy ID</button></div>
    {rule.rejection_reason && <p className="rule-warning" role="note">{rule.rejection_reason}</p>}
    <dl className="rule-metadata">
      <div><dt>Source incident</dt><dd>{rule.incident_id!=null?<Link to={`/alerts?incident=${encodeURIComponent(rule.incident_id)}`}>Incident #{rule.incident_id}</Link>:'Not recorded'}</dd></div>
      <div><dt>Source confirmation</dt><dd>{text(rule.confirmation_source)}</dd></div>
      <div><dt>Created</dt><dd><time title={text(rule.created_at)}>{formatDate(utcEpoch(rule.created_at))}</time></dd></div>
      <div><dt>Reviewer</dt><dd>{text(rule.reviewed_by)}</dd></div>
      <div><dt>Reviewed</dt><dd><time title={text(rule.reviewed_at)}>{formatDate(utcEpoch(rule.reviewed_at))}</time></dd></div>
    </dl>
    {rule.historyIncomplete && <p className="rule-warning">This rule has incomplete or changing history. Current pending fields are available; some source/backtest/lifecycle details are not recorded in this response.</p>}
    <section className="rule-detail-section" aria-label="Backtest evidence">
      <h3>Benign backtest <StatusBadge tone={test.tone}>{test.label}</StatusBadge></h3>
      <dl><div><dt>Recorded false-positive rate</dt><dd>{formatNumber(test.rate,{style:'percent',maximumFractionDigits:2})}</dd></div>
        <div><dt>Usable events tested</dt><dd>{formatNumber(test.events)}</dd></div>
        <div><dt>Recorded false positives</dt><dd>{formatNumber(report?.false_positives ?? report?.matched_events)}</dd></div>
        <div><dt>Recorded true negatives</dt><dd>{formatNumber(report?.true_negatives)}</dd></div>
      </dl>
      <p>{test.reason}</p>
      <p className="rule-caption">Benign-only testing does not measure true positives, attack coverage or production accuracy. No missing result is treated as a zero.</p>
      {test.blocked && <p className="rule-warning">Approve is blocked. Revise and resubmit the candidate; a typed reason cannot override the authoritative backend gate.</p>}
    </section>
    <section className="rule-detail-section" aria-label="Rule pattern and YAML">
      <h3>Recorded pattern</h3><p className="rule-condition">{recordedCondition(rule.rule_yaml) || 'Pattern summary unavailable; inspect the exact YAML below.'}</p>
      <div className="rule-detail-heading"><h3>Rule YAML</h3><button type="button" className="shell-button" disabled={typeof rule.rule_yaml!=='string' || !rule.rule_yaml} onClick={()=>copy(rule.rule_yaml,'Rule YAML')}><Copy size={16} aria-hidden="true"/>Copy YAML</button></div>
      <YamlCode value={rule.rule_yaml}/>
    </section>
    <section className="rule-detail-section" aria-label="Deployment result"><h3>Deployment result</h3><StatusBadge tone={deployment.tone}>{deployment.label}</StatusBadge><p>{deployment.detail}</p>
      <p>Native re-fire: {Array.isArray(rule.native_refires)?`${rule.native_refires.length} recorded matches`:'Not recorded'}. A match alone is not a validated true positive.</p>
    </section>
    <section className="rule-detail-section" aria-label="Human decision">
      <h3>Human decision</h3>
      {!token && <p>Operator token missing. Configure it in <Link to="/monitor">Monitor → Session credentials</Link>.</p>}
      {writeUnavailable && <p>Current pending-state verification is unavailable. Refresh the queue before submitting a decision.</p>}
      {!actionableRule(rule) && <p>This rule is not awaiting approval, deployment retry or rejection.</p>}
      <div className="rule-decision-buttons">
        <button type="button" className="btn btn-approve" disabled={!editable || busy || test.blocked || !rule.rule_yaml} onClick={()=>choose('approve')}>{rule.status==='approved'?'Retry deployment':'Review & approve'}</button>
        <button type="button" className="btn btn-reject" disabled={!editable || busy} onClick={()=>choose('reject')}>Reject</button>
      </div>
      {issue && <><ErrorState status={issue.status} error={issue.message} onRetry={()=>{setIssue(null);onChanged()}}/><p className="rule-caption">Retry refreshes evidence; it does not repeat the decision. A failed reload may leave approval recorded while deployment is pending.</p></>}
      {decision && <form className="rule-confirmation" aria-label={`${decision.action==='approve'?'Approve':'Reject'} rule confirmation`} onSubmit={submit}>
        <h4>{decision.action==='approve'?(decision.rule.status==='approved'?'Confirm deployment retry':'Confirm approval and deployment'):'Confirm rejection'} of rule #{rule.id}</h4>
        <p>{decision.action==='approve'?'This requests a new backend backtest and, if it passes, a Falco deployment and reload.':'Record why this candidate should not be deployed.'}</p>
        {changed && <p role="alert" className="rule-warning">The rule changed while this dialog was open. Cancel and review the current evidence.</p>}
        <label htmlFor="rule-reviewer">Reviewer name</label><input id="rule-reviewer" value={reviewer} onChange={event=>setReviewer(event.target.value)} required disabled={busy} autoFocus autoComplete="off"/>
        {decision.action==='reject' && <><label htmlFor="rule-rejection">Rejection reason</label><textarea id="rule-rejection" value={reason} onChange={event=>setReason(event.target.value)} required disabled={busy}/></>}
        <button type="submit" className={`btn ${decision.action==='approve'?'btn-primary':'btn-reject'}`} disabled={busy || !editable || !validName || changed || (decision.action==='reject'&&!reason.trim()) || (decision.action==='approve'&&test.blocked)}>{busy?'Submitting…':decision.action==='approve'?'Confirm deployment':'Confirm rejection'}</button>
        <button type="button" className="btn btn-ghost" disabled={busy} onClick={()=>setDecision(null)}>Cancel review</button>
      </form>}
    </section>
    <section className="rule-detail-section" aria-label="Rule status history"><h3>Recorded status history</h3><p className="rule-caption">Events are shown in API order. Missing audit events are not reconstructed.</p>
      {events.length?<ul className="rule-lifecycle">{events.map((event,index)=><li key={index}><strong>{text(event?.event_type)}</strong> · <time title={text(event?.occurred_at || event?.created_at)}>{formatDate(utcEpoch(event?.occurred_at || event?.created_at))}</time><pre>{event && typeof event==='object'?JSON.stringify(event.detail ?? null,null,2):text(event)}</pre></li>)}</ul>:<p>Status history: not recorded.</p>}
    </section>
  </Drawer>
}
