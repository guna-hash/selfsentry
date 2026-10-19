import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Pause, Play, RefreshCw } from 'lucide-react'
import { DataTable, Drawer, EmptyState, ErrorState, FilterChips, Notice, PageHeader, Skeleton, StatusBadge } from '../components/ui.jsx'
import RuleReviewDialog from '../components/RuleReviewDialog.jsx'
import useRules from '../hooks/useRules.js'
import { actionableRule, backtestSummary, ruleStatus } from '../utils/ruleView.js'
import { RANGE_MS, utcEpoch } from '../utils/overviewModel.js'
import { formatDate, formatNumber, relativeTime } from '../utils/format.js'
import './rules.css'

const columns=[
  {key:'id',label:'Rule ID',render:value=>`#${value}`},
  {key:'incident_id',label:'Source incident',render:value=>value!=null?<Link to={`/alerts?incident=${encodeURIComponent(value)}`}>#{value}</Link>:'Not recorded'},
  {key:'status',label:'Status',render:value=><StatusBadge tone={value==='deployed'?'low':value==='rejected'?'critical':value==='approved'?'medium':'neutral'}>{ruleStatus(value)}</StatusBadge>},
  {key:'rate',label:'Backtest FP rate',accessor:rule=>backtestSummary(rule).rate,render:(value,rule)=><StatusBadge tone={backtestSummary(rule).tone}>{formatNumber(value,{style:'percent',maximumFractionDigits:2})} · {backtestSummary(rule).label}</StatusBadge>},
  {key:'reviewed_by',label:'Reviewer'},
  {key:'created',label:'Created',accessor:rule=>utcEpoch(rule.created_at),render:value=><time title={formatDate(value)} dateTime={value===null?undefined:new Date(value).toISOString()}>{relativeTime(value)}</time>},
]
export default function RuleReviewQueue(){
  const {rules,history,pending,errors,loading,refreshing,updatedAt,paused,refresh,togglePaused}=useRules()
  const [search,setSearch]=useSearchParams()
  const [status,setStatus]=useState('actionable'),[period,setPeriod]=useState('all'),[notice,setNotice]=useState(null)
  const selected=search.get('rule')
  const selectedRule=rules?.find(rule=>String(rule.id)===selected)
  const rows=useMemo(()=>{
    const end=updatedAt ?? Date.now()
    return (rules || []).filter(rule=>{
      const time=utcEpoch(rule.created_at)
      return (status==='all' || (status==='actionable'?actionableRule(rule):rule.status===status)) && (period==='all' || (time!==null && time>=end-RANGE_MS[period] && time<=end))
    })
  },[rules,status,period,updatedAt])
  const chips=[...(status==='all'?[]:[{id:'status',label:`Status: ${status==='actionable'?'Needs action':ruleStatus(status)}`}]),...(period==='all'?[]:[{id:'period',label:`Creation period: ${period}`}])]
  function open(rule){const params=new URLSearchParams(search);params.set('rule',rule.id);setSearch(params)}
  function close(){const params=new URLSearchParams(search);params.delete('rule');setSearch(params)}
  return <div className="rule-queue-page">
    <div className="rule-queue-heading"><PageHeader title="Rule review queue">Inspect candidate evidence and record a human decision before deployment.</PageHeader>
      <div className="rule-queue-refresh"><span title={formatDate(updatedAt)}>Last complete update: {updatedAt?relativeTime(updatedAt):'Not recorded'}</span><div>
        <button type="button" className="shell-button" onClick={togglePaused} aria-pressed={paused}>{paused?<Play size={16} aria-hidden="true"/>:<Pause size={16} aria-hidden="true"/>}{paused?'Resume queue refresh':'Pause queue refresh'}</button>
        <button type="button" className="shell-button" onClick={refresh} disabled={refreshing} aria-label="Refresh rule queue"><RefreshCw size={16} className={refreshing?'spin':''} aria-hidden="true"/>Refresh</button>
      </div></div>
    </div>
    <Notice notice={notice} onDismiss={()=>setNotice(null)}/>
    <p className="rule-caption">{pending===null?'Pending queue total unavailable.':`${pending.length} rules await review or deployment retry in the current host-wide queue.`} Every deployment requires a human name and confirmation. Approval rechecks the backend benign corpus.</p>
    {history && history.length>=100 && <p className="rule-warning" role="note">History is limited to the latest 100 rules. All current pending rules are merged from the separate pending endpoint; older completed history may be missing.</p>}
    {Object.entries(errors).map(([source,error])=><section key={source} aria-label={`${source} rule source error`}><ErrorState error={`${source==='history'?'Rule history':'Current pending queue'}: ${error.message}`} status={error.status} onRetry={refresh} retrying={refreshing}/></section>)}
    {paused && <p role="status" className="rule-caption">Queue refresh paused. Decisions still verify current pending state before writing; monitor health and security services continue.</p>}
    <div className="rule-queue-controls">
      <label htmlFor="rule-status">Status<select id="rule-status" value={status} onChange={event=>setStatus(event.target.value)}>
        <option value="actionable">Needs action</option><option value="all">All available history</option><option value="pending_review">Pending review</option><option value="approved">Approved · retry deployment</option><option value="deployed">Deployed</option><option value="rejected">Rejected</option><option value="retired">Retired (disabled)</option><option value="disabled">Disabled</option>
      </select></label>
      <label htmlFor="rule-period">Creation period<select id="rule-period" value={period} onChange={event=>setPeriod(event.target.value)}><option value="all">All recorded time</option><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option></select></label>
    </div>
    <FilterChips filters={chips} onRemove={id=>id==='status'?setStatus('all'):setPeriod('all')} onClear={()=>{setStatus('all');setPeriod('all')}}/>
    {!loading && rules!==null && !rows.length
      ? <EmptyState title={rules.length?'No rules match these filters':'No candidates recorded in available sources'}>Change the status or creation-period filters, or refresh the source requests.</EmptyState>
      : <DataTable rows={rows} columns={columns} caption="Rule candidates" loading={loading} initialSort={{key:'id',direction:'desc'}} onRowOpen={open} error={rules===null && !loading?'Rule records unavailable. Retry the source requests above.':null} onRetry={refresh}/>}
    {selected && (selectedRule?<RuleReviewDialog key={selected} rule={selectedRule} onClose={close} onChanged={refresh} onNotice={setNotice} writeUnavailable={pending===null}/>
      :<Drawer open title={`Rule #${selected}`} onClose={close}>{loading?<Skeleton label="Loading selected rule…"/>:<><p>This rule is not in the available records. The API exposes recent history and current pending records; an older completed rule may be outside that scope.</p><button type="button" className="btn" onClick={refresh} disabled={refreshing}>Refresh available rules</button></>}</Drawer>)}
  </div>
}
