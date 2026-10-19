import { finiteNumber } from './format.js'
import { utcEpoch } from './overviewModel.js'

export const actionableRule = (rule) => ['pending_review', 'approved'].includes(rule?.status)
export const ruleStatus = (status) => ({pending_review:'Pending review',approved:'Approved · deployment pending',deployed:'Deployed',rejected:'Rejected',retired:'Retired (disabled)',disabled:'Disabled'})[status] || status || 'Not recorded'
export function backtestSummary(rule) {
  const gate = latestEvent(rule, ['RULE_CANDIDATE_CREATED','RULE_BACKTEST_REVALIDATED','RULE_BACKTEST_BLOCKED_DEPLOYMENT'])
  const blockedReport = gate?.event_type === 'RULE_BACKTEST_BLOCKED_DEPLOYMENT' ? gate.detail?.reason : null
  const report = blockedReport && typeof blockedReport === 'object' ? blockedReport
    : gate?.detail?.backtest && typeof gate.detail.backtest === 'object' ? gate.detail.backtest : rule.backtest
  const recordedRate = finiteNumber(report?.false_positive_rate) ?? finiteNumber(rule.backtested_fp_rate)
  const rate = recordedRate !== null && recordedRate >= 0 && recordedRate <= 1 ? recordedRate : null
  const events = Number.isInteger(report?.events_tested) && report.events_tested >= 0 ? report.events_tested : null
  const verdict = report?.verdict
  if (gate?.event_type === 'RULE_BACKTEST_BLOCKED_DEPLOYMENT' && (!blockedReport || typeof blockedReport !== 'object'))
    return {report:null,rate,events:null,label:'Approval backtest unavailable',tone:'neutral',blocked:false,reason:typeof blockedReport === 'string' ? blockedReport : 'The last approval backtest was unavailable. The backend must retest before deployment.'}
  if (events === 0) return {report,rate,events,label:'No usable test events',tone:'critical',blocked:true,reason:'The backend refuses deployment when no usable benign events were tested.'}
  if (['fail','failed','error','rejected'].includes(verdict) || (rate !== null && rate > 0.05 && verdict !== 'flag_for_revision'))
    return {report,rate,events,label:'Failed backtest',tone:'critical',blocked:true,reason:'Revise and resubmit; the backend does not allow a failed-backtest override.'}
  if (verdict === 'flag_for_revision') return {report,rate,events,label:'Revision recommended',tone:'medium',blocked:true,reason:'Revise and resubmit. A reviewer note cannot override the backend backtest gate.'}
  if (verdict === 'pass' && events > 0 && rate !== null && rate <= 0.05)
    return {report,rate,events,label:'Recorded pass',tone:'low',blocked:false,reason:'The backend rechecks the configured benign corpus on approval.'}
  return {report,rate,events,label:'Detailed backtest unavailable',tone:'neutral',blocked:false,reason:'Historical evidence is incomplete. The backend must perform a passing backtest before deployment.'}
}
export function lifecycleEvents(rule) {
  return Array.isArray(rule.lifecycle_events) ? rule.lifecycle_events : []
}
function latestEvent(rule, types) {
  return lifecycleEvents(rule).filter((e)=>e && types.includes(e.event_type))
    .map((event,index)=>({event,index,time:utcEpoch(event.occurred_at || event.created_at)}))
    .sort((a,b)=>(a.time ?? -Infinity)-(b.time ?? -Infinity) || a.index-b.index).at(-1)?.event
}
export function deploymentSummary(rule) {
  const last = latestEvent(rule, ['RULE_DEPLOYED','RULE_DEPLOYMENT_FAILED'])
  if (rule.status === 'deployed') return {label:'Deployed',tone:'low',detail:last?.event_type==='RULE_DEPLOYED'?'Backend recorded deployment after Falco reload. Native re-fire is separate evidence.':'Backend status is deployed; detailed reload history is not recorded.'}
  if (last?.event_type === 'RULE_DEPLOYMENT_FAILED') return {label:'Reload / deployment failed',tone:'critical',detail:typeof last.detail?.reason==='string'?last.detail.reason:'Failure reason not recorded.'}
  if (rule.status === 'approved') return {label:'Deployment pending',tone:'medium',detail:'Approval is recorded. Successful deployment is not recorded in the current status.'}
  return {label:'No current deployment recorded',tone:'neutral',detail:'See the lifecycle evidence for any historical deployment or retirement.'}
}
export function recordedCondition(yaml) {
  if (typeof yaml !== 'string') return null
  const match = yaml.match(/^[ \t]*(?:-[ \t]*)?condition:[ \t]*(.+)$/m)
  if (!match || ['>', '|', '>-', '|-'].includes(match[1].trim())) return null
  return match[1].trim()
}
export function mergeRuleSources(history, pending) {
  if (history === null && pending === null) return null
  const rows = new Map((history || []).map((rule)=>[String(rule.id),{...rule,historyIncomplete:false}]))
  for (const current of pending || []) {
    const previous=rows.get(String(current.id))
    const changedYaml=previous && (previous.rule_yaml!==current.rule_yaml || previous.backtested_fp_rate!==current.backtested_fp_rate)
    rows.set(String(current.id),{...previous,...current,
      ...(changedYaml?{backtest:null,lifecycle_events:null,native_refires:null}:{}),
      historyIncomplete:!previous || !!changedYaml || previous.status!==current.status,
    })
  }
  return [...rows.values()]
}
