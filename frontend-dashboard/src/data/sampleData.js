// Synthetic UI fixtures only. Never evaluation evidence, never persisted to the backend.
import { SAMPLE_TIME } from '../utils/demoMode.js'
const cid = 'aaaaaaaaaaaa', other = 'bbbbbbbbbbbb'
const time = minutes => new Date(Date.parse(SAMPLE_TIME) - minutes * 60000).toISOString()
const confirmation = {confirmed_by:'sample-reviewer',confirmed_at:time(40)}
const yaml = '- rule: Sample_Process_From_Shell\n  desc: Synthetic UI demonstration only\n  condition: spawned_process and container and proc.name="sample-process"\n  output: "Sample rule match"\n  priority: WARNING'
function incident(id, minutes, rule, risk, confirmed = false, anomaly = null) {
  return {id,container_id:cid,created_at:time(minutes),risk_score:risk,confidence:'Sample',
    falco_alert:rule ? {rule,priority:risk>=90?'Critical':'Warning',output:'Sample event; no workload was executed.'} : null,
    anomaly_features:anomaly == null ? null : {anomaly_score:anomaly},confirmation:confirmed?{...confirmation,confirmed_at:time(minutes-2)}:null,
    monitor_evidence:{effective_score:risk,cross_layer_agreement:!!rule && anomaly!=null,
      baseline_state:'MODEL_READY',anomaly_status:'Sample model ready',anomaly_assessment:{model_algorithm:'isolation_forest',anomaly_score:anomaly,availability:'ready',qualifies:anomaly!=null},
      observed_timeline:[{step:1,description:'Synthetic UI event; no command was executed',timestamp:time(minutes),source:'sample',rule:rule || 'Sample anomaly',output:'Synthetic event for dashboard demonstration'}]},
    monitor_workflow:{response:{status:'not_attempted',reason:'Sample data mode; all writes disabled'},explanation:{status:'unavailable'}},ai_summary:null}
}
const incidents = [incident(9001,5,'Sample terminal shell',95),incident(9002,240,'Sample process execution',90,true,0.91),incident(9003,80,null,55,false,0.83),incident(9004,20,'Sample generated rule re-fire',70,true),incident(9005,150,'Sample file read',65,true),incident(9006,1560,'Sample previous-period alert',75)]
const rules = [
  {id:9101,incident_id:9002,confirmed_incident_id:9202,status:'deployed',created_at:time(230),reviewed_by:'sample-reviewer',reviewed_at:time(200),confirmation_source:'human',rule_yaml:yaml,backtested_fp_rate:0,backtest:{events_tested:40,matched_events:0,false_positive_rate:0,verdict:'pass'},native_refires:[{incident_id:9004}],lifecycle_events:[{event_type:'RULE_APPROVED',occurred_at:time(200),detail:{reviewed_by:'sample-reviewer'}},{event_type:'RULE_DEPLOYED',occurred_at:time(199)},{event_type:'RULE_NATIVE_REFIRE',occurred_at:time(20),detail:{incident_id:9004}}]},
  {id:9102,incident_id:9005,confirmed_incident_id:9205,status:'pending_review',created_at:time(140),rule_yaml:yaml,backtested_fp_rate:0.025,backtest:{events_tested:40,matched_events:1,false_positive_rate:0.025,verdict:'pass'},lifecycle_events:[]},
]
const containers = [
  {id:cid,full_id:cid.repeat(5)+'aaaa',name:'sample-web',image:'sample/web:demo',status:'running',protected:false,isolated:false,containment_label:'running',latest_risk_score:95,monitoring:{active:true,label:'Sample monitoring active'}},
  {id:other,full_id:other.repeat(5)+'bbbb',name:'sample-protected-db',image:'sample/db:demo',status:'running',protected:true,isolated:false,containment_label:'running',monitoring:{active:false,label:'Sample learning state'}},
]
const monitor = {running:true,healthy:true,reason:'Sample monitor state; no live connection',updated_at:SAMPLE_TIME,last_event_at:time(1),status_age_seconds:0,containers:{tracked:2},models_ready:1,containers_learning:1,unconfirmed_incidents:3,failed_response_actions:0,incident_outbox_size:0,audit_spool_size:0,rule_matching:'all',components:{falco_ingest:{state:'ok',detail:'Sample journal connection'},backend:{state:'ok',detail:'Local fixtures; no API connection'},database:{state:'ok',detail:'Sample state; no database connection'}},configuration:{auto_isolation_enabled:false,protected_containers:['sample-protected-db']},baselines:{[cid]:{state:'MODEL_READY',samples:40,reason:'Synthetic model state'},[other]:{state:'LEARNING',samples:8,reason:'Synthetic learning state'}}}
const deployments = [{id:9301,created_at:time(180),container_name:'sample-web',image_name:'sample/web:demo',decision:'allowed',requested_by:'sample-operator',scan:{critical:0,high:0,secrets_found:0,misconfigurations_found:0,top_findings:[]},policy_violations:[],policy_summary:'Sample gate decision'}]
const audit = [{id:9401,event_type:'SAMPLE_RULE_DEPLOYED',source:'sample',severity:'info',container_id:cid,container_name:'sample-web',occurred_at:time(199),detail:{reviewed_by:'sample-reviewer',outcome:'Synthetic deployment; no actual reload'}}]
export function sampleResult(path) {
  const url = new URL(path,'http://sample.invalid'), route = url.pathname.replace(/\/$/,'')
  let value
  if (route==='/monitor/status') value=monitor
  else if(route==='/containers') value=containers
  else if(route==='/incidents') value=incidents
  else if(/^\/incidents\/\d+$/.test(route)) value=incidents.find(r=>String(r.id)===route.split('/').at(-1))
  else if(route==='/rules/history') value=rules
  else if(route==='/rules/pending') value=rules.filter(r=>r.status==='pending_review')
  else if(route==='/deployments') value=deployments
  else if(route==='/audit') value=audit.filter(r=>(!url.searchParams.has('event_type') || r.event_type===url.searchParams.get('event_type')) && (!url.searchParams.has('event_id') || String(r.id)===url.searchParams.get('event_id')) && (!url.searchParams.has('container_id') || r.container_id===url.searchParams.get('container_id')) && (!url.searchParams.has('before_id') || r.id<Number(url.searchParams.get('before_id'))))
  if(value===undefined) return {status:404,body:{detail:'No sample record for this request. Live API fallback is disabled.'}}
  return {status:200,body:JSON.parse(JSON.stringify(value))}
}
