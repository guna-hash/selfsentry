import {expect,it} from 'vitest'
import {backtestSummary,deploymentSummary,mergeRuleSources,recordedCondition} from './ruleView.js'
const pass={false_positive_rate:0,events_tested:20,verdict:'pass'}
it('distinguishes measured passes, revision, no-event failures and missing data',()=>{
  expect(backtestSummary({backtest:pass})).toMatchObject({rate:0,events:20,tone:'low',blocked:false})
  expect(backtestSummary({backtest:{...pass,verdict:'flag_for_revision'}})).toMatchObject({tone:'medium',blocked:true})
  expect(backtestSummary({backtest:{...pass,events_tested:0}})).toMatchObject({tone:'critical',blocked:true})
  expect(backtestSummary({backtested_fp_rate:0})).toMatchObject({rate:0,events:null,tone:'neutral'})
  expect(backtestSummary({backtested_fp_rate:.2})).toMatchObject({tone:'critical',blocked:true})
  expect(backtestSummary({})).toMatchObject({rate:null,events:null})
})
it('uses a newer authoritative blocked report instead of an older passing rate',()=>{
  const rule={backtest:pass,lifecycle_events:[
    {event_type:'RULE_CANDIDATE_CREATED',occurred_at:'2026-10-19T09:00:00',detail:{backtest:pass}},
    {event_type:'RULE_BACKTEST_BLOCKED_DEPLOYMENT',occurred_at:'2026-10-19T10:00:00',detail:{reason:{false_positive_rate:.1,events_tested:10,verdict:'flag_for_revision'}}},
  ]}
  expect(backtestSummary(rule)).toMatchObject({rate:.1,events:10,blocked:true})
  rule.lifecycle_events.push({event_type:'RULE_BACKTEST_REVALIDATED',occurred_at:'2026-10-19T11:00:00',detail:{backtest:{...pass,events_tested:30}}})
  expect(backtestSummary(rule)).toMatchObject({events:30,blocked:false})
})
it('reports unavailable approval evidence without claiming the prior pass is current',()=>{
  const result=backtestSummary({backtest:pass,lifecycle_events:[{event_type:'RULE_BACKTEST_BLOCKED_DEPLOYMENT',detail:{reason:'Corpus unavailable'}}]})
  expect(result).toMatchObject({label:'Approval backtest unavailable',events:null,report:null})
})
it('keeps all pending records, de-duplicates overlapping history and discards mismatched evidence',()=>{
  const history=[{id:3,status:'pending_review',rule_yaml:'old',backtested_fp_rate:0,backtest:pass,incident_id:7}]
  const pending=[{id:3,status:'pending_review',rule_yaml:'new',backtested_fp_rate:0},{id:1,status:'approved',rule_yaml:'legacy'}]
  const rows=mergeRuleSources(history,pending)
  expect(rows).toHaveLength(2)
  expect(rows[0]).toMatchObject({id:3,rule_yaml:'new',backtest:null,incident_id:7,historyIncomplete:true})
  expect(rows[1].historyIncomplete).toBe(true)
  expect(mergeRuleSources(null,null)).toBeNull()
  expect(mergeRuleSources([],[])).toEqual([])
})
it('reports actual failed reload reasons and never infers a native re-fire from deployment',()=>{
  expect(deploymentSummary({status:'approved',lifecycle_events:[{event_type:'RULE_DEPLOYMENT_FAILED',detail:{reason:'Reload exit 1'}}]})).toMatchObject({tone:'critical',detail:'Reload exit 1'})
  expect(deploymentSummary({status:'deployed'}).detail).toContain('not recorded')
})
it('summarizes only recorded single-line conditions without executing or inventing YAML',()=>{
  expect(recordedCondition('- rule: x\n  condition: proc.name="sh"')).toBe('proc.name="sh"')
  expect(recordedCondition('condition: >\n  multi line')).toBeNull()
  expect(recordedCondition('condition:\nnext: value')).toBeNull()
})
