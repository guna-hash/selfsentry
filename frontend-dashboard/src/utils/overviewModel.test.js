import { describe, expect, it } from 'vitest'
import { DAY, effectiveRisk, layersFired, lookupContainer, normalizeIncidents, periodSummary, learningLoop, utcEpoch } from './overviewModel.js'

const now = Date.parse('2026-10-19T10:00:00Z')
const incident = (id, offset, extra = {}) => ({ id, container_id: 'a'.repeat(64), created_at: new Date(now + offset).toISOString(), risk_score: 50, ...extra })
const rows = [
  incident(1, -1000),
  incident(2, -DAY, { confirmation: { confirmed_by: 'operator' }, risk_score: 90 }),
  incident(3, -DAY - 1, { risk_score: 40 }),
  incident(4, -2 * DAY, { monitor_workflow: { disposition: { status: 'benign' } } }),
  incident(5, 1),
  { id: 6, created_at: null, container_id: 'unknown' },
]

describe('honest Overview measurements', () => {
  it('normalizes naive backend UTC timestamps without local-time drift', () => {
    expect(utcEpoch('2026-10-19T10:00:00')).toBe(now)
    expect(utcEpoch('2026-10-19T15:30:00+05:30')).toBe(now)
    expect(utcEpoch('invalid')).toBeNull()
    expect(utcEpoch(null)).toBeNull()
  })
  it('uses non-overlapping current/previous creation periods and excludes future or missing times', () => {
    const result = periodSummary(normalizeIncidents(rows), '24h', now)
    expect(result.current.map(r=>r.id)).toEqual([1,2])
    expect(result.previous.map(r=>r.id)).toEqual([3,4])
    expect(result.open).toBe(1)
    expect(result.previousOpen).toBe(1)
    expect(result.highest).toBe(90)
    expect(result.previousHighest).toBe(50)
    expect(result.excluded).toBe(2)
    expect(result.trend.reduce((n,b)=>n+b.current,0)).toBe(2)
    expect(result.trend.reduce((n,b)=>n+b.previous,0)).toBe(2)
    expect(result.trend.reduce((n,b)=>n+b.open,0)).toBe(1)
  })
  it('handles seven-day bins and preserves unknown versus observed empty results', () => {
    expect(periodSummary(normalizeIncidents(rows), '7d', now).trend).toHaveLength(7)
    expect(periodSummary(null,'24h',now).open).toBeNull()
    expect(periodSummary([],'24h',now).open).toBe(0)
    expect(periodSummary([],'24h',now).highest).toBeNull()
  })
  it('uses recorded correlated layers; model availability and AI text alone never imply ML detection', () => {
    const falco={falco_alert:{rule:'Shell'}}
    expect(layersFired({...falco,monitor_evidence:{anomaly_status:'used',anomaly_assessment:{qualifies:true}}})).toBe('Falco only')
    expect(layersFired({...falco,anomaly_features:{anomaly_score:0.9}})).toBe('Both')
    expect(layersFired({anomaly_features:{anomaly_score:0.8}})).toBe('ML only')
    expect(layersFired({ai_summary:{plain_summary:'Attack detected'}})).toBe('Not recorded')
    expect(layersFired({falco_alert:{rule:'Baseline Process Spawn'}})).toBe('Not recorded')
    expect(layersFired({anomaly_features:{anomaly_score:5}})).toBe('Not recorded')
    expect(effectiveRisk({risk_score:50,monitor_evidence:{effective_score:0}})).toBe(0)
    expect(effectiveRisk({risk_score:null})).toBeNull()
  })
  it('matches only unique Docker IDs, never a reused container name', () => {
    const containers=[{id:'a'.repeat(12),full_id:'a'.repeat(64),name:'nginx'}, {id:'b'.repeat(12),full_id:'b'.repeat(64),name:'worker'}]
    expect(lookupContainer('a'.repeat(20),containers).name).toBe('nginx')
    expect(lookupContainer('nginx',containers)).toBeNull()
    expect(lookupContainer('a'.repeat(12),[{full_id:'a'.repeat(12)+'b'.repeat(52)},{full_id:'a'.repeat(12)+'c'.repeat(52)}])).toBeNull()
    const normalized=normalizeIncidents(rows,containers)
    expect(periodSummary(normalized,'24h',now,'b'.repeat(64)).current).toEqual([])
    expect(periodSummary(normalized,'24h',now,'a'.repeat(64)).current).toHaveLength(2)
  })
  it('counts lifecycle evidence once per rule, not once per retry or refire event', () => {
    const incidents=normalizeIncidents([incident(1,-1,{confirmation:{confirmed_by:'operator'}}),incident(2,-2)])
    const rules=[
      {id:1,incident_id:1,status:'deployed',native_refires:[{},{}],lifecycle_events:[{event_type:'RULE_APPROVED'},{event_type:'RULE_APPROVED'},{event_type:'RULE_DEPLOYED'}]},
      {id:2,incident_id:1,status:'rejected',native_refires:[]},
      {id:3,incident_id:99,status:'deployed',native_refires:[{}]},
      {id:4,incident_id:null,status:'deployed',native_refires:[{}]},
    ]
    const result=learningLoop(incidents,rules)
    expect(result.stages.map(s=>s.value)).toEqual([2,1,2,1,1,1])
    expect(result.unlinked).toBe(1)
    expect(learningLoop(incidents,null).stages.map(s=>s.value)).toEqual([2,1,null,null,null,null])
    expect(learningLoop(null,rules).stages.every(s=>s.value===null)).toBe(true)
    expect(learningLoop(incidents,Array.from({length:100},()=>rules[0])).limited).toBe(true)
    expect(learningLoop(incidents,[{id:9,incident_id:1,status:'deployed'}]).stages.at(-1).value).toBeNull()
  })
})
