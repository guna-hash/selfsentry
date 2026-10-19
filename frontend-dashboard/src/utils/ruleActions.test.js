import {beforeEach,expect,it,vi} from 'vitest'
import {reviewRule} from './ruleActions.js'
import {requestJson,requireWriteToken} from './requests.js'
vi.mock('./requests.js',()=>({requestJson:vi.fn(),requireWriteToken:vi.fn()}))
const rule={id:3,status:'pending_review',rule_yaml:'- rule: example',backtested_fp_rate:0,backtest:{events_tested:20,false_positive_rate:0,verdict:'pass'}}
beforeEach(()=>vi.resetAllMocks())
it('requires credentials, explicit human identity and a rejection reason before requests',async()=>{
  requireWriteToken.mockImplementationOnce(()=>{throw new Error('Token missing')})
  await expect(reviewRule(rule,{action:'approve',reviewer:'guna'})).rejects.toThrow('Token missing')
  await expect(reviewRule(rule,{action:'approve',reviewer:'selfsentry-auto'})).rejects.toThrow('human reviewer')
  await expect(reviewRule(rule,{action:'reject',reviewer:'guna',reason:' '})).rejects.toThrow('rejection reason')
  expect(requestJson).not.toHaveBeenCalled()
})
it('blocks revision and zero-event backtests even with an arbitrary typed reason',async()=>{
  await expect(reviewRule({...rule,backtest:{...rule.backtest,verdict:'flag_for_revision'}},{action:'approve',reviewer:'guna',reason:'override'})).rejects.toThrow('override')
  await expect(reviewRule({...rule,backtest:{...rule.backtest,events_tested:0}},{action:'approve',reviewer:'guna'})).rejects.toThrow('no usable benign events')
  expect(requestJson).not.toHaveBeenCalled()
})
it('re-reads the pending queue and sends the explicit human approval only after matching evidence',async()=>{
  requestJson.mockResolvedValueOnce([rule]).mockResolvedValueOnce({rule_id:3,status:'deployed'})
  await expect(reviewRule(rule,{action:'approve',reviewer:'guna & team'})).resolves.toMatchObject({status:'deployed'})
  expect(requestJson.mock.calls[0][0]).toBe('/rules/pending')
  expect(requestJson.mock.calls[1]).toEqual(['/rules/3/approve?reviewed_by=guna+%26+team',{method:'POST',timeoutMs:45000}])
})
it('rejects stale YAML/state instead of deploying material changed since human review',async()=>{
  requestJson.mockResolvedValue([{...rule,rule_yaml:'changed'}])
  await expect(reviewRule(rule,{action:'approve',reviewer:'guna'})).rejects.toMatchObject({status:409})
  expect(requestJson).toHaveBeenCalledOnce()
})
it('encodes and records a rejection reason through the existing endpoint',async()=>{
  requestJson.mockResolvedValueOnce([rule]).mockResolvedValueOnce({rule_id:3,status:'rejected'})
  await reviewRule(rule,{action:'reject',reviewer:'guna',reason:'too broad & noisy'})
  expect(requestJson.mock.calls[1][0]).toBe('/rules/3/reject?reviewed_by=guna&reason=too+broad+%26+noisy')
})
it('preserves deployment failures and refuses responses that do not confirm the requested result',async()=>{
  requestJson.mockResolvedValueOnce([rule]).mockRejectedValueOnce(Object.assign(new Error('Approved but reload failed'),{status:502}))
  await expect(reviewRule(rule,{action:'approve',reviewer:'guna'})).rejects.toMatchObject({status:502})
  requestJson.mockResolvedValueOnce([rule]).mockResolvedValueOnce({rule_id:3,status:'approved'})
  await expect(reviewRule(rule,{action:'approve',reviewer:'guna'})).rejects.toMatchObject({uncertain:true})
})
