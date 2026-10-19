import { beforeEach, expect, it, vi } from 'vitest'
import { requestJson, requireWriteToken } from './requests.js'
import { confirmIncident, createCandidate } from './incidentActions.js'
vi.mock('./requests.js',()=>({requestJson:vi.fn(),requireWriteToken:vi.fn()}))
const incident={id:12,confirmation:{confirmed_by:'selfsentry-auto'}}
const form={actor:'guna',yaml:'- rule: generated\n  condition: safe',fpPercent:'0'}
const notFound=()=>Object.assign(new Error('No active candidate'),{status:404})
beforeEach(()=>{vi.resetAllMocks()})
it('requires a human name and encodes it in an idempotent confirmation request',async()=>{
  await expect(confirmIncident(12,'selfsentry-auto')).rejects.toThrow('human operator')
  expect(requestJson).not.toHaveBeenCalled()
  requestJson.mockResolvedValue({confirmed_incident_id:8,status:'confirmed'})
  await confirmIncident(12,'guna & team')
  expect(requestJson).toHaveBeenCalledWith('/incidents/12/confirm?confirmed_by=guna%20%26%20team',{method:'POST'})
})
it('requires token, confirmation and an actual reported rate before candidate requests',async()=>{
  requireWriteToken.mockImplementationOnce(()=>{throw new Error('Token missing')})
  await expect(confirmIncident(12,'guna')).rejects.toThrow('Token missing')
  await expect(createCandidate({id:12},form)).rejects.toThrow('Confirm this incident')
  await expect(createCandidate(incident,{...form,fpPercent:''})).rejects.toThrow('recorded benign backtest')
  await expect(createCandidate(incident,{...form,fpPercent:'6'})).rejects.toThrow('recorded benign backtest')
  await expect(createCandidate({...incident,monitor_workflow:{disposition:{status:'benign'}}},form)).rejects.toThrow('marked benign')
  expect(requestJson).not.toHaveBeenCalled()
})
it('submits YAML and a user-reported zero rate to the authoritative backend, never approval',async()=>{
  requestJson.mockResolvedValueOnce({confirmed_incident_id:8,status:'already_confirmed'})
    .mockRejectedValueOnce(notFound()).mockResolvedValueOnce({id:23,status:'pending_review'})
  await expect(createCandidate(incident,form)).resolves.toEqual({id:23,status:'pending_review'})
  expect(requestJson.mock.calls[2]).toEqual(['/rules/',{method:'POST',timeoutMs:30000,body:{confirmed_incident_id:8,rule_yaml:form.yaml,backtested_fp_rate:0}}])
  expect(requestJson.mock.calls.some(([path])=>path.includes('/approve'))).toBe(false)
})
it('reuses a recorded active candidate without a second candidate submission',async()=>{
  requestJson.mockResolvedValueOnce({confirmed_incident_id:8}).mockResolvedValueOnce({id:23,confirmed_incident_id:8,status:'deployed'})
  await expect(createCandidate(incident,form)).resolves.toMatchObject({id:23,existing:true,status:'deployed'})
  expect(requestJson).toHaveBeenCalledTimes(2)
})
it('reconciles a concurrent candidate but propagates an authoritative backtest rejection',async()=>{
  requestJson.mockResolvedValueOnce({confirmed_incident_id:8}).mockRejectedValueOnce(notFound())
    .mockRejectedValueOnce(Object.assign(new Error('Duplicate'),{status:409}))
    .mockResolvedValueOnce({id:24,confirmed_incident_id:8,status:'pending_review'})
  await expect(createCandidate(incident,form)).resolves.toMatchObject({id:24,existing:true})
  requestJson.mockReset()
  requestJson.mockResolvedValueOnce({confirmed_incident_id:8}).mockRejectedValueOnce(notFound())
    .mockRejectedValueOnce(Object.assign(new Error('Backtest failed'),{status:422}))
  await expect(createCandidate(incident,form)).rejects.toMatchObject({status:422})
  expect(requestJson).toHaveBeenCalledTimes(3)
})
