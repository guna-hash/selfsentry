// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest'
import { apiFetch } from '../api.js'
import { requestJson, requireWriteToken, writeTokenAvailable } from './requests.js'
vi.mock('../api.js',()=>({API:'',apiFetch:vi.fn(),describeFailure:async(response)=>response.detail}))
afterEach(()=>{sessionStorage.clear();vi.clearAllMocks();vi.useRealTimers()})
it('requires a session token without exposing any default credential',()=>{
  expect(writeTokenAvailable()).toBe(false)
  expect(requireWriteToken).toThrow('Operator token missing')
  sessionStorage.setItem('selfsentry-api-token','test-only')
  expect(requireWriteToken()).toBeUndefined()
})
it('preserves backend rejection status and safely serializes JSON',async()=>{
  apiFetch.mockResolvedValue({ok:false,status:422,detail:'Authoritative backtest rejected'})
  await expect(requestJson('/rules/',{method:'POST',body:{rule_yaml:'<text>'}})).rejects.toMatchObject({status:422,message:'Authoritative backtest rejected'})
  expect(apiFetch.mock.calls[0][1].body).toBe('{"rule_yaml":"<text>"}')
})
it('marks interrupted writes as uncertain without automatically replaying them',async()=>{
  apiFetch.mockRejectedValue(new Error('Network offline'))
  await expect(requestJson('/incidents/1/confirm',{method:'POST'})).rejects.toMatchObject({uncertain:true})
  expect(apiFetch).toHaveBeenCalledOnce()
})
it('bounds reads and aborts their fetch signal',async()=>{
  vi.useFakeTimers()
  apiFetch.mockImplementation((url,{signal})=>new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(new Error('aborted')))))
  const result=requestJson('/incidents/',{timeoutMs:10}).catch(error=>error)
  await vi.advanceTimersByTimeAsync(10)
  expect((await result).message).toContain('timed out')
})
