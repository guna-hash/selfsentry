// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import useOverviewData, { OVERVIEW_REFRESH_MS, OVERVIEW_REQUEST_TIMEOUT_MS } from './useOverviewData.js'
import { apiFetch } from '../api.js'
vi.mock('../api.js',()=>({API:'',apiFetch:vi.fn(),describeFailure:async(r)=>r.message}))
let root, host, value
function Probe(){ value=useOverviewData(); return <span>{value.loading?'loading':'ready'}</span> }
const ok=(body=[])=>({ok:true,json:async()=>body})
beforeEach(()=>{
  vi.useFakeTimers(); globalThis.IS_REACT_ACT_ENVIRONMENT=true
  host=document.createElement('div');document.body.append(host);root=createRoot(host)
  apiFetch.mockResolvedValue(ok([{id:1}]))
})
afterEach(async()=>{ await act(async()=>root.unmount());host.remove();vi.useRealTimers();vi.clearAllMocks();delete globalThis.IS_REACT_ACT_ENVIRONMENT })
it('loads each source, pauses polling, allows manual refresh and refreshes on resume',async()=>{
  await act(async()=>root.render(<Probe/>))
  expect(apiFetch).toHaveBeenCalledTimes(4)
  expect(value.data.incidents).toEqual([{id:1}])
  expect(value.updatedAt).not.toBeNull()
  await act(async()=>value.togglePaused())
  await act(async()=>vi.advanceTimersByTimeAsync(2*OVERVIEW_REFRESH_MS))
  expect(apiFetch).toHaveBeenCalledTimes(4)
  await act(async()=>value.refresh())
  expect(apiFetch).toHaveBeenCalledTimes(8)
  expect(value.paused).toBe(true)
  await act(async()=>value.togglePaused())
  expect(apiFetch).toHaveBeenCalledTimes(12)
  await act(async()=>vi.advanceTimersByTimeAsync(OVERVIEW_REFRESH_MS))
  expect(apiFetch).toHaveBeenCalledTimes(16)
})
it('clears a failed source instead of presenting stale cached data as current',async()=>{
  await act(async()=>root.render(<Probe/>))
  const firstComplete=value.updatedAt
  apiFetch.mockImplementation(async(url)=>url==='/incidents/?limit=500'?{ok:false,status:403,message:'Denied'}:ok([{id:2}]))
  await act(async()=>value.refresh())
  expect(value.data.incidents).toBeNull()
  expect(value.errors.incidents).toEqual({message:'Denied',status:403})
  expect(value.data.containers).toEqual([{id:2}])
  expect(value.updatedAt).toBe(firstComplete)
})
it('rejects unexpected API payloads instead of treating them as empty measurements',async()=>{
  apiFetch.mockResolvedValue(ok({message:'not a list'}))
  await act(async()=>root.render(<Probe/>))
  expect(value.data.rules).toBeNull()
  expect(Object.keys(value.errors)).toHaveLength(4)
  expect(value.updatedAt).toBeNull()
})
it('prevents overlapping requests and aborts requests on unmount',async()=>{
  let release
  const wait=new Promise(resolve=>{release=resolve})
  apiFetch.mockReturnValue(wait)
  await act(async()=>root.render(<Probe/>))
  await act(async()=>vi.advanceTimersByTimeAsync(OVERVIEW_REFRESH_MS))
  expect(apiFetch).toHaveBeenCalledTimes(4)
  const signal=apiFetch.mock.calls[0][1].signal
  await act(async()=>root.render(null))
  expect(signal.aborted).toBe(true)
  await act(async()=>release(ok()))
})

it('bounds slow requests so one unavailable dependency cannot freeze the entire overview',async()=>{
  apiFetch.mockImplementation((url,{signal})=>url==='/containers/'
    ? new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(new Error('aborted')),{once:true}))
    : Promise.resolve(ok([{id:1}])))
  await act(async()=>root.render(<Probe/>))
  await act(async()=>vi.advanceTimersByTimeAsync(OVERVIEW_REQUEST_TIMEOUT_MS))
  expect(value.loading).toBe(false)
  expect(value.errors.containers.message).toContain('timed out')
  expect(value.data.incidents).toEqual([{id:1}])
})
