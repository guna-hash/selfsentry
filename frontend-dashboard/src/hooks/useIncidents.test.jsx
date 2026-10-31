// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { useIncidents, useIncidentDetail, INCIDENT_REFRESH_MS } from './useIncidents.js'
import { requestJson } from '../utils/requests.js'
vi.mock('../utils/requests.js',()=>({requestJson:vi.fn()}))
let root,host,value
function Feed(){value=useIncidents();return null}
function Detail({id}){value=useIncidentDetail(id);return null}
beforeEach(()=>{vi.useFakeTimers();globalThis.IS_REACT_ACT_ENVIRONMENT=true;host=document.createElement('div');document.body.append(host);root=createRoot(host);requestJson.mockResolvedValue([{id:1}])})
afterEach(async()=>{await act(async()=>root.unmount());host.remove();vi.useRealTimers();vi.resetAllMocks();delete globalThis.IS_REACT_ACT_ENVIRONMENT})
it('pauses list polling, allows manual refresh and resumes without pausing security services',async()=>{
  await act(async()=>root.render(<Feed/>))
  expect(requestJson).toHaveBeenCalledTimes(2)
  await act(async()=>value.togglePaused())
  await act(async()=>vi.advanceTimersByTimeAsync(INCIDENT_REFRESH_MS))
  expect(requestJson).toHaveBeenCalledTimes(2)
  await act(async()=>value.refresh())
  expect(requestJson).toHaveBeenCalledTimes(4)
  await act(async()=>value.togglePaused())
  expect(requestJson).toHaveBeenCalledTimes(6)
})
it('keeps incident evidence usable when inventory fails, and clears failed incident reads',async()=>{
  requestJson.mockImplementation(async(path)=>{if(path==='/containers/')throw new Error('Docker unavailable');return [{id:1}]})
  await act(async()=>root.render(<Feed/>))
  expect(value.incidents).toEqual([{id:1}]);expect(value.containers).toBeNull();expect(value.inventoryError.message).toBe('Docker unavailable')
  requestJson.mockRejectedValue(Object.assign(new Error('Denied'),{status:403}))
  await act(async()=>value.refresh())
  expect(value.incidents).toBeNull();expect(value.error.status).toBe(403)
})
it('rejects missing or mismatched detail records and supports explicit retry',async()=>{
  requestJson.mockRejectedValue(Object.assign(new Error('Not found'),{status:404}))
  await act(async()=>root.render(<Detail id="1"/>))
  expect(value.error.status).toBe(404)
  requestJson.mockResolvedValue({id:2})
  await act(async()=>value.refresh())
  expect(value.error.message).toContain('different incident')
  requestJson.mockResolvedValue({id:1})
  await act(async()=>value.refresh())
  expect(value.incident.id).toBe(1)
})
it('aborts an obsolete detail request on navigation and ignores its late completion',async()=>{
  let release
  requestJson.mockReturnValueOnce(new Promise(resolve=>{release=resolve})).mockResolvedValue({id:2})
  await act(async()=>root.render(<Detail id="1"/>))
  const signal=requestJson.mock.calls[0][1].signal
  await act(async()=>root.render(<Detail id="2"/>))
  expect(signal.aborted).toBe(true)
  await act(async()=>release({id:1}))
  expect(value.incident.id).toBe(2)
})

it('browses bounded history with a stable cursor and can return to the latest batch', async () => {
  const first = Array.from({length: 200}, (_, n) => ({id: 600 - n}))
  requestJson.mockImplementation(async path => path.startsWith('/incidents/')
    ? path.includes('before_id=401') ? [{id:400}] : first : [])
  await act(async () => root.render(<Feed/>))
  expect(requestJson.mock.calls[0][0]).toBe('/incidents/?limit=200')
  expect(value.hasOlder).toBe(true)
  await act(async () => value.older())
  expect(value.pageNumber).toBe(2)
  expect(value.incidents).toEqual([{id:400}])
  expect(value.hasOlder).toBe(false)
  expect(requestJson.mock.calls.some(([path]) => path === '/incidents/?limit=200&before_id=401')).toBe(true)
  await act(async () => value.newer())
  expect(value.pageNumber).toBe(1)
  expect(value.incidents).toEqual(first)
  await act(async () => value.older())
  await act(async () => value.latest())
  expect(value.hasNewer).toBe(false)
})
it('blocks history navigation during an in-flight refresh', async () => {
  const first = Array.from({length:200}, (_, n) => ({id:600 - n}))
  requestJson.mockImplementation(async path => path.startsWith('/incidents/') ? first : [])
  await act(async () => root.render(<Feed/>))
  let release
  requestJson.mockImplementation(path => path.includes('before_id=401')
    ? Promise.resolve([{id:400}]) : path.startsWith('/incidents/')
      ? new Promise(resolve => {release=resolve}) : Promise.resolve([]))
  await act(async () => {value.refresh()})
  // Navigation is blocked while the current refresh is in flight.
  await act(async () => value.older())
  expect(value.pageNumber).toBe(1)
  await act(async () => release(first))
  await act(async () => value.older())
  expect(value.incidents).toEqual([{id:400}])
})
