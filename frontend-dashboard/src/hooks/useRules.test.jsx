// @vitest-environment jsdom
import {act} from 'react'
import {createRoot} from 'react-dom/client'
import {beforeEach,afterEach,expect,it,vi} from 'vitest'
import useRules,{RULE_REFRESH_MS} from './useRules.js'
import {requestJson} from '../utils/requests.js'
vi.mock('../utils/requests.js',()=>({requestJson:vi.fn()}))
let root,host,value
function Probe(){value=useRules();return null}
beforeEach(()=>{vi.useFakeTimers();globalThis.IS_REACT_ACT_ENVIRONMENT=true;host=document.createElement('div');document.body.append(host);root=createRoot(host)})
afterEach(async()=>{await act(async()=>root.unmount());host.remove();vi.useRealTimers();vi.resetAllMocks();delete globalThis.IS_REACT_ACT_ENVIRONMENT})
it('merges pending records beyond exposed history and supports pause/manual refresh',async()=>{
  requestJson.mockImplementation(async(path)=>path==='/rules/history'?[{id:3,status:'deployed'}]:[{id:1,status:'approved'}])
  await act(async()=>root.render(<Probe/>))
  expect(value.rules.map(r=>r.id)).toEqual([3,1])
  await act(async()=>value.togglePaused())
  await act(async()=>vi.advanceTimersByTimeAsync(RULE_REFRESH_MS))
  expect(requestJson).toHaveBeenCalledTimes(2)
  await act(async()=>value.refresh())
  expect(requestJson).toHaveBeenCalledTimes(4)
})
it('keeps partial source failures explicit and never converts failed reads into empty history',async()=>{
  requestJson.mockImplementation(async(path)=>{if(path==='/rules/history')throw new Error('History offline');return [{id:1,status:'pending_review'}]})
  await act(async()=>root.render(<Probe/>))
  expect(value.rules).toHaveLength(1);expect(value.history).toBeNull();expect(value.errors.history.message).toBe('History offline')
  requestJson.mockRejectedValue(new Error('Offline'))
  await act(async()=>value.refresh())
  expect(value.rules).toBeNull();expect(value.pending).toBeNull()
})
it('rejects malformed records and aborts outstanding reads on unmount',async()=>{
  requestJson.mockResolvedValue([null])
  await act(async()=>root.render(<Probe/>))
  expect(value.rules).toBeNull()
  const signal=requestJson.mock.calls[0][1].signal
  await act(async()=>root.render(null))
  expect(signal.aborted).toBe(true)
})
