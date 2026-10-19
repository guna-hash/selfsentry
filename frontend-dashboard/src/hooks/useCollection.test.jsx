// @vitest-environment jsdom
import {act} from 'react'
import {createRoot} from 'react-dom/client'
import {afterEach,beforeEach,expect,it,vi} from 'vitest'
import useCollection from './useCollection.js'
import {requestJson} from '../utils/requests.js'
vi.mock('../utils/requests.js',()=>({requestJson:vi.fn()}))
let root,host,value
function Probe({path='/items'}){value=useCollection(path);return null}
beforeEach(()=>{globalThis.IS_REACT_ACT_ENVIRONMENT=true;vi.useFakeTimers();host=document.createElement('div');root=createRoot(host)})
afterEach(async()=>{await act(async()=>root.unmount());vi.useRealTimers();vi.resetAllMocks();delete globalThis.IS_REACT_ACT_ENVIRONMENT})
it('pauses without discarding snapshot, permits manual refresh and resumes polling',async()=>{
  requestJson.mockResolvedValue([{id:1}]);await act(async()=>root.render(<Probe/>))
  await act(async()=>value.setPaused(true));expect(value.rows).toEqual([{id:1}])
  await act(async()=>vi.advanceTimersByTimeAsync(6000));expect(requestJson).toHaveBeenCalledOnce()
  await act(async()=>value.refresh());expect(requestJson).toHaveBeenCalledTimes(2)
  await act(async()=>value.setPaused(false));await act(async()=>vi.advanceTimersByTimeAsync(3000));expect(requestJson).toHaveBeenCalledTimes(3)
})
it('aborts old scopes and never replaces new data with stale reads',async()=>{
  let resolve;requestJson.mockImplementationOnce(()=>new Promise(r=>{resolve=r})).mockResolvedValue([{id:2}])
  await act(async()=>root.render(<Probe path="/old"/>));const signal=requestJson.mock.calls[0][1].signal
  await act(async()=>root.render(<Probe path="/new"/>));expect(signal.aborted).toBe(true)
  await act(async()=>resolve([{id:1}]));expect(value.rows).toEqual([{id:2}])
})
it('exposes failed reads and malformed responses without inventing a measured count',async()=>{
  requestJson.mockResolvedValue([null]);await act(async()=>root.render(<Probe/>));expect(value.error.message).toContain('Unexpected')
  requestJson.mockRejectedValue(Object.assign(new Error('Denied'),{status:403}));await act(async()=>value.refresh())
  expect(value.error.status).toBe(403);expect(value.updatedAt).toBeNull()
})
