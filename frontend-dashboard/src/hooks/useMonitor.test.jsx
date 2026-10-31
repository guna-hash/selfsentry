// @vitest-environment jsdom
import {act} from 'react'
import {createRoot} from 'react-dom/client'
import {afterEach,beforeEach,expect,it,vi} from 'vitest'
import {MonitorProvider,useMonitor,useMonitorSnapshot} from './useMonitor.jsx'
import {requestJson} from '../utils/requests.js'
vi.mock('../utils/requests.js',()=>({requestJson:vi.fn()}))
let root,live,page
function Probe(){live=useMonitor();page=useMonitorSnapshot();return null}
beforeEach(()=>{globalThis.IS_REACT_ACT_ENVIRONMENT=true;vi.useFakeTimers();root=createRoot(document.createElement('div'))})
afterEach(async()=>{await act(async()=>root.unmount());vi.useRealTimers();vi.resetAllMocks();delete globalThis.IS_REACT_ACT_ENVIRONMENT})
it('keeps global safety polling active while page telemetry is paused',async()=>{
  requestJson.mockResolvedValue({running:true});await act(async()=>root.render(<MonitorProvider><Probe/></MonitorProvider>))
  await act(async()=>page.setPaused(true));requestJson.mockResolvedValue({running:false})
  await act(async()=>vi.advanceTimersByTimeAsync(3000))
  expect(live.status.running).toBe(false);expect(page.status.running).toBe(true)
  await act(async()=>page.refresh());expect(page.paused).toBe(false);expect(page.status.running).toBe(false)
})
it('exposes stale cached telemetry with an error instead of claiming current health',async()=>{
  requestJson.mockResolvedValue({running:true});await act(async()=>root.render(<MonitorProvider><Probe/></MonitorProvider>))
  requestJson.mockRejectedValue(new Error('Offline'));await act(async()=>vi.advanceTimersByTimeAsync(3000))
  expect(live.error).toBe('Offline');expect(live.status.running).toBe(true)
})

it('exposes authentication failures and refreshes after session credentials are configured', async () => {
  requestJson.mockRejectedValue(Object.assign(new Error('Bearer token required'),{status:401}))
  await act(async () => root.render(<MonitorProvider><Probe/></MonitorProvider>))
  expect(live.errorStatus).toBe(401)
  expect(live.status).toBeNull()
  requestJson.mockResolvedValue({running:true})
  await act(async () => page.refresh())
  expect(live.errorStatus).toBeNull()
  expect(live.status.running).toBe(true)
})
