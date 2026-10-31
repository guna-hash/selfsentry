// @vitest-environment jsdom
import {act} from 'react'
import {createRoot} from 'react-dom/client'
import {beforeEach,afterEach,expect,it,vi} from 'vitest'
import Evidence,{EvidenceContent,LIMITATION} from './Evidence.jsx'
let root,host
beforeEach(()=>{globalThis.IS_REACT_ACT_ENVIRONMENT=true;host=document.createElement('div');document.body.append(host);root=createRoot(host);history.replaceState({},'','/evidence')})
afterEach(async()=>{await act(async()=>root.unmount());host.remove();vi.restoreAllMocks();delete globalThis.IS_REACT_ACT_ENVIRONMENT;history.replaceState({},'','/')})
it('always states the limitation and shows honest missing-file state',async()=>{
  vi.spyOn(globalThis,'fetch').mockResolvedValue({status:404})
  await act(async()=>root.render(<Evidence/>))
  expect(host.textContent).toContain(LIMITATION);expect(host.textContent).toContain('No evidence snapshot available')
  expect(host.textContent).not.toContain('100 / 100')
})
it('retries a failed static evidence load and escapes source material',async()=>{
  const fetch=vi.spyOn(globalThis,'fetch').mockRejectedValueOnce(new Error('offline')).mockResolvedValue({ok:true,json:async()=>({schema:1,benchmark:null,cases:[],mini:null,sources:[{path:'source.md',text:'<img src=x onerror=bad()>',sha256:'source-hash'}]})})
  await act(async()=>root.render(<Evidence/>));expect(host.textContent).toContain('offline')
  await act(async()=>[...host.querySelectorAll('button')].find(b=>b.textContent.includes('Retry')).click())
  expect(fetch).toHaveBeenCalledTimes(2);expect(host.textContent).toContain('<img src=x onerror=bad()>');expect(host.querySelector('img')).toBeNull()
  expect(host.textContent).toContain('200-trial summary unavailable')
})
it('does not calculate study latency from timezone-naive reviewer timestamps or pool studies',async()=>{
  const mini={study:'separate-study',valid_captures:17,backtests_recomputed:{sensitive:{incident_id:201,pattern:{proc_name:'cat',parent_proc:'sh'},events_tested:36,matched_events:3,false_positive_rate:0.0833,verdict:'flag_for_revision'}},decisions:[],native_refire:{also_detected_by_existing_Falco_rule:true},not_measured:['learning_loop_latency']}
  await act(async()=>root.render(<EvidenceContent snapshot={{benchmark:null,cases:[],mini,sources:[]}}/>))
  expect(host.textContent).toContain('Not submitted (preview only)');expect(host.textContent).toContain('never pooled')
  expect(host.textContent).toContain('not actual failed submission calls')
})
it('shows a malformed-snapshot error instead of crashing the route',async()=>{
  vi.spyOn(globalThis,'fetch').mockResolvedValue({ok:true,json:async()=>({schema:1,cases:[],sources:[],mini:{study:'bad-shape'}})})
  await act(async()=>root.render(<Evidence/>))
  expect(host.textContent).toContain('Unsupported evidence snapshot');expect(host.textContent).toContain(LIMITATION)
})
