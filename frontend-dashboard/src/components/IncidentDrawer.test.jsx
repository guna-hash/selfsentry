// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, afterEach, expect, it, vi } from 'vitest'
import IncidentDrawer from './IncidentDrawer.jsx'
import { useIncidentDetail } from '../hooks/useIncidents.js'
import { confirmIncident, createCandidate } from '../utils/incidentActions.js'
import { writeTokenAvailable } from '../utils/requests.js'
vi.mock('../hooks/useIncidents.js',()=>({useIncidentDetail:vi.fn()}))
vi.mock('../utils/incidentActions.js',()=>({confirmIncident:vi.fn(),createCandidate:vi.fn()}))
vi.mock('../utils/requests.js',()=>({writeTokenAvailable:vi.fn()}))
let root,host,detail,changed,notice,closed
const incident={id:1,container_id:'abcdef123456',risk_score:0,falco_alert:{rule:'Shell',priority:'NOTICE'},monitor_evidence:{cross_layer_agreement:false,anomaly_status:'unavailable',observed_timeline:[{step:9,timestamp:'2026-10-19T09:00:00Z',source:'falco',description:'first stored',output:'<img src=x onerror=bad()>'},{step:2,description:'second stored'}]}}
beforeEach(()=>{
  globalThis.IS_REACT_ACT_ENVIRONMENT=true;host=document.createElement('div');document.body.append(host);root=createRoot(host)
  Object.defineProperty(HTMLDialogElement.prototype,'showModal',{configurable:true,value:function(){this.open=true}})
  Object.defineProperty(HTMLDialogElement.prototype,'close',{configurable:true,value:function(){this.open=false}})
  detail={incident,loading:false,error:null,refresh:vi.fn()};useIncidentDetail.mockImplementation(()=>detail);writeTokenAvailable.mockReturnValue(true)
  changed=vi.fn();notice=vi.fn();closed=vi.fn()
})
afterEach(async()=>{await act(async()=>root.unmount());host.remove();vi.resetAllMocks();delete HTMLDialogElement.prototype.showModal;delete HTMLDialogElement.prototype.close;delete globalThis.IS_REACT_ACT_ENVIRONMENT})
const render=()=>act(async()=>root.render(<MemoryRouter><IncidentDrawer id="1" onClose={closed} onChanged={changed} onNotice={notice}/></MemoryRouter>))
const dialog=()=>document.querySelector('dialog')
const button=(text)=>[...dialog().querySelectorAll('button')].find(b=>b.textContent===text)
async function enter(selector,text){await act(async()=>{const input=dialog().querySelector(selector);Object.getOwnPropertyDescriptor(input.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,'value').set.call(input,text);input.dispatchEvent(new Event('input',{bubbles:true}))})}
const click=(element)=>act(async()=>element.click())
it('shows recorded zero and false values, preserves timeline order and escapes evidence',async()=>{
  detail={...detail,incident:{...incident,monitor_evidence:{...incident.monitor_evidence,observed_timeline:[...incident.monitor_evidence.observed_timeline,null]}}}
  await render()
  const items=[...dialog().querySelectorAll('.observed-timeline li')]
  expect(items[0].textContent).toContain('Step 9');expect(items[1].textContent).toContain('Step 2');expect(items[2].textContent).toContain('Recorded entry: Not recorded')
  expect(dialog().querySelector('img')).toBeNull()
  expect(dialog().textContent).toContain('<img src=x onerror=bad()>')
  expect(dialog().querySelector('[aria-label="Risk breakdown"]').textContent).toContain('0 / 100')
  expect(dialog().querySelector('[aria-label="Risk breakdown"]').textContent).toContain('No')
  expect(dialog().textContent).toContain('Advisory');expect(dialog().textContent).toContain('AI explanation unavailable')
  expect(dialog().textContent).toContain('Falco alerts still produce incidents')
})
it('requires a human name, prevents repeated confirmation and blocks closing while in flight',async()=>{
  let resolve;confirmIncident.mockReturnValue(new Promise(done=>{resolve=done}))
  await render();await click(button('Confirm incident'))
  expect(button('Record confirmation').disabled).toBe(true)
  await enter('#incident-operator','guna')
  await click(button('Record confirmation'))
  expect(confirmIncident).toHaveBeenCalledWith(1,'guna')
  expect(dialog().querySelector('[aria-label="Close details"]').disabled).toBe(true)
  await act(async()=>dialog().dispatchEvent(new Event('cancel',{cancelable:true})))
  expect(closed).not.toHaveBeenCalled()
  await act(async()=>resolve({status:'confirmed',confirmed_by:'guna',confirmed_incident_id:8}))
  expect(changed).toHaveBeenCalledOnce();expect(detail.refresh).toHaveBeenCalledOnce()
})
it('disables writes without credentials and requires confirmation before a candidate',async()=>{
  writeTokenAvailable.mockReturnValue(false);await render()
  expect(button('Confirm incident').disabled).toBe(true)
  expect(button('Create candidate').disabled).toBe(true)
  expect(dialog().textContent).toContain('Operator token missing')
  writeTokenAvailable.mockReturnValue(true);await render()
  expect(button('Create candidate').disabled).toBe(true)
})
it('accepts explicitly entered candidate material and a measured zero rate without approving',async()=>{
  detail={...detail,incident:{...incident,confirmation:{confirmed_by:'selfsentry-auto',confirmed_at:'2026-10-19T09:00:00Z'}}}
  createCandidate.mockResolvedValue({id:8,status:'pending_review'})
  await render();expect(dialog().textContent).toContain('Auto-confirmed')
  await click(button('Create candidate'))
  expect(dialog().querySelector('#candidate-fp').value).toBe('')
  await enter('#incident-operator','guna');await enter('#candidate-yaml','- rule: generated');await enter('#candidate-fp','0')
  await click(button('Submit for human review'))
  expect(createCandidate).toHaveBeenCalledWith(detail.incident,{actor:'guna',yaml:'- rule: generated',fpPercent:'0'})
  expect(dialog().textContent).toContain('queued for human review')
})
it('shows a specific detail error and a retry without inventing evidence',async()=>{
  detail={...detail,incident:null,error:Object.assign(new Error('Gone'),{status:404})}
  await render();expect(dialog().textContent).toContain('no longer available')
  await click(button('Retry'));expect(detail.refresh).toHaveBeenCalledOnce()
})
it('keeps action errors visible and does not turn backend failures into success',async()=>{
  confirmIncident.mockRejectedValue(Object.assign(new Error('Write forbidden'),{status:403}))
  await render();await click(button('Confirm incident'));await enter('#incident-operator','guna');await click(button('Record confirmation'))
  expect(dialog().textContent).toContain('Access denied');expect(dialog().textContent).toContain('Write forbidden')
  expect(changed).not.toHaveBeenCalled();expect(notice).not.toHaveBeenCalled()
})
