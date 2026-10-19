// @vitest-environment jsdom
import {act} from 'react'
import {createRoot} from 'react-dom/client'
import {afterEach,beforeEach,expect,it,vi} from 'vitest'
import ContainerActionDialog from './ContainerActionDialog.jsx'
import {requestJson,requireWriteToken} from '../utils/requests.js'
vi.mock('../utils/requests.js',()=>({requestJson:vi.fn(),requireWriteToken:vi.fn()}))
let root,host,onComplete,onClose
beforeEach(()=>{
  globalThis.IS_REACT_ACT_ENVIRONMENT=true;host=document.createElement('div');document.body.append(host);root=createRoot(host);onComplete=vi.fn();onClose=vi.fn()
  HTMLDialogElement.prototype.showModal=function(){this.open=true};HTMLDialogElement.prototype.close=function(){this.open=false}
})
afterEach(async()=>{await act(async()=>root.unmount());host.remove();vi.resetAllMocks();delete globalThis.IS_REACT_ACT_ENVIRONMENT})
async function setup(){await act(async()=>root.render(<ContainerActionDialog container={{id:'a',isolated:true}} action="resume" onComplete={onComplete} onClose={onClose}/>))}
async function actor(){const input=document.querySelector('dialog input');await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,'Ada');input.dispatchEvent(new Event('input',{bubbles:true}))})}
const submit=()=>act(async()=>document.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})))
it('requires identity and prevents duplicate in-flight and completed submissions',async()=>{
  let finish;requestJson.mockImplementation(()=>new Promise(resolve=>{finish=resolve}))
  await setup();expect(document.querySelector('form button').disabled).toBe(true);expect(requestJson).not.toHaveBeenCalled()
  await actor();await act(async()=>{const form=document.querySelector('form');form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))});expect(requestJson).toHaveBeenCalledOnce();expect(document.querySelector('[aria-label="Close details"]').disabled).toBe(true)
  await act(async()=>finish({container_id:'a',networks:['app'],policy_recheck:{status:'allowed'}}))
  expect(document.querySelector('dialog').textContent).toContain('Backend verified running')
  expect(document.querySelector('dialog').textContent).toContain('policy_recheck')
  await submit();expect(requestJson).toHaveBeenCalledOnce();expect(onComplete).toHaveBeenCalledOnce()
})
it('does not retry uncertain writes and directs the operator to refresh evidence',async()=>{
  requestJson.mockRejectedValue(Object.assign(new Error('Outcome unknown; refresh recorded state'),{uncertain:true}))
  await setup();await actor();await submit();await submit()
  expect(requestJson).toHaveBeenCalledOnce();expect(document.querySelector('[role="alert"]').textContent).toContain('Outcome unknown')
  expect(document.querySelector('form button').disabled).toBe(true);expect(onComplete).toHaveBeenCalledOnce()
})
it('surfaces token failure without sending a write',async()=>{
  requireWriteToken.mockImplementation(()=>{throw new Error('Operator token missing')})
  await setup();await actor();await submit();expect(requestJson).not.toHaveBeenCalled()
  expect(document.querySelector('[role="alert"]').textContent).toContain('Operator token missing')
})
