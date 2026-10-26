// @vitest-environment jsdom
import {act} from 'react'
import {createRoot} from 'react-dom/client'
import {MemoryRouter} from 'react-router-dom'
import {beforeEach,afterEach,expect,it,vi} from 'vitest'
import RuleReviewDialog from './RuleReviewDialog.jsx'
import {reviewRule} from '../utils/ruleActions.js'
import {writeTokenAvailable} from '../utils/requests.js'
vi.mock('../utils/ruleActions.js',()=>({reviewRule:vi.fn()}))
vi.mock('../utils/requests.js',()=>({writeTokenAvailable:vi.fn()}))
let root,host,rule,changed,notice,closed
beforeEach(()=>{
  globalThis.IS_REACT_ACT_ENVIRONMENT=true;host=document.createElement('div');document.body.append(host);root=createRoot(host)
  Object.defineProperty(HTMLDialogElement.prototype,'showModal',{configurable:true,value:function(){this.open=true}})
  Object.defineProperty(HTMLDialogElement.prototype,'close',{configurable:true,value:function(){this.open=false}})
  rule={id:3,status:'pending_review',incident_id:9,rule_yaml:'- rule: "<script>bad()</script>"\n  condition: proc.name="sh"',backtested_fp_rate:0,backtest:{events_tested:20,false_positive_rate:0,verdict:'pass'},lifecycle_events:[],native_refires:[]}
  changed=vi.fn();notice=vi.fn();closed=vi.fn();writeTokenAvailable.mockReturnValue(true)
})
afterEach(async()=>{await act(async()=>root.unmount());host.remove();vi.resetAllMocks();delete HTMLDialogElement.prototype.showModal;delete HTMLDialogElement.prototype.close;delete globalThis.IS_REACT_ACT_ENVIRONMENT})
// Rendering and controlled input events are synchronous. Reserve async act for
// interactions that can settle the mocked review request, rather than yielding
// to the scheduler for every keystroke on a resource-constrained test host.
const render=(extra={})=>act(()=>root.render(<MemoryRouter><RuleReviewDialog rule={rule} onClose={closed} onChanged={changed} onNotice={notice} {...extra}/></MemoryRouter>))
const dialog=()=>document.querySelector('dialog')
const button=(name)=>[...dialog().querySelectorAll('button')].find(b=>b.textContent===name)
const click=(target)=>act(async()=>target.click())
function enter(selector,value){act(()=>{const input=dialog().querySelector(selector);Object.getOwnPropertyDescriptor(input.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,'value').set.call(input,value);input.dispatchEvent(new Event('input',{bubbles:true}))})}
it('does not deploy when a review is opened; requires a human name and explicit submit',async()=>{
  reviewRule.mockResolvedValue({rule_id:3,status:'deployed'})
  await render();await click(button('Review & approve'))
  expect(reviewRule).not.toHaveBeenCalled();expect(button('Confirm deployment').disabled).toBe(true)
  await enter('#rule-reviewer','selfsentry-auto');expect(button('Confirm deployment').disabled).toBe(true)
  await enter('#rule-reviewer','guna');await click(button('Confirm deployment'))
  expect(reviewRule).toHaveBeenCalledWith(expect.objectContaining({id:3}),{action:'approve',reviewer:'guna',reason:''})
  expect(dialog().textContent).toContain('backend confirmed deployment')
  expect(changed).toHaveBeenCalledOnce()
})
it('requires a rejection reason and never calls the approve path for rejection',async()=>{
  reviewRule.mockResolvedValue({rule_id:3,status:'rejected'})
  await render();await click(button('Reject'));await enter('#rule-reviewer','guna')
  expect(button('Confirm rejection').disabled).toBe(true)
  await enter('#rule-rejection','Too broad');await click(button('Confirm rejection'))
  expect(reviewRule).toHaveBeenCalledWith(expect.any(Object),{action:'reject',reviewer:'guna',reason:'Too broad'})
})
it('blocks revision approval and missing credentials without bypass forms',async()=>{
  rule={...rule,backtest:{...rule.backtest,verdict:'flag_for_revision'}}
  await render();expect(button('Review & approve').disabled).toBe(true)
  expect(dialog().textContent).toContain('typed reason cannot override')
  writeTokenAvailable.mockReturnValue(false);await render();expect(button('Reject').disabled).toBe(true)
})
it('detects changed material while a confirmation is open',async()=>{
  await render();await click(button('Review & approve'));await enter('#rule-reviewer','guna')
  rule={...rule,rule_yaml:'changed material'};await render()
  expect(button('Confirm deployment').disabled).toBe(true)
  expect(dialog().textContent).toContain('rule changed while this dialog')
  expect(reviewRule).not.toHaveBeenCalled()
})
it('locks duplicate submits and dismissal while busy, and shows failed reload without success',async()=>{
  let reject;reviewRule.mockReturnValue(new Promise((resolve,fail)=>{reject=fail}))
  await render();await click(button('Review & approve'));await enter('#rule-reviewer','guna');await click(button('Confirm deployment'))
  expect(dialog().querySelector('[aria-label="Close details"]').disabled).toBe(true)
  await act(async()=>dialog().dispatchEvent(new Event('cancel',{cancelable:true})))
  expect(closed).not.toHaveBeenCalled();expect(reviewRule).toHaveBeenCalledOnce()
  await act(async()=>reject(Object.assign(new Error('Rule approved but reload failed'),{status:502})))
  expect(dialog().textContent).toContain('reload failed')
  expect(dialog().textContent).not.toContain('backend confirmed deployment')
  expect(changed).toHaveBeenCalledOnce()
})
it('renders escaped YAML, actual history and source-incident link',async()=>{
  rule={...rule,lifecycle_events:[{event_type:'RULE_REJECTED',detail:{reason:'<img src=x>'}}]}
  await render();expect(dialog().querySelector('script')).toBeNull();expect(dialog().querySelector('img')).toBeNull()
  expect(dialog().querySelector('a[href="/alerts?incident=9"]')).not.toBeNull()
  expect(dialog().textContent).toContain('<img src=x>')
})
