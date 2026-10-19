// @vitest-environment jsdom
import {act} from 'react'
import {createRoot} from 'react-dom/client'
import {MemoryRouter,useLocation} from 'react-router-dom'
import {beforeEach,afterEach,expect,it,vi} from 'vitest'
import RuleReviewQueue from './RuleReviewQueue.jsx'
import useRules from '../hooks/useRules.js'
vi.mock('../hooks/useRules.js',()=>({default:vi.fn()}))
vi.mock('../components/RuleReviewDialog.jsx',()=>({default:({rule,onClose})=><section aria-label="Selected rule">Rule {rule.id}<button onClick={onClose}>Close selected rule</button></section>}))
let root,host,snapshot
function Location(){return <output aria-label="URL">{useLocation().search}</output>}
beforeEach(()=>{
  globalThis.IS_REACT_ACT_ENVIRONMENT=true;host=document.createElement('div');document.body.append(host);root=createRoot(host)
  snapshot={rules:[{id:1,status:'pending_review',incident_id:9},{id:2,status:'deployed'}],history:[{id:2}],pending:[{id:1}],errors:{},loading:false,refreshing:false,updatedAt:Date.now(),paused:false,refresh:vi.fn(),togglePaused:vi.fn()}
  useRules.mockImplementation(()=>snapshot)
})
afterEach(async()=>{await act(async()=>root.unmount());host.remove();vi.resetAllMocks();delete globalThis.IS_REACT_ACT_ENVIRONMENT})
const render=(url='/rules')=>act(async()=>root.render(<MemoryRouter initialEntries={[url]}><RuleReviewQueue/><Location/></MemoryRouter>))
it('defaults to actionable rules and opens/closes stable review URLs',async()=>{
  await render();expect(host.querySelectorAll('tbody tr')).toHaveLength(1)
  await act(async()=>host.querySelector('[aria-label="View record 1"]').click())
  expect(host.querySelector('[aria-label="URL"]').textContent).toBe('?rule=1')
  await act(async()=>[...host.querySelectorAll('button')].find(b=>b.textContent==='Close selected rule').click())
  expect(host.querySelector('[aria-label="URL"]').textContent).toBe('')
})
it('exposes historical statuses and discloses history limits',async()=>{
  snapshot={...snapshot,history:Array.from({length:100},(_,id)=>({id}))}
  await render()
  await act(async()=>{const select=host.querySelector('#rule-status');select.value='all';select.dispatchEvent(new Event('change',{bubbles:true}))})
  expect(host.querySelectorAll('tbody tr')).toHaveLength(2)
  expect(host.textContent).toContain('latest 100 rules')
})
it('keeps failed source totals unavailable rather than measured zero',async()=>{
  snapshot={...snapshot,rules:null,history:null,pending:null,errors:{pending:Object.assign(new Error('Offline'),{status:500})}}
  await render();expect(host.querySelector('tbody')).toBeNull()
  expect(host.textContent).toContain('Pending queue total unavailable')
})

it('does not claim history is empty when the actionable filter excludes completed records',async()=>{
  snapshot={...snapshot,rules:[{id:2,status:'deployed'}],pending:[]}
  await render()
  expect(host.textContent).toContain('No rules match these filters')
  expect(host.textContent).not.toContain('No candidates recorded')
})

it('separates duplicate rejections with reasons from the actionable queue',async()=>{
  const duplicate={id:3,status:'rejected_duplicate',rejection_reason:'Exact match with existing rule: Administrator Shell'}
  snapshot={...snapshot,rules:[...snapshot.rules,duplicate],history:[duplicate]}
  await render()
  expect(host.querySelectorAll('tbody tr')).toHaveLength(1)
  const section=host.querySelector('[aria-label="Rejected duplicates"]')
  expect(section.textContent).toContain('Administrator Shell')
  expect(section.textContent).toContain('blocked from review and deployment')
  await act(async()=>section.querySelector('button').click())
  expect(host.querySelector('[aria-label="URL"]').textContent).toBe('?rule=3')
})
