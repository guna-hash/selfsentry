// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import Overview from './Overview.jsx'
import useOverviewData from '../hooks/useOverviewData.js'
vi.mock('../hooks/useOverviewData.js',()=>({default:vi.fn()}))
vi.mock('../hooks/useMonitor.jsx',()=>({useMonitor:()=>({status:{running:true,healthy:true,models_ready:1,components:{}},error:null})}))
vi.mock('../components/OverviewCharts.jsx',()=>({default:({stages})=><div aria-label="Learning stages">{stages.map(s=><span key={s.key}>{s.label}: {s.value??'No data'}; </span>)}</div>,OpenSparkline:()=>null}))
const now=Date.parse('2026-10-19T10:00:00Z')
let host,root,snapshot
beforeEach(()=>{
  globalThis.IS_REACT_ACT_ENVIRONMENT=true
  host=document.createElement('div');document.body.append(host);root=createRoot(host)
  snapshot={data:{incidents:[
    {id:1,container_id:'a'.repeat(64),created_at:'2026-10-19T09:00:00Z',risk_score:50,falco_alert:{rule:'Shell'}},
    {id:2,container_id:'b'.repeat(64),created_at:'2026-10-19T09:00:00Z',risk_score:90,anomaly_features:{anomaly_score:.9}},
  ],containers:[{id:'a'.repeat(12),full_id:'a'.repeat(64),name:'nginx',protected:true}],rules:[],pending:[{id:1,status:'pending_review'},{id:2,status:'approved'}]},errors:{},loading:false,refreshing:false,updatedAt:now,asOf:now,paused:false,togglePaused:vi.fn(),refresh:vi.fn()}
  useOverviewData.mockImplementation(()=>snapshot)
})
afterEach(async()=>{await act(async()=>root.unmount());host.remove();vi.clearAllMocks();delete globalThis.IS_REACT_ACT_ENVIRONMENT})
const render=()=>act(async()=>root.render(<MemoryRouter><Overview/></MemoryRouter>))
it('renders all five cards and a risk-sorted table with incident links',async()=>{
  await render()
  expect(host.querySelectorAll('.overview-kpis .metric-card')).toHaveLength(5)
  expect(host.querySelector('[aria-label="Open incidents"] .metric-value').textContent).toBe('2')
  expect(host.querySelector('[aria-label="Pending rule reviews"] .metric-value').textContent).toBe('1')
  expect(host.querySelector('tbody tr a').getAttribute('href')).toBe('/alerts?incident=2')
  expect(host.textContent).toContain('Falco-backed')
  expect(host.textContent).toContain('ML contributed')
})
it('applies container and period filters to incident scope and exposes refresh controls',async()=>{
  await render()
  await act(async()=>{const select=host.querySelector('#overview-container');select.value='a'.repeat(64);select.dispatchEvent(new Event('change',{bubbles:true}))})
  expect(host.querySelectorAll('tbody tr')).toHaveLength(1)
  expect(host.querySelector('[aria-label="Open incidents"] .metric-value').textContent).toBe('1')
  await act(async()=>{const select=host.querySelector('#overview-range');select.value='7d';select.dispatchEvent(new Event('change',{bubbles:true}))})
  expect(host.querySelector('[aria-label="Remove Period: Last 7 days filter"]')).not.toBeNull()
  await act(async()=>host.querySelector('[aria-label="Refresh overview now"]').click())
  expect(snapshot.refresh).toHaveBeenCalledOnce()
  await act(async()=>[...host.querySelectorAll('button')].find(b=>b.textContent==='Pause overview refresh').click())
  expect(snapshot.togglePaused).toHaveBeenCalledOnce()
})
it('shows unavailable rather than zero for failed incident and queue requests',async()=>{
  snapshot={...snapshot,data:{...snapshot.data,incidents:null,pending:null},errors:{incidents:{status:500,message:'Unavailable'},pending:{status:403,message:'Denied'}}}
  await render()
  expect(host.querySelector('[aria-label="Open incidents"] .metric-value').textContent).toBe('—')
  expect(host.querySelector('[aria-label="Pending rule reviews"] .metric-value').textContent).toBe('—')
  expect(host.querySelector('tbody')).toBeNull()
  expect(host.textContent).toContain('Access denied')
})
it('renders initial skeletons and pause notice without making sample measurements',async()=>{
  snapshot={...snapshot,loading:true,paused:true,data:{incidents:null,pending:null,rules:null,containers:null}}
  await render()
  expect(host.querySelector('[aria-label="Loading overview metrics…"]')).not.toBeNull()
  expect(host.textContent).toContain('security monitoring continues')
})
