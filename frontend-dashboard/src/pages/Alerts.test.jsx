// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import Alerts from './Alerts.jsx'
import { useIncidents } from '../hooks/useIncidents.js'
vi.mock('../hooks/useIncidents.js',()=>({useIncidents:vi.fn()}))
vi.mock('../components/IncidentDrawer.jsx',()=>({default:({id,onClose})=><section aria-label="Selected incident">Incident {id}<button onClick={onClose}>Close selected</button></section>}))
let root,host,snapshot
function Location(){return <output aria-label="URL">{useLocation().search}</output>}
beforeEach(()=>{
  globalThis.IS_REACT_ACT_ENVIRONMENT=true;host=document.createElement('div');document.body.append(host);root=createRoot(host)
  snapshot={incidents:[{id:1,container_id:'aaa',risk_score:10,created_at:'2026-10-10T10:00:00Z'},{id:2,container_id:'bbb',risk_score:90,created_at:'2026-10-19T09:00:00Z',falco_alert:{rule:'Shell'}}],containers:[],error:null,inventoryError:null,loading:false,refreshing:false,updatedAt:Date.parse('2026-10-19T10:00:00Z'),paused:false,refresh:vi.fn(),togglePaused:vi.fn()}
  useIncidents.mockImplementation(()=>snapshot)
})
afterEach(async()=>{await act(async()=>root.unmount());host.remove();vi.resetAllMocks();delete globalThis.IS_REACT_ACT_ENVIRONMENT})
const render=(url='/alerts')=>act(async()=>root.render(<MemoryRouter initialEntries={[url]}><Alerts/><Location/></MemoryRouter>))
it('renders a risk-first shared table and opens/closes stable incident URLs',async()=>{
  await render()
  expect(host.querySelector('tbody tr').textContent).toContain('#2')
  await act(async()=>host.querySelector('[aria-label="View record 2"]').click())
  expect(host.querySelector('[aria-label="URL"]').textContent).toBe('?incident=2')
  expect(host.querySelector('[aria-label="Selected incident"]').textContent).toContain('Incident 2')
  await act(async()=>[...host.querySelectorAll('button')].find(b=>b.textContent==='Close selected').click())
  expect(host.querySelector('[aria-label="URL"]').textContent).toBe('')
})
it('honors a deep link, scopes by creation period and keeps current record accessible',async()=>{
  await render('/alerts?incident=1')
  await act(async()=>{const select=host.querySelector('#incident-period');select.value='24h';select.dispatchEvent(new Event('change',{bubbles:true}))})
  expect(host.querySelectorAll('tbody tr')).toHaveLength(1)
  expect(host.querySelector('[aria-label="Selected incident"]').textContent).toContain('Incident 1')
})
it('handles invalid incident URLs, backend failures and unavailable inventory explicitly',async()=>{
  snapshot={...snapshot,incidents:null,error:Object.assign(new Error('Offline'),{status:500}),inventoryError:new Error('Docker unavailable')}
  await render('/alerts?incident=bad')
  expect(host.querySelector('tbody')).toBeNull()
  expect(host.textContent).toContain('invalid ID')
  expect(host.textContent).toContain('Container names unavailable')
  expect(host.textContent).toContain('server could not complete')
})

it('labels the bounded history window and exposes older/newer batch navigation', async () => {
  snapshot = {...snapshot, pageNumber:2, pageSize:200, hasOlder:true, hasNewer:true,
    older:vi.fn(), newer:vi.fn(), latest:vi.fn()}
  await render()
  const nav = host.querySelector('[aria-label="Incident history"]')
  expect(nav.textContent).toContain('History batch 2')
  expect(nav.textContent).toContain('filters apply to this batch')
  for (const [text, action] of [['Older batch','older'],['Newer batch','newer'],['Latest incidents','latest']]) {
    await act(async () => [...nav.querySelectorAll('button')].find(b => b.textContent===text).click())
    expect(snapshot[action]).toHaveBeenCalledOnce()
  }
})
