// @vitest-environment jsdom
import {act} from 'react'
import {createRoot} from 'react-dom/client'
import {MemoryRouter,Link,useLocation} from 'react-router-dom'
import {afterEach,beforeEach,expect,it,vi} from 'vitest'
import {PresentationProvider} from '../hooks/usePresentation.jsx'
import DemoControls from './DemoControls.jsx'
import PresentationFocus from './PresentationFocus.jsx'
let root,host
function Location(){return <output>{useLocation().search}</output>}
beforeEach(()=>{globalThis.IS_REACT_ACT_ENVIRONMENT=true;host=document.createElement('div');document.body.append(host);root=createRoot(host)})
afterEach(async()=>{await act(async()=>root.unmount());host.remove();history.replaceState({},'','/');vi.restoreAllMocks();delete globalThis.IS_REACT_ACT_ENVIRONMENT})
it('keeps presentation mode and selected incident in stable URLs across navigation and exit',async()=>{
  await act(async()=>root.render(<MemoryRouter initialEntries={['/overview?present=1']}><PresentationProvider><DemoControls/><Link to="/alerts?incident=9001">Inspect</Link><Location/></PresentationProvider></MemoryRouter>))
  expect(host.querySelector('button').getAttribute('aria-pressed')).toBe('true')
  await act(async()=>[...host.querySelectorAll('a')].find(a=>a.textContent==='Inspect').click())
  expect(host.querySelector('output').textContent).toContain('incident=9001');expect(host.querySelector('output').textContent).toContain('present=1')
  await act(async()=>host.querySelector('button').click());expect(host.querySelector('output').textContent).toBe('?incident=9001')
})
it('marks sample mode prominently and switches via a reload link without carrying record IDs',async()=>{
  history.replaceState({},'','/sample/alerts?incident=9001')
  await act(async()=>root.render(<MemoryRouter><PresentationProvider><DemoControls/></PresentationProvider></MemoryRouter>))
  expect(host.querySelector('[aria-label="Sample data notice"]').textContent).toContain('Synthetic, read-only')
  expect(host.querySelector('a').getAttribute('href')).toBe('/overview')
})
it('keeps the highest-risk unconfirmed incident visible in presentation mode',async()=>{
  const rows=[{id:1,score:100,state:'Human-confirmed'},{id:2,score:80,state:'Unconfirmed',containerName:'worker',layer:'Falco only',falco_alert:{rule:'Shell'}}]
  await act(async()=>root.render(<MemoryRouter initialEntries={['/?present=1']}><PresentationProvider><PresentationFocus rows={rows}/></PresentationProvider></MemoryRouter>))
  expect(host.textContent).toContain('Incident #2');expect(host.textContent).not.toContain('Incident #1')
  expect(host.querySelector('a').getAttribute('href')).toBe('/alerts?incident=2')
})
