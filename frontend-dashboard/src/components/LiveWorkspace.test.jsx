// @vitest-environment jsdom
import {act} from 'react'
import {createRoot} from 'react-dom/client'
import {afterEach,beforeEach,expect,it,vi} from 'vitest'
import App from '../App.jsx'
vi.mock('./OverviewCharts.jsx',()=>({default:()=> <section>Learning-loop chart</section>,OpenSparkline:()=>null}))
const loadPage = {
  overview: () => import('../pages/Overview.jsx'), alerts: () => import('../pages/Alerts.jsx'),
  rules: () => import('../pages/RuleReviewQueue.jsx'), containers: () => import('../pages/Containers.jsx'),
  deployments: () => import('../pages/Deployments.jsx'), audit: () => import('../pages/AuditLog.jsx'),
  monitor: () => import('../pages/Monitor.jsx'), models: () => import('../pages/Models.jsx'),
  evidence: () => import('../pages/Evidence.jsx'),
}
let root,host,fetch
beforeEach(()=>{
  globalThis.IS_REACT_ACT_ENVIRONMENT=true
  window.matchMedia=()=>({matches:false,addEventListener:()=>{},removeEventListener:()=>{}})
  fetch=vi.spyOn(globalThis,'fetch').mockImplementation(async url=>{
    const path=new URL(url,window.location.origin).pathname
    const body=path==='/monitor/status' ? {running:true,healthy:true,containers:{tracked:0},configuration:{auto_isolation_enabled:false}}
      : path==='/evidence/snapshot.json' ? {schema:1,sources:[],cases:[],mini:null,benchmark:null} : []
    return new Response(JSON.stringify(body),{status:200})
  })
  sessionStorage.setItem('selfsentry-api-token','test-token')
  host=document.createElement('div');document.body.append(host);root=createRoot(host)
})
afterEach(async()=>{await act(async()=>root.unmount());host.remove();vi.restoreAllMocks();sessionStorage.clear();history.replaceState({},'','/');delete globalThis.IS_REACT_ACT_ENVIRONMENT})
it.each([
  ['/overview?present=1','Security overview'],['/alerts','Alerts'],['/rules','Rule review'],
  ['/containers','Containers'],['/deployments','Deployments'],['/audit','Audit log'],
  ['/monitor','Monitor'],['/models','Models'],['/evidence','Evidence / evaluation'],
])('loads %s through the authenticated shell without fabricated records',async(url,heading)=>{
  history.replaceState({},'',url)
  await act(async()=>root.render(<App/>))
  const page=new URL(url,window.location.origin).pathname.split('/').pop()
  await act(async()=>{await loadPage[page]()})
  await vi.waitFor(()=>{
    const title=host.querySelector('.page-header h2')
    expect(title).not.toBeNull();expect(title.textContent.toLowerCase()).toContain(heading.toLowerCase())
  })
  expect(host.textContent).not.toContain('Open sample data')
  expect(host.textContent).not.toContain('Sample workspace')
  expect(fetch).toHaveBeenCalled()
  for(const [url,options] of fetch.mock.calls) {
    if(String(url).includes(':8000')) expect(options.headers.Authorization).toBe('Bearer test-token')
  }
  expect(host.textContent).toContain('API connected')
  if(url.includes('present=1')) expect(host.querySelector('.sidebar').hidden).toBe(true)
},15000)
it.each(['/sample','/sample/overview','/sample/alerts?incident=9001','/missing'])('refuses retired or unknown address %s without API calls',async url=>{
  history.replaceState({},'',url)
  await act(async()=>root.render(<App/>))
  expect(host.textContent).toContain('Page not found')
  expect(fetch).not.toHaveBeenCalled()
  expect(host.querySelector('a').getAttribute('href')).toBe('/overview')
})
it('shows the backend failure instead of substituting records',async()=>{
  fetch.mockResolvedValue(new Response(JSON.stringify({detail:'Bearer token required'}),{status:401}))
  history.replaceState({},'','/alerts')
  await act(async()=>root.render(<App/>))
  await act(async()=>{await loadPage.alerts()})
  await vi.waitFor(()=>expect(host.textContent).toContain('Authentication required'))
  expect(host.textContent).not.toContain('Sample terminal shell')
  expect(host.querySelector('tbody')).toBeNull()
})
