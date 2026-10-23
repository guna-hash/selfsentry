// @vitest-environment jsdom
import {act} from 'react'
import {createRoot} from 'react-dom/client'
import {afterEach,beforeEach,expect,it,vi} from 'vitest'
import App from '../App.jsx'
vi.mock('./OverviewCharts.jsx',()=>({default:()=> <section>Learning-loop chart</section>,OpenSparkline:()=>null}))
let root,host,fetch
beforeEach(()=>{
  globalThis.IS_REACT_ACT_ENVIRONMENT=true
  window.matchMedia=()=>({matches:false,addEventListener:()=>{},removeEventListener:()=>{}})
  HTMLDialogElement.prototype.showModal=function(){this.open=true};HTMLDialogElement.prototype.close=function(){this.open=false}
  fetch=vi.spyOn(globalThis,'fetch').mockRejectedValue(new Error('No live fetch permitted in sample integration test'))
  sessionStorage.setItem('selfsentry-api-token','test-live-token');host=document.createElement('div');document.body.append(host);root=createRoot(host)
})
afterEach(async()=>{await act(async()=>root.unmount());host.remove();vi.restoreAllMocks();sessionStorage.clear();history.replaceState({},'','/');delete globalThis.IS_REACT_ACT_ENVIRONMENT})
it.each([
  ['/sample/overview?present=1','Security overview'],['/sample/alerts?incident=9001','Alerts'],
  ['/sample/rules?rule=9102','Rule review'],['/sample/containers','Containers'],['/sample/deployments','Deployments'],
  ['/sample/audit','Audit log'],['/sample/monitor','Monitor'],['/sample/models','Models'],['/sample/evidence','Evidence / evaluation'],
])('renders %s through the real shell and data hooks without live network traffic',async(url,heading)=>{
  history.replaceState({},'',url)
  await act(async()=>root.render(<App/>))
  await vi.waitFor(async () => {
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 10))
    })
    const title = host.querySelector('.page-header h2')
    expect(title, `Missing page heading for ${url}`).not.toBeNull()
    expect(title.textContent.toLowerCase()).toContain(heading.toLowerCase())
  }, {timeout: 3000, interval: 20})
  expect(host.querySelector('[aria-label="Sample data notice"]')).not.toBeNull()
  expect(host.textContent).toContain('no API connection');expect(host.textContent).not.toContain('API connected')
  expect(fetch).not.toHaveBeenCalled()
  if(url.includes('present=1')) {expect(host.querySelector('.sidebar').hidden).toBe(true);expect(host.textContent).toContain('Incident #9001');expect(host.textContent).toContain('Learning-loop chart')}
  if(url.includes('/alerts')) {expect(document.querySelector('dialog')).not.toBeNull();expect([...document.querySelectorAll('dialog button')].find(b=>b.textContent==='Confirm incident')?.disabled).toBe(true)}
  if(url.includes('/rules')) {const approve=[...document.querySelectorAll('dialog button')].find(b=>b.textContent==='Review & approve');expect(approve?.disabled).toBe(true)}
})
