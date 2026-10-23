// @vitest-environment jsdom
import {act} from 'react'
import {createRoot} from 'react-dom/client'
import {MemoryRouter} from 'react-router-dom'
import {afterEach,beforeEach,expect,it,vi} from 'vitest'
import Containers from './Containers.jsx'
import Deployments from './Deployments.jsx'
import AuditLog from './AuditLog.jsx'
import Models from './Models.jsx'
import Monitor from './Monitor.jsx'
import useCollection from '../hooks/useCollection.js'
import {useMonitorSnapshot} from '../hooks/useMonitor.jsx'
import {downloadCsv} from '../utils/operations.js'
vi.mock('../hooks/useCollection.js',()=>({default:vi.fn()}))
vi.mock('../hooks/useMonitor.jsx',()=>({useMonitorSnapshot:vi.fn()}))
vi.mock('../utils/operations.js',async importOriginal=>({...await importOriginal(),downloadCsv:vi.fn()}))
let root,host,collection,telemetry
beforeEach(()=>{
  globalThis.IS_REACT_ACT_ENVIRONMENT=true;host=document.createElement('div');document.body.append(host);root=createRoot(host)
  HTMLDialogElement.prototype.showModal=function(){this.open=true};HTMLDialogElement.prototype.close=function(){this.open=false}
  collection={rows:[],loading:false,error:null,updatedAt:new Date(),paused:false,setPaused:vi.fn(),refresh:vi.fn()}
  telemetry={status:{running:true,healthy:true},loading:false,error:null,updatedAt:new Date(),paused:false,setPaused:vi.fn(),refresh:vi.fn()}
  useCollection.mockImplementation(()=>collection);useMonitorSnapshot.mockImplementation(()=>telemetry)
})
afterEach(async()=>{await act(async()=>root.unmount());host.remove();vi.resetAllMocks();delete globalThis.IS_REACT_ACT_ENVIRONMENT})
const render=(page,url='/')=>act(async()=>root.render(<MemoryRouter initialEntries={[url]}>{page}</MemoryRouter>))
const button=label=>[...document.querySelectorAll('button')].find(b=>b.textContent===label)
async function input(node,value){await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(node,value);node.dispatchEvent(new Event('input',{bubbles:true}))})}
it('renders protected inventory and disables isolation, while exposing evidence history',async()=>{
  collection.rows=[{id:'abc',full_id:'abcdef',name:'<img src=x>',status:'running',protected:true,containment_label:'running'}]
  await render(<Containers/>);expect(host.querySelector('img')).toBeNull()
  await act(async()=>host.querySelector('[aria-label="View record abc"]').click())
  expect(button('Isolate').disabled).toBe(true);expect(button('Resume / restore networks').disabled).toBe(true)
  expect(document.querySelector('dialog a').getAttribute('href')).toContain('legacy_container_id=abc')
})
it('disables both actions when containment recovery state is unavailable',async()=>{
  collection.rows=[{id:'abc',name:'worker',status:'paused',protected:false,isolated:null,containment_state:'record_unavailable',containment_label:'Recovery record unavailable — containment unverified',isolation_error:'Operator repair required'}]
  await render(<Containers/>);await act(async()=>host.querySelector('[aria-label="View record abc"]').click())
  expect(button('Isolate').disabled).toBe(true)
  expect(button('Resume / restore networks').disabled).toBe(true)
  expect(document.querySelector('dialog').textContent).toContain('Operator repair required')
})
it('opens a separate confirmation before any restore action',async()=>{
  collection.rows=[{id:'abc',name:'worker',isolated:true,status:'paused',protected:false}]
  await render(<Containers/>);await act(async()=>host.querySelector('[aria-label="View record abc"]').click())
  await act(async()=>button('Resume / restore networks').click())
  expect(document.querySelector('dialog h2').textContent).toBe('Confirm resume / restore networks')
  expect(button('Confirm restore networks').disabled).toBe(true)
})
it('renders recorded gate, scanner summary and override evidence without zero-filling absent scans',async()=>{
  collection.rows=[{id:1,decision:'overridden',requested_by:'Ada',override_reason:'reviewed locally',scan:{critical:2,high:3,secrets_found:1,misconfigurations_found:4}}]
  await render(<Deployments/>);expect(host.textContent).toContain('overridden');expect(host.textContent).toContain('reviewed locally')
  await act(async()=>host.querySelector('[aria-label="View record 1"]').click())
  expect(document.querySelector('dialog').textContent).toContain('"critical": 2')
})
it('retains server-side exact ID and older cursor queries and exports current selection',async()=>{
  collection.rows=Array.from({length:200},(_,n)=>({id:500-n,event_type:'CONTAINER_RESUMED',source:'backend',detail:{resumed_by:n===0?'Ada':'Bob'}}))
  await render(<AuditLog/>,'/audit?container_id=full&legacy_container_id=short')
  await act(async()=>button('Older records').click())
  expect(useCollection.mock.lastCall[0]).toContain('before_id=301')
  await input(host.querySelector('input[type="number"]'),'829')
  expect(useCollection.mock.lastCall[0]).toContain('event_id=829');expect(useCollection.mock.lastCall[0]).not.toContain('before_id')
  expect(button('Older records').disabled).toBe(true)
  await input(host.querySelector('input[type="search"]'),'Ada')
  await act(async()=>button('Export filtered CSV').click())
  expect(downloadCsv.mock.calls[0][0]).toHaveLength(1)
  expect(host.textContent).toContain('verified running')
  await act(async()=>button('Switch recorded short / full ID').click())
  expect(useCollection.mock.lastCall[0]).toContain('container_id=short')
})
it('keeps unreported models unknown and explains Falco coverage without a valid model',async()=>{
  collection.rows=[{id:'a',name:'api'},{id:'b',name:'worker'}]
  telemetry.status.baselines={a:{state:'MODEL_UNAVAILABLE',samples:9,reason:'invalid baseline'}}
  await render(<Models/>);expect(host.textContent).toContain('Model invalid / unavailable');expect(host.textContent).toContain('Unknown')
  expect(host.textContent).toContain('Falco still produces incidents when ingestion is healthy')
  expect(host.querySelectorAll('tbody tr')).toHaveLength(2)
})
it('warns for non-all rule matching, shows unavailable queues and current service failure',async()=>{
  telemetry.status={running:true,healthy:false,health_reason:'Components require attention: database',control_status_age_seconds:42,rule_matching:'first',components:{database:{state:'unavailable',detail:'offline'}}}
  await render(<Monitor/>);expect(host.textContent).toContain('Degraded');expect(host.textContent).toContain('Rule matching is not')
  expect(host.textContent).toContain('offline');expect(host.textContent).toContain('Not recorded')
  expect(host.textContent).toContain('Components require attention: database')
  expect(host.textContent).toContain('Control cycle age: 42 seconds')
  await input(host.querySelector('#operator-token'),'secret-not-in-notice')
  await act(async()=>button('Save token').click())
  expect(sessionStorage.getItem('selfsentry-api-token')).toBe('secret-not-in-notice')
  expect(host.textContent).not.toContain('secret-not-in-notice');expect(telemetry.refresh).toHaveBeenCalledOnce();sessionStorage.clear()
})
it('renders read failures with retry and no stale table controls',async()=>{
  collection.error=Object.assign(new Error('Backend unavailable'),{status:503})
  await render(<Deployments/>);expect(host.textContent).toContain('Backend unavailable')
  expect(host.querySelector('tbody')).toBeNull()
})
