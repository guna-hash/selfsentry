// @vitest-environment jsdom
import {afterEach,expect,it,vi} from 'vitest'
import {dashboardNow,isSampleMode,SAMPLE_TIME,switchModeUrl} from './demoMode.js'
import {apiFetch,API} from '../api.js'
import {requestJson,requireWriteToken,writeTokenAvailable} from './requests.js'
import {sampleResult} from '../data/sampleData.js'
afterEach(()=>{history.replaceState({},'','/');sessionStorage.clear();vi.restoreAllMocks()})
it('recognizes only the separate sample URL space and fixes its clock',()=>{
  expect(isSampleMode('/sampleevil')).toBe(false);expect(isSampleMode('/alerts?sample=1')).toBe(false)
  history.replaceState({},'','/sample/overview');expect(dashboardNow()).toBe(Date.parse(SAMPLE_TIME))
  expect(switchModeUrl(false,true)).toBe('/overview?present=1')
  expect(switchModeUrl(true)).toBe('/sample/overview')
})
it('serves all dashboard reads locally without fetching or reading a saved token',async()=>{
  history.replaceState({},'','/sample/overview');sessionStorage.setItem('selfsentry-api-token','test-live-token')
  const fetch=vi.spyOn(globalThis,'fetch'),read=vi.spyOn(Storage.prototype,'getItem')
  for(const path of ['/monitor/status','/containers/','/incidents/','/incidents/9001','/rules/history','/rules/pending','/deployments/?limit=500','/audit/?limit=200']){
    const response=await apiFetch(API.replace(/\/$/,'')+path);expect(response.ok).toBe(true);expect(await response.json()).toBeTruthy()
  }
  expect(fetch).not.toHaveBeenCalled();expect(read).not.toHaveBeenCalled()
})
it('blocks every write method at both request boundaries even with a live token',async()=>{
  history.replaceState({},'','/sample/rules');sessionStorage.setItem('selfsentry-api-token','test-live-token')
  const fetch=vi.spyOn(globalThis,'fetch');expect(writeTokenAvailable()).toBe(false);expect(requireWriteToken).toThrow('Sample data mode is read-only')
  for(const method of ['POST','PUT','PATCH','DELETE']){
    await expect(requestJson('/rules/9102/approve',{method})).rejects.toMatchObject({status:403})
    expect((await apiFetch(API+'/rules/9102/approve',{method})).status).toBe(403)
  }
  expect(fetch).not.toHaveBeenCalled()
})
it('never falls back for an unsupported endpoint or missing sample incident',async()=>{
  history.replaceState({},'','/sample/alerts');const fetch=vi.spyOn(globalThis,'fetch')
  expect((await apiFetch(API+'/incidents/123')).status).toBe(404)
  expect((await apiFetch(API+'/not-a-fixture')).status).toBe(404)
  expect((await apiFetch('https://unrelated.invalid/incidents/')).status).toBe(404)
  expect(fetch).not.toHaveBeenCalled()
})
it('returns fresh fixture copies and applies exact audit scopes',()=>{
  sampleResult('/incidents/9001').body.risk_score=0
  expect(sampleResult('/incidents/9001').body.risk_score).toBe(95)
  expect(sampleResult('/audit/?event_id=99').body).toEqual([])
  expect(sampleResult('/audit/?before_id=9401').body).toEqual([])
})
it('continues normal live reads and authorization outside sample mode',async()=>{
  history.replaceState({},'','/overview');sessionStorage.setItem('selfsentry-api-token','test-live-token')
  const fetch=vi.spyOn(globalThis,'fetch').mockResolvedValue({ok:true})
  await apiFetch(API+'/monitor/status')
  expect(fetch).toHaveBeenCalledOnce();expect(fetch.mock.calls[0][1].headers.Authorization).toBe('Bearer test-live-token')
})
it('labels exported sample CSV outside the UI and leaves live exports unchanged',async()=>{
  const {auditExport}=await import('./operations.js')
  const rows=[{id:1}],columns=[{label:'ID',value:r=>r.id}]
  history.replaceState({},'','/sample/audit')
  const sample=auditExport(rows,columns)
  expect(sample.filename).toBe('selfsentry-sample-audit.csv')
  expect(sample.text).toContain('Synthetic sample data; not evaluation evidence')
  history.replaceState({},'','/audit')
  const live=auditExport(rows,columns)
  expect(live.filename).toBe('selfsentry-audit.csv');expect(live.text).not.toContain('Synthetic sample data')
})
