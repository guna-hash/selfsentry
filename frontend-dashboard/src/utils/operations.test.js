import {expect,it,vi} from 'vitest'
import {auditActor,auditInRange,auditVerification,auditExport,csvText,modelLabel,containerAction,operationDate} from './operations.js'
it('finds only recorded actors without inventing a system identity',()=>{
  expect(auditActor({detail:{resumed_by:'Ada'}})).toBe('Ada')
  expect(auditActor({detail:{reason:'auto'}})).toBe('Not recorded')
})
it('filters inclusive UTC dates and excludes missing dates only when scoped',()=>{
  expect(auditInRange({created_at:'2026-10-19T23:59:59'},'2026-10-19','2026-10-19')).toBe(true)
  expect(auditInRange({created_at:'2026-10-20T00:00:00Z'},'','2026-10-19')).toBe(false)
  expect(auditInRange({},'2026-10-19','')).toBe(false)
  expect(auditInRange({},'','')).toBe(true)
  expect(operationDate(null)).toBe('Not recorded')
})
it('escapes CSV quotes, newlines and formula cells including leading whitespace',()=>{
  const csv=csvText([{v:'=CMD()'},{v:'  @formula'},{v:'a,"b"\nc'},{v:'\ttext'}],[{label:'Value',value:r=>r.v}])
  expect(csv).toContain('"\'=CMD()"');expect(csv).toContain('"\'  @formula"')
  expect(csv).toContain('"a,""b""\nc"');expect(csv).toContain('"\'\ttext"')
})
it('keeps unknown models unknown and recognizes intermediate recorded states',()=>{
  expect(modelLabel('MODEL_READY')).toBe('Model ready')
  expect(modelLabel('MODEL_UNAVAILABLE')).toContain('invalid')
  expect(modelLabel('UNRECOGNIZED')).toBe('Unknown')
  expect(modelLabel('NO_BASELINE')).toBe('No baseline')
})
it('distinguishes recorded backend verification from unverified events',()=>{
  expect(auditVerification({source:'backend',event_type:'CONTAINER_RESUMED'})).toContain('verified running')
  expect(auditVerification({source:'backend',event_type:'CONTAINER_RESUME_FAILED'})).toContain('not verified')
  expect(auditVerification({source:'monitor',event_type:'CONTAINER_RESUMED'})).toBe('Verification not recorded')
})
it('blocks protected or unknown protection, missing identity, and resume without isolation',async()=>{
  const request=vi.fn(),token=vi.fn()
  for(const protectedFlag of [true,undefined]) await expect(containerAction({id:'a',protected:protectedFlag},'isolate','Ada','reason',request,token)).rejects.toThrow('unprotected')
  await expect(containerAction({id:'a'},'resume','Ada','',request,token)).rejects.toThrow('active isolation')
  await expect(containerAction({isolated:true},'resume',' ','',request,token)).rejects.toThrow('operator')
  expect(request).not.toHaveBeenCalled()
})
it('blocks actions when the backend cannot validate the recovery record',async()=>{
  const request=vi.fn(),token=vi.fn()
  for (const action of ['isolate','resume']) {
    await expect(containerAction({id:'a',protected:false,isolated:null,containment_state:'record_unavailable'},action,'Ada','reason',request,token)).rejects.toThrow('recovery record')
  }
  expect(request).not.toHaveBeenCalled()
  expect(token).not.toHaveBeenCalled()
})
it('sends one attributed write with encoded full ID and existing token precondition',async()=>{
  const request=vi.fn().mockResolvedValue({networks:['app']}),token=vi.fn()
  await containerAction({id:'short',full_id:'full/id',isolated:true},'resume',' Ada ','',request,token)
  expect(token).toHaveBeenCalledOnce()
  expect(request).toHaveBeenCalledWith('/containers/full%2Fid/resume?resumed_by=Ada&recheck=true',{method:'POST'})
  token.mockImplementation(()=>{throw new Error('Token missing')})
  await expect(containerAction({isolated:true},'resume','Ada','',request,token)).rejects.toThrow('Token missing')
  expect(request).toHaveBeenCalledOnce()
})

it('exports only recorded audit columns with the normal filename and safe CSV escaping', () => {
  const rows=[{actor:'=FORMULA()'}], columns=[{label:'Actor',value:row=>row.actor}]
  const file=auditExport(rows,columns)
  expect(file.filename).toBe('selfsentry-audit.csv')
  expect(file.text).toBe(csvText(rows,columns))
  expect(file.text).not.toContain('Data provenance')
})
