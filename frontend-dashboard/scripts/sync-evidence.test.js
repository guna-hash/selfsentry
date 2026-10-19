import {afterEach,expect,it} from 'vitest'
import {mkdtemp,rm} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {resolve} from 'node:path'
import {createHash} from 'node:crypto'
import {buildEvidence,measuredSummary} from './sync-evidence.mjs'
let temp
afterEach(async()=>{if(temp){await rm(temp,{recursive:true,force:true});temp=null}})
it('derives frozen benchmark counts/timing from tracked source bytes and preserves study separation',async()=>{
  const data=await buildEvidence(resolve(process.cwd(),'..'))
  expect(data.benchmark).toMatchObject({attackTrials:100,benignTrials:100,attackIncidents:100,benignIncidents:13,autoConfirmed:5,latency:{median:68.154,p95:68.588,max:69.279,n:100}})
  expect(data.cases).toHaveLength(14);expect(data.mini.valid_captures).toBe(17)
  expect(data.mini.backtests_recomputed.sensitive.verdict).toBe('flag_for_revision')
  for(const source of data.sources)expect(source.sha256).toBe(createHash('sha256').update(source.text).digest('hex'))
})
it('keeps absent files unavailable without importing or fabricating replacement numbers',async()=>{
  temp=await mkdtemp(resolve(tmpdir(),'selfsentry-evidence-'))
  const data=await buildEvidence(temp)
  expect(data.benchmark).toBeNull();expect(data.mini).toBeNull();expect(data.cases).toEqual([])
  expect(data.sources.every(s=>s.missing)).toBe(true)
})
it('rejects unreadable outcome counts instead of displaying a plausible zero',()=>{
  expect(measuredSummary('| Scenario | Labeled trials | Persisted incident | ML | Auto |\n|---|---|---|---|---|\n| Demo | 20 attack | missing | 0 | 0 |')).toBeNull()
})
