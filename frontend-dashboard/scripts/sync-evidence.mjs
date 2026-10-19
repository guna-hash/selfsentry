import { readFile, mkdir, writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export function markdownTable(text, headerStart) {
  const lines=text.split('\n'), start=lines.findIndex(line=>line.startsWith('| '+headerStart+' |'))
  if(start<0) return []
  const rows=[]
  for(const line of lines.slice(start+2)) {
    if(!line.startsWith('|')) break
    rows.push(line.split('|').slice(1,-1).map(cell=>cell.trim()))
  }
  return rows
}
const number = value => /^\d+$/.test(value) ? Number(value) : null
export function measuredSummary(text) {
  const rows=markdownTable(text,'Scenario').map(([scenario,trials,incidents,ml,confirmed])=>{
    const match=trials?.match(/^(\d+) (attack|benign)$/)
    return {id:scenario,scenario,trials:match?Number(match[1]):null,label:match?.[2] ?? 'Unknown',incidents:number(incidents),ml:ml || 'Not recorded',confirmed:number(confirmed)}
  })
  if(!rows.length || rows.some(r=>r.trials===null || r.incidents===null || r.confirmed===null || r.incidents>r.trials || r.confirmed>r.incidents)) return null
  const total=(kind,key)=>rows.filter(r=>r.label===kind).reduce((sum,r)=>sum+r[key],0)
  const latency=text.match(/median\s+([\d.]+) seconds; nearest-rank p95\s+([\d.]+) seconds; maximum\s+([\d.]+) seconds, n=(\d+)/)
  return {rows,attackTrials:total('attack','trials'),benignTrials:total('benign','trials'),attackIncidents:total('attack','incidents'),benignIncidents:total('benign','incidents'),autoConfirmed:total('attack','confirmed'),
    latency:latency?{median:Number(latency[1]),p95:Number(latency[2]),max:Number(latency[3]),n:Number(latency[4])}:null}
}
export async function buildEvidence(repoRoot) {
  const paths=['docs/monitor_measured_results_20261011.md','docs/academic_case_matrix.md','docs/academic_results_20261015.md','docs/academic_results_20261015.json']
  const sources=await Promise.all(paths.map(async path=>{
    try {const text=await readFile(resolve(repoRoot,path),'utf8');return {path,text,sha256:createHash('sha256').update(text).digest('hex')}}
    catch(error) {if(error.code==='ENOENT')return {path,missing:true};throw error}
  }))
  const [report,matrix,miniReport,miniJson]=sources
  let mini=null, miniError=null
  if(!miniJson.missing) {
    try {const parsed=JSON.parse(miniJson.text);if(!parsed.study || !parsed.backtests_recomputed || !Array.isArray(parsed.decisions))throw new Error('schema');mini=parsed}
    catch {miniError='Study JSON is invalid or has an unsupported schema.'}
  }
  return {schema:1,limitation:'controlled results, not production guarantees, not evidence of coverage beyond Falco.',
    sources,benchmark:report.missing?null:measuredSummary(report.text),
    cases:matrix.missing?[]:markdownTable(matrix.text,'Case').map(([name,expected,evidence,result],id)=>({id,name,expected,evidence,result})),
    mini,miniError,miniReportAvailable:!miniReport.missing}
}
export async function syncEvidence(repoRoot,output) {
  const data=await buildEvidence(repoRoot);await mkdir(dirname(output),{recursive:true});await writeFile(output,JSON.stringify(data,null,2)+'\n');return data
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const dashboard=resolve(dirname(fileURLToPath(import.meta.url)),'..')
  const data=await syncEvidence(resolve(dashboard,'..'),resolve(dashboard,'public/evidence/snapshot.json'))
  console.log(`Evidence snapshot: ${data.sources.filter(s=>!s.missing).length}/${data.sources.length} source files available; no runtime data queried.`)
}
