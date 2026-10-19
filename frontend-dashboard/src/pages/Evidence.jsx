import { useEffect, useState } from 'react'
import { DataTable, EmptyState, ErrorState, KpiCard, PageHeader, Skeleton, StatusBadge } from '../components/ui.jsx'
import { isSampleMode } from '../utils/demoMode.js'
import { formatNumber } from '../utils/format.js'
import './evidence.css'
export const LIMITATION='controlled results, not production guarantees, not evidence of coverage beyond Falco.'
const numeric=(v)=>typeof v==='number'?formatNumber(v):'Not recorded'
const comparison='Frozen study; historical comparison unavailable'
export function EvidenceContent({snapshot}) {
  const {benchmark,cases,mini,sources}=snapshot
  const miniRows=mini?Object.entries(mini.backtests_recomputed).map(([id,item])=>({id,...item,decision:mini.decisions.find(d=>d.incident_id===item.incident_id)?.status || 'Not submitted (preview only)'})):[]
  return <>
    <section aria-labelledby="benchmark-title"><h3 id="benchmark-title">11 October · frozen pipeline evaluation</h3>
      <p>Historical report; these are controlled scenario labels. This view does not rerun trials or query current incidents.</p>
      {!benchmark?<EmptyState title="200-trial summary unavailable">The source report is missing or its table could not be read. No replacement figures are supplied.</EmptyState>:<>
        <div className="metrics-grid">
          <KpiCard label="Attack trials with incidents" value={`${numeric(benchmark.attackIncidents)} / ${numeric(benchmark.attackTrials)}`} comparisonLabel={comparison}/>
          <KpiCard label="Benign trials with incidents" value={`${numeric(benchmark.benignIncidents)} / ${numeric(benchmark.benignTrials)}`} comparisonLabel={comparison}/>
          <KpiCard label="Auto-confirmed attack trials" value={`${numeric(benchmark.autoConfirmed)} / ${numeric(benchmark.attackTrials)}`} comparisonLabel={comparison}/>
          <KpiCard label="Median start-to-row timestamp" value={benchmark.latency?`${benchmark.latency.median.toFixed(3)} s`:'Unavailable'} comparisonLabel={comparison} detail={benchmark.latency?`p95 ${benchmark.latency.p95.toFixed(3)} s · max ${benchmark.latency.max.toFixed(3)} s · n=${benchmark.latency.n}`:'Timing not recorded'}/>
        </div>
        <p className="evidence-warning">Timing ends at the database row timestamp, not verified commit or dashboard visibility. Naive row times were interpreted as Asia/Kolkata in the original analysis. Layer, response and learning latencies remain unmeasured.</p>
        <DataTable rows={benchmark.rows} caption="Controlled trial outcomes" columns={[
          {key:'scenario',label:'Scenario'}, {key:'label',label:'Trial label',filterOptions:[{value:'attack',label:'attack'},{value:'benign',label:'benign'}]},
          {key:'trials',label:'Trials'},{key:'incidents',label:'Incident trials'},{key:'ml',label:'Qualifying ML evidence (source wording)'},{key:'confirmed',label:'Auto-confirmed'},
        ]}/>
        <p>All attack incidents had Falco alerts. The retained comparison is a retrospective replay from one pipeline execution, not independent live ablations. Quiet windows were not scored by ML. Benign detections remain false positives under the supplied labels.</p>
      </>}
    </section>
    <section><h3>15 October · supervised rule-loop mini-study</h3><p>Separate dataset; never pooled with the 200-trial benchmark. Offline audit of operator-supplied artifacts, not independent VM execution.</p>
      {!mini?<EmptyState title="Mini-study unavailable">{snapshot.miniError || 'The recorded study file is missing.'}</EmptyState>:<>
        <p>Study: {mini.study} · Valid captures: {numeric(mini.valid_captures)} · Source tree: {mini.source_working_tree_dirty?'dirty as recorded':'see source evidence'}.</p>
        <DataTable rows={miniRows} caption="Mini-study pattern previews" columns={[
          {key:'id',label:'Case'},{key:'incident_id',label:'Historical incident'},
          {key:'pattern',label:'Process / parent',accessor:r=>`${r.pattern?.proc_name ?? 'Not recorded'} / ${r.pattern?.parent_proc ?? 'Not recorded'}`},
          {key:'matched_events',label:'Corpus matches'},{key:'events_tested',label:'Eligible events'},
          {key:'false_positive_rate',label:'Event match rate',render:v=>formatNumber(v,{style:'percent',maximumFractionDigits:2})},
          {key:'verdict',label:'Preview verdict',render:v=><StatusBadge tone={v==='pass'?'low':'medium'}>{v}</StatusBadge>},{key:'decision',label:'Recorded workflow'},
        ]}/>
        <DataTable rows={mini.decisions.map(r=>({...r,id:r.rule_id}))} caption="Historical human decisions" columns={[
          {key:'rule_id',label:'Rule'},{key:'incident_id',label:'Source incident'},{key:'status',label:'Recorded decision',render:v=><StatusBadge status={v}/>},
          {key:'reviewed_by',label:'Reviewer'},{key:'reviewed_at',label:'Recorded time (timezone not encoded)'},
        ]}/>
        <p>Recorded native re-fire: {mini.native_refire?.rule || 'Not recorded'} · incident {mini.native_refire?.incident_id ?? 'Not recorded'} · {mini.native_refire?.timestamp || 'Not recorded'}. Existing Falco detection: {mini.native_refire?.also_detected_by_existing_Falco_rule===true?'also present':'not established'}.</p>
        <p>Rejected rule {mini.rejection_control?.rule_id ?? 'not recorded'} absent from rule file: {mini.rejection_control?.rejected_rule_absent===true?'recorded yes':'not established'}. Later benign windows: {numeric(mini.holdout?.valid_windows)}, generated-rule hits: {numeric(mini.holdout?.generated_rule_hits)}, incident windows: {numeric(mini.holdout?.incident_windows)}.</p>
        <p>Preview match rates describe the retained benign corpus, not production FPR. A passing preview does not prove safe deployment. Revision previews were not actual failed submission calls. No added attack coverage was demonstrated.</p>
        <p>Not measured: {(mini.not_measured || []).join(', ') || 'See source report'}.</p>
      </>}
    </section>
    <section><h3>Designed-case evidence matrix</h3><p>Historical status wording is preserved, including PASS-E, PASS-H, TEST and RE-RUN. It is not a current release test report. Earlier unsupported-feature statements describe that snapshot.</p>
      <DataTable rows={cases || []} caption="Designed cases" columns={[{key:'name',label:'Case'},{key:'expected',label:'Expected behavior'},{key:'evidence',label:'Evidence / next artifact'},{key:'result',label:'Recorded status'}]}/>
    </section>
    <section><h3>Source provenance</h3><p>Build-time copies of tracked reports. SHA-256 identifies source bytes; it does not independently authenticate the experiment. Source material is displayed as escaped text.</p>
      {sources.map(source=><details className="evidence-source" key={source.path}><summary>{source.path}{source.missing?' · unavailable':''}</summary>{!source.missing&&<><p>SHA-256: <code>{source.sha256}</code></p><pre>{source.text}</pre></>}</details>)}
    </section>
  </>
}
export default function Evidence() {
  const sample=isSampleMode(), [value,setValue]=useState({loading:true,error:null,snapshot:null}), [revision,setRevision]=useState(0)
  useEffect(()=>{
    if(sample)return
    const controller=new AbortController();let active=true
    setValue({loading:true,error:null,snapshot:null})
    const timer=setTimeout(()=>controller.abort(),10000)
    fetch(`${import.meta.env.BASE_URL}evidence/snapshot.json`,{signal:controller.signal,cache:'no-cache'}).then(async response=>{
      if(response.status===404)return null
      if(!response.ok)throw new Error(`Evidence snapshot request failed (HTTP ${response.status}).`)
      const data=await response.json()
      if(!data || data.schema!==1 || !Array.isArray(data.sources) || data.sources.some(s=>!s || typeof s.path!=='string') || !Array.isArray(data.cases) || data.cases.some(r=>!r || typeof r!=='object') || (data.benchmark && !Array.isArray(data.benchmark.rows)) || (data.mini && (!data.mini.backtests_recomputed || typeof data.mini.backtests_recomputed!=='object' || !Array.isArray(data.mini.decisions))))throw new Error('Unsupported evidence snapshot. Regenerate it with npm run evidence:sync.')
      return data
    }).then(snapshot=>{if(active)setValue({loading:false,error:null,snapshot})}).catch(error=>{if(active)setValue({loading:false,error:error.name==='AbortError'?'Evidence request timed out. Retry to load the snapshot.':error.message,snapshot:null})}).finally(()=>clearTimeout(timer))
    return()=>{active=false;controller.abort();clearTimeout(timer)}
  },[sample,revision])
  return <div className="evidence-page"><PageHeader title="Evidence / evaluation">Read-only historical results for the academic defense.</PageHeader>
    <p className="evidence-limitation" role="note">{LIMITATION}</p>
    {sample?<EmptyState title="Evaluation evidence is hidden in sample mode">Exit sample mode to inspect the recorded historical studies. Synthetic UI records are never used as evaluation results.</EmptyState>:value.loading?<Skeleton label="Loading recorded evidence…"/>:value.error?<ErrorState error={value.error} onRetry={()=>setRevision(v=>v+1)}/>:!value.snapshot?<EmptyState title="No evidence snapshot available">Run npm run evidence:sync or restore the source documents. Missing files do not produce invented numbers.</EmptyState>:<EvidenceContent snapshot={value.snapshot}/>}
  </div>
}
