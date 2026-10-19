import { dashboardNow } from '../utils/demoMode.js'
import { useCallback, useEffect, useRef, useState } from 'react'
import { requestJson } from '../utils/requests.js'
import { mergeRuleSources } from '../utils/ruleView.js'

export const RULE_REFRESH_MS=15000
export default function useRules() {
  const [value,setValue]=useState({rules:null,history:null,pending:null,errors:{},loading:true,refreshing:false,updatedAt:null})
  const [paused,setPaused]=useState(false)
  const pauseRef=useRef(false),refreshRef=useRef(null)
  useEffect(()=>{
    let active=true,inFlight=false
    const controller=new AbortController()
    async function refresh(){
      if(!active || inFlight)return
      inFlight=true;setValue(old=>({...old,refreshing:true}))
      const results=await Promise.allSettled(['/rules/history','/rules/pending'].map(async(path)=>{
        const rows=await requestJson(path,{signal:controller.signal})
        if(!Array.isArray(rows) || rows.some(row=>!row || typeof row!=='object' || row.id==null))throw new Error('Unexpected rule response. Expected records with IDs.')
        return rows
      }))
      inFlight=false
      if(!active)return
      const history=results[0].status==='fulfilled'?results[0].value:null
      const pending=results[1].status==='fulfilled'?results[1].value:null
      const errors={}
      if(results[0].status==='rejected')errors.history=results[0].reason
      if(results[1].status==='rejected')errors.pending=results[1].reason
      setValue(old=>({rules:mergeRuleSources(history,pending),history,pending,errors,loading:false,refreshing:false,
        updatedAt:Object.keys(errors).length?old.updatedAt:dashboardNow()}))
    }
    refreshRef.current=refresh;refresh()
    const timer=setInterval(()=>{if(!pauseRef.current)refresh()},RULE_REFRESH_MS)
    return()=>{active=false;controller.abort();clearInterval(timer);refreshRef.current=null}
  },[])
  const refresh=useCallback(()=>refreshRef.current?.(),[])
  const togglePaused=useCallback(()=>{pauseRef.current=!pauseRef.current;setPaused(pauseRef.current);if(!pauseRef.current)refreshRef.current?.()},[])
  return{...value,paused,refresh,togglePaused}
}
