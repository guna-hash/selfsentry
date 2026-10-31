import { dashboardNow } from '../utils/demoMode.js'
import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { requestJson } from '../utils/requests.js'
const MonitorContext = createContext(null)
export function MonitorProvider({ children }) {
  const [value,setValue] = useState({ status:null,error:null,errorStatus:null,loading:true,updatedAt:null })
  const [version,setVersion] = useState(0)
  const refresh = useCallback(() => setVersion(v => v + 1), [])
  useEffect(() => {
    let active = true, pending = false
    const controller = new AbortController()
    async function load() {
      if (pending) return
      pending = true
      try {
        const status = await requestJson('/monitor/status',{signal:controller.signal})
        if (active) setValue({status,error:null,errorStatus:null,loading:false,updatedAt:new Date(dashboardNow())})
      } catch (err) {
        if (active) setValue(old => ({...old,error:err.message,errorStatus:err.status,loading:false}))
      } finally { pending = false }
    }
    load(); const timer = setInterval(load,3000)
    return () => {active=false;controller.abort();clearInterval(timer)}
  },[version])
  return <MonitorContext.Provider value={{...value,refresh}}>{children}</MonitorContext.Provider>
}
export const useMonitor = () => useContext(MonitorContext)
// Pause only the page snapshot; global safety status keeps polling.
export function useMonitorSnapshot() {
  const live = useMonitor()
  const [snapshot,setSnapshot] = useState(null)
  const paused = snapshot !== null
  return { ...(snapshot || live), paused, setPaused: value => setSnapshot(value ? live : null),
    refresh: () => {setSnapshot(null);live.refresh()} }
}
