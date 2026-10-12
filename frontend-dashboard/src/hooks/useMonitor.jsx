import { createContext, useContext, useEffect, useState } from 'react'
import { API, apiFetch, describeFailure } from '../api.js'

const MonitorContext = createContext(null)
export function MonitorProvider({ children }) {
  const [value, setValue] = useState({
    status: null,
    error: null,
    loading: true,
  })
  useEffect(() => {
    let active = true
    let pending = false
    const controller = new AbortController()
    async function refresh() {
      if (pending) return
      pending = true
      try {
        const res = await apiFetch(`${API}/monitor/status`, {
          signal: controller.signal,
        })
        if (!res.ok) throw new Error(await describeFailure(res))
        const status = await res.json()
        if (active) setValue({ status, error: null, loading: false })
      } catch (err) {
        if (active)
          setValue((old) => ({ ...old, error: err.message, loading: false }))
      } finally {
        pending = false
      }
    }
    refresh()
    const timer = setInterval(refresh, 3000)
    return () => {
      active = false
      controller.abort()
      clearInterval(timer)
    }
  }, [])
  return (
    <MonitorContext.Provider value={value}>{children}</MonitorContext.Provider>
  )
}
export const useMonitor = () => useContext(MonitorContext)
