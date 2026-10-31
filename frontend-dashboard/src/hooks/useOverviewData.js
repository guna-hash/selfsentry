import { dashboardNow } from '../utils/demoMode.js'
import { useCallback, useEffect, useRef, useState } from 'react'
import { API, apiFetch, describeFailure } from '../api.js'

export const OVERVIEW_REFRESH_MS = 15000
export const OVERVIEW_REQUEST_TIMEOUT_MS = 10000
const SOURCES = { incidents: '/incidents/?limit=500', containers: '/containers/', rules: '/rules/history', pending: '/rules/pending' }
export default function useOverviewData() {
  const [snapshot, setSnapshot] = useState({
    data: { incidents: null, containers: null, rules: null, pending: null },
    errors: {}, loading: true, refreshing: false, updatedAt: null, asOf: dashboardNow(),
  })
  const [paused, setPaused] = useState(false)
  const pausedRef = useRef(false)
  const refreshRef = useRef(null)
  useEffect(() => {
    let active = true, pending = false
    const controller = new AbortController()
    async function refresh() {
      if (pending || !active) return
      pending = true
      setSnapshot((old) => ({ ...old, refreshing: true }))
      const entries = Object.entries(SOURCES)
      const results = await Promise.allSettled(entries.map(async ([, path]) => {
        const request = new AbortController()
        const abort = () => request.abort()
        controller.signal.addEventListener('abort', abort, { once: true })
        const timeout = setTimeout(abort, OVERVIEW_REQUEST_TIMEOUT_MS)
        try {
          const response = await apiFetch(API + path, { signal: request.signal })
          if (!response.ok) {
            const failure = new Error(await describeFailure(response)); failure.status = response.status; throw failure
          }
          const value = await response.json()
          if (!Array.isArray(value) || value.some((row) => !row || typeof row !== 'object' || row.id == null))
            throw new Error('Unexpected response: expected a list of records with IDs.')
          return value
        } catch (error) {
          if (request.signal.aborted && !controller.signal.aborted) throw new Error('Request timed out after 10 seconds.')
          throw error
        } finally {
          clearTimeout(timeout)
          controller.signal.removeEventListener('abort', abort)
        }
      }))
      pending = false
      if (!active) return
      const data = {}, errors = {}
      results.forEach((result, index) => {
        const [key] = entries[index]
        if (result.status === 'fulfilled') data[key] = result.value
        else { data[key] = null; errors[key] = { message: result.reason?.message || 'Request failed', status: result.reason?.status } }
      })
      const now = dashboardNow()
      // Failed sources become unavailable; cached records are never presented as live measurements.
      setSnapshot((old) => ({ data, errors, loading: false, refreshing: false, asOf: now,
        updatedAt: Object.keys(errors).length ? old.updatedAt : now }))
    }
    refreshRef.current = refresh
    refresh()
    const timer = setInterval(() => { if (!pausedRef.current) refresh() }, OVERVIEW_REFRESH_MS)
    return () => { active = false; refreshRef.current = null; controller.abort(); clearInterval(timer) }
  }, [])
  const refresh = useCallback(() => refreshRef.current?.(), [])
  const togglePaused = useCallback(() => {
    pausedRef.current = !pausedRef.current
    setPaused(pausedRef.current)
    if (!pausedRef.current) refreshRef.current?.()
  }, [])
  return { ...snapshot, paused, togglePaused, refresh }
}
