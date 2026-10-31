import { useCallback, useEffect, useRef, useState } from 'react'
import { requestJson } from '../utils/requests.js'

export const INCIDENT_REFRESH_MS = 15000
export const INCIDENT_PAGE_SIZE = 200
function records(value) {
  if (!Array.isArray(value) || value.some((row) => !row || typeof row !== 'object' || row.id == null))
    throw new Error('Unexpected incident/inventory response. Expected records with IDs.')
  return value
}
export function useIncidents() {
  const [value, setValue] = useState({ incidents: null, containers: null, error: null, inventoryError: null, loading: true, refreshing: false, updatedAt: null })
  const [cursors, setCursors] = useState([null])
  const beforeId = cursors[cursors.length - 1]
  const [paused, setPaused] = useState(false)
  const pausedRef = useRef(false), refreshRef = useRef(null)
  useEffect(() => {
    let active = true, pending = false
    setValue({ incidents: null, containers: null, error: null, inventoryError: null, loading: true, refreshing: false, updatedAt: null })
    const controller = new AbortController()
    async function refresh() {
      if (!active || pending) return
      pending = true
      setValue((old) => ({ ...old, refreshing: true }))
      const path = `/incidents/?limit=${INCIDENT_PAGE_SIZE}${beforeId ? `&before_id=${beforeId}` : ''}`
      const results = await Promise.allSettled([path, '/containers/'].map(async(path) => records(await requestJson(path, { signal: controller.signal }))))
      pending = false
      if (!active) return
      setValue((old) => ({
        incidents: results[0].status === 'fulfilled' ? results[0].value : null,
        containers: results[1].status === 'fulfilled' ? results[1].value : null,
        error: results[0].status === 'rejected' ? results[0].reason : null,
        inventoryError: results[1].status === 'rejected' ? results[1].reason : null,
        loading: false, refreshing: false,
        updatedAt: results[0].status === 'fulfilled' ? Date.now() : old.updatedAt,
      }))
    }
    refreshRef.current = refresh; refresh()
    const timer = setInterval(() => { if (!pausedRef.current) refresh() }, INCIDENT_REFRESH_MS)
    return () => { active = false; controller.abort(); clearInterval(timer); refreshRef.current = null }
  }, [beforeId])
  const refresh = useCallback(() => refreshRef.current?.(), [])
  const togglePaused = useCallback(() => {
    pausedRef.current = !pausedRef.current; setPaused(pausedRef.current)
    if (!pausedRef.current) refreshRef.current?.()
  }, [])
  const hasOlder = value.incidents?.length === INCIDENT_PAGE_SIZE
  const older = () => {
    if (!hasOlder || value.loading || value.refreshing || value.error) return
    const lastId = Math.min(...value.incidents.map(row => Number(row.id)))
    if (Number.isSafeInteger(lastId) && lastId > 0) setCursors(old => [...old, lastId])
  }
  const newer = () => setCursors(old => old.length > 1 ? old.slice(0, -1) : old)
  const latest = () => setCursors([null])
  return { ...value, paused, refresh, togglePaused, hasOlder, older, newer, latest,
    pageNumber: cursors.length, hasNewer: cursors.length > 1, pageSize: INCIDENT_PAGE_SIZE }
}
export function useIncidentDetail(id, paused = false) {
  const [value, setValue] = useState({ incident: null, loading: true, error: null })
  const [revision, setRevision] = useState(0)
  const pausedRef = useRef(paused)
  pausedRef.current = paused
  useEffect(() => {
    if (!id) return
    let active = true, pending = false
    const controller = new AbortController()
    async function read() {
      if (pending || !active) return
      pending = true
      try {
        const incident = await requestJson(`/incidents/${encodeURIComponent(id)}`, { signal: controller.signal })
        if (!incident || String(incident.id) !== String(id)) throw new Error('The backend returned a different incident. Refresh to retry.')
        if (active) setValue({ incident, error: null, loading: false })
      } catch(error) { if (active) setValue({ incident: null, error, loading: false }) }
      finally { pending = false }
    }
    setValue({ incident: null, loading: true, error: null }); read()
    const timer = setInterval(() => { if (!pausedRef.current) read() }, INCIDENT_REFRESH_MS)
    return () => { active = false; controller.abort(); clearInterval(timer) }
  }, [id, revision])
  const refresh = useCallback(() => setRevision((old) => old + 1), [])
  return { ...value, refresh }
}
