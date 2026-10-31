import { useCallback, useEffect, useRef, useState } from 'react'
import { requestJson } from '../utils/requests.js'

// Polls one bounded API window. Aborts stale requests when the scope changes.
export default function useCollection(path) {
  const [state, setState] = useState({ rows: [], loading: true, error: null, updatedAt: null })
  const [paused, setPaused] = useState(false)
  const pause = useRef(paused)
  pause.current = paused
  const [version, setVersion] = useState(0)
  const refresh = useCallback(() => setVersion(v => v + 1), [])
  useEffect(() => {
    let active = true, pending = false
    const controller = new AbortController()
    setState({ rows: [], loading: true, error: null, updatedAt: null })
    async function load() {
      if (pending) return
      pending = true
      try {
        const rows = await requestJson(path, { signal: controller.signal })
        if (!Array.isArray(rows) || rows.some(row => !row || typeof row !== 'object')) throw new Error('Unexpected collection response.')
        if (active) setState({ rows, loading: false, error: null, updatedAt: new Date(Date.now()) })
      } catch (error) {
        if (active) setState(old => ({ ...old, loading: false, error }))
      } finally { pending = false }
    }
    load()
    const timer = setInterval(() => { if (!pause.current) load() }, 3000)
    return () => { active = false; controller.abort(); clearInterval(timer) }
  }, [path, version])
  return { ...state, paused, setPaused, refresh }
}
