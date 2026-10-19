import { useEffect, useState } from 'react'

export const THEME_KEY = 'selfsentry-theme'
export function readThemePreference() {
  try {
    const value = localStorage.getItem(THEME_KEY)
    return ['light', 'dark'].includes(value) ? value : null
  } catch { return null }
}
export function systemTheme() {
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}
export function applyTheme(theme) {
  document.documentElement.dataset.theme = theme
}
export function initializeTheme() {
  applyTheme(readThemePreference() || systemTheme())
}
export function useTheme() {
  const [preference, setPreference] = useState(readThemePreference)
  const [system, setSystem] = useState(systemTheme)
  const theme = preference || system
  useEffect(() => {
    const media = window.matchMedia?.('(prefers-color-scheme: dark)')
    const update = () => setSystem(systemTheme())
    const sync = (event) => {
      if (event.key === THEME_KEY || event.key === null) setPreference(readThemePreference())
    }
    update()
    media?.addEventListener('change', update)
    window.addEventListener('storage', sync)
    return () => {
      media?.removeEventListener('change', update)
      window.removeEventListener('storage', sync)
    }
  }, [])
  useEffect(() => applyTheme(theme), [theme])
  function toggleTheme() {
    const next = theme === 'dark' ? 'light' : 'dark'
    setPreference(next)
    applyTheme(next)
    try { localStorage.setItem(THEME_KEY, next) } catch { /* Session-only preference. */ }
  }
  return { theme, toggleTheme }
}
