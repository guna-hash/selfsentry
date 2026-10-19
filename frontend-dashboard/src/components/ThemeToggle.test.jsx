import { afterEach, describe, expect, it, vi } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import ThemeToggle from './ThemeToggle.jsx'
import { initializeTheme, readThemePreference } from '../hooks/useTheme.js'

afterEach(() => vi.unstubAllGlobals())
function environment(saved, dark = false) {
  vi.stubGlobal('localStorage', { getItem: () => saved })
  vi.stubGlobal('window', { matchMedia: () => ({ matches: dark }) })
  vi.stubGlobal('document', { documentElement: { dataset: {} } })
}
describe('theme toggle', () => {
  it('defaults to system preference before rendering', () => {
    environment(null, true)
    initializeTheme()
    expect(document.documentElement.dataset.theme).toBe('dark')
    const html = renderToStaticMarkup(<ThemeToggle />)
    expect(html).toContain('aria-pressed="true"')
    expect(html).toContain('Switch to light theme')
  })
  it('honors persisted preference over system settings', () => {
    environment('light', true)
    initializeTheme()
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(renderToStaticMarkup(<ThemeToggle />)).toContain('aria-pressed="false"')
  })
  it('ignores invalid preferences and tolerates unavailable storage', () => {
    environment('invalid')
    expect(readThemePreference()).toBeNull()
    vi.stubGlobal('localStorage', { getItem: () => { throw new Error('blocked') } })
    expect(() => initializeTheme()).not.toThrow()
    expect(document.documentElement.dataset.theme).toBe('light')
  })
})

import { readFileSync } from 'node:fs'
it('keeps theme text tokens at WCAG AA contrast on primary surfaces', () => {
  const css = readFileSync(new URL('../theme.css', import.meta.url), 'utf8')
  const luminance = (hex) => {
    const values = hex.slice(1).match(/../g).map((c) => parseInt(c, 16) / 255)
      .map((c) => c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)
    return values[0] * 0.2126 + values[1] * 0.7152 + values[2] * 0.0722
  }
  for (const block of css.matchAll(/:root[^}]+}/g)) {
    const colors = Object.fromEntries([...block[0].matchAll(/(--[\w-]+): (#[\da-f]{6});/g)].map((m) => [m[1], m[2]]))
    for (const fg of ['--text', '--text-muted', '--text-dim', '--accent', '--sev-low', '--sev-medium', '--sev-high', '--sev-critical']) {
      for (const bg of ['--bg', '--panel', '--panel-hover']) {
        const a = luminance(colors[fg]), b = luminance(colors[bg])
        expect((Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05), `${fg} on ${bg}`).toBeGreaterThanOrEqual(4.5)
      }
    }
  }
})
