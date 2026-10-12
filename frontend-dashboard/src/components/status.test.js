import { describe, expect, it } from 'vitest'
import { monitorState, eventAge } from './status.js'

describe('operational status', () => {
  it('does not present cached healthy data as live after a request failure', () => {
    expect(
      monitorState({ running: true, healthy: true }, 'Offline').label,
    ).toBe('Unavailable')
  })
  it('distinguishes stopped, stale, component failure, and healthy monitors', () => {
    expect(monitorState({ running: false }).label).toBe('Stopped')
    expect(monitorState({ running: true, healthy: false }).label).toBe(
      'Degraded',
    )
    expect(
      monitorState({
        running: true,
        healthy: true,
        components: { database: { state: 'unavailable' } },
      }).label,
    ).toBe('Degraded')
    expect(
      monitorState({
        running: true,
        healthy: true,
        components: { docker: { state: 'connected' } },
      }).label,
    ).toBe('Running')
  })
  it('handles missing events, invalid timestamps, and clock skew explicitly', () => {
    const now = Date.parse('2026-10-12T12:00:00Z')
    expect(eventAge(null, now)).toBe('No events yet')
    expect(eventAge('invalid', now)).toBe('Unknown')
    expect(eventAge('2026-10-12T12:00:10Z', now)).toBe('Clock ahead')
    expect(eventAge('2026-10-12T11:59:30Z', now)).toBe('30s ago')
  })
})
