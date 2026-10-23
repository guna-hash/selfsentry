import { afterEach, describe, expect, it, vi } from 'vitest'
import { apiFetch, incidentSeverity } from './api.js'

describe('live API with unavailable browser storage', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('keeps reads available without inventing credentials', async () => {
    vi.stubGlobal('sessionStorage', { getItem() { throw new DOMException('Blocked', 'SecurityError') } })
    const response = new Response('[]')
    const request = vi.fn().mockResolvedValue(response)
    vi.stubGlobal('fetch', request)
    expect(await apiFetch('http://127.0.0.1:8000/incidents/')).toBe(response)
    expect(request.mock.calls[0][1].headers).not.toHaveProperty('Authorization')
  })
})

describe('incident severity when AI is absent', () => {
  it('retains critical Falco evidence', () => {
    expect(incidentSeverity({ falco_alert: { priority: 'Critical' } })).toBe('critical')
  })
  it('uses the recorded effective score', () => {
    expect(incidentSeverity({ monitor_evidence: { effective_score: 100 } })).toBe('critical')
    expect(incidentSeverity({ risk_score: 78 })).toBe('high')
    expect(incidentSeverity({ risk_score: 45 })).toBe('medium')
    expect(incidentSeverity({ risk_score: 29 })).toBe('low')
  })
  it('does not label missing evidence as low', () => {
    expect(incidentSeverity({})).toBe('unknown')
    expect(incidentSeverity({ risk_score: 'invalid' })).toBe('unknown')
  })
  it('uses deterministic severity and prevents AI from changing risk classification', () => {
    expect(incidentSeverity({ ai_summary: { severity: 'HIGH' }, risk_score: 10 })).toBe('low')
    expect(incidentSeverity({ risk_explanation: { severity: 'HIGH' } })).toBe('high')
    expect(incidentSeverity({ ai_summary: { severity: 'bad-value' }, risk_score: 100 })).toBe('critical')
  })
})
