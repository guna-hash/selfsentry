import { describe, expect, it } from 'vitest'
import { incidentSeverity } from './api.js'

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
  it('handles advisory severity without accepting arbitrary class names', () => {
    expect(incidentSeverity({ ai_summary: { severity: 'HIGH' } })).toBe('high')
    expect(incidentSeverity({ ai_summary: { severity: 'bad-value' }, risk_score: 100 })).toBe('critical')
  })
})
