import { requestJson, requireWriteToken } from './requests.js'

function humanName(value) {
  const name = value.trim()
  if (!name || name.toLowerCase() === 'selfsentry-auto') throw new Error('Enter a human operator name; selfsentry-auto is reserved for policy automation.')
  return name
}
function incidentId(value) {
  if (!/^\d+$/.test(String(value)) || Number(value) <= 0) throw new Error('A valid incident ID is required.')
  return encodeURIComponent(value)
}
export async function confirmIncident(id, actor) {
  requireWriteToken()
  const name = humanName(actor)
  const result = await requestJson(`/incidents/${incidentId(id)}/confirm?confirmed_by=${encodeURIComponent(name)}`, { method: 'POST' })
  if (!result || !Number.isInteger(result.confirmed_incident_id) || result.confirmed_incident_id <= 0)
    throw new Error('Confirmation response omitted the confirmed-record ID. Refresh before retrying.')
  return result
}
export async function createCandidate(incident, { actor, yaml, fpPercent }) {
  requireWriteToken()
  humanName(actor)
  if (!incident.confirmation) throw new Error('Confirm this incident before submitting a candidate.')
  if (incident.monitor_workflow?.disposition?.status === 'benign') throw new Error('This incident is marked benign; candidate submission is disabled.')
  if (!yaml.trim()) throw new Error('Paste the template-generated rule YAML.')
  const rate = fpPercent.trim() === '' ? NaN : Number(fpPercent)
  if (!Number.isFinite(rate) || rate < 0 || rate > 5) throw new Error('Enter the recorded benign backtest rate from 0% to 5%.')
  // Existing serialization omits the confirmed-record primary key. This endpoint is
  // idempotent and returns that key without replacing an existing confirmation.
  const confirmation = await confirmIncident(incident.id, actor)
  const confirmedId = confirmation.confirmed_incident_id
  const existing = async () => {
    try {
      const rule = await requestJson(`/rules/for-confirmed/${confirmedId}`)
      if (rule?.confirmed_incident_id !== confirmedId || !rule?.id) throw new Error('Unexpected existing-candidate response. Refresh the queue.')
      return { ...rule, existing: true }
    } catch (error) { if (error.status === 404) return null; throw error }
  }
  const found = await existing()
  if (found) return found
  try {
    const rule = await requestJson('/rules/', { method: 'POST', timeoutMs: 30000, body: {
      confirmed_incident_id: confirmedId, rule_yaml: yaml, backtested_fp_rate: rate / 100,
    } })
    if (!rule?.id || rule.status !== 'pending_review') throw new Error('Unexpected candidate response. Refresh the review queue before retrying.')
    return rule
  } catch (error) {
    // A concurrent monitor proposal may have won. Reconcile only against a recorded
    // active candidate for this same confirmed incident; never bypass a failed test.
    if (error.status === 409) { const concurrent = await existing(); if (concurrent) return concurrent }
    throw error
  }
}
