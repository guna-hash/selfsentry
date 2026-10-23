import { isSampleMode } from './utils/demoMode.js'
export const API = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'

export const NOTICE_STYLES = {
  success: { background: 'rgba(46, 160, 100, 0.15)', borderLeft: '4px solid #2ea064' },
  error: { background: 'rgba(220, 70, 70, 0.15)', borderLeft: '4px solid #dc4646' },
}

export async function describeFailure(res) {
  try {
    const body = await res.json()
    return typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
  } catch {
    return `HTTP ${res.status}`
  }
}

export async function apiFetch(url, options = {}) {
  if (isSampleMode()) {
    if (options.signal?.aborted) throw new DOMException('Request aborted', 'AbortError')
    let result
    if ((options.method || 'GET').toUpperCase() !== 'GET') result={status:403,body:{detail:'Sample data mode is read-only; no live API request was sent.'}}
    else {
      const { sampleResult } = await import('./data/sampleData.js')
      const base = API.replace(/\/$/,'')
      const path = String(url).startsWith(base + '/') ? String(url).slice(base.length) : '/unsupported-sample-request'
      result=sampleResult(path)
    }
    if (options.signal?.aborted) throw new DOMException('Request aborted', 'AbortError')
    return new Response(JSON.stringify(result.body),{status:result.status,headers:{'Content-Type':'application/json'}})
  }
  let token = null
  try {
    token = sessionStorage.getItem('selfsentry-api-token')
  } catch {
    // Storage may be blocked by browser policy. Reads remain available;
    // the backend still requires a valid bearer token for every write.
  }
  return fetch(url, {
    ...options,
    headers: { ...options.headers, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  })
}

// An absent AI summary must not turn a high-risk incident into a low-severity card.
export function incidentSeverity(incident) {
  const suggested = incident.risk_explanation?.severity?.toLowerCase?.()
  if (['low', 'medium', 'high', 'critical'].includes(suggested)) return suggested
  const priority = String(incident.falco_alert?.priority || '').toUpperCase()
  if (['EMERGENCY', 'ALERT', 'CRITICAL'].includes(priority)) return 'critical'
  if (['ERROR', 'WARNING'].includes(priority)) return 'high'
  const value = incident.monitor_evidence?.effective_score ?? incident.risk_score
  const score = value == null ? NaN : Number(value)
  if (!Number.isFinite(score)) return 'unknown'
  if (score >= 90) return 'critical'
  if (score >= 70) return 'high'
  if (score >= 40) return 'medium'
  return 'low'
}
