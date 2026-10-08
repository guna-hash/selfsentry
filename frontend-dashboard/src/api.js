export const API = 'http://localhost:8000'

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
