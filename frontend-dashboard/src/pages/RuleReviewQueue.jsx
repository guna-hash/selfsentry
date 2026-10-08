import { useState, useEffect } from 'react'

const API = 'http://localhost:8000'

const NOTICE_STYLES = {
  success: { background: 'rgba(46, 160, 100, 0.15)', borderLeft: '4px solid #2ea064' },
  error: { background: 'rgba(220, 70, 70, 0.15)', borderLeft: '4px solid #dc4646' },
}

async function describeFailure(res) {
  try {
    const body = await res.json()
    return typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
  } catch {
    return `HTTP ${res.status}`
  }
}

function formatFpRate(rate) {
  return rate === null || rate === undefined ? 'n/a' : `${(rate * 100).toFixed(2)}%`
}

export default function RuleReviewQueue() {
  const [rules, setRules] = useState([])
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [busyId, setBusyId] = useState(null)

  async function fetchPendingRules() {
    try {
      const res = await fetch(`${API}/rules/pending`)
      if (!res.ok) throw new Error('Failed to fetch pending rules')
      setRules(await res.json())
      setError(null)
    } catch (err) {
      setError(err.message)
    }
  }

  useEffect(() => {
    fetchPendingRules()
    const interval = setInterval(fetchPendingRules, 3000)
    return () => clearInterval(interval)
  }, [])

  async function submitDecision(ruleId, url, successText) {
    setBusyId(ruleId)
    try {
      const res = await fetch(url, { method: 'POST' })
      if (res.ok) {
        setNotice({ kind: 'success', text: successText })
      } else {
        setNotice({ kind: 'error', text: `Rule ${ruleId}: ${await describeFailure(res)}` })
      }
    } catch (err) {
      setNotice({
        kind: 'error',
        text: `Rule ${ruleId}: could not reach the backend (${err.message})`,
      })
    } finally {
      setBusyId(null)
      fetchPendingRules()
    }
  }

  function handleApprove(ruleId) {
    const reviewedBy = prompt('Your name (for review record):')
    if (!reviewedBy) return
    submitDecision(
      ruleId,
      `${API}/rules/${ruleId}/approve?reviewed_by=${encodeURIComponent(reviewedBy)}`,
      `Rule ${ruleId} approved and deployed to Falco.`
    )
  }

  function handleReject(ruleId) {
    const reviewedBy = prompt('Your name (for review record):')
    if (!reviewedBy) return
    const reason = prompt('Reason for rejection:')
    if (!reason) return
    submitDecision(
      ruleId,
      `${API}/rules/${ruleId}/reject?reviewed_by=${encodeURIComponent(reviewedBy)}` +
        `&reason=${encodeURIComponent(reason)}`,
      `Rule ${ruleId} rejected.`
    )
  }

  return (
    <div>
      <h2>Rule review queue</h2>
      {error && <p className="error-state">Couldn't reach the backend: {error}</p>}
      {notice && (
        <p
          style={{ padding: '10px 14px', borderRadius: 4, ...NOTICE_STYLES[notice.kind] }}
          onClick={() => setNotice(null)}
          title="Click to dismiss"
        >
          {notice.text}
        </p>
      )}
      {rules.length === 0 && !error && (
        <p className="empty-state">
          No rules awaiting action. Auto-generated rules appear here after an incident is
          confirmed and the candidate passes backtesting.
        </p>
      )}
      {rules.map((rule) => {
        const awaitingRetry = rule.status === 'approved'
        return (
          <div key={rule.id} className="incident-card">
            <div className="incident-meta">
              <span>rule #{rule.id}</span>
              <span>false positive rate {formatFpRate(rule.backtested_fp_rate)}</span>
              <span>
                {awaitingRetry ? 'approved - deployment pending' : 'pending review'}
              </span>
              {rule.created_at && <span>{new Date(rule.created_at).toLocaleString()}</span>}
            </div>
            <pre className="rule-yaml">{rule.rule_yaml}</pre>
            <button
              className="btn btn-approve"
              disabled={busyId === rule.id}
              onClick={() => handleApprove(rule.id)}
            >
              {awaitingRetry ? 'Retry deploy' : 'Approve'}
            </button>
            <button
              className="btn btn-reject"
              disabled={busyId === rule.id}
              onClick={() => handleReject(rule.id)}
            >
              Reject
            </button>
          </div>
        )
      })}
    </div>
  )
}
