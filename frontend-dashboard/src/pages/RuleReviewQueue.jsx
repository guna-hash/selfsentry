import { useState, useEffect } from 'react'

export default function RuleReviewQueue() {
  const [rules, setRules] = useState([])
  const [error, setError] = useState(null)

  async function fetchPendingRules() {
    try {
      const res = await fetch('http://localhost:8000/rules/pending')
      if (!res.ok) throw new Error('Failed to fetch pending rules')
      const data = await res.json()
      setRules(data)
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

  async function handleApprove(ruleId) {
    const reviewedBy = prompt('Your name (for review record):')
    if (!reviewedBy) return
    await fetch(
      `http://localhost:8000/rules/${ruleId}/approve?reviewed_by=${encodeURIComponent(reviewedBy)}`,
      { method: 'POST' }
    )
    fetchPendingRules()
  }

  async function handleReject(ruleId) {
    const reviewedBy = prompt('Your name (for review record):')
    if (!reviewedBy) return
    const reason = prompt('Reason for rejection:')
    if (!reason) return
    await fetch(
      `http://localhost:8000/rules/${ruleId}/reject?reviewed_by=${encodeURIComponent(reviewedBy)}&reason=${encodeURIComponent(reason)}`,
      { method: 'POST' }
    )
    fetchPendingRules()
  }

  return (
    <>
      <h2>Rule Review Queue</h2>
      <p className="page-subtitle">Auto-generated rules awaiting human approval before deployment</p>
      {error && <p className="error-state">Couldn't reach the backend: {error}</p>}
      {rules.length === 0 && !error && (
        <p className="empty-state">No rules pending review. Auto-generated rules will appear here once confirmed.</p>
      )}
      {rules.map((rule) => (
        <div key={rule.id} className="distribution" style={{ marginBottom: '1rem' }}>
          <p className="page-subtitle" style={{ margin: '0 0 0.75rem 0' }}>
            false positive rate: <span className="mono">{rule.backtested_fp_rate}</span>
          </p>
          <pre className="rule-yaml">{rule.rule_yaml}</pre>
          <div className="btn-row" style={{ marginTop: '0.75rem' }}>
            <button className="btn btn-approve" onClick={() => handleApprove(rule.id)}>Approve</button>
            <button className="btn btn-reject" onClick={() => handleReject(rule.id)}>Reject</button>
          </div>
        </div>
      ))}
    </>
  )
}
