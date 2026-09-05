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
    <div style={{ padding: '1rem' }}>
      <h1>Rule Review Queue</h1>
      {error && <p style={{ color: 'red' }}>Error: {error}</p>}
      {rules.length === 0 && !error && <p>No rules pending review.</p>}
      {rules.map((rule) => (
        <div
          key={rule.id}
          style={{ border: '1px solid #ccc', padding: '1rem', marginBottom: '1rem' }}
        >
          <p><strong>Backtested FP Rate:</strong> {rule.backtested_fp_rate}</p>
          <pre style={{ background: '#f5f5f5', padding: '0.5rem' }}>{rule.rule_yaml}</pre>
          <button onClick={() => handleApprove(rule.id)} style={{ marginRight: '0.5rem' }}>
            Approve
          </button>
          <button onClick={() => handleReject(rule.id)}>Reject</button>
        </div>
      ))}
    </div>
  )
}