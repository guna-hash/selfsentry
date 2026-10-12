import { useState, useEffect } from 'react'

import { API, apiFetch, describeFailure } from '../api.js'

import {
  Badge,
  EmptyState,
  Loading,
  PageHeader,
  Notice,
} from '../components/ui.jsx'

function formatFpRate(rate) {
  return rate === null || rate === undefined
    ? 'n/a'
    : `${(rate * 100).toFixed(2)}%`
}

export default function RuleReviewQueue() {
  const [rules, setRules] = useState([])
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [busyId, setBusyId] = useState(null)
  const [loading, setLoading] = useState(true)
  const [review, setReview] = useState(null)
  const [reviewer, setReviewer] = useState('')
  const [reason, setReason] = useState('')

  async function fetchPendingRules() {
    try {
      const res = await apiFetch(`${API}/rules/pending`)
      if (!res.ok) throw new Error('Failed to fetch pending rules')
      setRules(await res.json())
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchPendingRules()
    const interval = setInterval(fetchPendingRules, 3000)
    return () => clearInterval(interval)
  }, [])

  async function submitDecision(ruleId, url, successText) {
    if (busyId !== null) return
    setBusyId(ruleId)
    try {
      const res = await apiFetch(url, { method: 'POST' })
      if (res.ok) {
        setNotice({ kind: 'success', text: successText })
        setReview(null)
        setReason('')
      } else {
        setNotice({
          kind: 'error',
          text: `Rule ${ruleId}: ${await describeFailure(res)}`,
        })
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

  function openReview(rule, action) {
    setReview({ id: rule.id, action, retry: rule.status === 'approved' })
    setReason('')
  }
  function confirmReview(event) {
    event.preventDefault()
    if (!reviewer.trim() || (review.action === 'reject' && !reason.trim()))
      return
    const url =
      `${API}/rules/${review.id}/${review.action}?reviewed_by=${encodeURIComponent(reviewer.trim())}` +
      (review.action === 'reject'
        ? `&reason=${encodeURIComponent(reason.trim())}`
        : '')
    submitDecision(
      review.id,
      url,
      review.action === 'approve'
        ? `Rule ${review.id} approved and deployed to Falco.`
        : `Rule ${review.id} rejected.`,
    )
  }

  return (
    <div>
      <PageHeader title="Rule review queue">
        Review generated detection rules and their backtest evidence before
        deployment.
      </PageHeader>
      {error && (
        <p className="error-state" role="alert">Couldn't reach the backend: {error}</p>
      )}
      <Notice notice={notice} onDismiss={() => setNotice(null)} />
      {loading && <Loading />}
      {review && (
        <form className="review-form" onSubmit={confirmReview}>
          <h3>
            {review.action === 'approve'
              ? review.retry
                ? 'Retry deployment'
                : 'Approve and deploy'
              : 'Reject'}{' '}
            rule #{review.id}
          </h3>
          <p>
            {review.action === 'approve'
              ? 'This sends the rule to Falco. Review the YAML and false-positive rate before continuing.'
              : 'Record why this candidate should not be deployed.'}
          </p>
          <label htmlFor="reviewer">Reviewer name</label>
          <input
            id="reviewer"
            value={reviewer}
            onChange={(e) => setReviewer(e.target.value)}
            required
            disabled={busyId !== null}
            autoFocus
          />
          {review.action === 'reject' && (
            <>
              <label htmlFor="reason">Rejection reason</label>
              <textarea
                id="reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                required
                disabled={busyId !== null}
              />
            </>
          )}
          <div>
            <button
              className={`btn ${review.action === 'approve' ? 'btn-primary' : 'btn-reject'}`}
              disabled={
                busyId !== null ||
                !reviewer.trim() ||
                (review.action === 'reject' && !reason.trim())
              }
            >
              {busyId !== null
                ? 'Submitting…'
                : review.action === 'approve'
                  ? 'Confirm deployment'
                  : 'Confirm rejection'}
            </button>
            <button
              type="button"
              className="btn btn-ghost"
              disabled={busyId !== null}
              onClick={() => setReview(null)}
            >
              Cancel
            </button>
          </div>
        </form>
      )}
      {rules.length === 0 && !error && !loading && (
        <EmptyState title="All reviews complete">
          No rules awaiting action. Auto-generated rules appear here after an
          incident is confirmed and the candidate passes backtesting.
        </EmptyState>
      )}
      {rules.map((rule) => {
        const awaitingRetry = rule.status === 'approved'
        return (
          <div key={rule.id} className="incident-card rule-card">
            <div className="incident-meta">
              <span>rule #{rule.id}</span>
              <span>
                false positive rate {formatFpRate(rule.backtested_fp_rate)}
              </span>
              <Badge tone={awaitingRetry ? 'medium' : 'accent'}>
                {awaitingRetry
                  ? 'Approved · deployment pending'
                  : 'Pending review'}
              </Badge>
              {rule.created_at && (
                <span>{new Date(rule.created_at).toLocaleString()}</span>
              )}
            </div>
            <div className="backtest-summary">
              <strong>Backtest false-positive rate</strong>
              <span>{formatFpRate(rule.backtested_fp_rate)}</span>
              <small>
                {rule.backtested_fp_rate == null
                  ? 'No rate reported — inspect available evidence before approval.'
                  : 'Reported by the backtest pipeline'}
              </small>
            </div>
            <pre className="rule-yaml">{rule.rule_yaml}</pre>
            <button
              className="btn btn-approve"
              disabled={busyId !== null}
              onClick={() => openReview(rule, 'approve')}
            >
              {busyId === rule.id
                ? 'Submitting…'
                : awaitingRetry
                  ? 'Retry deploy'
                  : 'Review & approve'}
            </button>
            <button
              className="btn btn-reject"
              disabled={busyId !== null}
              onClick={() => openReview(rule, 'reject')}
            >
              Reject
            </button>
          </div>
        )
      })}
    </div>
  )
}
