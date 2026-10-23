export default function RiskExplanation({ value }) {
  if (!value) return <p>Risk guidance unavailable. Refresh to retry the backend.</p>
  return (
    <section className="risk-guidance">
      <h4>{value.title}</h4>
      <p>{value.explanation}</p>
      <h4>Why this is risky</h4>
      <p>{value.risk_rationale}</p>
      <h4>Suggested fixes</h4>
      <ol>{value.suggested_fixes?.map((fix) => <li key={fix}>{fix}</li>)}</ol>
    </section>
  )
}
