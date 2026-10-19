import { requestJson, requireWriteToken } from './requests.js'
import { actionableRule, backtestSummary } from './ruleView.js'

export async function reviewRule(rule, {action,reviewer,reason=''}) {
  requireWriteToken()
  const name=reviewer.trim()
  if (!name || name.toLowerCase()==='selfsentry-auto') throw new Error('An explicit human reviewer name is required; selfsentry-auto is reserved.')
  if (!['approve','reject'].includes(action)) throw new Error('Unsupported rule review action.')
  if (!/^[1-9]\d*$/.test(String(rule.id))) throw new Error('A valid rule ID is required.')
  if (action==='approve' && (typeof rule.rule_yaml!=='string' || !rule.rule_yaml.trim())) throw new Error('Rule YAML is unavailable; approval is disabled.')
  if (!actionableRule(rule)) throw new Error('This rule is no longer awaiting a review or deployment retry.')
  if (action==='reject' && !reason.trim()) throw new Error('Record a rejection reason.')
  if (action==='approve' && backtestSummary(rule).blocked) throw new Error(backtestSummary(rule).reason)
  // Re-read the full pending queue before writing. If the reviewed material or state
  // changed while the dialog was open, require the human to inspect it again.
  const pending=await requestJson('/rules/pending')
  if (!Array.isArray(pending)) throw new Error('Pending-state verification failed. Refresh the rule queue.')
  const current=pending.find((row)=>String(row.id)===String(rule.id))
  const same = current && actionableRule(current) && ['status','rule_yaml','backtested_fp_rate','reviewed_by','reviewed_at']
    .every((key)=>(current[key] ?? null)===(rule[key] ?? null))
  if (!same) throw Object.assign(new Error('The rule changed since review. Refresh and review the current YAML and state before submitting.'),{status:409})
  if (action==='approve' && backtestSummary(current).blocked) throw new Error(backtestSummary(current).reason)
  const params=new URLSearchParams({reviewed_by:name})
  if (action==='reject') params.set('reason',reason.trim())
  const result=await requestJson(`/rules/${encodeURIComponent(rule.id)}/${action}?${params}`,{method:'POST',timeoutMs:45000})
  if (String(result?.rule_id)!==String(rule.id) || result?.status!==(action==='approve'?'deployed':'rejected')) {
    const failure=new Error('The response did not confirm the requested outcome. Refresh the recorded state before retrying.')
    failure.uncertain=true
    throw failure
  }
  return result
}
