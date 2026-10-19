import { isSampleMode, sampleWriteError } from './demoMode.js'
import { API, apiFetch, describeFailure } from '../api.js'

export function writeTokenAvailable() {
  if (isSampleMode()) return false
  try { return !!sessionStorage.getItem('selfsentry-api-token')?.trim() } catch { return false }
}
export function requireWriteToken() {
  if (isSampleMode()) throw sampleWriteError()
  if (!writeTokenAvailable()) {
    const error = new Error('Operator token missing. Add it in Monitor → Session credentials before writing.')
    error.status = 401
    throw error
  }
}
export async function requestJson(path, { method = 'GET', body, signal, timeoutMs = 10000 } = {}) {
  if (isSampleMode() && method.toUpperCase() !== 'GET') throw sampleWriteError()
  const controller = new AbortController()
  let timedOut = false
  const abort = () => controller.abort()
  if (signal?.aborted) controller.abort()
  signal?.addEventListener('abort', abort, { once: true })
  const timer = setTimeout(() => { timedOut = true; controller.abort() }, timeoutMs)
  try {
    const response = await apiFetch(API + path, {
      method, signal: controller.signal,
      ...(body === undefined ? {} : { body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' } }),
    })
    if (!response.ok) {
      const error = new Error(await describeFailure(response)); error.status = response.status; throw error
    }
    return response.status === 204 ? null : await response.json()
  } catch (error) {
    if (signal?.aborted) throw error
    if (timedOut || (!error.status && method !== 'GET')) {
      const failure = new Error(method === 'GET'
        ? 'Request timed out. Retry to refresh the recorded data.'
        : 'The response was interrupted; the action outcome is unknown. Refresh the recorded state before retrying.')
      failure.uncertain = method !== 'GET'
      throw failure
    }
    throw error
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', abort)
  }
}
