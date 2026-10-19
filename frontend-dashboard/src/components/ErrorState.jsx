export function errorMessage(status) {
  return ({
    401: 'Authentication required. Enter your write token and try again.',
    403: 'Access denied. Your credentials do not permit this action.',
    404: 'This record is no longer available. Refresh the data.',
    429: 'Request limit reached. Wait a moment, then retry.',
    500: 'The server could not complete the request. Try again.',
  })[status] || 'The request could not be completed. Check the connection and retry.'
}
export default function ErrorState({ error, status, onRetry, retrying = false }) {
  return <div className="error-state shared-error" role="alert">
    <div><strong>{errorMessage(status)}</strong>{error && <p>{typeof error === 'string' ? error : error.message}</p>}</div>
    {onRetry && <button type="button" className="btn" disabled={retrying} onClick={onRetry}>{retrying ? 'Retrying…' : 'Retry'}</button>}
  </div>
}
