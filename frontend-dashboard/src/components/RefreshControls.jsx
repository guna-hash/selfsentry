import { formatDate } from '../utils/format.js'
export default function RefreshControls({ paused, setPaused, refresh, updatedAt }) {
  return <div className="table-toolbar">
    <button className="shell-button" onClick={() => setPaused(!paused)}>{paused ? 'Resume auto-refresh' : 'Pause auto-refresh'}</button>
    <button className="shell-button" onClick={refresh}>Refresh now</button>
    <span role="status">{paused ? 'Paused snapshot' : 'Refreshes every 3 seconds'} · Updated: {formatDate(updatedAt)}</span>
  </div>
}
