import { Link } from 'react-router-dom'
import { usePresentation } from '../hooks/usePresentation.jsx'
import { formatNumber, formatDate } from '../utils/format.js'
import { EmptyState, StatusBadge } from './ui.jsx'
export default function PresentationFocus({rows,unavailable=false}) {
  const {presentation}=usePresentation()
  if(!presentation) return null
  const current=rows?.filter(r=>r.state==='Unconfirmed').slice().sort((a,b)=>(b.score ?? -1)-(a.score ?? -1) || (b.time ?? 0)-(a.time ?? 0))[0]
  return <section className="presentation-focus" aria-label="Current incident focus"><h3>Incident needing attention</h3>
    {unavailable?<p role="status">Current incident evidence unavailable. Refresh the Overview.</p>:current?<><p><Link to={`/alerts?incident=${current.id}`}>Incident #{current.id}</Link> · {current.containerName}</p>
      <p><StatusBadge tone={current.score>=90?'critical':'medium'}>Risk {formatNumber(current.score)} / 100</StatusBadge> · {current.layer} · {current.state}</p>
      <p>{current.falco_alert?.rule || 'Behavioral anomaly'} · {formatDate(current.time)}</p><p>Highest-risk open incident in the selected creation period. AI is advisory.</p></>:<EmptyState title="No open incidents in this selection">Adjust the period or container filter to inspect another cohort.</EmptyState>}
  </section>
}
