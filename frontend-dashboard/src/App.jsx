import { BrowserRouter, Routes, Route, Link } from 'react-router-dom'
import Alerts from './pages/Alerts.jsx'
import RuleReviewQueue from './pages/RuleReviewQueue.jsx'

export default function App() {
  return (
    <BrowserRouter>
      <nav style={{ padding: '1rem', borderBottom: '1px solid #ccc' }}>
        <Link to="/" style={{ marginRight: '1rem' }}>Alerts</Link>
        <Link to="/rules">Rule Review Queue</Link>
      </nav>
      <Routes>
        <Route path="/" element={<Alerts />} />
        <Route path="/rules" element={<RuleReviewQueue />} />
      </Routes>
    </BrowserRouter>
  )
}
