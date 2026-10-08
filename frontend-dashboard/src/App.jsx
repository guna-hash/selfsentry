import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import Alerts from './pages/Alerts.jsx'
import RuleReviewQueue from './pages/RuleReviewQueue.jsx'

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-shell">
        <aside className="sidebar">
          <h1>SelfSentry</h1>
          <nav>
            <NavLink to="/" end className={({ isActive }) => isActive ? 'active' : ''}>
              Alerts
            </NavLink>
            <NavLink to="/rules" className={({ isActive }) => isActive ? 'active' : ''}>
              Rule Review Queue
            </NavLink>
          </nav>
        </aside>
        <main className="main">
          <Routes>
            <Route path="/" element={<Alerts />} />
            <Route path="/rules" element={<RuleReviewQueue />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
