import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import { Shield, Bell, Search, AlertTriangle, GitPullRequest, Box, Image, Activity, BarChart3, FileText } from 'lucide-react'
import Alerts from './pages/Alerts.jsx'
import RuleReviewQueue from './pages/RuleReviewQueue.jsx'

function ComingSoon({ icon: Icon, label }) {
  return (
    <span className="soon">
      <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <Icon size={15} /> {label}
      </span>
      <span className="soon-tag">soon</span>
    </span>
  )
}

export default function App() {
  const [backendOk, setBackendOk] = useState(null)

  useEffect(() => {
    async function checkBackend() {
      try {
        const res = await fetch('http://localhost:8000/')
        setBackendOk(res.ok)
      } catch {
        setBackendOk(false)
      }
    }
    checkBackend()
    const interval = setInterval(checkBackend, 5000)
    return () => clearInterval(interval)
  }, [])

  return (
    <BrowserRouter>
      <div className="app-shell">
        <aside className="sidebar">
          <h1>ContainerGuard</h1>
          <p className="tagline">SECURE CONTAINERS. SAFER TOMORROW.</p>

          <p className="group-label">THREATS</p>
          <nav>
            <NavLink to="/" end className={({ isActive }) => isActive ? 'active' : ''}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <AlertTriangle size={15} /> Alerts
              </span>
            </NavLink>
            <NavLink to="/rules" className={({ isActive }) => isActive ? 'active' : ''}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <GitPullRequest size={15} /> Rule Review Queue
              </span>
            </NavLink>
          </nav>

          <p className="group-label">INFRASTRUCTURE</p>
          <nav>
            <ComingSoon icon={Box} label="Containers" />
            <ComingSoon icon={Image} label="Images" />
            <ComingSoon icon={Activity} label="Runtime Activity" />
          </nav>

          <p className="group-label">ANALYTICS</p>
          <nav>
            <ComingSoon icon={BarChart3} label="Risk Analytics" />
            <ComingSoon icon={FileText} label="Audit Logs" />
          </nav>
        </aside>

        <div className="content-area">
          <div className="topbar">
            <div className="topbar-search">
              <Search size={15} /> Search containers, alerts, rules...
            </div>
            <div className="topbar-status">
              <Bell size={16} />
              {backendOk === null ? (
                <><span className="dot dot-unknown" /> Checking backend...</>
              ) : backendOk ? (
                <><span className="dot dot-ok" /> Backend connected</>
              ) : (
                <><span className="dot dot-error" /> Backend unreachable</>
              )}
            </div>
          </div>
          <main className="main">
            <Routes>
              <Route path="/" element={<Alerts />} />
              <Route path="/rules" element={<RuleReviewQueue />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  )
}
