import {
  BrowserRouter,
  Routes,
  Route,
  NavLink,
  useLocation,
} from 'react-router-dom'
import {
  Activity,
  ShieldCheck,
  Bell,
  Rocket,
  Boxes,
  ScrollText,
  ListChecks,
} from 'lucide-react'
import { motion, MotionConfig } from 'framer-motion'
import Alerts from './pages/Alerts.jsx'
import RuleReviewQueue from './pages/RuleReviewQueue.jsx'
import Containers from './pages/Containers.jsx'
import Deployments from './pages/Deployments.jsx'
import AuditLog from './pages/AuditLog.jsx'
import Monitor from './pages/Monitor.jsx'
import StatusBar from './components/StatusBar.jsx'
import { MonitorProvider } from './hooks/useMonitor.jsx'
const links = [
  ['/monitor', 'Monitor', Activity],
  ['/', 'Alerts', Bell],
  ['/deployments', 'Deployments', Rocket],
  ['/containers', 'Containers', Boxes],
  ['/audit', 'Audit log', ScrollText],
  ['/rules', 'Rule review', ListChecks],
]
function Shell() {
  const { pathname } = useLocation()
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">
            <ShieldCheck size={25} />
          </span>
          <div>
            <h1>SelfSentry</h1>
            <span>CONTAINER DEFENSE</span>
          </div>
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav aria-label="Main navigation">
          {links.map(([to, label, Icon]) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                isActive || (to === '/' && pathname === '/alerts')
                  ? 'active'
                  : ''
              }
            >
              <Icon size={18} />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <ShieldCheck size={17} />
          <div>
            SelfSentry<span>v0.9 · Demo</span>
          </div>
        </div>
      </aside>
      <div className="workspace">
        <StatusBar />
        <main className="main">
          <motion.div
            key={pathname}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.18 }}
          >
            <Routes>
              <Route path="/" element={<Alerts />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/monitor" element={<Monitor />} />
              <Route path="/deployments" element={<Deployments />} />
              <Route path="/containers" element={<Containers />} />
              <Route path="/audit" element={<AuditLog />} />
              <Route path="/rules" element={<RuleReviewQueue />} />
            </Routes>
          </motion.div>
        </main>
      </div>
    </div>
  )
}
export default function App() {
  return (
    <BrowserRouter>
      <MotionConfig reducedMotion="user">
        <MonitorProvider>
          <Shell />
        </MonitorProvider>
      </MotionConfig>
    </BrowserRouter>
  )
}
