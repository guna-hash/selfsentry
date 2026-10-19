import { useState, lazy, Suspense } from 'react'
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
const Alerts = lazy(() => import('./pages/Alerts.jsx'))
const Overview = lazy(() => import('./pages/Overview.jsx'))
const RuleReviewQueue = lazy(() => import('./pages/RuleReviewQueue.jsx'))
const Containers = lazy(() => import('./pages/Containers.jsx'))
const Deployments = lazy(() => import('./pages/Deployments.jsx'))
const AuditLog = lazy(() => import('./pages/AuditLog.jsx'))
const Monitor = lazy(() => import('./pages/Monitor.jsx'))
const Models = lazy(() => import('./pages/Models.jsx'))
const Evidence = lazy(() => import('./pages/Evidence.jsx'))
import { isSampleMode } from './utils/demoMode.js'
import { PresentationProvider, usePresentation } from './hooks/usePresentation.jsx'
import DemoControls from './components/DemoControls.jsx'
import Skeleton from './components/Skeleton.jsx'
import HealthBanner from './components/HealthBanner.jsx'
import StatusBar from './components/StatusBar.jsx'
import { MonitorProvider } from './hooks/useMonitor.jsx'
const links = [
  ['/overview', 'Overview', ShieldCheck],
  ['/monitor', 'Monitor', Activity],
  ['/models', 'Models', Activity],
  ['/alerts', 'Alerts', Bell],
  ['/deployments', 'Deployments', Rocket],
  ['/containers', 'Containers', Boxes],
  ['/audit', 'Audit log', ScrollText],
  ['/rules', 'Rule review', ListChecks],
  ['/evidence', 'Evidence', ScrollText],
]
function Shell() {
  const { pathname } = useLocation()
  const { presentation } = usePresentation()
  const [navigationOpen, setNavigationOpen] = useState(() => !window.matchMedia('(max-width: 760px)').matches)
  return (
    <div className={`app-shell${navigationOpen ? '' : ' navigation-collapsed'}${presentation ? ' presentation-mode' : ''}`} >
      <a className="skip-link" href="#main-content">Skip to content</a>
      <aside id="workspace-navigation" className="sidebar" hidden={!navigationOpen || presentation}>
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
              onClick={() => { if (window.matchMedia('(max-width: 760px)').matches) setNavigationOpen(false) }}
              className={({ isActive }) =>
                isActive || (to === '/overview' && pathname === '/')
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
        <StatusBar navigationOpen={navigationOpen} onToggleNavigation={() => setNavigationOpen((open) => !open)} />
        <main id="main-content" className="main" tabIndex={-1}>
          <DemoControls />
          <HealthBanner />
          <motion.div
            key={pathname}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.18 }}
          >
            <Suspense fallback={<Skeleton label="Loading page…" />}><Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/overview" element={<Overview />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/monitor" element={<Monitor />} />
              <Route path="/models" element={<Models />} />
              <Route path="/deployments" element={<Deployments />} />
              <Route path="/containers" element={<Containers />} />
              <Route path="/audit" element={<AuditLog />} />
              <Route path="/rules" element={<RuleReviewQueue />} />
              <Route path="/evidence" element={<Evidence />} />
            </Routes></Suspense>
          </motion.div>
        </main>
      </div>
    </div>
  )
}
export default function App() {
  return (
    <BrowserRouter basename={isSampleMode() ? '/sample' : '/'}>
      <MotionConfig reducedMotion="user">
        <PresentationProvider><MonitorProvider>
          <Shell />
        </MonitorProvider></PresentationProvider>
      </MotionConfig>
    </BrowserRouter>
  )
}
