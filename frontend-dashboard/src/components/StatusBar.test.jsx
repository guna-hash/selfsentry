// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import StatusBar from './StatusBar.jsx'

vi.mock('../hooks/useMonitor.jsx', () => ({
  useMonitor: () => ({
    status: { running: true, healthy: true, configuration: { auto_isolation_enabled: false },
      components: {}, containers: { tracked: 2 }, unconfirmed_incidents: 3 },
    error: null,
  }),
}))
let host, root
beforeEach(() => { globalThis.IS_REACT_ACT_ENVIRONMENT=true; host=document.createElement('div'); document.body.append(host); root=createRoot(host) })
afterEach(async () => { await act(async()=>root.unmount()); host.remove(); delete globalThis.IS_REACT_ACT_ENVIRONMENT })
describe('status header', () => {
  it('renders health, isolation and actions without crashing', async () => {
    await act(async()=>root.render(<StatusBar navigationOpen onToggleNavigation={()=>{}} />))
    expect(host.textContent).toContain('Isolation: off (default)')
    expect(host.textContent).toContain('Monitor: Running')
    expect(host.textContent).toContain('2 tracked containers')
    expect(host.querySelector('[aria-label="Toggle navigation"]')).not.toBeNull()
    expect(host.querySelector('[aria-label="Dark theme"]')).not.toBeNull()
  })
})
