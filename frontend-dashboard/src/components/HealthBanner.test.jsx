import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { StaticRouter } from 'react-router-dom'
import { HealthNotice } from './HealthBanner.jsx'
const render = (status, error) => renderToStaticMarkup(
  <StaticRouter location="/"><HealthNotice status={status} error={error} /></StaticRouter>,
)
describe('global health notices', () => {
  it('shows no warning for connecting or healthy monitors', () => {
    expect(render(null)).toBe('')
    expect(render({ running: true, healthy: true })).toBe('')
  })
  it('links to monitor health when stopped, degraded or unavailable', () => {
    expect(render({ running: false })).toContain('Monitor stopped')
    expect(render({ running: true, healthy: false })).toContain('Monitor degraded')
    const html = render({ running: true, healthy: true }, 'Offline')
    expect(html).toContain('Monitor unavailable')
    expect(html).toContain('href="/monitor"')
  })
  it('warns about enabled isolation including cached configuration', () => {
    const status = { running: true, healthy: true, configuration: { auto_isolation_enabled: true } }
    expect(render(status)).toContain('Auto-isolation enabled')
    expect(render(status, 'Offline')).toContain('(last reported)')
  })
  it('escapes backend reasons', () => {
    expect(render({ running: false, reason: '<script>bad()</script>' })).toContain('&lt;script&gt;')
  })
  it('reports missing status as unavailable and displays the aggregate health reason', () => {
    expect(render({status_available:false,running:null,healthy:false,reason:'Process state unknown'}))
      .toContain('Monitor unavailable')
    const html = render({running:true,healthy:false,health_reason:'Components require attention: docker'})
    expect(html).toContain('Components require attention: docker')
  })
  it('escapes aggregate health reasons as text', () => {
    expect(render({running:true,healthy:false,health_reason:'<script>bad()</script>'}))
      .toContain('&lt;script&gt;')
  })

})
