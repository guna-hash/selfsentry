import {expect,it} from 'vitest'
import {captureOrigin,scenes,withGallery} from './capture-dashboard.mjs'
it('restricts capture to local origins and synthetic routes',()=>{
  expect(captureOrigin('http://127.0.0.1:5173')).toBe('http://127.0.0.1:5173')
  for(const input of ['https://example.com','http://user:pass@localhost:5173','http://localhost:5173/live','http://localhost:5173/?token=x'])expect(()=>captureOrigin(input)).toThrow('local HTTP origin')
  expect(scenes.every(s=>s.path.startsWith('/sample/'))).toBe(true)
})
it('adds an idempotent labelled gallery while retaining historical VM images',()=>{
  const original='# SelfSentry\n\n## Dashboard screenshots\n\n![Earlier VM](docs/screenshots/monitor-live.png)\n'
  const next=withGallery(original)
  expect(withGallery(next)).toBe(next)
  expect(next).toContain('synthetic Sample data');expect(next).toContain('not live incidents or academic')
  expect(next).toContain('monitor-live.png');expect(next).toContain('before the redesign')
  expect((next.match(/!\[/g)||[]).length).toBe(9)
})
it('refuses to silently rewrite an unexpected README',()=>{
  expect(()=>withGallery('# Unrelated content')).toThrow('screenshot section is missing')
})
