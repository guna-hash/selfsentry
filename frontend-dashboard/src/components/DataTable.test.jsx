// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import DataTable from './DataTable.jsx'
import { selectRows } from './tableModel.js'

const rows = [
  { id: 1, container: 'nginx', risk: 9, layer: 'Falco only' },
  { id: 2, container: 'worker', risk: 100, layer: 'Both' },
  { id: 3, container: 'nginx-test', risk: null, layer: 'Both' },
  { id: 4, container: '<img src=x onerror=bad()>', risk: 40, layer: 'ML only' },
]
const columns = [
  { key: 'id', label: 'Incident ID' }, { key: 'container', label: 'Container' },
  { key: 'risk', label: 'Risk' },
  { key: 'layer', label: 'Layers', filterOptions: [{value:'Both',label:'Both'}, {value:'Falco only',label:'Falco only'}] },
]
let host, root
beforeEach(() => { globalThis.IS_REACT_ACT_ENVIRONMENT = true; host = document.createElement('div'); document.body.append(host); root = createRoot(host) })
afterEach(async () => { await act(async () => root.unmount()); host.remove(); delete globalThis.IS_REACT_ACT_ENVIRONMENT })
const render = (props = {}) => act(async () => root.render(<DataTable rows={rows} columns={columns} caption="Incidents" {...props} />))
const click = (button) => act(async () => button.click())
const button = (label) => [...host.querySelectorAll('button')].find((item) => item.textContent === label)
const ids = () => [...host.querySelectorAll('tbody tr')].map((tr) => tr.firstElementChild.textContent)
async function search(text) {
  const input = host.querySelector('input')
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, text)
    input.dispatchEvent(new Event('input', { bubbles: true }))
  })
}
describe('shared data table', () => {
  it('sorts numeric columns in both directions and keeps missing values last', async () => {
    await render()
    await click(button('Risk'))
    expect(ids()).toEqual(['1', '4', '2', '3'])
    expect(host.querySelectorAll('th')[2].getAttribute('aria-sort')).toBe('ascending')
    await click(button('Risk'))
    expect(ids()).toEqual(['2', '4', '1', '3'])
    expect(rows.map((r) => r.id)).toEqual([1, 2, 3, 4])
  })
  it('combines search and filters and removes active chips', async () => {
    await render()
    await search('NGINX')
    expect(ids()).toEqual(['1', '3'])
    await act(async () => { const select=host.querySelector('select'); select.value='Both'; select.dispatchEvent(new Event('change',{bubbles:true})) })
    expect(ids()).toEqual(['3'])
    await click(host.querySelector('[aria-label="Remove Layers: Both filter"]'))
    expect(ids()).toEqual(['1', '3'])
    await click(button('Clear all'))
    expect(ids()).toHaveLength(4)
    await search('2')
    expect(ids()).toEqual(['2'])
  })
  it('paginates, resets on search, and clamps after row changes', async () => {
    await render({pageSize:2})
    expect(button('Previous').disabled).toBe(true)
    await click(button('Next'))
    expect(ids()).toEqual(['3','4'])
    expect(button('Next').disabled).toBe(true)
    await search('nginx')
    expect(ids()).toEqual(['1','3'])
    expect(host.textContent).toContain('Page 1 of 1')
    await click(button('Clear all'))
    await click(button('Next'))
    await render({pageSize:2, rows:rows.slice(0,1)})
    expect(ids()).toEqual(['1'])
    expect(host.textContent).toContain('Page 1 of 1')
  })
  it('opens details via an accessible button and escapes row text', async () => {
    const onRowOpen=vi.fn()
    await render({onRowOpen})
    expect(host.querySelector('img')).toBeNull()
    await click(host.querySelector('[aria-label="View record 2"]'))
    expect(onRowOpen).toHaveBeenCalledWith(rows[1])
    expect(host.querySelector('[role="region"]').tabIndex).toBe(0)
  })
  it('renders loading, retryable errors, empty and no-match states without stale rows', async () => {
    await render({loading:true})
    expect(host.querySelector('[aria-busy="true"]')).not.toBeNull()
    expect(ids()).toEqual([])
    const retry=vi.fn()
    await render({error:'Backend offline', errorStatus:500, onRetry:retry})
    expect(host.querySelector('[role="alert"]').textContent).toContain('server')
    await click(button('Retry')); expect(retry).toHaveBeenCalledOnce()
    await render({rows:[]}); expect(host.textContent).toContain('No records yet')
    await render(); await search('not-a-container'); expect(host.textContent).toContain('No matching records')
  })
  it('supports custom date comparators and stable equal-value ordering', () => {
    const records = [{id:1,time:'2026-10-02T00:00:00Z'}, {id:2,time:'2026-09-01T00:00:00Z'}, {id:3,time:'2026-10-02T00:00:00Z'}]
    const schema=[{key:'time',compare:(a,b)=>Date.parse(a)-Date.parse(b)}]
    expect(selectRows(records,schema,{sort:{key:'time',direction:'desc'}}).map(r=>r.id)).toEqual([1,3,2])
  })
})
it('exports filtered sorted rows across all pages and disables export on failure',async()=>{
  const onExport=vi.fn();await render({onExport,pageSize:1})
  await search('nginx');await click(button('Risk'));await click(button('Export filtered CSV'))
  expect(onExport.mock.calls[0][0].map(r=>r.id)).toEqual([1,3])
  await render({onExport,error:'Offline'});expect(button('Export filtered CSV').disabled).toBe(true)
})
