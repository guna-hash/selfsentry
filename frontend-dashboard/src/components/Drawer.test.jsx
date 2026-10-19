// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { beforeEach, afterEach, expect, it, vi } from 'vitest'
import Drawer from './Drawer.jsx'
let root, host, trigger
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true
  // jsdom does not implement native modal top-layer behavior. Real browser QA remains required.
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value: function () { this.open = true } })
  Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value: function () { this.open = false } })
  trigger = document.createElement('button'); document.body.append(trigger); trigger.focus()
  host = document.createElement('div'); document.body.append(host); root = createRoot(host)
})
afterEach(async () => { await act(async () => root.unmount()); host.remove(); trigger.remove(); vi.restoreAllMocks(); delete HTMLDialogElement.prototype.showModal; delete HTMLDialogElement.prototype.close; delete globalThis.IS_REACT_ACT_ENVIRONMENT })
const render = (props={}) => act(async () => root.render(<Drawer open title="Incident evidence" onClose={()=>{}} {...props}><p>Observed event</p></Drawer>))
it('labels the modal, focuses close, locks scrolling and restores focus on close', async () => {
  await render()
  const dialog=document.querySelector('dialog')
  expect(dialog.open).toBe(true)
  expect(document.getElementById(dialog.getAttribute('aria-labelledby')).textContent).toBe('Incident evidence')
  expect(document.activeElement.getAttribute('aria-label')).toBe('Close details')
  expect(document.body.style.overflow).toBe('hidden')
  await render({open:false})
  expect(document.activeElement).toBe(trigger)
  expect(document.body.style.overflow).toBe('')
})
it('requests dismissal on Escape/cancel and blocks it while busy', async () => {
  const close=vi.fn(); await render({onClose:close})
  await act(async () => document.querySelector('dialog').dispatchEvent(new Event('cancel',{cancelable:true})))
  expect(close).toHaveBeenCalledOnce()
  close.mockClear(); await render({onClose:close,busy:true})
  await act(async () => document.querySelector('dialog').dispatchEvent(new Event('cancel',{cancelable:true})))
  expect(close).not.toHaveBeenCalled()
  expect(document.querySelector('[aria-label="Close details"]').disabled).toBe(true)
})
