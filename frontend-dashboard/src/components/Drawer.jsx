import { useEffect, useId, useRef } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'

// Native modal dialog supplies focus trapping and background inertness.
export default function Drawer({ open, title, children, onClose, busy = false }) {
  const id = useId()
  const dialog = useRef(null)
  const closeButton = useRef(null)
  useEffect(() => {
    if (!open) return
    const previous = document.activeElement
    const node = dialog.current
    const overflow = document.body.style.overflow
    node.showModal()
    closeButton.current?.focus()
    document.body.style.overflow = 'hidden'
    return () => {
      node.close()
      document.body.style.overflow = overflow
      if (previous?.isConnected) previous.focus()
    }
  }, [open])
  if (!open) return null
  return createPortal(<dialog ref={dialog} className="shared-drawer" aria-labelledby={id} aria-modal="true" aria-busy={busy}
    onCancel={(event) => { event.preventDefault(); if (!busy) onClose() }}>
    <header className="drawer-header"><h2 id={id}>{title}</h2>
      <button ref={closeButton} type="button" className="shell-button" aria-label="Close details" disabled={busy} onClick={onClose}><X size={16} aria-hidden="true" /></button>
    </header>
    <div className="drawer-content">{children}</div>
  </dialog>, document.body)
}
