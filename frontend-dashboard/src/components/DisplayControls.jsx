import { usePresentation } from '../hooks/usePresentation.jsx'

export default function DisplayControls() {
  const {presentation,togglePresentation}=usePresentation()
  return <div className="display-controls" aria-label="Display options">
    <button className="shell-button" aria-pressed={presentation} onClick={togglePresentation}>{presentation?'Exit presentation':'Presentation mode'}</button>
  </div>
}
