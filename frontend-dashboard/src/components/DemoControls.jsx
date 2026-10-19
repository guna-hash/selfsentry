import { isSampleMode, switchModeUrl, SAMPLE_TIME } from '../utils/demoMode.js'
import { usePresentation } from '../hooks/usePresentation.jsx'
export default function DemoControls() {
  const sample=isSampleMode(), {presentation,togglePresentation}=usePresentation()
  return <><div className="demo-controls" aria-label="Display modes">
    <button className="shell-button" aria-pressed={presentation} onClick={togglePresentation}>{presentation?'Exit presentation':'Presentation mode'}</button>
    <a className="shell-button" href={switchModeUrl(!sample,presentation)}>{sample?'Exit sample mode':'Open sample data'}</a>
    <span>{sample?'Sample workspace':'Live workspace'}</span>
  </div>{sample && <section className="sample-banner" role="status" aria-label="Sample data notice"><strong>Sample data</strong> · Synthetic, read-only UI demonstration. No live API connection or write actions. Not evaluation evidence.<br />Frozen sample clock: {SAMPLE_TIME}</section>}</>
}
