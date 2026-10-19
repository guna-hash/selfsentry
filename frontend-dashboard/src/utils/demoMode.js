export const SAMPLE_TIME = '2026-10-19T12:00:00.000Z'
export function isSampleMode(path = globalThis.location?.pathname || '') {
  return path === '/sample' || path.startsWith('/sample/')
}
export const dashboardNow = () => isSampleMode() ? Date.parse(SAMPLE_TIME) : Date.now()
export function switchModeUrl(sample, presentation = false) {
  return `${sample ? '/sample' : ''}/overview${presentation ? '?present=1' : ''}`
}
export function sampleWriteError() {
  return Object.assign(new Error('Sample data mode is read-only. Exit sample mode to operate the live system.'), {status:403})
}
