import { createRequire } from 'node:module'
import { mkdtemp, readFile, writeFile, mkdir, copyFile, rm } from 'node:fs/promises'
import { dirname, resolve, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'
import { SAMPLE_TIME } from '../src/utils/demoMode.js'

export const scenes=[
  {name:'overview',path:'/sample/overview',heading:'Security overview',charts:true},
  {name:'incident',path:'/sample/alerts?incident=9001',heading:'Alerts',dialog:'Incident #9001'},
  {name:'rule-review',path:'/sample/rules?rule=9102',heading:'Rule review queue',dialog:'Rule #9102'},
  {name:'presentation',path:'/sample/overview?present=1',heading:'Security overview',charts:true,presentation:true},
]
export function captureOrigin(value) {
  const url=new URL(value)
  if(url.protocol!=='http:' || !['localhost','127.0.0.1','[::1]'].includes(url.hostname) || url.username || url.password || url.pathname!=='/' || url.search || url.hash)throw new Error('Capture requires a local HTTP origin, e.g. http://127.0.0.1:5173. Only sample routes are captured.')
  return url.origin
}
export function galleryMarkdown() {
  const lines=['<!-- redesign-gallery:start -->','## Dashboard redesign gallery','','These browser captures use **synthetic Sample data**, not live incidents or academic','evaluation results. The visible banner is retained. Historical VM screenshots below','remain separate evidence of the earlier interface.','']
  for(const [name,label] of [['overview','Overview'],['incident','Incident evidence'],['rule-review','Human rule review (read-only sample)'],['presentation','Presentation mode']]) {
    lines.push(`### ${label}`,'',`![${label} — light theme, Sample data](docs/screenshots/redesign-${name}-light.png)`,'',`![${label} — dark theme, Sample data](docs/screenshots/redesign-${name}-dark.png)`,'')
  }
  lines.push('Capture method and limits: [screenshot guide](docs/dashboard_screenshots.md).','<!-- redesign-gallery:end -->','')
  return lines.join('\n')
}
export function withGallery(readme) {
  const gallery=galleryMarkdown()
  if(readme.includes('<!-- redesign-gallery:start -->'))return readme.replace(/<!-- redesign-gallery:start -->[\s\S]*?<!-- redesign-gallery:end -->\n?/,gallery)
  const heading='## Historical VM screenshots (before the redesign)'
  if(!readme.includes(heading) && !readme.includes('## Dashboard screenshots'))throw new Error('README screenshot section is missing; no README changes made.')
  return readme.replace(/## (?:Dashboard screenshots|Historical VM screenshots \(before the redesign\))/,gallery+'\n'+heading)
}
async function playwrightModule() {
  const require=createRequire(import.meta.url)
  try {return require(process.env.PLAYWRIGHT_MODULE_PATH || 'playwright')}
  catch {throw new Error('Playwright is unavailable. Follow docs/dashboard_screenshots.md to install the optional capture tool outside project dependencies, then set PLAYWRIGHT_MODULE_PATH.')}
}
async function ready(page,scene,theme) {
  await page.locator('.page-header h2').filter({hasText:scene.heading}).waitFor()
  await page.locator('[aria-label="Sample data notice"]').waitFor()
  await page.waitForFunction(()=>document.documentElement.dataset.theme===localStorage.getItem('selfsentry-theme') && !document.querySelector('[aria-busy="true"]'))
  if(await page.locator('html').getAttribute('data-theme')!==theme)throw new Error('Theme mismatch')
  if(scene.dialog)await page.getByRole('dialog',{name:scene.dialog,exact:true}).waitFor()
  if(scene.charts) {
    await page.locator('.recharts-surface').first().waitFor()
    await page.getByRole('heading',{name:'Learning loop',exact:true}).waitFor()
  }
  if(scene.presentation) {
    await page.getByRole('region',{name:'Current incident focus'}).waitFor()
    if(!await page.locator('.sidebar').isHidden())throw new Error('Presentation sidebar is visible')
  }
  await page.evaluate(()=>document.fonts.ready)
  // Two rendered frames allow responsive charts to settle without a fixed sleep.
  await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))))
  if(!await page.locator('[aria-label="Sample data notice"]').isVisible())throw new Error('Sample banner is not visible')
}
export async function captureDashboard({origin,repoRoot,playwright,executablePath}) {
  origin=captureOrigin(origin)
  const stage=await mkdtemp(join(tmpdir(),'selfsentry-captures-'))
  let browser
  const report={mode:'Synthetic Sample data — not evaluation evidence',viewport:{width:1600,height:1200},reducedMotion:'reduce',timezoneId:'Asia/Kolkata',locale:'en-IN',sampleClock:SAMPLE_TIME,captures:[],checks:[],browser:null}
  try {
    browser=await playwright.chromium.launch({headless:true,...(executablePath?{executablePath}:{})})
    report.browser=browser.version()
    for(const theme of ['light','dark']) {
      const context=await browser.newContext({viewport:report.viewport,colorScheme:theme,reducedMotion:'reduce',deviceScaleFactor:1,timezoneId:report.timezoneId,locale:report.locale})
      await context.addInitScript(value=>localStorage.setItem('selfsentry-theme',value),theme)
      const failures=[]
      await context.route('**/*',async route=>{
        const request=route.request(),url=new URL(request.url())
        const navigation=request.isNavigationRequest() && url.pathname.startsWith('/sample/')
        const api=/\/(monitor\/status|incidents|containers|rules\/(history|pending)|deployments|audit)(\/|$)/.test(url.pathname)
        if(url.origin!==origin || request.method()!=='GET' || request.headers().authorization || (!navigation && api)) {
          failures.push('Unexpected network request (blocked)');await route.abort();return
        }
        await route.continue()
      })
      const page=await context.newPage()
      page.setDefaultTimeout(20000)
      page.on('pageerror',error=>failures.push(`JavaScript error: ${error.message}`))
      for(const scene of scenes) {
        await page.goto(origin+scene.path,{waitUntil:'networkidle'})
        await ready(page,scene,theme)
        if(await page.locator('body').evaluate(node=>node.scrollWidth>window.innerWidth+1))throw new Error(`Horizontal page overflow: ${scene.name}/${theme}`)
        if(failures.length)throw new Error(failures.join('\n'))
        const filename=`redesign-${scene.name}-${theme}.png`
        await page.screenshot({path:join(stage,filename),fullPage:true,animations:'disabled'})
        report.captures.push({filename,theme,path:scene.path})
        if(scene.dialog) {
          await page.keyboard.press('Tab')
          if(!await page.evaluate(()=>!!document.activeElement?.closest('dialog')))throw new Error('Dialog focus escaped after Tab')
          await page.keyboard.press('Shift+Tab')
          if(!await page.evaluate(()=>!!document.activeElement?.closest('dialog')))throw new Error('Dialog focus escaped after Shift+Tab')
          await page.keyboard.press('Escape')
          await page.getByRole('dialog').waitFor({state:'detached'})
          report.checks.push(`PASS: ${scene.name}/${theme} modal Tab, Shift+Tab and Escape`)
        }
      }
      await page.setViewportSize({width:390,height:844})
      await page.goto(origin+'/sample/overview',{waitUntil:'networkidle'})
      await ready(page,scenes[0],theme)
      if(await page.locator('body').evaluate(node=>node.scrollWidth>window.innerWidth+1))throw new Error(`Narrow page overflow: ${theme}`)
      if(!await page.locator('.sidebar').isHidden())throw new Error('Narrow sidebar should start collapsed')
      await page.getByRole('button',{name:'Toggle navigation',exact:true}).click()
      if(!await page.locator('.sidebar').isVisible())throw new Error('Narrow navigation toggle failed')
      if(failures.length)throw new Error(failures.join('\n'))
      report.checks.push(`PASS: ${theme} 390px layout/navigation and no backend requests or page errors`)
      await context.close()
    }
    const readmePath=resolve(repoRoot,'README.md'),readme=withGallery(await readFile(readmePath,'utf8'))
    const output=resolve(repoRoot,'docs/screenshots');await mkdir(output,{recursive:true})
    for(const item of report.captures)await copyFile(join(stage,item.filename),join(output,item.filename))
    await writeFile(join(output,'redesign-capture-report.json'),JSON.stringify(report,null,2)+'\n')
    await writeFile(readmePath,readme)
    console.log(`Captured ${report.captures.length} browser PNGs; README gallery updated. Review images before committing.`)
    return report
  } finally {await browser?.close();await rm(stage,{recursive:true,force:true})}
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {
    const repoRoot=resolve(dirname(fileURLToPath(import.meta.url)),'../..')
    await captureDashboard({origin:process.env.SELFSENTRY_CAPTURE_ORIGIN || 'http://127.0.0.1:5173',repoRoot,playwright:await playwrightModule(),executablePath:process.env.SELFSENTRY_BROWSER_EXECUTABLE})
  } catch(error) {console.error(`Capture failed: ${error.message}`);process.exitCode=1}
}
