// @vitest-environment jsdom
import {renderToStaticMarkup} from 'react-dom/server'
import {expect,it} from 'vitest'
import YamlCode from './YamlCode.jsx'
it('escapes untrusted YAML and preserves exact text through highlighting',()=>{
  const yaml='# note\n- rule: "<img src=x onerror=bad()>"\n  condition: proc.name="sh"\n  enabled: true\n'
  const host=document.createElement('div');host.innerHTML=renderToStaticMarkup(<YamlCode value={yaml}/>)
  expect(host.querySelector('img')).toBeNull()
  expect(host.querySelector('code').textContent).toBe(yaml)
  expect(host.querySelector('.yaml-key')).not.toBeNull()
})
it('does not replace missing YAML with a generated example',()=>{
  expect(renderToStaticMarkup(<YamlCode value={null}/>)).toContain('not recorded')
})
