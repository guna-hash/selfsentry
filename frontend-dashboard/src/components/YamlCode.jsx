import { Fragment } from 'react'

// Lightweight lexical highlighting only. YAML is never executed, interpreted as
// HTML, or rewritten; copying uses the original string, not the highlighted DOM.
export default function YamlCode({value}) {
  if(typeof value!=='string' || !value)return <p>Rule YAML: not recorded.</p>
  const lines=value.split('\n')
  return <pre className="review-yaml"><code>{lines.map((line,index)=>{
    const key=line.match(/^(\s*(?:-\s*)?)([\w.-]+)(\s*:)(.*)$/)
    let content=line
    if(/^\s*#/.test(line))content=<span className="yaml-comment">{line}</span>
    else if(key && !line.endsWith('\r'))content=<>{key[1]}<span className="yaml-key">{key[2]}</span>{key[3]}<span className={/^\s*['"]/.test(key[4])?'yaml-string':/^\s*(?:true|false|[-+]?\d+(?:\.\d+)?)\s*$/.test(key[4])?'yaml-literal':undefined}>{key[4]}</span></>
    return <Fragment key={index}>{content}{index<lines.length-1?'\n':''}</Fragment>
  })}</code></pre>
}
