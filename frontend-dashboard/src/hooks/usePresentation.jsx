import { createContext, useContext, useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
const Presentation = createContext({presentation:false,togglePresentation:()=>{}})
export function PresentationProvider({children}) {
  const location=useLocation(), navigate=useNavigate()
  const [presentation,setPresentation]=useState(()=>new URLSearchParams(location.search).get('present')==='1')
  useEffect(()=>{
    const params=new URLSearchParams(location.search)
    if(presentation) params.set('present','1'); else params.delete('present')
    const search=params.toString() ? '?' + params : ''
    if(search!==location.search) navigate({pathname:location.pathname,search,hash:location.hash},{replace:true})
  },[presentation,location.pathname,location.search,location.hash,navigate])
  return <Presentation.Provider value={{presentation,togglePresentation:()=>setPresentation(v=>!v)}}>{children}</Presentation.Provider>
}
export const usePresentation=()=>useContext(Presentation)
