import { useEffect, useRef, useState } from 'react'
import { Info } from 'lucide-react'

interface InfoTooltipProps {
  content: string
}

export default function InfoTooltip({ content }: InfoTooltipProps) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLSpanElement>(null)

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    if (open) {
      document.addEventListener('mousedown', handleClickOutside)
      return () => document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [open])

  const handleIconClick = (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setOpen((prev) => !prev)
  }

  const handleTooltipClick = (e: React.MouseEvent) => {
    e.stopPropagation()
  }

  return (
    <span ref={ref} className="relative inline-flex">
      <Info
        className="w-3 h-3 text-slate-500 cursor-pointer"
        aria-label={content}
        onClick={handleIconClick}
      />
      {open && (
        <div
          onClick={handleTooltipClick}
          className="absolute start-0 top-full mt-1 z-50 w-max max-w-[14rem] p-2 rounded-md bg-slate-800 text-slate-200 text-xs border border-slate-700 shadow-md"
        >
          {content}
        </div>
      )}
    </span>
  )
}
