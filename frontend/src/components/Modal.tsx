import React from 'react'
import { X } from 'lucide-react'

interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  children: React.ReactNode
  showClose?: boolean
}

export default function Modal({ open, onClose, title, children, showClose = true }: ModalProps) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-3xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 sticky top-0 bg-slate-900">
          <h3 className="text-lg font-semibold">{title}</h3>
          {showClose && <button onClick={onClose} className="p-1 rounded hover:bg-slate-800"><X className="w-5 h-5" /></button>}
        </div>
        <div className="p-6">{children}</div>
      </div>
    </div>
  )
}
