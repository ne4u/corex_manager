import React from 'react'
import { X } from 'lucide-react'

interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  children: React.ReactNode
  showClose?: boolean
  size?: 'md' | 'xl'
}

export default function Modal({ open, onClose, title, children, showClose = true, size = 'md' }: ModalProps) {
  if (!open) return null
  const maxWidth = size === 'xl' ? 'max-w-5xl' : 'max-w-3xl'
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className={`bg-card border border-border rounded-xl w-full ${maxWidth} max-h-[90vh] overflow-y-auto`}>
        <div className="flex items-center justify-between px-6 py-4 border-b border-border sticky top-0 bg-card">
          <h3 className="text-lg font-semibold">{title}</h3>
          {showClose && <button onClick={onClose} className="p-1 rounded hover:bg-muted"><X className="w-5 h-5" /></button>}
        </div>
        <div className="p-6">{children}</div>
      </div>
    </div>
  )
}
