import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNotifications, Notification } from '../contexts/NotificationContext'
import { X, CheckCircle, AlertCircle, Info, AlertTriangle, ChevronDown, ChevronUp } from 'lucide-react'

const typeStyles: Record<Notification['type'], string> = {
  info: 'bg-slate-800 border-slate-700 text-slate-100',
  success: 'bg-green-900/40 border-green-700/50 text-green-100',
  error: 'bg-red-900/40 border-red-700/50 text-red-100',
  warning: 'bg-amber-900/40 border-amber-700/50 text-amber-100',
}

const icons: Record<Notification['type'], typeof Info> = {
  info: Info,
  success: CheckCircle,
  error: AlertCircle,
  warning: AlertTriangle,
}

function Toast({ n }: { n: Notification }) {
  const { t } = useTranslation(['pages', 'common'])
  const { removeNotification } = useNotifications()
  const [showDetail, setShowDetail] = useState(false)
  const Icon = icons[n.type]

  return (
    <div
      className={`rounded-lg border shadow-lg p-4 min-w-[20rem] max-w-md backdrop-blur-sm ${typeStyles[n.type]}`}
    >
      <div className="flex items-start gap-3">
        <Icon className="w-5 h-5 mt-0.5 shrink-0" />
        <div className="flex-1 min-w-0">
          <p className="font-semibold text-sm">{n.title}</p>
          <p className="text-sm opacity-90 break-words">{n.message}</p>
          {n.detail && (
            <div className="mt-2">
              <button
                onClick={() => setShowDetail((s) => !s)}
                className="flex items-center text-xs opacity-80 hover:opacity-100 underline"
              >
                {showDetail ? <ChevronUp className="w-3 h-3 me-1" /> : <ChevronDown className="w-3 h-3 me-1" />}
                {showDetail ? t('pages:toaster.hideDetails') : t('pages:toaster.showDetails')}
              </button>
              {showDetail && (
                <pre className="mt-2 text-xs bg-black/30 p-2 rounded overflow-auto max-h-60 whitespace-pre-wrap font-mono">
                  {n.detail}
                </pre>
              )}
            </div>
          )}
        </div>
        <button
          onClick={() => removeNotification(n.id)}
          className="p-1 rounded hover:bg-white/10 opacity-80 hover:opacity-100"
          aria-label={t('pages:toaster.dismiss')}
        >
          <X className="w-4 h-4" />
        </button>
      </div>
    </div>
  )
}

export default function Toaster() {
  const { notifications } = useNotifications()
  if (notifications.length === 0) return null

  return (
    <div className="fixed bottom-4 end-4 z-[100] flex flex-col gap-3">
      {notifications.map((n) => (
        <Toast key={n.id} n={n} />
      ))}
    </div>
  )
}
