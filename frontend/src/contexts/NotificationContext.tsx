import { createContext, useContext, useCallback, useState, useEffect, useRef, ReactNode } from 'react'
import { getTask } from '../services/api'

export type NotificationType = 'info' | 'success' | 'error' | 'warning'

export interface Notification {
  id: string
  title: string
  message: string
  type: NotificationType
  detail?: string
  createdAt: number
}

interface TrackedTask {
  notificationId: string
  taskId: number
  title: string
  successMessage?: string
  errorMessage?: string
}

interface NotificationContextValue {
  notifications: Notification[]
  addNotification: (n: Omit<Notification, 'id' | 'createdAt'>) => string
  updateNotification: (id: string, n: Partial<Omit<Notification, 'id'>>) => void
  removeNotification: (id: string) => void
  trackTask: (taskId: number, notificationId: string, meta?: Partial<TrackedTask>) => void
}

const POLL_INTERVAL_MS = 1500

const NotificationContext = createContext<NotificationContextValue | undefined>(undefined)

export function NotificationProvider({ children }: { children: ReactNode }) {
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [tracked, setTracked] = useState<TrackedTask[]>([])
  const trackedRef = useRef(tracked)
  trackedRef.current = tracked

  const addNotification = useCallback((n: Omit<Notification, 'id' | 'createdAt'>): string => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`
    setNotifications((prev) => [...prev, { ...n, id, createdAt: Date.now() }])
    return id
  }, [])

  const updateNotification = useCallback((id: string, n: Partial<Omit<Notification, 'id'>>) => {
    setNotifications((prev) => prev.map((x) => (x.id === id ? { ...x, ...n } : x)))
  }, [])

  const removeNotification = useCallback((id: string) => {
    setNotifications((prev) => prev.filter((x) => x.id !== id))
    setTracked((prev) => prev.filter((x) => x.notificationId !== id))
  }, [])

  const trackTask = useCallback((taskId: number, notificationId: string, meta?: Partial<TrackedTask>) => {
    setTracked((prev) => {
      if (prev.some((x) => x.notificationId === notificationId)) return prev
      return [...prev, { notificationId, taskId, title: 'Task', ...meta }]
    })
  }, [])

  useEffect(() => {
    if (tracked.length === 0) return
    const interval = setInterval(async () => {
      const current = trackedRef.current
      if (current.length === 0) return

      const results = await Promise.allSettled(
        current.map(async (t) => {
          const r = await getTask(t.taskId)
          return { t, task: r.data }
        })
      )

      results.forEach((res) => {
        if (res.status !== 'fulfilled') return
        const { t, task } = res.value
        if (task.status === 'pending' || task.status === 'running') {
          updateNotification(t.notificationId, {
            type: 'info',
            title: t.title,
            message: `${t.title} in progress (status: ${task.status})...`,
          })
          return
        }

        setTracked((prev) => prev.filter((x) => x.notificationId !== t.notificationId))

        if (task.status === 'success') {
          updateNotification(t.notificationId, {
            type: 'success',
            title: `${t.title} Complete`,
            message: t.successMessage || task.result?.message || `${t.title} completed successfully.`,
          })
        } else {
          updateNotification(t.notificationId, {
            type: 'error',
            title: `${t.title} Failed`,
            message: t.errorMessage || task.result?.message || `${t.title} failed.`,
            detail: task.error || JSON.stringify(task.result, null, 2),
          })
        }
      })
    }, POLL_INTERVAL_MS)

    return () => clearInterval(interval)
  }, [tracked.length])

  return (
    <NotificationContext.Provider
      value={{ notifications, addNotification, updateNotification, removeNotification, trackTask }}
    >
      {children}
    </NotificationContext.Provider>
  )
}

export function useNotifications(): NotificationContextValue {
  const ctx = useContext(NotificationContext)
  if (!ctx) {
    throw new Error('useNotifications must be used within a NotificationProvider')
  }
  return ctx
}
