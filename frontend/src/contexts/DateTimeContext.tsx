/**
 * DateTimeProvider — manages the user's date/time display preferences.
 *
 * Resolution order (highest priority first):
 *  1. Explicit user choice via setDateFormat/setTimeFormat/setTimezone
 *     (persists to localStorage + backend)
 *  2. Backend preference (auth.getPreferences().datetime_format / .timezone)
 *  3. localStorage cache — instant paint before backend responds
 *  4. Defaults (local timezone, 'yyyy-MM-dd HH:mm:ss')
 *
 * The backend stores/sends UTC; all conversion to the display timezone
 * happens client-side via date-fns-tz.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  ReactNode,
} from 'react'
import { auth } from '../services/api'
import {
  DATETIME_FORMAT_KEY,
  TIMEZONE_KEY,
  DEFAULT_DATE_FORMAT,
  DEFAULT_TIME_FORMAT,
  DEFAULT_TIMEZONE,
  COMPACT_TIME_FORMAT,
  COMPACT_DATETIME_FORMAT,
  isValidTimezone,
  isValidFormatString,
  parseDateTimeFormat,
  combineDateTimeFormat,
  resolveTimezone,
  formatInTzSafe,
  formatLogTimestamp,
} from '../lib/dateTime'

interface DateTimeContextType {
  /** date-fns date format string (e.g. 'yyyy-MM-dd'). */
  dateFormat: string
  /** date-fns time format string (e.g. 'HH:mm:ss'). */
  timeFormat: string
  /** Stored timezone: 'local', 'utc', or an IANA zone. */
  timezone: string
  setDateFormat: (fmt: string) => void
  setTimeFormat: (fmt: string) => void
  setTimezone: (tz: string) => void
  /** Format a full date+time (date format + ' ' + time format). */
  formatDateTime: (iso: string | number | Date) => string
  /** Format just the date portion. */
  formatDate: (iso: string | number | Date) => string
  /** Format just the time portion. */
  formatTime: (iso: string | number | Date) => string
  /** Compact time for chart axes (always 'HH:mm'). */
  formatTimeCompact: (iso: string | number | Date) => string
  /** Compact date+time for chart tooltips/labels (always 'MMM d HH:mm'). */
  formatDateTimeCompact: (iso: string | number | Date) => string
  /** Format a raw log timestamp (HAProxy %t, ISO, etc.) in the user's tz. */
  formatLogTimestamp: (raw: string | undefined | null) => string
}

export const DateTimeContext = createContext<DateTimeContextType>({
  dateFormat: DEFAULT_DATE_FORMAT,
  timeFormat: DEFAULT_TIME_FORMAT,
  timezone: DEFAULT_TIMEZONE,
  setDateFormat: () => {},
  setTimeFormat: () => {},
  setTimezone: () => {},
  formatDateTime: () => '',
  formatDate: () => '',
  formatTime: () => '',
  formatTimeCompact: () => '',
  formatDateTimeCompact: () => '',
  formatLogTimestamp: () => '-',
})

interface DateTimeProviderProps {
  children: ReactNode
}

export function DateTimeProvider({ children }: DateTimeProviderProps) {
  // Seed from localStorage for instant paint.
  const [timezone, setTimezoneState] = useState<string>(() => {
    const cached = localStorage.getItem(TIMEZONE_KEY)
    if (cached && isValidTimezone(cached)) return cached
    return DEFAULT_TIMEZONE
  })

  const [dateFormat, setDateFormatState] = useState<string>(() => {
    const cached = localStorage.getItem(DATETIME_FORMAT_KEY)
    if (cached && isValidFormatString(cached)) {
      return parseDateTimeFormat(cached).dateFormat
    }
    return DEFAULT_DATE_FORMAT
  })

  const [timeFormat, setTimeFormatState] = useState<string>(() => {
    const cached = localStorage.getItem(DATETIME_FORMAT_KEY)
    if (cached && isValidFormatString(cached)) {
      return parseDateTimeFormat(cached).timeFormat
    }
    return DEFAULT_TIME_FORMAT
  })

  // Load preference from backend on mount (authoritative for returning users).
  useEffect(() => {
    let cancelled = false
    auth
      .getPreferences()
      .then((res) => {
        if (cancelled) return
        const data = res.data
        if (data?.timezone && isValidTimezone(data.timezone)) {
          setTimezoneState(data.timezone)
          localStorage.setItem(TIMEZONE_KEY, data.timezone)
        }
        if (data?.datetime_format && isValidFormatString(data.datetime_format)) {
          const { dateFormat: df, timeFormat: tf } = parseDateTimeFormat(data.datetime_format)
          setDateFormatState(df)
          setTimeFormatState(tf)
          localStorage.setItem(DATETIME_FORMAT_KEY, data.datetime_format)
        }
      })
      .catch(() => {
        // Not logged in or API unavailable — keep localStorage/defaults.
      })
    return () => {
      cancelled = true
    }
  }, [])

  // Debounced save to backend.
  const saveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const debouncedSave = useCallback((payload: Record<string, unknown>) => {
    if (saveTimer.current) clearTimeout(saveTimer.current)
    saveTimer.current = setTimeout(() => {
      auth.updatePreferences(payload).catch(() => {})
    }, 500)
  }, [])

  const setDateFormat = useCallback(
    (fmt: string) => {
      if (!isValidFormatString(fmt)) return
      setDateFormatState(fmt)
      localStorage.setItem(DATETIME_FORMAT_KEY, combineDateTimeFormat(fmt, timeFormat))
      debouncedSave({ datetime_format: combineDateTimeFormat(fmt, timeFormat) })
    },
    [timeFormat, debouncedSave],
  )

  const setTimeFormat = useCallback(
    (fmt: string) => {
      if (!isValidFormatString(fmt)) return
      setTimeFormatState(fmt)
      localStorage.setItem(DATETIME_FORMAT_KEY, combineDateTimeFormat(dateFormat, fmt))
      debouncedSave({ datetime_format: combineDateTimeFormat(dateFormat, fmt) })
    },
    [dateFormat, debouncedSave],
  )

  const setTimezone = useCallback(
    (tz: string) => {
      if (!isValidTimezone(tz)) return
      setTimezoneState(tz)
      localStorage.setItem(TIMEZONE_KEY, tz)
      debouncedSave({ timezone: tz })
    },
    [debouncedSave],
  )

  // Formatters — rebuild when inputs change.
  const resolvedTz = resolveTimezone(timezone)
  const formatDateTime = useCallback(
    (iso: string | number | Date) =>
      formatInTzSafe(iso, resolvedTz, `${dateFormat} ${timeFormat}`),
    [resolvedTz, dateFormat, timeFormat],
  )
  const formatDate = useCallback(
    (iso: string | number | Date) => formatInTzSafe(iso, resolvedTz, dateFormat),
    [resolvedTz, dateFormat],
  )
  const formatTime = useCallback(
    (iso: string | number | Date) => formatInTzSafe(iso, resolvedTz, timeFormat),
    [resolvedTz, timeFormat],
  )
  const formatTimeCompact = useCallback(
    (iso: string | number | Date) => formatInTzSafe(iso, resolvedTz, COMPACT_TIME_FORMAT),
    [resolvedTz],
  )
  const formatDateTimeCompact = useCallback(
    (iso: string | number | Date) => formatInTzSafe(iso, resolvedTz, COMPACT_DATETIME_FORMAT),
    [resolvedTz],
  )
  const formatLogTimestampCb = useCallback(
    (raw: string | undefined | null) =>
      formatLogTimestamp(raw, resolvedTz, `${dateFormat} ${timeFormat}`),
    [resolvedTz, dateFormat, timeFormat],
  )

  return (
    <DateTimeContext.Provider
      value={{
        dateFormat,
        timeFormat,
        timezone,
        setDateFormat,
        setTimeFormat,
        setTimezone,
        formatDateTime,
        formatDate,
        formatTime,
        formatTimeCompact,
        formatDateTimeCompact,
        formatLogTimestamp: formatLogTimestampCb,
      }}
    >
      {children}
    </DateTimeContext.Provider>
  )
}

export function useDateTime() {
  const ctx = useContext(DateTimeContext)
  if (!ctx) {
    throw new Error('useDateTime must be used within a DateTimeProvider')
  }
  return ctx
}
