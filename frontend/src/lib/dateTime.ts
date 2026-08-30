/**
 * Date/time format & timezone definitions and helpers.
 *
 * The backend stores/sends UTC ISO strings. All conversion to the user's
 * chosen display timezone happens client-side via date-fns-tz.
 *
 * A user picks:
 *  - a timezone: 'local' (browser), 'utc', or an IANA zone (e.g. 'America/New_York')
 *  - a date format string (date-fns tokens, e.g. 'yyyy-MM-dd')
 *  - a time format string (date-fns tokens, e.g. 'HH:mm:ss')
 *
 * Presets are just predefined format strings, so presets and custom share
 * one formatting code path.
 */

/** A selectable date or time format preset. */
export interface FormatPreset {
  /** Stable id used as the dropdown value. */
  id: string
  /** date-fns token string. */
  format: string
  /** Human-readable example label shown in the selector. */
  label: string
}

/** Date format presets (date-fns tokens). */
export const DATE_FORMAT_PRESETS: FormatPreset[] = [
  { id: 'yyyy-MM-dd', format: 'yyyy-MM-dd', label: '2026-08-28' },
  { id: 'dd/MM/yyyy', format: 'dd/MM/yyyy', label: '28/08/2026' },
  { id: 'MM/dd/yyyy', format: 'MM/dd/yyyy', label: '08/28/2026' },
  { id: 'MMM d, yyyy', format: 'MMM d, yyyy', label: 'Aug 28, 2026' },
  { id: 'd MMM yyyy', format: 'd MMM yyyy', label: '28 Aug 2026' },
  { id: 'yyyy/MM/dd', format: 'yyyy/MM/dd', label: '2026/08/28' },
]

/** Time format presets (date-fns tokens). */
export const TIME_FORMAT_PRESETS: FormatPreset[] = [
  { id: 'HH:mm:ss', format: 'HH:mm:ss', label: '14:30:05' },
  { id: 'HH:mm', format: 'HH:mm', label: '14:30' },
  { id: 'h:mm a', format: 'h:mm a', label: '2:30 PM' },
  { id: 'h:mm:ss a', format: 'h:mm:ss a', label: '2:30:05 PM' },
  { id: 'HH:mm:ss.SSS', format: 'HH:mm:ss.SSS', label: '14:30:05.123' },
]

/** Combined date+time presets (pairs of date and time presets). */
export interface DateTimePreset {
  id: string
  dateFormat: string
  timeFormat: string
  label: string
}

export const DATETIME_FORMAT_PRESETS: DateTimePreset[] = [
  { id: 'iso', dateFormat: 'yyyy-MM-dd', timeFormat: 'HH:mm:ss', label: '2026-08-28 14:30:05' },
  { id: 'eu', dateFormat: 'dd/MM/yyyy', timeFormat: 'HH:mm:ss', label: '28/08/2026 14:30:05' },
  { id: 'us', dateFormat: 'MM/dd/yyyy', timeFormat: 'h:mm a', label: '08/28/2026 2:30 PM' },
  { id: 'short', dateFormat: 'MMM d, yyyy', timeFormat: 'HH:mm', label: 'Aug 28, 2026 14:30' },
  { id: 'readable', dateFormat: 'MMM d, yyyy', timeFormat: 'h:mm:ss a', label: 'Aug 28, 2026 2:30:05 PM' },
]

export const DEFAULT_DATE_FORMAT = 'yyyy-MM-dd'
export const DEFAULT_TIME_FORMAT = 'HH:mm:ss'
export const DEFAULT_TIMEZONE = 'local'

/** Compact format used for chart axes (space-constrained). */
export const COMPACT_TIME_FORMAT = 'HH:mm'
/** Compact date+time format used for chart tooltips/labels. */
export const COMPACT_DATETIME_FORMAT = 'MMM d HH:mm'

/** localStorage keys. */
export const DATETIME_FORMAT_KEY = 'datetime-format'
export const TIMEZONE_KEY = 'datetime-timezone'

/**
 * The browser's resolved IANA timezone (e.g. 'America/New_York').
 * Falls back to 'UTC' if the browser doesn't expose it.
 */
export function systemTimezone(): string {
  try {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone
    if (tz) return tz
  } catch {
    // ignore
  }
  return 'UTC'
}

/**
 * Map a stored timezone preference to a concrete IANA zone for formatting.
 *  - 'local' → the browser's resolved IANA zone
 *  - 'utc'   → 'UTC'
 *  - anything else → assumed to be a valid IANA zone
 */
export function resolveTimezone(tz: string | null | undefined): string {
  if (!tz || tz === 'local') return systemTimezone()
  if (tz === 'utc') return 'UTC'
  return tz
}

/**
 * All IANA timezones supported by this browser, plus the special 'local'/'utc'
 * pseudo-zones. Falls back to a curated static list when
 * `Intl.supportedValuesOf` is unavailable (older browsers).
 */
export function getAvailableTimezones(): string[] {
  let zones: string[]
  try {
    const supported = (Intl as any).supportedValuesOf?.('timeZone')
    if (Array.isArray(supported) && supported.length > 0) {
      zones = [...supported]
    } else {
      zones = [...FALLBACK_TIMEZONES]
    }
  } catch {
    zones = [...FALLBACK_TIMEZONES]
  }
  // Deduplicate and sort; 'local'/'utc' are handled separately in the UI.
  return Array.from(new Set(zones)).sort((a, b) => a.localeCompare(b))
}

/** Curated fallback IANA timezone list for older browsers. */
const FALLBACK_TIMEZONES: string[] = [
  'UTC',
  'Africa/Cairo',
  'Africa/Johannesburg',
  'America/Anchorage',
  'America/Argentina/Buenos_Aires',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
  'America/New_York',
  'America/Sao_Paulo',
  'America/Toronto',
  'Asia/Bangkok',
  'Asia/Dubai',
  'Asia/Hong_Kong',
  'Asia/Jerusalem',
  'Asia/Kolkata',
  'Asia/Seoul',
  'Asia/Shanghai',
  'Asia/Singapore',
  'Asia/Tokyo',
  'Australia/Sydney',
  'Europe/Amsterdam',
  'Europe/Berlin',
  'Europe/Istanbul',
  'Europe/London',
  'Europe/Madrid',
  'Europe/Moscow',
  'Europe/Paris',
  'Pacific/Auckland',
  'Pacific/Honolulu',
]

/** Validate that a timezone string is 'local', 'utc', or a known IANA zone. */
export function isValidTimezone(tz: string): boolean {
  if (!tz) return false
  if (tz === 'local' || tz === 'utc') return true
  try {
    // Intl.DateTimeFormat throws on invalid timezones.
    Intl.DateTimeFormat('en-US', { timeZone: tz })
    return true
  } catch {
    return false
  }
}

/** Validate that a format string is non-empty and not too long. */
export function isValidFormatString(s: string): boolean {
  return !!s && s.trim().length > 0 && s.length <= 64
}

/**
 * Parse a stored datetime-format preference into date + time format strings.
 * The stored value may be:
 *  - a combined string 'yyyy-MM-dd HH:mm:ss' (split on the first space)
 *  - just a date format (time defaults to DEFAULT_TIME_FORMAT)
 *  - null/undefined (both default)
 *
 * Returns `{ dateFormat, timeFormat }`.
 */
export function parseDateTimeFormat(stored: string | null | undefined): {
  dateFormat: string
  timeFormat: string
} {
  if (!stored || !stored.trim()) {
    return { dateFormat: DEFAULT_DATE_FORMAT, timeFormat: DEFAULT_TIME_FORMAT }
  }
  const trimmed = stored.trim()
  const spaceIdx = trimmed.indexOf(' ')
  if (spaceIdx === -1) {
    // Only a date format provided.
    return { dateFormat: trimmed, timeFormat: DEFAULT_TIME_FORMAT }
  }
  return {
    dateFormat: trimmed.slice(0, spaceIdx),
    timeFormat: trimmed.slice(spaceIdx + 1).trim() || DEFAULT_TIME_FORMAT,
  }
}

/**
 * Combine a date format and time format into a single stored string.
 * Matches the format the backend `datetime_format` column expects.
 */
export function combineDateTimeFormat(dateFormat: string, timeFormat: string): string {
  return `${dateFormat} ${timeFormat}`
}

/**
 * Convert a Date to a value suitable for an `<input type="datetime-local">`
 * element, formatted in the given timezone (wall-clock time in that zone).
 * Returns 'yyyy-MM-ddTHH:mm' (no seconds, no tz offset).
 */
export function toDatetimeLocalInTz(d: Date, tz: string): string {
  const resolved = resolveTimezone(tz)
  // Format in the target tz, then strip seconds from the ISO-ish output.
  const fmt = formatInTzSafe(d, resolved, "yyyy-MM-dd'T'HH:mm")
  return fmt
}

/**
 * Parse a datetime-local string (wall-clock in the given tz) back into a
 * UTC Date. The input has no timezone info; we treat it as local time in
 * the given timezone and convert to UTC.
 */
export function fromDatetimeLocalToUtc(localStr: string, tz: string): Date {
  if (!localStr) return new Date(NaN)
  const resolved = resolveTimezone(tz)
  // Parse the datetime-local string (yyyy-MM-ddTHH:mm) into components,
  // then use Intl to compute the UTC offset for that wall-clock time in
  // the target zone, and subtract it to get UTC.
  const m = localStr.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/)
  if (!m) return new Date(NaN)
  const [, y, mo, da, h, mi] = m.map(Number) as [unknown, number, number, number, number, number, number]
  // Build a Date as if the wall-clock components are UTC (for offset calc)
  const wallUtc = new Date(Date.UTC(y, mo - 1, da, h, mi))
  // Get the zone's offset at that instant via Intl
  const offsetMs = getZoneOffsetMs(resolved, wallUtc)
  // wall-clock-in-zone = UTC + offset, so UTC = wallUtc - offset
  return new Date(wallUtc.getTime() - offsetMs)
}

// ---------------------------------------------------------------------------
// Formatting helpers — uses Intl.DateTimeFormat for timezone conversion and
// date-fns/format for token-based formatting. This avoids date-fns-tz
// compatibility issues between date-fns v4 and date-fns-tz v3.
// ---------------------------------------------------------------------------

import { format as dateFnsFormat } from 'date-fns/format'

/**
 * Get the timezone offset (in milliseconds) for a given IANA zone at a
 * specific UTC instant. Positive = ahead of UTC.
 */
function getZoneOffsetMs(timeZone: string, date: Date): number {
  // Use Intl to get the wall-clock time in the target zone, then compare
  // it to the UTC time to derive the offset.
  const dtf = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
  const parts = dtf.formatToParts(date)
  const map: Record<string, number> = {}
  for (const p of parts) {
    if (p.type !== 'literal') map[p.type] = parseInt(p.value, 10)
  }
  const zonedAsUtc = Date.UTC(
    map.year, map.month - 1, map.day,
    map.hour % 24, map.minute, map.second,
  )
  // offset = zonedWallClockAsUtc - originalUtc
  // If zone is ahead of UTC (e.g. Tokyo +9), zonedAsUtc > date.getTime()
  return zonedAsUtc - date.getTime()
}

/**
 * Convert a UTC Date to a "zoned" Date whose local-time components represent
 * the wall-clock time in the target timezone. This is what date-fns/format
 * reads when it calls getHours(), getFullYear(), etc.
 *
 * This replaces date-fns-tz's toZonedTime with a direct Intl implementation.
 */
function toZonedDate(date: Date, timeZone: string): Date {
  const offsetMs = getZoneOffsetMs(timeZone, date)
  // Shift the UTC instant by the zone offset to get the zoned time as UTC.
  const shifted = new Date(date.getTime() + offsetMs)
  // Create a new Date with LOCAL fields set from the shifted UTC fields,
  // so date-fns/format's getHours()/getFullYear() etc. return the zoned
  // wall-clock values regardless of the system timezone.
  const result = new Date(0)
  result.setFullYear(
    shifted.getUTCFullYear(),
    shifted.getUTCMonth(),
    shifted.getUTCDate(),
  )
  result.setHours(
    shifted.getUTCHours(),
    shifted.getUTCMinutes(),
    shifted.getUTCSeconds(),
    shifted.getUTCMilliseconds(),
  )
  return result
}

/**
 * Parse a date value into a Date object, treating naive ISO strings (no
 * timezone suffix) as UTC. The backend stores timestamps as naive UTC
 * datetimes (DateTime without timezone=True), and Pydantic serializes them
 * without a 'Z' suffix. JavaScript's Date constructor would incorrectly
 * interpret those as local time, so we append 'Z' to force UTC parsing.
 *
 * Also handles HAProxy's `%t` log format (e.g. `29/Aug/2026:14:30:05.123`),
 * treating it as UTC since the HAProxy container runs in UTC.
 */
function parseAsUtcDate(date: Date | string | number): Date {
  if (typeof date === 'string') {
    // HAProxy %t format: "29/Aug/2026:14:30:05.123" (UTC, no timezone suffix)
    const haproxyMatch = date.match(
      /^(\d{1,2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?$/,
    )
    if (haproxyMatch) {
      const [, da, mon, y, h, mi, s, ms] = haproxyMatch
      const months: Record<string, number> = {
        Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
        Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
      }
      const mo = months[mon]
      if (mo !== undefined) {
        return new Date(
          Date.UTC(
            Number(y), mo, Number(da),
            Number(h), Number(mi), Number(s),
            ms ? Number(ms) : 0,
          ),
        )
      }
    }
    // If the string has no timezone info (no Z, no +/-HH:MM suffix), treat as UTC.
    // Match ISO-like strings: yyyy-MM-dd or yyyy-MM-ddTHH:mm:ss(.fff)
    if (!/[Zz]$/.test(date) && !/[+-]\d{2}:?\d{2}$/.test(date)) {
      return new Date(date + 'Z')
    }
    return new Date(date)
  }
  return new Date(date)
}

/**
 * Format a date (or ISO string / timestamp) in the given timezone using the
 * given date-fns format string. Falls back to a basic ISO string on error.
 */
export function formatInTzSafe(
  date: Date | string | number,
  tz: string,
  formatStr: string,
): string {
  try {
    const resolved = resolveTimezone(tz)
    const d = parseAsUtcDate(date)
    if (isNaN(d.getTime())) return ''
    const zoned = toZonedDate(d, resolved)
    return dateFnsFormat(zoned, formatStr)
  } catch {
    try {
      return parseAsUtcDate(date).toISOString()
    } catch {
      return ''
    }
  }
}

/**
 * Format a raw log timestamp string (which may be in HAProxy %t format,
 * ISO 8601, Docker ISO, or other formats) in the given timezone. Falls back
 * to the original string if parsing fails, so log timestamps are always
 * shown even if the format is unrecognized.
 */
export function formatLogTimestamp(
  raw: string | undefined | null,
  tz: string,
  formatStr: string,
): string {
  if (!raw) return '-'
  try {
    const d = parseAsUtcDate(raw)
    if (isNaN(d.getTime())) return raw
    const resolved = resolveTimezone(tz)
    const zoned = toZonedDate(d, resolved)
    return dateFnsFormat(zoned, formatStr)
  } catch {
    return raw
  }
}
