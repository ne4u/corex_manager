import { describe, it, expect } from 'vitest'
import {
  DATE_FORMAT_PRESETS,
  TIME_FORMAT_PRESETS,
  DEFAULT_DATE_FORMAT,
  DEFAULT_TIME_FORMAT,
  DEFAULT_TIMEZONE,
  COMPACT_TIME_FORMAT,
  COMPACT_DATETIME_FORMAT,
  resolveTimezone,
  systemTimezone,
  isValidTimezone,
  isValidFormatString,
  parseDateTimeFormat,
  combineDateTimeFormat,
  toDatetimeLocalInTz,
  fromDatetimeLocalToUtc,
  formatInTzSafe,
  getAvailableTimezones,
} from '../dateTime'

describe('dateTime', () => {
  // Fixed UTC timestamp for deterministic tests: 2026-08-28T14:30:05.123Z
  const UTC_ISO = '2026-08-28T14:30:05.123Z'

  describe('constants', () => {
    it('exports non-empty preset arrays', () => {
      expect(DATE_FORMAT_PRESETS.length).toBeGreaterThan(0)
      expect(TIME_FORMAT_PRESETS.length).toBeGreaterThan(0)
    })

    it('has sensible defaults', () => {
      expect(DEFAULT_DATE_FORMAT).toBe('yyyy-MM-dd')
      expect(DEFAULT_TIME_FORMAT).toBe('HH:mm:ss')
      expect(DEFAULT_TIMEZONE).toBe('local')
      expect(COMPACT_TIME_FORMAT).toBe('HH:mm')
      expect(COMPACT_DATETIME_FORMAT).toBe('MMM d HH:mm')
    })
  })

  describe('systemTimezone', () => {
    it('returns a non-empty string', () => {
      const tz = systemTimezone()
      expect(tz).toBeTruthy()
      expect(tz.length).toBeGreaterThan(0)
    })
  })

  describe('resolveTimezone', () => {
    it('resolves "local" to the system timezone', () => {
      expect(resolveTimezone('local')).toBe(systemTimezone())
    })

    it('resolves "utc" to "UTC"', () => {
      expect(resolveTimezone('utc')).toBe('UTC')
    })

    it('resolves null/undefined to the system timezone', () => {
      expect(resolveTimezone(null)).toBe(systemTimezone())
      expect(resolveTimezone(undefined)).toBe(systemTimezone())
    })

    it('passes through IANA zones', () => {
      expect(resolveTimezone('America/New_York')).toBe('America/New_York')
      expect(resolveTimezone('Europe/London')).toBe('Europe/London')
    })
  })

  describe('isValidTimezone', () => {
    it('accepts local, utc, and valid IANA zones', () => {
      expect(isValidTimezone('local')).toBe(true)
      expect(isValidTimezone('utc')).toBe(true)
      expect(isValidTimezone('America/New_York')).toBe(true)
      expect(isValidTimezone('Europe/Paris')).toBe(true)
      expect(isValidTimezone('Asia/Tokyo')).toBe(true)
    })

    it('rejects empty and invalid zones', () => {
      expect(isValidTimezone('')).toBe(false)
      expect(isValidTimezone('Fake/Zone')).toBe(false)
      expect(isValidTimezone('NotATimezone')).toBe(false)
    })
  })

  describe('isValidFormatString', () => {
    it('accepts non-empty strings within length limit', () => {
      expect(isValidFormatString('yyyy-MM-dd')).toBe(true)
      expect(isValidFormatString('HH:mm:ss')).toBe(true)
      expect(isValidFormatString('x')).toBe(true)
    })

    it('rejects empty and too-long strings', () => {
      expect(isValidFormatString('')).toBe(false)
      expect(isValidFormatString('   ')).toBe(false)
      expect(isValidFormatString('x'.repeat(65))).toBe(false)
    })
  })

  describe('parseDateTimeFormat', () => {
    it('returns defaults for null/undefined/empty', () => {
      const result = parseDateTimeFormat(null)
      expect(result.dateFormat).toBe(DEFAULT_DATE_FORMAT)
      expect(result.timeFormat).toBe(DEFAULT_TIME_FORMAT)
    })

    it('splits combined format on first space', () => {
      const result = parseDateTimeFormat('yyyy-MM-dd HH:mm:ss')
      expect(result.dateFormat).toBe('yyyy-MM-dd')
      expect(result.timeFormat).toBe('HH:mm:ss')
    })

    it('handles date-only format (no space)', () => {
      const result = parseDateTimeFormat('dd/MM/yyyy')
      expect(result.dateFormat).toBe('dd/MM/yyyy')
      expect(result.timeFormat).toBe(DEFAULT_TIME_FORMAT)
    })

    it('handles format with extra spaces in time portion', () => {
      const result = parseDateTimeFormat('yyyy-MM-dd h:mm a')
      expect(result.dateFormat).toBe('yyyy-MM-dd')
      expect(result.timeFormat).toBe('h:mm a')
    })
  })

  describe('combineDateTimeFormat', () => {
    it('joins date and time with a space', () => {
      expect(combineDateTimeFormat('yyyy-MM-dd', 'HH:mm:ss')).toBe('yyyy-MM-dd HH:mm:ss')
    })
  })

  describe('formatInTzSafe', () => {
    it('formats a UTC timestamp in UTC timezone', () => {
      const result = formatInTzSafe(UTC_ISO, 'UTC', 'yyyy-MM-dd HH:mm:ss')
      expect(result).toBe('2026-08-28 14:30:05')
    })

    it('formats a UTC timestamp in America/New_York (UTC-4 in August)', () => {
      const result = formatInTzSafe(UTC_ISO, 'America/New_York', 'yyyy-MM-dd HH:mm:ss')
      // August: EDT = UTC-4, so 14:30 UTC → 10:30 EDT
      expect(result).toBe('2026-08-28 10:30:05')
    })

    it('treats naive ISO strings (no Z suffix) as UTC', () => {
      // The backend returns naive UTC datetimes like '2026-08-28T14:30:05'
      // without a Z suffix. These must be treated as UTC, not local time.
      const naive = '2026-08-28T14:30:05'
      const result = formatInTzSafe(naive, 'UTC', 'yyyy-MM-dd HH:mm:ss')
      expect(result).toBe('2026-08-28 14:30:05')
    })

    it('treats naive ISO strings in America/New_York', () => {
      const naive = '2026-08-28T14:30:05'
      const result = formatInTzSafe(naive, 'America/New_York', 'yyyy-MM-dd HH:mm:ss')
      expect(result).toBe('2026-08-28 10:30:05')
    })

    it('formats date-only', () => {
      const result = formatInTzSafe(UTC_ISO, 'UTC', 'yyyy-MM-dd')
      expect(result).toBe('2026-08-28')
    })

    it('formats time-only', () => {
      const result = formatInTzSafe(UTC_ISO, 'UTC', 'HH:mm:ss')
      expect(result).toBe('14:30:05')
    })

    it('returns fallback for invalid date', () => {
      const result = formatInTzSafe('not-a-date', 'UTC', 'yyyy-MM-dd')
      // Should not throw, should return some string
      expect(typeof result).toBe('string')
    })

    it('returns fallback for null input (epoch)', () => {
      // new Date(null) = epoch, not Invalid Date — so it formats as 1970
      const result = formatInTzSafe(null as any, 'UTC', 'yyyy-MM-dd')
      expect(typeof result).toBe('string')
    })
  })

  describe('toDatetimeLocalInTz', () => {
    it('formats a UTC date as datetime-local in UTC', () => {
      const d = new Date(UTC_ISO)
      const result = toDatetimeLocalInTz(d, 'utc')
      expect(result).toBe('2026-08-28T14:30')
    })

    it('formats a UTC date as datetime-local in America/New_York', () => {
      const d = new Date(UTC_ISO)
      const result = toDatetimeLocalInTz(d, 'America/New_York')
      expect(result).toBe('2026-08-28T10:30')
    })
  })

  describe('fromDatetimeLocalToUtc', () => {
    it('converts a UTC wall-clock string to the correct UTC Date', () => {
      const result = fromDatetimeLocalToUtc('2026-08-28T14:30', 'utc')
      expect(result.toISOString()).toBe('2026-08-28T14:30:00.000Z')
    })

    it('converts a New York wall-clock string to the correct UTC Date', () => {
      // 10:30 EDT in August = 14:30 UTC
      const result = fromDatetimeLocalToUtc('2026-08-28T10:30', 'America/New_York')
      expect(result.toISOString()).toBe('2026-08-28T14:30:00.000Z')
    })

    it('round-trips with toDatetimeLocalInTz in UTC', () => {
      const original = new Date(UTC_ISO)
      const localStr = toDatetimeLocalInTz(original, 'utc')
      const roundTripped = fromDatetimeLocalToUtc(localStr, 'utc')
      // Seconds are truncated in datetime-local format
      expect(roundTripped.toISOString()).toBe('2026-08-28T14:30:00.000Z')
    })

    it('round-trips with toDatetimeLocalInTz in America/New_York', () => {
      const original = new Date(UTC_ISO)
      const localStr = toDatetimeLocalInTz(original, 'America/New_York')
      const roundTripped = fromDatetimeLocalToUtc(localStr, 'America/New_York')
      expect(roundTripped.toISOString()).toBe('2026-08-28T14:30:00.000Z')
    })
  })

  describe('getAvailableTimezones', () => {
    it('returns a sorted array of IANA zones', () => {
      const zones = getAvailableTimezones()
      expect(zones.length).toBeGreaterThan(0)
      // Should be sorted
      const sorted = [...zones].sort((a, b) => a.localeCompare(b))
      expect(zones).toEqual(sorted)
    })

    it('includes common zones', () => {
      const zones = getAvailableTimezones()
      expect(zones).toContain('America/New_York')
      expect(zones).toContain('Europe/London')
      expect(zones).toContain('Asia/Tokyo')
    })
  })
})
