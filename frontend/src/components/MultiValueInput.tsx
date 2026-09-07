import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { X } from 'lucide-react'

export interface MultiValueOption {
  value: string
  label?: string
  hint?: string
}

interface MultiValueInputProps {
  /** Selected values as a comma-separated string. */
  value: string
  onChange: (csv: string) => void
  options?: MultiValueOption[]
  placeholder?: string
  /** Allow values that are not in `options` (default true). */
  allowCustom?: boolean
  /** Maximum number of selected values; when 1, picking replaces the value. */
  max?: number
  loading?: boolean
  id?: string
}

function splitCsv(value: string): string[] {
  return value
    .split(',')
    .map(v => v.trim())
    .filter(Boolean)
}

export default function MultiValueInput({
  value,
  onChange,
  options = [],
  placeholder,
  allowCustom = true,
  max,
  loading,
  id,
}: MultiValueInputProps) {
  const { t } = useTranslation(['pages'])
  const [query, setQuery] = useState('')
  const [isOpen, setIsOpen] = useState(false)
  const [highlighted, setHighlighted] = useState(0)
  const containerRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const selected = useMemo(() => splitCsv(value), [value])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    const avail = options.filter(o => !selected.includes(o.value))
    if (!q) return avail
    return avail.filter(
      o =>
        o.value.toLowerCase().includes(q) ||
        (o.label && o.label.toLowerCase().includes(q)) ||
        (o.hint && o.hint.toLowerCase().includes(q))
    )
  }, [options, selected, query])

  useEffect(() => {
    setHighlighted(0)
  }, [filtered])

  useEffect(() => {
    function onClick(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [])

  function commit(raw: string) {
    const v = raw.trim().replace(/,+$/g, '')
    if (!v) return
    let next: string[]
    if (max === 1) {
      next = [v]
    } else {
      next = selected.includes(v) ? selected : [...selected, v]
      if (max && next.length > max) next = next.slice(next.length - max)
    }
    onChange(next.join(','))
    setQuery('')
  }

  function removeAt(i: number) {
    const next = selected.filter((_, idx) => idx !== i)
    onChange(next.join(','))
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (!isOpen) setIsOpen(true)
      setHighlighted(i => Math.min(i + 1, filtered.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setHighlighted(i => Math.max(i - 1, 0))
    } else if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      if (isOpen && filtered[highlighted]) {
        commit(filtered[highlighted].value)
      } else if (allowCustom) {
        commit(query)
      }
    } else if (e.key === 'Tab') {
      if (isOpen && filtered[highlighted]) {
        e.preventDefault()
        commit(filtered[highlighted].value)
      }
    } else if (e.key === 'Escape') {
      setIsOpen(false)
    } else if (e.key === 'Backspace' && query === '' && selected.length) {
      removeAt(selected.length - 1)
    }
  }

  // With max=1 a new pick replaces the current chip, so the dropdown stays open.
  const full = max !== undefined && max > 1 && selected.length >= max

  return (
    <div
      ref={containerRef}
      className="relative input flex flex-wrap items-center gap-1 cursor-text min-h-[38px] !p-1.5"
      onClick={() => inputRef.current?.focus()}
    >
      {selected.map((v, i) => (
        <span
          key={`${v}-${i}`}
          className="inline-flex items-center gap-1 rounded bg-slate-700/60 border border-slate-600 px-1.5 py-0.5 text-xs font-mono text-slate-200"
        >
          {v}
          <button
            type="button"
            aria-label={`Remove ${v}`}
            className="text-slate-400 hover:text-slate-100"
            onMouseDown={e => {
              e.preventDefault()
              removeAt(i)
            }}
          >
            <X className="w-3 h-3" />
          </button>
        </span>
      ))}
      <input
        ref={inputRef}
        id={id}
        type="text"
        className="flex-1 min-w-[8ch] bg-transparent border-0 outline-none text-sm py-0.5 px-1 placeholder:text-slate-500"
        value={query}
        placeholder={selected.length === 0 ? placeholder : undefined}
        disabled={loading}
        autoComplete="off"
        onChange={e => {
          const text = e.target.value
          // A typed comma commits the pending value.
          if (text.includes(',')) {
            const parts = text.split(',')
            for (const p of parts.slice(0, -1)) commit(p)
            setQuery(parts[parts.length - 1])
          } else {
            setQuery(text)
          }
          setIsOpen(true)
        }}
        onFocus={() => setIsOpen(true)}
        onKeyDown={onKeyDown}
        aria-autocomplete="list"
      />
      {isOpen && !full && (
        <div className="absolute z-50 start-0 end-0 top-full mt-1 max-h-60 overflow-auto rounded-lg border border-slate-700 bg-slate-900 shadow-lg">
          {filtered.length === 0 ? (
            <div className="p-2 text-sm text-slate-500">
              {loading
                ? t('pages:multiValue.loading')
                : allowCustom && query.trim()
                  ? t('pages:multiValue.addValue', { value: query.trim() })
                  : t('pages:multiValue.noOptions')}
            </div>
          ) : (
            filtered.map((o, i) => (
              <button
                key={o.value}
                type="button"
                onMouseDown={e => {
                  e.preventDefault()
                  commit(o.value)
                }}
                onMouseEnter={() => setHighlighted(i)}
                className={`w-full px-3 py-2 text-start text-sm ${
                  i === highlighted ? 'bg-slate-800 text-white' : 'text-slate-200'
                }`}
              >
                <span className="font-mono">{o.label ?? o.value}</span>
                {o.hint && <span className="ms-2 text-xs text-slate-400">{o.hint}</span>}
              </button>
            ))
          )}
        </div>
      )}
    </div>
  )
}
