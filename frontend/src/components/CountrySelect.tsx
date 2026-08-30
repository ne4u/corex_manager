import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

interface CountryOption {
  code: string
  name: string
}

interface CountrySelectProps {
  value: string
  onChange: (code: string) => void
  options: CountryOption[]
  loading?: boolean
  placeholder?: string
  required?: boolean
  id?: string
}

export default function CountrySelect({
  value,
  onChange,
  options,
  loading,
  placeholder,
  required,
  id,
}: CountrySelectProps) {
  const { t } = useTranslation(['pages', 'common'])
  const effectivePlaceholder = placeholder || t('pages:countrySelect.searchCountry')
  const [query, setQuery] = useState('')
  const [isOpen, setIsOpen] = useState(false)
  const [highlighted, setHighlighted] = useState(0)
  const containerRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const selected = useMemo(() => options.find(o => o.code === value), [options, value])

  useEffect(() => {
    setQuery(selected ? format(selected) : '')
  }, [selected])

  useEffect(() => {
    function onClick(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return options
    return options.filter(
      o =>
        o.name.toLowerCase().includes(q) ||
        o.code.toLowerCase().startsWith(q) ||
        o.code.toLowerCase() === q
    )
  }, [options, query])

  useEffect(() => {
    setHighlighted(0)
  }, [filtered])

  function format(o: CountryOption) {
    return `${o.name} (${o.code})`
  }

  function select(option: CountryOption) {
    onChange(option.code)
    setQuery(format(option))
    setIsOpen(false)
    inputRef.current?.blur()
  }

  function clear() {
    onChange('')
    setQuery('')
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (!isOpen) setIsOpen(true)
      setHighlighted(i => Math.min(i + 1, filtered.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setHighlighted(i => Math.max(i - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      if (filtered[highlighted]) {
        select(filtered[highlighted])
      }
    } else if (e.key === 'Escape') {
      setIsOpen(false)
    } else if (e.key === 'Tab') {
      setIsOpen(false)
    } else if (e.key === 'Backspace' && query === '') {
      clear()
    }
  }

  function onInputChange(e: React.ChangeEvent<HTMLInputElement>) {
    const text = e.target.value
    setQuery(text)
    setIsOpen(true)
    // Clear the selected code while the user is typing until they pick again.
    if (selected && text !== format(selected)) {
      onChange('')
    }
  }

  function onFocus() {
    setIsOpen(true)
    if (selected) {
      inputRef.current?.select()
    }
  }

  return (
    <div ref={containerRef} className="relative">
      <input
        ref={inputRef}
        id={id}
        type="text"
        className="input w-full"
        value={query}
        onChange={onInputChange}
        onFocus={onFocus}
        onKeyDown={onKeyDown}
        placeholder={loading ? t('pages:countrySelect.loadingCountries') : effectivePlaceholder}
        disabled={loading}
        autoComplete="off"
        aria-autocomplete="list"
        aria-controls="country-listbox"
      />
      <input type="hidden" value={value} required={required} />
      {isOpen && (
        <div
          id="country-listbox"
          className="absolute z-50 mt-1 max-h-60 w-full overflow-auto rounded-lg border border-slate-700 bg-slate-900 shadow-lg"
        >
          {loading ? (
            <div className="p-2 text-sm text-slate-400">{t('pages:countrySelect.loading')}</div>
          ) : filtered.length === 0 ? (
            <div className="p-2 text-sm text-slate-500">{t('pages:countrySelect.noCountriesFound')}</div>
          ) : (
            filtered.map((o, i) => (
              <button
                key={o.code}
                type="button"
                onMouseDown={() => select(o)}
                onMouseEnter={() => setHighlighted(i)}
                className={`w-full px-3 py-2 text-start text-sm ${
                  i === highlighted ? 'bg-slate-800 text-white' : 'text-slate-200'
                }`}
              >
                <span className="font-medium">{o.name}</span>
                <span className="ms-2 text-xs text-slate-400 font-mono">{o.code}</span>
              </button>
            ))
          )}
        </div>
      )}
    </div>
  )
}
