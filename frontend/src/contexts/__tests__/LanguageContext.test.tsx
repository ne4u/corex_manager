// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { ReactNode } from 'react'
import { LanguageProvider, useLanguage } from '../LanguageContext'

// Mock the API
vi.mock('../../services/api', () => ({
  auth: {
    getPreferences: vi.fn(() => Promise.resolve({ data: { language: null } })),
    updatePreferences: vi.fn(() => Promise.resolve({ data: {} })),
  },
}))

// Mock i18n config
vi.mock('../../i18n/config', () => ({
  default: {
    language: 'en',
    changeLanguage: vi.fn(),
  },
}))

// Mock navigator.languages
const mockNavigator = (languages: string[]) => {
  Object.defineProperty(navigator, 'languages', {
    value: languages,
    configurable: true,
  })
  Object.defineProperty(navigator, 'language', {
    value: languages[0] || 'en',
    configurable: true,
  })
}

const wrapper = ({ children }: { children: ReactNode }) => (
  <LanguageProvider>{children}</LanguageProvider>
)

describe('LanguageContext', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    mockNavigator(['en'])
    document.documentElement.lang = ''
    document.documentElement.dir = ''
  })

  it('defaults to English when no localStorage and no browser preference', () => {
    mockNavigator(['en'])
    const { result } = renderHook(() => useLanguage(), { wrapper })
    expect(result.current.language).toBe('en')
    expect(result.current.dir).toBe('ltr')
  })

  it('detects browser language on first visit', () => {
    mockNavigator(['es-ES', 'es', 'en'])
    const { result } = renderHook(() => useLanguage(), { wrapper })
    expect(result.current.language).toBe('es')
  })

  it('uses localStorage cached language', () => {
    localStorage.setItem('language', 'fr')
    const { result } = renderHook(() => useLanguage(), { wrapper })
    expect(result.current.language).toBe('fr')
  })

  it('setLanguage updates language and persists to localStorage', () => {
    const { result } = renderHook(() => useLanguage(), { wrapper })
    act(() => {
      result.current.setLanguage('de')
    })
    expect(result.current.language).toBe('de')
    expect(localStorage.getItem('language')).toBe('de')
  })

  it('setLanguage ignores unsupported language codes', () => {
    const { result } = renderHook(() => useLanguage(), { wrapper })
    const initial = result.current.language
    act(() => {
      result.current.setLanguage('xx')
    })
    expect(result.current.language).toBe(initial)
  })

  it('returns rtl dir for Arabic', () => {
    localStorage.setItem('language', 'ar')
    const { result } = renderHook(() => useLanguage(), { wrapper })
    expect(result.current.language).toBe('ar')
    expect(result.current.dir).toBe('rtl')
  })

  it('sets document.documentElement.lang and dir', () => {
    localStorage.setItem('language', 'ar')
    renderHook(() => useLanguage(), { wrapper })
    expect(document.documentElement.lang).toBe('ar')
    expect(document.documentElement.dir).toBe('rtl')
  })

  it('exports all 12 supported languages', () => {
    const { result } = renderHook(() => useLanguage(), { wrapper })
    expect(result.current.languages).toHaveLength(12)
  })

  it('loads backend preference on mount', async () => {
    const { auth } = await import('../../services/api')
    ;(auth.getPreferences as any).mockResolvedValue({ data: { language: 'ja' } })
    const { result } = renderHook(() => useLanguage(), { wrapper })
    // Wait for the promise to resolve
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0))
    })
    expect(result.current.language).toBe('ja')
    expect(localStorage.getItem('language')).toBe('ja')
  })
})
