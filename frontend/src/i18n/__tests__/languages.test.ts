import { describe, it, expect, vi, beforeEach } from 'vitest'

// Mock navigator.languages for detection tests
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

describe('languages', () => {
  beforeEach(() => {
    vi.resetModules()
  })

  it('exports 12 supported languages', async () => {
    const mod = await import('../languages')
    expect(mod.LANGUAGES).toHaveLength(12)
    expect(mod.LANGUAGES.map((l) => l.code)).toContain('en')
    expect(mod.LANGUAGES.map((l) => l.code)).toContain('ar')
    expect(mod.LANGUAGES.map((l) => l.code)).toContain('hi')
  })

  it('English is the default language', async () => {
    const mod = await import('../languages')
    expect(mod.DEFAULT_LANGUAGE).toBe('en')
  })

  it('Arabic is the only RTL language', async () => {
    const mod = await import('../languages')
    expect(mod.RTL_LANGUAGES).toEqual(['ar'])
  })

  it('getLanguageDir returns rtl for Arabic, ltr otherwise', async () => {
    const mod = await import('../languages')
    expect(mod.getLanguageDir('ar')).toBe('rtl')
    expect(mod.getLanguageDir('en')).toBe('ltr')
    expect(mod.getLanguageDir('es')).toBe('ltr')
    expect(mod.getLanguageDir('unknown')).toBe('ltr')
  })

  it('isSupportedLanguage returns true for known codes', async () => {
    const mod = await import('../languages')
    expect(mod.isSupportedLanguage('en')).toBe(true)
    expect(mod.isSupportedLanguage('ar')).toBe(true)
    expect(mod.isSupportedLanguage('xx')).toBe(false)
  })

  it('detectBrowserLanguage returns matching base code from navigator.languages', async () => {
    mockNavigator(['es-ES', 'es', 'en'])
    const mod = await import('../languages')
    expect(mod.detectBrowserLanguage()).toBe('es')
  })

  it('detectBrowserLanguage collapses regional variants to base code', async () => {
    mockNavigator(['pt-BR', 'pt', 'en'])
    const mod = await import('../languages')
    expect(mod.detectBrowserLanguage()).toBe('pt')
  })

  it('detectBrowserLanguage falls back to English when no supported language matches', async () => {
    mockNavigator(['sv-SE', 'sv', 'fi'])
    const mod = await import('../languages')
    expect(mod.detectBrowserLanguage()).toBe('en')
  })

  it('detectBrowserLanguage falls back to English when navigator.languages is empty', async () => {
    mockNavigator([])
    const mod = await import('../languages')
    expect(mod.detectBrowserLanguage()).toBe('en')
  })

  it('detectBrowserLanguage picks the first supported language in priority order', async () => {
    mockNavigator(['de-DE', 'fr-FR', 'en-US'])
    const mod = await import('../languages')
    expect(mod.detectBrowserLanguage()).toBe('de')
  })
})
