/**
 * LanguageProvider — manages the active UI language.
 *
 * Resolution order (highest priority first):
 *  1. Explicit user choice via setLanguage() (persists to localStorage + backend)
 *  2. Backend preference (auth.getPreferences().language) — authoritative for returning users
 *  3. localStorage cache ('language' key) — instant paint before backend responds
 *  4. Browser detection (navigator.languages, mirrors Accept-Language) — first visit only
 *  5. English default
 *
 * On a true first visit (no localStorage, no backend pref), the detected
 * language is seeded to localStorage AND persisted to the backend so it
 * becomes the user's stable preference across devices/browsers.
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
import i18n from '../i18n/config'
import {
  DEFAULT_LANGUAGE,
  LANGUAGES,
  LanguageMeta,
  detectBrowserLanguage,
  getLanguageDir,
  isSupportedLanguage,
} from '../i18n/languages'
import { auth } from '../services/api'

const LANGUAGE_KEY = 'language'

interface LanguageContextType {
  language: string
  setLanguage: (code: string) => void
  dir: 'ltr' | 'rtl'
  languages: LanguageMeta[]
}

export const LanguageContext = createContext<LanguageContextType>({
  language: DEFAULT_LANGUAGE,
  setLanguage: () => {},
  dir: 'ltr',
  languages: LANGUAGES,
})

interface LanguageProviderProps {
  children: ReactNode
}

function applyLanguageToDocument(code: string) {
  const dir = getLanguageDir(code)
  document.documentElement.lang = code
  document.documentElement.dir = dir
}

export function LanguageProvider({ children }: LanguageProviderProps) {
  // Seed: localStorage > browser detection > default
  const [language, setLanguageState] = useState<string>(() => {
    const cached = localStorage.getItem(LANGUAGE_KEY)
    if (cached && isSupportedLanguage(cached)) return cached
    const detected = detectBrowserLanguage()
    if (detected !== DEFAULT_LANGUAGE) {
      // Seed localStorage so the detected choice is stable across reloads
      // before the backend preference loads.
      localStorage.setItem(LANGUAGE_KEY, detected)
    }
    return detected
  })

  const dir = getLanguageDir(language)
  const loadedFromBackend = useRef(false)

  // Apply language to <html> + i18n on every change
  useEffect(() => {
    applyLanguageToDocument(language)
    if (i18n.language !== language) {
      i18n.changeLanguage(language)
    }
  }, [language])

  // Load preference from backend on mount
  useEffect(() => {
    let cancelled = false
    auth
      .getPreferences()
      .then((res) => {
        if (cancelled) return
        const prefLang = res.data?.language
        if (prefLang && isSupportedLanguage(prefLang)) {
          // Backend preference wins for returning users
          setLanguageState(prefLang)
          localStorage.setItem(LANGUAGE_KEY, prefLang)
        } else {
          // First-time user (no backend pref): persist the detected/seeded
          // language so it becomes the stable preference.
          const current = localStorage.getItem(LANGUAGE_KEY) || DEFAULT_LANGUAGE
          if (isSupportedLanguage(current) && current !== prefLang) {
            debouncedSave(current)
          }
        }
        loadedFromBackend.current = true
      })
      .catch(() => {
        // Not logged in or API unavailable — keep localStorage/detected value
        loadedFromBackend.current = true
      })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Debounced save to backend
  const saveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const debouncedSave = useCallback((code: string) => {
    if (saveTimer.current) clearTimeout(saveTimer.current)
    saveTimer.current = setTimeout(() => {
      auth.updatePreferences({ language: code }).catch(() => {})
    }, 500)
  }, [])

  const setLanguage = useCallback(
    (code: string) => {
      if (!isSupportedLanguage(code)) return
      setLanguageState(code)
      localStorage.setItem(LANGUAGE_KEY, code)
      debouncedSave(code)
    },
    [debouncedSave],
  )

  return (
    <LanguageContext.Provider value={{ language, setLanguage, dir, languages: LANGUAGES }}>
      {children}
    </LanguageContext.Provider>
  )
}

export function useLanguage() {
  const ctx = useContext(LanguageContext)
  if (!ctx) {
    throw new Error('useLanguage must be used within a LanguageProvider')
  }
  return ctx
}
