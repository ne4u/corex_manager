import { createContext, useCallback, useEffect, useRef, useState, ReactNode } from 'react'
import { defaultTheme, themes as builtinThemes, Theme, ThemeColors } from './themeDefinitions'
import { auth } from '../services/api'

const CUSTOM_THEMES_KEY = 'custom-themes'
const ACTIVE_THEME_KEY = 'theme'
const THEME_STYLE_ID = 'theme-styles'

interface ThemeContextType {
  theme: string
  setTheme: (theme: string) => void
  /** All themes: built-in + custom. */
  allThemes: Record<string, Theme>
  /** Custom themes only (user-created). */
  customThemes: Record<string, Theme>
  /** Save or update a custom theme.  Also sets it as active. */
  saveCustomTheme: (theme: Theme) => void
  /** Delete a custom theme by name.  Falls back to default if it was active. */
  deleteCustomTheme: (name: string) => void
  /** Check whether a theme name is a built-in (non-deletable) theme. */
  isBuiltinTheme: (name: string) => boolean
  /** Re-fetch theme + custom themes from the backend.  Called on mount and
   *  after login, since the initial mount may run before a token exists
   *  (e.g. Safari/ITP evicts localStorage, so the first load 401s silently). */
  refreshPreferences: () => void
}

export const ThemeContext = createContext<ThemeContextType>({
  theme: defaultTheme,
  setTheme: () => {},
  allThemes: builtinThemes,
  customThemes: {},
  saveCustomTheme: () => {},
  deleteCustomTheme: () => {},
  isBuiltinTheme: () => true,
  refreshPreferences: () => {},
})

interface ThemeProviderProps {
  children: ReactNode
}

// ---------------------------------------------------------------------------
// CSS variable injection — all themes (built-in + custom) are generated from
// the TypeScript themeDefinitions.ts at runtime.  This eliminates the need for
// a separate static themes.css file, making themeDefinitions.ts the single
// source of truth for all theme colors.
// ---------------------------------------------------------------------------

const cssVarKeys: (keyof ThemeColors)[] = [
  'bgPrimary', 'bgSecondary', 'bgTertiary',
  'borderDefault', 'borderSubtle', 'borderFocus',
  'textPrimary', 'textSecondary', 'textTertiary', 'textAccent',
  'accentPrimary', 'accentSuccess', 'accentWarning', 'accentError', 'accentInfo',
  'statusEnabled', 'statusDisabled', 'statusPending',
]

const cssVarName: Record<keyof ThemeColors, string> = {
  bgPrimary: '--color-bg-primary',
  bgSecondary: '--color-bg-secondary',
  bgTertiary: '--color-bg-tertiary',
  borderDefault: '--color-border-default',
  borderSubtle: '--color-border-subtle',
  borderFocus: '--color-border-focus',
  textPrimary: '--color-text-primary',
  textSecondary: '--color-text-secondary',
  textTertiary: '--color-text-tertiary',
  textAccent: '--color-text-accent',
  accentPrimary: '--color-accent-primary',
  accentSuccess: '--color-accent-success',
  accentWarning: '--color-accent-warning',
  accentError: '--color-accent-error',
  accentInfo: '--color-accent-info',
  statusEnabled: '--color-status-enabled',
  statusDisabled: '--color-status-disabled',
  statusPending: '--color-status-pending',
}

function generateThemeCss(allThemes: Record<string, Theme>): string {
  return Object.values(allThemes).map(t => {
    const declarations = cssVarKeys
      .map(k => `  ${cssVarName[k]}: ${t.colors[k]};`)
      .join('\n')
    return `:root[data-theme="${t.name}"] {\n${declarations}\n}`
  }).join('\n\n')
}

function injectAllThemeCss(customThemes: Record<string, Theme>) {
  let styleEl = document.getElementById(THEME_STYLE_ID) as HTMLStyleElement | null
  if (!styleEl) {
    styleEl = document.createElement('style')
    styleEl.id = THEME_STYLE_ID
    document.head.appendChild(styleEl)
  }
  styleEl.textContent = generateThemeCss({ ...builtinThemes, ...customThemes })
}

// ---------------------------------------------------------------------------
// Dynamic favicon — recolor the unfold-horizontal icon to match the active
// theme's accent color so the browser tab matches the UI.
// ---------------------------------------------------------------------------

// Path data for the lucide "unfold-horizontal" icon (8 stroke paths).
const FAVICON_SVG_PATHS = [
  'M16 12h6',
  'M8 12H2',
  'M12 2v2',
  'M12 8v2',
  'M12 14v2',
  'M12 20v2',
  'm19 15 3-3-3-3',
  'm5 9-3 3 3 3',
]

function updateFavicon(accentColor: string) {
  // accentColor is an RGB triplet like "37 99 235"
  const hex = '#' + accentColor.split(' ').map(n => parseInt(n).toString(16).padStart(2, '0')).join('')
  const paths = FAVICON_SVG_PATHS.map(d => `<path d="${d}"/>`).join('')
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="${hex}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${paths}</svg>`
  const dataUri = `data:image/svg+xml,${encodeURIComponent(svg)}`
  let link = document.querySelector<HTMLLinkElement>('link[rel="icon"]')
  if (!link) {
    link = document.createElement('link')
    link.rel = 'icon'
    document.head.appendChild(link)
  }
  link.type = 'image/svg+xml'
  link.href = dataUri
}

// ---------------------------------------------------------------------------
// localStorage helpers (used as instant fallback / cache)
// ---------------------------------------------------------------------------

function loadCustomThemesLocal(): Record<string, Theme> {
  try {
    const raw = localStorage.getItem(CUSTOM_THEMES_KEY)
    if (!raw) return {}
    const parsed = JSON.parse(raw) as Record<string, Theme>
    if (typeof parsed !== 'object' || parsed === null) return {}
    for (const theme of Object.values(parsed)) {
      if (!theme.name || !theme.displayName || !theme.colors) return {}
    }
    return parsed
  } catch {
    return {}
  }
}

function saveCustomThemesLocal(custom: Record<string, Theme>) {
  try {
    localStorage.setItem(CUSTOM_THEMES_KEY, JSON.stringify(custom))
  } catch {
    // ignore quota errors
  }
}

// ---------------------------------------------------------------------------
// Module-level injection — runs synchronously when this module is imported,
// before React renders.  This eliminates the need for a static themes.css
// file: all theme CSS variables are generated from themeDefinitions.ts.
// ---------------------------------------------------------------------------

injectAllThemeCss(loadCustomThemesLocal())

// Set initial theme from localStorage immediately to prevent a flash
document.documentElement.dataset.theme = localStorage.getItem(ACTIVE_THEME_KEY) || defaultTheme

// ---------------------------------------------------------------------------
// Backend sync helpers
// ---------------------------------------------------------------------------

function isValidCustomThemes(obj: unknown): obj is Record<string, Theme> {
  if (typeof obj !== 'object' || obj === null) return false
  for (const theme of Object.values(obj as Record<string, any>)) {
    if (!theme.name || !theme.displayName || !theme.colors) return false
  }
  return true
}

// ---------------------------------------------------------------------------

export function ThemeProvider({ children }: ThemeProviderProps) {
  // Start with localStorage values for instant paint, then sync from backend
  const [customThemes, setCustomThemes] = useState<Record<string, Theme>>(() => loadCustomThemesLocal())
  const [theme, setThemeState] = useState<string>(() => {
    return localStorage.getItem(ACTIVE_THEME_KEY) || defaultTheme
  })

  // Track whether we've completed the initial backend load
  const loadedFromBackend = useRef(false)

  // Ref mirror of customThemes so the stable loadPreferences callback can read
  // the current value without being recreated on every state change.
  const customThemesRef = useRef(customThemes)
  useEffect(() => {
    customThemesRef.current = customThemes
  }, [customThemes])

  // Merge built-in and custom themes
  const allThemes: Record<string, Theme> = { ...builtinThemes, ...customThemes }

  // Re-inject all theme CSS whenever custom themes change (e.g. loaded from backend)
  useEffect(() => {
    injectAllThemeCss(customThemes)
  }, [customThemes])

  // Apply active theme + persist to localStorage (instant)
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem(ACTIVE_THEME_KEY, theme)
  }, [theme])

  // Update favicon to match the active theme's accent color
  useEffect(() => {
    const activeTheme = allThemes[theme]
    if (activeTheme?.colors?.accentPrimary) {
      updateFavicon(activeTheme.colors.accentPrimary)
    }
  }, [theme, allThemes])

  // (Re)load theme + custom themes from the backend.  Runs on mount and is
  // also exposed via the context as refreshPreferences so it can be re-run
  // after login — the initial mount may run before a token exists (e.g. when
  // Safari/ITP has evicted localStorage and the user must log in fresh), in
  // which case getPreferences 401s silently and would otherwise never retry.
  const loadPreferences = useCallback(() => {
    auth.getPreferences()
      .then(res => {
        const data = res.data
        if (data.theme) {
          setThemeState(data.theme)
        }
        if (data.custom_themes && isValidCustomThemes(data.custom_themes)) {
          setCustomThemes(data.custom_themes)
          saveCustomThemesLocal(data.custom_themes)
        } else if (Object.keys(customThemesRef.current).length > 0) {
          // Backend has no custom themes but localStorage does (e.g. created
          // before backend sync was added). Push them to the backend so they
          // sync across browsers.
          auth.updatePreferences({ custom_themes: customThemesRef.current }).catch(() => {})
        }
        loadedFromBackend.current = true
      })
      .catch(() => {
        // Not logged in or API unavailable — keep localStorage values
        loadedFromBackend.current = true
      })
  }, [])

  // Load preferences from backend on mount
  useEffect(() => {
    loadPreferences()
  }, [loadPreferences])

  // Debounced save refs
  const themeSaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const customThemesSaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const setTheme = useCallback((newTheme: string) => {
    setThemeState(newTheme)
    // Debounced save to backend
    if (themeSaveTimer.current) clearTimeout(themeSaveTimer.current)
    themeSaveTimer.current = setTimeout(() => {
      auth.updatePreferences({ theme: newTheme }).catch(() => {})
    }, 500)
  }, [])

  const saveCustomTheme = useCallback((t: Theme) => {
    setCustomThemes(prev => {
      const next = { ...prev, [t.name]: t }
      saveCustomThemesLocal(next)
      // Debounced save to backend
      if (customThemesSaveTimer.current) clearTimeout(customThemesSaveTimer.current)
      customThemesSaveTimer.current = setTimeout(() => {
        auth.updatePreferences({ custom_themes: next }).catch(() => {})
      }, 500)
      return next
    })
    // Activate the newly saved theme
    setThemeState(t.name)
    if (themeSaveTimer.current) clearTimeout(themeSaveTimer.current)
    themeSaveTimer.current = setTimeout(() => {
      auth.updatePreferences({ theme: t.name }).catch(() => {})
    }, 500)
  }, [])

  const deleteCustomTheme = useCallback((name: string) => {
    setCustomThemes(prev => {
      const next = { ...prev }
      delete next[name]
      saveCustomThemesLocal(next)
      // Debounced save to backend
      if (customThemesSaveTimer.current) clearTimeout(customThemesSaveTimer.current)
      customThemesSaveTimer.current = setTimeout(() => {
        auth.updatePreferences({ custom_themes: next }).catch(() => {})
      }, 500)
      return next
    })
    // If the deleted theme was active, fall back to default
    setThemeState(prev => {
      if (prev === name) {
        const fallback = defaultTheme
        if (themeSaveTimer.current) clearTimeout(themeSaveTimer.current)
        themeSaveTimer.current = setTimeout(() => {
          auth.updatePreferences({ theme: fallback }).catch(() => {})
        }, 500)
        return fallback
      }
      return prev
    })
  }, [])

  const isBuiltinTheme = useCallback(
    (name: string) => name in builtinThemes,
    [],
  )

  return (
    <ThemeContext.Provider
      value={{
        theme,
        setTheme,
        allThemes,
        customThemes,
        saveCustomTheme,
        deleteCustomTheme,
        isBuiltinTheme,
        refreshPreferences: loadPreferences,
      }}
    >
      {children}
    </ThemeContext.Provider>
  )
}
