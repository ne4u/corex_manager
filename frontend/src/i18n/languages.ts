/**
 * Supported UI languages and helpers.
 *
 * English is the default. Proper nouns (HAProxy, Coraza, WAF, TOTP, etc.)
 * stay in English in every language. The flag + native + English name are
 * shown in the selector so a user who accidentally picks an unreadable
 * language can navigate back by recognizing a known flag/name.
 */

export interface LanguageMeta {
  code: string
  /** Flag emoji shown in the selector. */
  flag: string
  /** Language name in the language itself (e.g. "Español"). */
  nativeName: string
  /** Language name in English (e.g. "Spanish"). */
  englishName: string
  /** Text direction. */
  dir: 'ltr' | 'rtl'
}

export const LANGUAGES: LanguageMeta[] = [
  { code: 'en', flag: '🇬🇧', nativeName: 'English', englishName: 'English', dir: 'ltr' },
  { code: 'es', flag: '🇪🇸', nativeName: 'Español', englishName: 'Spanish', dir: 'ltr' },
  { code: 'fr', flag: '🇫🇷', nativeName: 'Français', englishName: 'French', dir: 'ltr' },
  { code: 'de', flag: '🇩🇪', nativeName: 'Deutsch', englishName: 'German', dir: 'ltr' },
  { code: 'pt', flag: '🇵🇹', nativeName: 'Português', englishName: 'Portuguese', dir: 'ltr' },
  { code: 'it', flag: '🇮🇹', nativeName: 'Italiano', englishName: 'Italian', dir: 'ltr' },
  { code: 'ru', flag: '🇷🇺', nativeName: 'Русский', englishName: 'Russian', dir: 'ltr' },
  { code: 'ja', flag: '🇯🇵', nativeName: '日本語', englishName: 'Japanese', dir: 'ltr' },
  { code: 'ko', flag: '🇰🇷', nativeName: '한국어', englishName: 'Korean', dir: 'ltr' },
  { code: 'zh', flag: '🇨🇳', nativeName: '中文 (简体)', englishName: 'Chinese (Simplified)', dir: 'ltr' },
  { code: 'ar', flag: '🇸🇦', nativeName: 'العربية', englishName: 'Arabic', dir: 'rtl' },
  { code: 'hi', flag: '🇮🇳', nativeName: 'हिन्दी', englishName: 'Hindi', dir: 'ltr' },
]

export const DEFAULT_LANGUAGE = 'en'

export const SUPPORTED_LANGUAGE_CODES: string[] = LANGUAGES.map((l) => l.code)

export const RTL_LANGUAGES: string[] = LANGUAGES.filter((l) => l.dir === 'rtl').map((l) => l.code)

const LANGUAGE_BY_CODE: Record<string, LanguageMeta> = Object.fromEntries(
  LANGUAGES.map((l) => [l.code, l]),
)

export function getLanguageMeta(code: string): LanguageMeta | undefined {
  return LANGUAGE_BY_CODE[code]
}

export function getLanguageDir(code: string): 'ltr' | 'rtl' {
  return LANGUAGE_BY_CODE[code]?.dir ?? 'ltr'
}

export function isSupportedLanguage(code: string): boolean {
  return code in LANGUAGE_BY_CODE
}

/**
 * Pick the best supported language from the browser's Accept-Language
 * preference (exposed client-side as `navigator.languages`).
 * Returns the first matching base code, or the default language.
 */
export function detectBrowserLanguage(): string {
  const candidates =
    typeof navigator !== 'undefined' && navigator.languages?.length
      ? navigator.languages
      : typeof navigator !== 'undefined' && navigator.language
        ? [navigator.language]
        : []
  for (const c of candidates) {
    if (!c) continue
    const base = c.toLowerCase().split('-')[0]
    if (isSupportedLanguage(base)) return base
  }
  return DEFAULT_LANGUAGE
}
