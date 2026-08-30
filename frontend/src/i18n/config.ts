/**
 * i18next initialization.
 *
 * Locales are loaded lazily from /public/locales/{lng}/{ns}.json via
 * i18next-http-backend. The browser-language detector seeds the initial
 * language from localStorage (if present) or navigator.languages; the
 * LanguageProvider then overrides once the backend preference loads.
 */
import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import HttpBackend from 'i18next-http-backend'
import LanguageDetector from 'i18next-browser-languagedetector'

import { DEFAULT_LANGUAGE, SUPPORTED_LANGUAGE_CODES } from './languages'

export const I18N_NAMESPACES = ['common', 'nav', 'auth', 'profile', 'settings', 'pages'] as const
export type I18nNamespace = (typeof I18N_NAMESPACES)[number]

void i18n
  .use(HttpBackend)
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: DEFAULT_LANGUAGE,
    supportedLngs: SUPPORTED_LANGUAGE_CODES,
    load: 'languageOnly',
    ns: I18N_NAMESPACES,
    defaultNS: 'common',
    backend: {
      loadPath: '/locales/{{lng}}/{{ns}}.json',
    },
    detection: {
      // localStorage first (returning users), then browser navigator (first visit).
      order: ['localStorage', 'navigator'],
      lookupLocalStorage: 'language',
      // We cache manually in LanguageProvider to keep it in sync with the backend.
      caches: [],
      convertDetectedLanguage: (l: string) => l.split('-')[0],
    },
    interpolation: {
      escapeValue: false, // React escapes by default
    },
    returnNull: false, // missing keys fall back cleanly
    react: {
      useSuspense: false, // don't suspend; show fallback strings while loading
    },
  })

export default i18n
