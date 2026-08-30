/// <reference types="vitest/globals" />
import '@testing-library/jest-dom/vitest'
import { readFileSync } from 'fs'
import { join } from 'path'
import i18n from './i18n/config'
import { I18N_NAMESPACES } from './i18n/config'

// jsdom may not provide localStorage for opaque origins. Ensure a working
// localStorage mock is always available.
if (!globalThis.localStorage) {
  const store = new Map<string, string>()
  const localStorageMock: Storage = {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => { store.set(key, String(value)) },
    removeItem: (key: string) => { store.delete(key) },
    clear: () => { store.clear() },
    key: (index: number) => Array.from(store.keys())[index] ?? null,
    get length() { return store.size },
  }
  Object.defineProperty(globalThis, 'localStorage', {
    value: localStorageMock,
    writable: true,
    configurable: true,
  })
}

// In the test environment (jsdom) there is no HTTP server serving locale
// files, so i18next-http-backend cannot load them. We pre-load the English
// resources directly from the JSON files and add them to the i18n store
// before any test runs. This makes `t()` return the English strings just
// like in the browser.
const localesDir = join(process.cwd(), 'public', 'locales', 'en')
for (const ns of I18N_NAMESPACES) {
  try {
    const raw = readFileSync(join(localesDir, `${ns}.json`), 'utf-8')
    i18n.addResourceBundle('en', ns, JSON.parse(raw), true, true)
  } catch {
    // namespace file may not exist yet; skip silently
  }
}
void i18n.changeLanguage('en')
