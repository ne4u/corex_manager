import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { I18nextProvider } from 'react-i18next'
import i18n from '../../i18n/config'

// Mock the API
vi.mock('../../services/api', () => ({
  auth: {
    me: vi.fn(() => Promise.resolve({ data: { id: 1, username: 'testuser', role: 'admin', is_admin: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z' } })),
    getPreferences: vi.fn(() => Promise.resolve({ data: { theme: null, custom_themes: null, language: 'en' } })),
    updatePreferences: vi.fn(() => Promise.resolve({ data: {} })),
    changePassword: vi.fn(() => Promise.resolve({ data: { status: 'ok' } })),
  },
  totp: {
    setup: vi.fn(() => Promise.resolve({ data: { secret: 'test', provisioning_uri: 'otpauth://test', qr_code: 'data:image/svg+xml;base64,test' } })),
    verify: vi.fn(() => Promise.resolve({ data: { status: 'ok', enabled: true } })),
    disable: vi.fn(() => Promise.resolve({ data: { status: 'ok', enabled: false } })),
  },
}))

// Mock the theme context
vi.mock('../../themes/useTheme', () => ({
  useTheme: () => ({
    theme: 'slate-dark',
    setTheme: vi.fn(),
    allThemes: {},
    customThemes: {},
    saveCustomTheme: vi.fn(),
    deleteCustomTheme: vi.fn(),
    isBuiltinTheme: vi.fn(() => true),
    refreshPreferences: vi.fn(),
  }),
}))

// Mock the language context
vi.mock('../../contexts/LanguageContext', () => ({
  useLanguage: () => ({
    language: 'en',
    setLanguage: vi.fn(),
    dir: 'ltr' as const,
    languages: [
      { code: 'en', flag: '🇬🇧', nativeName: 'English', englishName: 'English', dir: 'ltr' as const },
      { code: 'es', flag: '🇪🇸', nativeName: 'Español', englishName: 'Spanish', dir: 'ltr' as const },
      { code: 'ar', flag: '🇸🇦', nativeName: 'العربية', englishName: 'Arabic', dir: 'rtl' as const },
    ],
  }),
}))

// Mock CustomThemeEditor to avoid rendering complexity
vi.mock('../CustomThemeEditor', () => ({
  CustomThemeEditor: () => null,
}))

import ProfileDrawer from '../ProfileDrawer'

function renderDrawer() {
  return render(
    <I18nextProvider i18n={i18n}>
      <MemoryRouter>
        <ProfileDrawer />
      </MemoryRouter>
    </I18nextProvider>,
  )
}

describe('ProfileDrawer', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the floating action button', () => {
    renderDrawer()
    // The FAB is the first button — it has the UserCircle icon
    const buttons = screen.getAllByRole('button')
    expect(buttons.length).toBeGreaterThanOrEqual(1)
  })

  it('opens the drawer when FAB is clicked', async () => {
    renderDrawer()
    // The FAB is the first button in the DOM
    const fab = screen.getAllByRole('button')[0]
    fireEvent.click(fab)
    // The drawer should show the username after loading
    await waitFor(() => {
      expect(screen.getAllByText('testuser').length).toBeGreaterThanOrEqual(1)
    })
  })

  it('shows all 4 tabs when open', async () => {
    renderDrawer()
    fireEvent.click(screen.getAllByRole('button')[0])
    await waitFor(() => {
      expect(screen.getAllByText('testuser').length).toBeGreaterThanOrEqual(1)
    })
    // Check for tab labels (they are rendered as buttons in the Tabs component)
    const tabButtons = screen.getAllByRole('button')
    const tabTexts = tabButtons.map((b) => b.textContent)
    expect(tabTexts.some((t) => t && /Profile/i.test(t))).toBe(true)
    expect(tabTexts.some((t) => t && /Appearance/i.test(t))).toBe(true)
    expect(tabTexts.some((t) => t && /Security/i.test(t))).toBe(true)
    expect(tabTexts.some((t) => t && /Language/i.test(t))).toBe(true)
  })

  it('shows language cards in the Language tab', async () => {
    renderDrawer()
    fireEvent.click(screen.getAllByRole('button')[0])
    await waitFor(() => {
      expect(screen.getAllByText('testuser').length).toBeGreaterThanOrEqual(1)
    })
    // Click the Language tab — find the button whose text is "Language"
    const langTab = screen.getAllByRole('button').find((b) => b.textContent === 'Language')
    expect(langTab).toBeDefined()
    if (langTab) fireEvent.click(langTab)
    expect(screen.getAllByText('English').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('Español').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('العربية').length).toBeGreaterThanOrEqual(1)
  })

  it('shows change password form in Security tab', async () => {
    renderDrawer()
    fireEvent.click(screen.getAllByRole('button')[0])
    await waitFor(() => {
      expect(screen.getAllByText('testuser').length).toBeGreaterThanOrEqual(1)
    })
    const secTab = screen.getAllByRole('button').find((b) => b.textContent === 'Security')
    expect(secTab).toBeDefined()
    if (secTab) fireEvent.click(secTab)
    expect(screen.getAllByText('Change Password').length).toBeGreaterThanOrEqual(1)
  })
})
