/// <reference types="vitest/globals" />
/// <reference types="@testing-library/jest-dom/vitest" />
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'
import PageProtect from '../PageProtect'
import { NotificationProvider } from '../../contexts/NotificationContext'

vi.mock('../../services/api', () => ({
  pageProtect: {
    settings: {
      get: vi.fn(() => Promise.resolve({ data: { monitoring_enabled: false, change_detection_enabled: false, change_detection_interval_hours: 24, report_retention_days: 7, report_path: '/_csp-report', beacon_injection_enabled: false, beacon_path: '/_asset-beacon', beacon_script_path: '/_asset-beacon.js', beacon_content_types: 'text/html', beacon_path_patterns: '', beacon_backend_ids: [], auto_prune_stale_days: 7 } })),
      update: vi.fn(() => Promise.resolve({ data: {} })),
    },
    sample: vi.fn(() => Promise.resolve({ data: { stored: 5 } })),
    policies: {
      list: vi.fn(() => Promise.resolve({ data: [] })),
      create: vi.fn(() => Promise.resolve({ data: {} })),
      update: vi.fn(() => Promise.resolve({ data: {} })),
      remove: vi.fn(() => Promise.resolve({ data: {} })),
    },
    reports: {
      list: vi.fn(() => Promise.resolve({ data: [] })),
      export: vi.fn(() => Promise.resolve({ data: '' })),
      clear: vi.fn(() => Promise.resolve({ data: {} })),
    },
    scripts: {
      list: vi.fn(() => Promise.resolve({ data: [] })),
      create: vi.fn(() => Promise.resolve({ data: {} })),
      update: vi.fn(() => Promise.resolve({ data: {} })),
      remove: vi.fn(() => Promise.resolve({ data: {} })),
      check: vi.fn(() => Promise.resolve({ data: {} })),
      resetHash: vi.fn(() => Promise.resolve({ data: {} })),
      checkAll: vi.fn(() => Promise.resolve({ data: {} })),
    },
    stats: vi.fn(() => Promise.resolve({ data: { total_scripts: 0, total_reports: 0, changed_scripts: 0, active_policies: 0, reports_24h: 0, top_violated_directives: [], top_blocked_uris: [] } })),
  },
  backends: {
    list: vi.fn(() => Promise.resolve({ data: [] })),
  },
  getErrorDetail: vi.fn((e: unknown) => String(e)),
}))

function renderPage() {
  return render(
    <NotificationProvider>
      <PageProtect />
    </NotificationProvider>
  )
}

describe('PageProtect', () => {
  it('renders the page title', async () => {
    renderPage()
    expect(screen.getByText('Page Armor')).toBeInTheDocument()
  })

  it('renders all 5 tabs', async () => {
    renderPage()
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Policies')).toBeInTheDocument()
    expect(screen.getByText('Inventory')).toBeInTheDocument()
    expect(screen.getByText('Reports')).toBeInTheDocument()
    expect(screen.getByText('Settings')).toBeInTheDocument()
  })

  it('shows dashboard stats cards on dashboard tab', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Total Scripts')).toBeInTheDocument()
      expect(screen.getByText('Violations (24h)')).toBeInTheDocument()
      expect(screen.getByText('Changed Scripts')).toBeInTheDocument()
      expect(screen.getByText('Active Policies')).toBeInTheDocument()
    })
  })

  it('switches to policies tab', async () => {
    renderPage()
    screen.getByText('Policies').click()
    await waitFor(() => {
      expect(screen.getByText('CSP Policies')).toBeInTheDocument()
      expect(screen.getByText('Add Policy')).toBeInTheDocument()
    })
  })

  it('switches to settings tab', async () => {
    renderPage()
    screen.getByText('Settings').click()
    await waitFor(() => {
      expect(screen.getByText('Page Armor Settings')).toBeInTheDocument()
    })
  })

  it('triggers a manual report sample from the settings tab', async () => {
    const user = userEvent.setup()
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})
    renderPage()
    await user.click(screen.getByText('Settings'))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sample reports now/i })).toBeInTheDocument()
    })
    await user.click(screen.getByRole('button', { name: /sample reports now/i }))
    await waitFor(() => {
      expect(alertSpy).toHaveBeenCalled()
    })
    alertSpy.mockRestore()
  })

  it('defaults new CSP directives to default-src', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByText('Policies'))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /add policy/i })).toBeInTheDocument()
    })
    await user.click(screen.getByRole('button', { name: /add policy/i }))
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /add policy/i })).toBeInTheDocument()
    })
    await user.click(screen.getByRole('button', { name: /add directive/i }))
    expect(screen.getByDisplayValue('default-src')).toBeInTheDocument()
  })
})
