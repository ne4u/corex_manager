/// <reference types="vitest/globals" />
/// <reference types="@testing-library/jest-dom/vitest" />
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import SecurityRules from '../SecurityRules'

const rule = {
  id: 1,
  name: 'Block WP logins',
  enabled: true,
  priority: 0,
  listener_ids: [],
  expression: 'http.request.uri.path = "/wp-login.php"',
  expression_ast: null,
  action: 'block',
  log: true,
  no_log: false,
  status_code: 403,
  created_at: '2026-08-04T00:00:00Z',
  updated_at: '2026-08-04T00:00:00Z',
}

const listener = { id: 1, name: 'http_in', enabled: true }

vi.mock('../../services/api', () => ({
  securityRules: {
    list: vi.fn(() => Promise.resolve({ data: [rule] })),
    create: vi.fn(() => Promise.resolve({ data: rule })),
    update: vi.fn(() => Promise.resolve({ data: rule })),
    remove: vi.fn(() => Promise.resolve({ data: {} })),
    reorder: vi.fn(() => Promise.resolve({ data: {} })),
    validate: vi.fn(() => Promise.resolve({ data: { ok: true, ast: null, error: null } })),
  },
  listeners: {
    list: vi.fn(() => Promise.resolve({ data: [listener] })),
  },
  errorPages: {
    list: vi.fn(() => Promise.resolve({ data: [] })),
  },
  securityLists: {
    network: { list: vi.fn(() => Promise.resolve({ data: [] })) },
    asn: { list: vi.fn(() => Promise.resolve({ data: [] })) },
    geo: { list: vi.fn(() => Promise.resolve({ data: [] })) },
    ja4: { list: vi.fn(() => Promise.resolve({ data: [] })) },
    pattern: { list: vi.fn(() => Promise.resolve({ data: [] })) },
  },
  riskRulesets: {
    list: vi.fn(() => Promise.resolve({ data: [
      { id: 1, name: 'Default', slug: 'default', description: '', enabled: true, priority: 0, rule_count: 0, created_at: '', updated_at: '' },
    ] })),
  },
  getErrorDetail: vi.fn((e: unknown) => String(e)),
}))

describe('SecurityRules page', () => {
  it('renders the security rules list', async () => {
    render(
      <MemoryRouter>
        <SecurityRules />
      </MemoryRouter>
    )
    await waitFor(() => {
      expect(screen.getByText('Block WP logins')).toBeInTheDocument()
    })
    expect(screen.getAllByText('Security Rules').length).toBeGreaterThan(0)
  })

  it('renders the execution order banner', async () => {
    render(
      <MemoryRouter>
        <SecurityRules />
      </MemoryRouter>
    )
    await waitFor(() => {
      expect(screen.getByText('Execution order:')).toBeInTheDocument()
    })
    expect(screen.getByText('Rate Limiting')).toBeInTheDocument()
    expect(screen.getByText('WAF Signatures')).toBeInTheDocument()
  })

  it('shows the Add Rule button', async () => {
    render(
      <MemoryRouter>
        <SecurityRules />
      </MemoryRouter>
    )
    await waitFor(() => {
      expect(screen.getByText('Add Rule')).toBeInTheDocument()
    })
  })

  it('displays rule action badge', async () => {
    render(
      <MemoryRouter>
        <SecurityRules />
      </MemoryRouter>
    )
    await waitFor(() => {
      expect(screen.getByText('Block')).toBeInTheDocument()
    })
  })

  it('switches to builder tab in Add Rule modal without locking up', async () => {
    render(
      <MemoryRouter>
        <SecurityRules />
      </MemoryRouter>
    )
    await waitFor(() => {
      expect(screen.getByText('Add Rule')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Add Rule'))
    expect(screen.getByText('Add Security Rule')).toBeInTheDocument()

    // Click Builder tab
    const builderTab = screen.getByRole('button', { name: /builder/i })
    fireEvent.click(builderTab)

    expect(screen.getByText('+ Add condition')).toBeInTheDocument()
    expect(screen.getByText('+ Add OR group')).toBeInTheDocument()
  })

  it('switches to builder tab in Edit Rule modal and displays parsed condition', async () => {
    render(
      <MemoryRouter>
        <SecurityRules />
      </MemoryRouter>
    )
    await waitFor(() => {
      expect(screen.getByText('Block WP logins')).toBeInTheDocument()
    })

    const editBtn = screen.getByRole('button', { name: /edit/i })
    fireEvent.click(editBtn)

    expect(screen.getByText('Edit Security Rule')).toBeInTheDocument()

    // Click Builder tab
    const builderTab = screen.getByRole('button', { name: /builder/i })
    fireEvent.click(builderTab)

    // Should not freeze and should show the parsed condition elements
    expect(screen.getByDisplayValue('/wp-login.php')).toBeInTheDocument()
    expect(screen.getByText('+ Add condition')).toBeInTheDocument()
  })
})
