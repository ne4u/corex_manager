/// <reference types="vitest/globals" />
/// <reference types="@testing-library/jest-dom/vitest" />
import { render, screen, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import Waf from '../Waf'

vi.mock('../../services/api', () => ({
  wafRules: {
    list: vi.fn(() => Promise.resolve({ data: [
      { id: 1, name: 'block-xss', listener_id: 1, backend_id: null, rule_set: 'coraza', rule_set_version: null, engine: 'On', paranoia_level: 1, action: 'block', enabled: true },
    ] })),
    create: vi.fn(() => Promise.resolve({ data: { id: 2 } })),
    update: vi.fn(() => Promise.resolve({ data: {} })),
    remove: vi.fn(() => Promise.resolve({ data: {} })),
    export: vi.fn(() => Promise.resolve({ data: { rules: [], exceptions: [] } })),
    import: vi.fn(() => Promise.resolve({ data: {} })),
  },
  wafExceptions: {
    list: vi.fn(() => Promise.resolve({ data: [
      { id: 1, waf_rule_id: 1, name: 'allow-admin', rule_id: '', rule_tag: '', rule_msg: '', action: 'remove' },
    ] })),
    create: vi.fn(() => Promise.resolve({ data: {} })),
    update: vi.fn(() => Promise.resolve({ data: {} })),
    remove: vi.fn(() => Promise.resolve({ data: {} })),
  },
  listeners: {
    list: vi.fn(() => Promise.resolve({ data: [
      { id: 1, name: 'http-80', bind_address: '0.0.0.0', bind_port: 80, protocol: 'http', mode: 'http' },
    ] })),
  },
  backends: {
    list: vi.fn(() => Promise.resolve({ data: [] })),
  },
  waf: {
    health: vi.fn(() => Promise.resolve({ data: { status: 'ok', coraza_spoa_reachable: true, config_present: true } })),
    logs: vi.fn(() => Promise.resolve({ data: [] })),
    siem: {
      list: vi.fn(() => Promise.resolve({ data: [] })),
      create: vi.fn(() => Promise.resolve({ data: {} })),
      update: vi.fn(() => Promise.resolve({ data: {} })),
      remove: vi.fn(() => Promise.resolve({ data: {} })),
    },
    ruleVersions: {
      list: vi.fn(() => Promise.resolve({ data: [] })),
      snapshot: vi.fn(() => Promise.resolve({ data: {} })),
      restore: vi.fn(() => Promise.resolve({ data: {} })),
      remove: vi.fn(() => Promise.resolve({ data: { status: 'ok' } })),
      getMax: vi.fn(() => Promise.resolve({ data: { value: '10' } })),
      setMax: vi.fn(() => Promise.resolve({ data: { value: '10' } })),
    },
  },
  settings: {
    getGeoipStatus: vi.fn(() => Promise.resolve({ data: { databases: [] } })),
  },
}))

function renderWaf() {
  return render(
    <MemoryRouter>
      <Waf />
    </MemoryRouter>,
  )
}

describe('Waf page', () => {
  test('renders WAF rules list', async () => {
    renderWaf()
    await waitFor(() => expect(screen.getByText('WAF Signatures')).toBeInTheDocument())
    await waitFor(() => expect(screen.getByText('block-xss')).toBeInTheDocument())
    expect(screen.getByText('On')).toBeInTheDocument()
    expect(screen.getByText('block')).toBeInTheDocument()
  })

  test('switches to Exceptions tab', async () => {
    renderWaf()
    await waitFor(() => expect(screen.getByText('WAF Signatures')).toBeInTheDocument())
    const user = userEvent.setup()
    const exceptionsTab = screen.getByRole('button', { name: /Exceptions/i })
    await user.click(exceptionsTab)
    await waitFor(() => expect(screen.getByText('allow-admin')).toBeInTheDocument())
  })

  test('opens the Add Rule modal', async () => {
    renderWaf()
    await waitFor(() => expect(screen.getByText('WAF Signatures')).toBeInTheDocument())
    const user = userEvent.setup()
    const addButton = screen.getByRole('button', { name: /Add Rule/i })
    await user.click(addButton)
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Add WAF Rule' })).toBeInTheDocument())
  })

  test('renders the Versions tab with max editor', async () => {
    renderWaf()
    await waitFor(() => expect(screen.getByText('WAF Signatures')).toBeInTheDocument())
    const user = userEvent.setup()
    const versionsTab = screen.getByRole('button', { name: /Versions/i })
    await user.click(versionsTab)
    await waitFor(() => expect(screen.getByText('Rule Snapshots')).toBeInTheDocument())
    await waitFor(() => expect(screen.getByPlaceholderText('10')).toBeInTheDocument())
    expect(screen.getByText(/0 = unlimited/)).toBeInTheDocument()
  })
})
