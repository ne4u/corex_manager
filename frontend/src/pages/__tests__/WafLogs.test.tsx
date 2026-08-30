/// <reference types="vitest/globals" />
/// <reference types="@testing-library/jest-dom/vitest" />
import { render, screen, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { I18nextProvider } from 'react-i18next'
import i18n from '../../i18n/config'
import WafLogs from '../WafLogs'

vi.mock('../../services/api', () => ({
  waf: {
    logs: vi.fn(() => Promise.resolve({ data: { events: [
      { time: '2024-01-01T00:00:00Z', unique_id: 'WAF-ABC-123', action: 'deny', rule_id: '123', severity: 'CRITICAL', client: '1.2.3.4', uri: '/admin', msg: 'SQLi' },
    ] } })),
  },
}))

describe('WafLogs page', () => {
  test('renders WAF live logs table', async () => {
    render(
      <I18nextProvider i18n={i18n}>
        <WafLogs />
      </I18nextProvider>,
    )
    await waitFor(() => expect(screen.getByText('SQLi')).toBeInTheDocument())
    expect(screen.getByText('WAF-ABC-123')).toBeInTheDocument()
    expect(screen.getByText('deny')).toBeInTheDocument()
    expect(screen.getByText('/admin')).toBeInTheDocument()
  })
})
