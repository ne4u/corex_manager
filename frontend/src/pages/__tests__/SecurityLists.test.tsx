/// <reference types="vitest/globals" />
/// <reference types="@testing-library/jest-dom/vitest" />
import { render, screen, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import SecurityLists from '../SecurityLists'

const networkList = { id: 1, name: 'blocklist', description: 'bad actors', entry_count: 2, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-08-04T12:00:00Z' }
const networkEntries = [
  { id: 10, list_id: 1, value: '10.0.0.1', note: 'scanner', created_at: '' },
  { id: 11, list_id: 1, value: '10.0.0.0/24', note: null, created_at: '' },
]

vi.mock('../../services/api', () => ({
  securityLists: {
    network: {
      list: vi.fn(() => Promise.resolve({ data: [networkList] })),
      create: vi.fn(() => Promise.resolve({ data: networkList })),
      update: vi.fn(() => Promise.resolve({ data: networkList })),
      remove: vi.fn(() => Promise.resolve({ data: {} })),
      entries: {
        list: vi.fn(() => Promise.resolve({ data: networkEntries })),
        create: vi.fn(() => Promise.resolve({ data: { id: 12, list_id: 1, value: '10.0.0.5', note: '', created_at: '' } })),
        update: vi.fn(() => Promise.resolve({ data: {} })),
        remove: vi.fn(() => Promise.resolve({ data: {} })),
      },
    },
    asn: {
      list: vi.fn(() => Promise.resolve({ data: [] })),
      create: vi.fn(() => Promise.resolve({ data: {} })),
      update: vi.fn(() => Promise.resolve({ data: {} })),
      remove: vi.fn(() => Promise.resolve({ data: {} })),
      entries: {
        list: vi.fn(() => Promise.resolve({ data: [] })),
        create: vi.fn(() => Promise.resolve({ data: {} })),
        update: vi.fn(() => Promise.resolve({ data: {} })),
        remove: vi.fn(() => Promise.resolve({ data: {} })),
      },
    },
    geo: (() => {
      const geoEntries = [
        { id: 30, list_id: 3, value: 'US', note: 'bad', created_at: '' },
      ]
      return {
        list: vi.fn(() => Promise.resolve({ data: [
          { id: 3, name: 'geo-blocklist', description: 'bad regions', entry_count: 1, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-08-04T12:00:00Z' },
        ] })),
        create: vi.fn(() => Promise.resolve({ data: {} })),
        update: vi.fn(() => Promise.resolve({ data: {} })),
        remove: vi.fn(() => Promise.resolve({ data: {} })),
        countries: vi.fn(() => Promise.resolve({ data: [
          { code: 'US', name: 'United States of America (the)' },
          { code: 'GB', name: 'United Kingdom of Great Britain and Northern Ireland (the)' },
        ] })),
        entries: {
          list: vi.fn(() => Promise.resolve({ data: geoEntries })),
          create: vi.fn((_lid: number, data: { value: string; note?: string }) => {
            geoEntries.push({ id: 31, list_id: 3, value: data.value, note: data.note || '', created_at: '' })
            return Promise.resolve({ data: { id: 31, list_id: 3, value: data.value, note: data.note || '', created_at: '' } })
          }),
          update: vi.fn(() => Promise.resolve({ data: {} })),
          remove: vi.fn(() => Promise.resolve({ data: {} })),
        },
      }
    })(),
    ja4: {
      list: vi.fn(() => Promise.resolve({ data: [
        { id: 2, name: 'ja4-blocklist', description: 'suspicious clients', entry_count: 1, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-08-04T12:00:00Z' },
      ] })),
      create: vi.fn(() => Promise.resolve({ data: {} })),
      update: vi.fn(() => Promise.resolve({ data: {} })),
      remove: vi.fn(() => Promise.resolve({ data: {} })),
      entries: {
        list: vi.fn(() => Promise.resolve({ data: [
          { id: 20, list_id: 2, value: 't13d1516h2_8daaf6152771_b186095e22b6', note: 'bot', created_at: '' },
        ] })),
        create: vi.fn(() => Promise.resolve({ data: {} })),
        update: vi.fn(() => Promise.resolve({ data: {} })),
        remove: vi.fn(() => Promise.resolve({ data: {} })),
      },
    },
    pattern: {
      list: vi.fn(() => Promise.resolve({ data: [] })),
      create: vi.fn(() => Promise.resolve({ data: {} })),
      update: vi.fn(() => Promise.resolve({ data: {} })),
      remove: vi.fn(() => Promise.resolve({ data: {} })),
      entries: {
        list: vi.fn(() => Promise.resolve({ data: [] })),
        create: vi.fn(() => Promise.resolve({ data: {} })),
        update: vi.fn(() => Promise.resolve({ data: {} })),
        remove: vi.fn(() => Promise.resolve({ data: {} })),
      },
    },
    feeds: {
      list: vi.fn(() => Promise.resolve({ data: [
        { id: 5, name: 'threat-feed', list_type: 'network', url: 'http://example.com/feed.txt', update_interval_hours: 12, description: '', enabled: true, target_list_id: 1, last_updated_at: '2026-08-04T12:00:00Z', last_error: null, last_entry_count: 2, created_at: '', updated_at: '' },
      ] })),
      create: vi.fn(() => Promise.resolve({ data: {} })),
      update: vi.fn(() => Promise.resolve({ data: {} })),
      remove: vi.fn(() => Promise.resolve({ data: {} })),
      refresh: vi.fn(() => Promise.resolve({ data: {} })),
    },
  },
  getErrorDetail: (err: unknown, fallback = 'Request failed') => {
    if (err instanceof Error) return err.message
    return fallback
  },
}))

function renderPage() {
  return render(
    <MemoryRouter>
      <SecurityLists />
    </MemoryRouter>,
  )
}

describe('SecurityLists page', () => {
  test('renders the Network list tab with lists', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('Security Lists')).toBeInTheDocument())
    await waitFor(() => expect(screen.getByText('blocklist')).toBeInTheDocument())
    expect(screen.getByText('bad actors')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument() // entry count
    expect(screen.getByText('Last Updated')).toBeInTheDocument() // column header
  })

  test('opens the Add List modal', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('blocklist')).toBeInTheDocument())
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: /Add List/i }))
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Add List' })).toBeInTheDocument())
  })

  test('selecting a list shows its entries', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('blocklist')).toBeInTheDocument())
    const user = userEvent.setup()
    await user.click(screen.getByText('blocklist'))
    await waitFor(() => expect(screen.getByText('10.0.0.1')).toBeInTheDocument())
    expect(screen.getByText('10.0.0.0/24')).toBeInTheDocument()
    expect(screen.getByText('scanner')).toBeInTheDocument()
  })

  test('switches to Threat Feeds tab', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('blocklist')).toBeInTheDocument())
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: /Threat Feeds/i }))
    await waitFor(() => expect(screen.getByText('threat-feed')).toBeInTheDocument())
  })

  test('View button on a feed opens the entries modal', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('blocklist')).toBeInTheDocument())
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: /Threat Feeds/i }))
    await waitFor(() => expect(screen.getByText('threat-feed')).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: /View/i }))
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Entries: threat-feed' })).toBeInTheDocument())
    await waitFor(() => expect(screen.getByText('10.0.0.1')).toBeInTheDocument())
    expect(screen.getByText('10.0.0.0/24')).toBeInTheDocument()
  })

  test('switches to JA4 tab and shows JA4 lists', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('blocklist')).toBeInTheDocument())
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: /^JA4$/i }))
    await waitFor(() => expect(screen.getByText('ja4-blocklist')).toBeInTheDocument())
    expect(screen.getByText('suspicious clients')).toBeInTheDocument()
  })

  test('selecting a JA4 list shows its entries', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('blocklist')).toBeInTheDocument())
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: /^JA4$/i }))
    await waitFor(() => expect(screen.getByText('ja4-blocklist')).toBeInTheDocument())
    await user.click(screen.getByText('ja4-blocklist'))
    await waitFor(() => expect(screen.getByText('t13d1516h2_8daaf6152771_b186095e22b6')).toBeInTheDocument())
    expect(screen.getByText('bot')).toBeInTheDocument()
  })

  test('switches to GeoIP tab and shows country names with codes', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('blocklist')).toBeInTheDocument())
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: /^GeoIP$/i }))
    await waitFor(() => expect(screen.getByText('geo-blocklist')).toBeInTheDocument())
    await user.click(screen.getByText('geo-blocklist'))
    await waitFor(() => expect(screen.getByText(/United States of America.*\(US\)/)).toBeInTheDocument())
    expect(screen.getByText('bad')).toBeInTheDocument()
  })

  test('adds a GeoIP entry using the country autocomplete', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('blocklist')).toBeInTheDocument())
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: /^GeoIP$/i }))
    await waitFor(() => expect(screen.getByText('geo-blocklist')).toBeInTheDocument())
    await user.click(screen.getByText('geo-blocklist'))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Add Entry' })).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'Add Entry' }))
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Add Entry' })).toBeInTheDocument())
    const input = screen.getByPlaceholderText('Search country...')
    await user.type(input, 'United Kingdom')
    await user.click(screen.getByText('United Kingdom of Great Britain and Northern Ireland (the)'))
    await waitFor(() => expect(input).toHaveValue('United Kingdom of Great Britain and Northern Ireland (the) (GB)'))
    await user.click(screen.getByRole('button', { name: /Save/i }))
    await waitFor(() => expect(screen.getByText(/United Kingdom.*\(GB\)/)).toBeInTheDocument())
  })
})
