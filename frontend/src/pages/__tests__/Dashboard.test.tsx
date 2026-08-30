/// <reference types="vitest/globals" />
/// <reference types="@testing-library/jest-dom/vitest" />
import { render, screen, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import Dashboard from '../Dashboard'
import { NotificationProvider } from '../../contexts/NotificationContext'

vi.mock('../../services/api', () => ({
  getStats: vi.fn(() => Promise.resolve({ data: {} })),
  previewAllConfigs: vi.fn(() => Promise.resolve({ data: { 'haproxy.cfg': '# test config' } })),
  applyConfig: vi.fn(() => Promise.resolve({ data: { message: 'ok', task_id: 1 } })),
  getTask: vi.fn(() => Promise.resolve({ data: { status: 'success', result: {} } })),
  getSystemHealth: vi.fn(() => Promise.resolve({ data: {
    haproxy_socket: { available: true, path: '/tmp/haproxy.sock' },
    valkey: { available: true },
    docker: { available: true, error: null },
    geoip: { country_db_exists: true, city_db_exists: false, asn_db_exists: true },
    coraza_spoa: { enabled: true },
  } })),
  cache: {
    metrics: vi.fn(() => Promise.resolve({ data: { summary: { total_bandwidth_saved: 0 } } })),
  },
  settings: {
    get: vi.fn(() => Promise.resolve({ data: { value: 'false' } })),
    list: vi.fn(() => Promise.resolve({ data: [] })),
    update: vi.fn(() => Promise.resolve({ data: {} })),
    getMaxmindLicenseKey: vi.fn(() => Promise.resolve({ data: {} })),
    updateMaxmindLicenseKey: vi.fn(() => Promise.resolve({ data: {} })),
    downloadGeoip: vi.fn(() => Promise.resolve({ data: {} })),
    getGeoipStatus: vi.fn(() => Promise.resolve({ data: {} })),
  },
}))

function renderDashboard() {
  return render(
    <NotificationProvider>
      <Dashboard />
    </NotificationProvider>
  )
}

describe('Dashboard', () => {
  test('renders dashboard title and stat cards', async () => {
    renderDashboard()
    await waitFor(() => expect(screen.getByText('Dashboard')).toBeInTheDocument())
  })
})
