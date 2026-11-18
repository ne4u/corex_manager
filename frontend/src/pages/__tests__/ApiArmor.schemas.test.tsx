/// <reference types="vitest/globals" />
/// <reference types="@testing-library/jest-dom/vitest" />
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'
import ApiArmor from '../ApiArmor'

const state = vi.hoisted(() => ({
  schemas: [] as Array<Record<string, unknown>>,
}))

const api = vi.hoisted(() => ({
  list: vi.fn(async () => ({ data: state.schemas })),
  delete: vi.fn(async (id: number) => {
    state.schemas = state.schemas.filter((s) => s.id !== id)
    return { data: { status: 'ok' } }
  }),
  deleteLearned: vi.fn(async () => {
    const deleted = state.schemas.filter((s) => s.source !== 'openapi').length
    state.schemas = state.schemas.filter((s) => s.source === 'openapi')
    return { data: { deleted } }
  }),
}))

vi.mock('../../services/api', () => ({
  apiArmor: {
    settings: { get: vi.fn(async () => ({ data: {} })), update: vi.fn() },
    presets: { list: vi.fn(async () => ({ data: [] })), apply: vi.fn() },
    specs: { list: vi.fn(async () => ({ data: [] })), create: vi.fn(), delete: vi.fn(), schemas: vi.fn() },
    schemas: api,
    authPolicies: { list: vi.fn(async () => ({ data: [] })) },
    apiKeyLists: { list: vi.fn(async () => ({ data: [] })) },
    profiles: { list: vi.fn(async () => ({ data: [] })) },
    anomalies: { list: vi.fn(async () => ({ data: [] })) },
  },
  settings: { get: vi.fn(async () => ({ data: { value: 'false' } })) },
  listeners: { list: vi.fn(async () => ({ data: [] })) },
  backends: { list: vi.fn(async () => ({ data: [] })) },
}))

const learned = {
  id: 1,
  name: 'learned:POST /wrong',
  method: 'POST',
  path: '/wrong',
  source: 'learned',
  enabled: true,
  sample_count: 3,
  schema_def: { type: 'object' },
}

const openapi = {
  id: 2,
  name: 'createUser',
  method: 'POST',
  path: '/api/v1/users',
  source: 'openapi',
  enabled: true,
  sample_count: 0,
  schema_def: { type: 'object' },
}

async function openSchemas() {
  render(<ApiArmor />)
  await userEvent.click(screen.getByRole('button', { name: 'Schemas' }))
  await screen.findByText('API Schemas')
}

describe('ApiArmor schemas cleanup', () => {
  beforeEach(() => {
    state.schemas = []
    api.list.mockClear()
    api.delete.mockClear()
    api.deleteLearned.mockClear()
  })

  it('deletes one learned schema and leaves the OpenAPI schema', async () => {
    state.schemas = [{ ...learned }, { ...openapi }]
    await openSchemas()
    expect(screen.getByRole('button', { name: 'Delete learned' })).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Delete' })).toHaveLength(1)

    await userEvent.click(screen.getByRole('button', { name: 'Delete' }))
    expect(screen.getByText(/Delete POST \/wrong\?/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Yes' }))

    await waitFor(() => {
      expect(api.delete).toHaveBeenCalledWith(1)
      expect(screen.getByText('Deleted 1 learned schema(s).')).toBeInTheDocument()
    })
    expect(screen.queryByText('/wrong', { exact: false })).not.toBeInTheDocument()
    expect(screen.getByText('POST /api/v1/users')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete learned' })).not.toBeInTheDocument()
  })

  it('deletes every learned schema and keeps OpenAPI schemas', async () => {
    state.schemas = [{ ...learned }, { ...openapi }]
    await openSchemas()
    await userEvent.click(screen.getByRole('button', { name: 'Delete learned' }))
    expect(screen.getByText(/Delete all 1 learned schemas\?/)).toBeInTheDocument()
    expect(screen.getByText(/OpenAPI schemas stay/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Yes' }))

    await waitFor(() => {
      expect(api.deleteLearned).toHaveBeenCalled()
      expect(screen.getByText('Deleted 1 learned schema(s).')).toBeInTheDocument()
    })
    expect(screen.queryByText('/wrong', { exact: false })).not.toBeInTheDocument()
    expect(screen.getByText('POST /api/v1/users')).toBeInTheDocument()
  })

  it('hides delete actions when every schema came from OpenAPI', async () => {
    state.schemas = [{ ...openapi }]
    await openSchemas()
    expect(screen.getByText('POST /api/v1/users')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete learned' })).not.toBeInTheDocument()
  })
})
