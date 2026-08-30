/// <reference types="vitest/globals" />
/// <reference types="@testing-library/jest-dom/vitest" />
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { decodeUniqueId } from '../../lib/uniqueId'
import UniqueIdDecoder from '../UniqueIdDecoder'

describe('decodeUniqueId', () => {
  test('decodes the example unique ID', () => {
    const result = decodeUniqueId('0A010170:E18D_6A721294_1274:006A')
    expect(result.valid).toBe(true)
    expect(result.decoded).toMatchObject({
      clientIp: '10.1.1.112',
      clientPort: 57741,
      timestamp: 1785860756,
      requestCounter: 4724,
      pid: 106,
    })
  })

  test('rejects empty input', () => {
    const result = decodeUniqueId('')
    expect(result.valid).toBe(false)
    expect(result.error).toBe('Enter a unique ID')
  })

  test('rejects invalid format', () => {
    const result = decodeUniqueId('not-valid')
    expect(result.valid).toBe(false)
    expect(result.error).toMatch(/Invalid format/)
  })

  test('decodes an IPv6 unique ID', () => {
    const result = decodeUniqueId('2A0698C0360000000000000000000103:32D9_6A921D7E_005E:014B')
    expect(result.valid).toBe(true)
    expect(result.decoded).toMatchObject({
      clientIp: '2a06:98c0:3600::103',
      clientPort: 13017,
      timestamp: 1787960702,
      requestCounter: 94,
      pid: 331,
    })
  })
})

describe('UniqueIdDecoder', () => {
  test('renders input and decode button', () => {
    render(<UniqueIdDecoder />)
    expect(screen.getByLabelText('HAProxy unique ID')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Decode/i })).toBeInTheDocument()
  })

  test('decodes a valid unique ID on submit', async () => {
    render(<UniqueIdDecoder />)
    const user = userEvent.setup()
    const input = screen.getByLabelText('HAProxy unique ID')
    await user.type(input, '0A010170:E18D_6A721294_1274:006A')
    await user.click(screen.getByRole('button', { name: /Decode/i }))

    await waitFor(() => expect(screen.getByText('10.1.1.112')).toBeInTheDocument())
    expect(screen.getByText('57741')).toBeInTheDocument()
    expect(screen.getByText('4724')).toBeInTheDocument()
    expect(screen.getByText('106')).toBeInTheDocument()
    expect(screen.getByText('epoch: 1785860756')).toBeInTheDocument()
  })

  test('shows error for invalid unique ID', async () => {
    render(<UniqueIdDecoder />)
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('HAProxy unique ID'), 'not-valid')
    await user.click(screen.getByRole('button', { name: /Decode/i }))
    expect(await screen.findByText(/Invalid format/i)).toBeInTheDocument()
  })
})
