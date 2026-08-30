import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import LabelWithTooltip from '../LabelWithTooltip'

describe('LabelWithTooltip', () => {
  it('renders the tooltip text in an aria-label on the info icon', () => {
    render(<LabelWithTooltip tooltip="This is helpful text">Field</LabelWithTooltip>)
    const iconWrapper = screen.getByLabelText('This is helpful text')
    expect(iconWrapper).toBeInTheDocument()
  })
})
