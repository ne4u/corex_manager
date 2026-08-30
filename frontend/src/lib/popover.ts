/**
 * Compute viewport-clamped position for a fixed-position popover.
 *
 * Prefers placing the popover below the trigger element. If there isn't
 * enough space below, tries above. If neither side has enough room, picks
 * the side with more space and clamps to keep the popover fully visible.
 *
 * @param rect           Trigger element's bounding rect (from getBoundingClientRect)
 * @param popoverWidth   Popover width in px
 * @param popoverHeight  Estimated popover height in px
 * @param gap            Gap between trigger and popover (default 8)
 * @param margin         Min margin from viewport edge (default 8)
 */
export interface PopoverPosition {
  left: number
  top: number
}

export function computePopoverPosition(
  rect: DOMRect,
  popoverWidth: number,
  popoverHeight: number,
  gap: number = 8,
  margin: number = 8,
): PopoverPosition {
  const vw = window.innerWidth
  const vh = window.innerHeight

  // Horizontal: clamp left so popover stays within [margin, vw - width - margin]
  const maxLeft = vw - popoverWidth - margin
  const minLeft = margin
  const left = Math.max(minLeft, Math.min(rect.left, maxLeft))

  // Vertical: prefer below, then above, then clamp to whichever side has more space
  const spaceBelow = vh - rect.bottom - gap
  const spaceAbove = rect.top - gap

  let top: number
  if (spaceBelow >= popoverHeight) {
    top = rect.bottom + gap
  } else if (spaceAbove >= popoverHeight) {
    top = rect.top - gap - popoverHeight
  } else if (spaceBelow >= spaceAbove) {
    top = rect.bottom + gap
  } else {
    top = rect.top - gap - popoverHeight
  }

  // Clamp to viewport
  top = Math.max(margin, Math.min(top, vh - popoverHeight - margin))

  return { left, top }
}
