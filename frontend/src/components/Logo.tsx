import logoRaw from '../../public/haproxy-manager-logo.svg?raw'

// Replace the hardcoded fill color with currentColor so the logo dynamically
// follows the active theme's accent color via the --color-accent-primary CSS
// variable (set by ThemeProvider).  Strip the fixed width/height so the SVG
// scales to the wrapper's height while preserving aspect ratio.
const logoHtml = logoRaw
  .replace(/fill="#0e6be5"/g, 'fill="currentColor"')
  .replace(/width="\d+" height="\d+"/, 'style="height: 100%; width: auto;"')

interface LogoProps {
  className?: string
}

/**
 * Inline SVG logo whose fill color dynamically tracks the active theme's
 * accent color.  The SVG is imported as raw text at build time, with the
 * original hardcoded #0e6be5 fill replaced by currentColor.  The wrapper
 * span sets `color` to the theme's --color-accent-primary CSS variable.
 *
 * Pass a height class (e.g. `h-[150px]`) via `className` to size the logo;
 * width scales automatically to preserve the aspect ratio.
 */
export function Logo({ className }: LogoProps) {
  return (
    <span
      className={className}
      style={{ color: 'rgb(var(--color-accent-primary))', display: 'inline-block' }}
      dangerouslySetInnerHTML={{ __html: logoHtml }}
    />
  )
}
