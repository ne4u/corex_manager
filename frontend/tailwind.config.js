/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Primary accent — wired to theme CSS variable
        primary: {
          DEFAULT: 'rgb(var(--color-accent-primary) / <alpha-value>)',
          hover: 'rgb(var(--color-accent-primary) / <alpha-value>)',
        },

        // Slate scale — mapped to theme CSS variables so theme switching works.
        // The "R G B" triplet format allows Tailwind's alpha modifier (e.g. /50) to work.
        slate: {
          50:  'rgb(var(--color-text-primary) / <alpha-value>)',
          100: 'rgb(var(--color-text-primary) / <alpha-value>)',
          200: 'rgb(var(--color-text-secondary) / <alpha-value>)',
          300: 'rgb(var(--color-text-secondary) / <alpha-value>)',
          400: 'rgb(var(--color-text-tertiary) / <alpha-value>)',
          500: 'rgb(var(--color-text-tertiary) / <alpha-value>)',
          600: 'rgb(var(--color-border-subtle) / <alpha-value>)',
          700: 'rgb(var(--color-border-subtle) / <alpha-value>)',
          800: 'rgb(var(--color-bg-tertiary) / <alpha-value>)',
          900: 'rgb(var(--color-bg-secondary) / <alpha-value>)',
          950: 'rgb(var(--color-bg-primary) / <alpha-value>)',
        },

        // Semantic colors — mapped to theme accent variables
        red: {
          300: 'rgb(var(--color-accent-error) / <alpha-value>)',
          400: 'rgb(var(--color-accent-error) / <alpha-value>)',
          500: 'rgb(var(--color-accent-error) / <alpha-value>)',
          600: 'rgb(var(--color-accent-error) / <alpha-value>)',
          700: 'rgb(var(--color-accent-error) / <alpha-value>)',
        },
        green: {
          300: 'rgb(var(--color-accent-success) / <alpha-value>)',
          400: 'rgb(var(--color-accent-success) / <alpha-value>)',
          500: 'rgb(var(--color-accent-success) / <alpha-value>)',
        },
        amber: {
          300: 'rgb(var(--color-accent-warning) / <alpha-value>)',
          400: 'rgb(var(--color-accent-warning) / <alpha-value>)',
          500: 'rgb(var(--color-accent-warning) / <alpha-value>)',
        },
        blue: {
          300: 'rgb(var(--color-accent-info) / <alpha-value>)',
          400: 'rgb(var(--color-accent-info) / <alpha-value>)',
          500: 'rgb(var(--color-accent-info) / <alpha-value>)',
          600: 'rgb(var(--color-accent-primary) / <alpha-value>)',
          700: 'rgb(var(--color-accent-primary) / <alpha-value>)',
        },

        // Aliases used in a few places
        surface: 'rgb(var(--color-bg-primary) / <alpha-value>)',
        muted: 'rgb(var(--color-text-tertiary) / <alpha-value>)',
      },
    },
  },
  plugins: [],
}
