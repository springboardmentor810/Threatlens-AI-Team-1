/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      // Theme-aware tokens. Values live as RGB triplets in src/index.css so a
      // single class on <html> flips the whole palette; the accent and severity
      // hues are deliberately identical in both themes.
      //
      // Written as rgb(... / <alpha-value>) so Tailwind's opacity modifiers
      // (bg-white/5, border-border/50) keep working.
      colors: {
        background: {
          DEFAULT: "rgb(var(--c-bg) / <alpha-value>)",
          surface: "rgb(var(--c-surface) / <alpha-value>)",
          elevated: "rgb(var(--c-elevated) / <alpha-value>)",
        },
        border: {
          DEFAULT: "rgb(var(--c-border) / 0.10)",
          strong: "rgb(var(--c-border) / <alpha-value>)",
        },
        accent: {
          cyan: "rgb(var(--c-accent-cyan) / <alpha-value>)",
          blue: "rgb(var(--c-accent-blue) / <alpha-value>)",
          purple: "rgb(var(--c-accent-purple) / <alpha-value>)",
          indigo: "rgb(var(--c-accent-indigo) / <alpha-value>)",
        },
        severity: {
          critical: "rgb(var(--c-severity-critical) / <alpha-value>)",
          high: "rgb(var(--c-severity-high) / <alpha-value>)",
          medium: "rgb(var(--c-severity-medium) / <alpha-value>)",
          low: "rgb(var(--c-severity-low) / <alpha-value>)",
          info: "rgb(var(--c-severity-info) / <alpha-value>)",
        },
        muted: "rgb(var(--c-muted) / <alpha-value>)",

        // Text ramp. slate-100 is the strongest ink and slate-600 the faintest
        // in BOTH themes - the values invert, the meaning does not, so no
        // component had to change. slate-950 is the exception: it is ink on the
        // accent gradient (buttons, logo) and stays dark either way.
        slate: {
          100: "rgb(var(--c-slate-100) / <alpha-value>)",
          200: "rgb(var(--c-slate-200) / <alpha-value>)",
          300: "rgb(var(--c-slate-300) / <alpha-value>)",
          400: "rgb(var(--c-slate-400) / <alpha-value>)",
          500: "rgb(var(--c-slate-500) / <alpha-value>)",
          600: "rgb(var(--c-slate-600) / <alpha-value>)",
          700: "rgb(var(--c-slate-700) / <alpha-value>)",
          950: "#020617",
        },

        // Subtle overlays (bg-white/5, border-white/10) must lighten on dark
        // and darken on light, so this follows the theme too.
        white: "rgb(var(--c-overlay) / <alpha-value>)",
      },
      fontFamily: {
        display: ["'Space Grotesk'", "sans-serif"],
        body: ["'Inter'", "sans-serif"],
        mono: ["'JetBrains Mono'", "monospace"],
      },
      boxShadow: {
        glow: "var(--shadow-glow)",
        "glow-purple": "var(--shadow-glow-purple)",
        card: "var(--shadow-card)",
      },
      backgroundImage: {
        "grid-pattern":
          "linear-gradient(rgba(148,163,184,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.05) 1px, transparent 1px)",
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        scan: "scan 2.5s linear infinite",
      },
      keyframes: {
        scan: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        },
      },
    },
  },
  plugins: [],
};
