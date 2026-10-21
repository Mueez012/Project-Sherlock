---
version: "1.0"
name: "Slate Analyst"
description: "Professional, readable theme for Sherklock Honed: a security analysis tool, not a game. Dark by default with a full light theme. All values live in src/styles/tokens.css; this file documents them."
colors:
  dark:
    bg: "#0B0F14"
    surface: "#121821"
    surface-raised: "#19212C"
    border: "#2A3442"
    border-control: "#647186"
    text: "#E6EBF1"
    text-secondary: "#A7B2C0"
    text-muted: "#8492A3"
    accent: "#5B9BFF"
    accent-text: "#8AB8FF"
    on-accent: "#0B0F14"
    success: "#3DBE8B"
    warning: "#E6A23C"
    danger: "#F06A62"
  light:
    bg: "#F6F8FB"
    surface: "#FFFFFF"
    surface-raised: "#EEF2F7"
    border: "#D5DCE5"
    border-control: "#7C8A9C"
    text: "#0F1722"
    text-secondary: "#465264"
    text-muted: "#5D6B7D"
    accent: "#1F5FD1"
    accent-text: "#1F5FD1"
    on-accent: "#FFFFFF"
    success: "#167A55"
    warning: "#9A5B00"
    danger: "#C2352D"
typography:
  ui: { fontFamily: "Inter Variable", body: "16px / 1.6", ui: "1.45", headings: "600, 1.1-1.15, -0.025em" }
  mono: { fontFamily: "Geist Mono Variable", use: "ATT&CK ids, hashes, sizes, timestamps, numbers" }
  scale: ["12", "13", "14", "16 (body)", "18", "20", "24", "32", "40", "56 (hero only)"]
  minimum: "12px anywhere (enforced by stylelint)"
rounded: { control: "6px", card: "10px", dialog: "14px", pill: "999px (pills only)" }
spacing: { base: "4px", scale: ["4", "8", "12", "16", "24", "32", "48", "64", "96"] }
---

## Overview

The interface reads like an analyst's tool: calm surfaces, one blue accent, high-contrast text and
numbers you can trust at a glance. Decoration never competes with data.

## Colours

- One accent (blue) for actions, links, focus and selected states. Status colours (success, warning,
  danger) are only used for status.
- **Confidence scale** uses the accent at three strengths: high = full accent, medium = 60% tint,
  low = 22–30% tint plus a dashed outline. The number and the band name are always shown next to the colour.
- Every text/background pair is at least 4.5:1 and every control border at least 3:1 in both themes;
  `npm run contrast` checks this and fails otherwise.
- No hex values outside `src/styles/tokens.css` (stylelint `color-no-hex`).

## Typography

Inter for all UI text, Geist Mono only for identifiers and numbers (`T1059.001`, sha256, `12.4 KB`).
Paragraphs are limited to 68 characters per line. Tables, metrics and confidence values use tabular numbers.
Uppercase is used only for small eyebrow labels (12px, +0.06em).

## Layout

Centered content up to 1280px with a responsive gutter (16–48px). 4px spacing rhythm.
Checked at 1440, 1024, 768 and 390px with no page-level horizontal scroll; the ATT&CK matrix and
the technique table scroll inside their own containers on small screens.

## Elevation

Cards: `surface` background, 1px `border`, one soft shadow level. No glows, no glass blur on content.
The sticky header uses a light backdrop blur only.

## Components

- **Buttons:** primary (accent fill), secondary (surface + control border), ghost. 40px high (44px on touch).
- **Focus:** visible 2px accent outline with 2px offset on every interactive element.
- **Tables:** 44px rows, sticky header, light zebra striping, right-aligned numbers.
- **Dialog:** focus trap, Esc closes, focus returns to the button that opened it.

## Motion

150–250ms ease-out for state changes only. Section reveals (GSAP) run only when
`prefers-reduced-motion: no-preference`; the global reduced-motion rule turns all animation off.
The radar sweep, marquee and word-by-word text fade of the POC were removed.

## Do and don't

- Do take every colour, size and radius from tokens.
- Do pair colour with text (numbers, band labels, status words).
- Don't use font sizes below 12px or low-opacity text.
- Don't load external images or fonts at runtime (fonts are bundled with @fontsource).
