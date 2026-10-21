---
version: "alpha"
name: "Nexus Forge Interactive Workspace"
description: "Nexus Forge Dashboard Section is designed for demonstrating application workflows and interface hierarchy. Key features include clear information density, modular panels, and interface rhythm. It is suitable for product showcases, admin panels, and analytics experiences."
colors:
  primary: "#6366F1"
  secondary: "#4338CA"
  tertiary: "#818CF8"
  neutral: "#111111"
  background: "#111111"
  surface: "#262626"
  text-primary: "#A3A3A3"
  text-secondary: "#D4D4D4"
  border: "#000000"
  accent: "#6366F1"
typography:
  display-lg:
    fontFamily: "Inter"
    fontSize: "96px"
    fontWeight: 300
    lineHeight: "96px"
    letterSpacing: "-0.025em"
  body-md:
    fontFamily: "Inter"
    fontSize: "10px"
    fontWeight: 500
    lineHeight: "15px"
    textTransform: "uppercase"
rounded:
  md: "4px"
spacing:
  base: "4px"
  sm: "1px"
  md: "2px"
  lg: "4px"
  xl: "6px"
  gap: "4px"
  card-padding: "8px"
  section-padding: "32px"
components:
  button-primary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.tertiary}"
    typography: "{typography.body-md}"
    rounded: "{rounded.md}"
    padding: "6px"
  button-link:
    textColor: "#737373"
    rounded: "0px"
    padding: "6px"
  card:
    rounded: "11px"
    padding: "16px"
---

## Overview

- **Composition cues:**
  - Layout: Grid
  - Content Width: Full Bleed
  - Framing: Glassy
  - Grid: Strong

## Colors

The color system uses dark mode with #6366F1 as the main accent and #111111 as the neutral foundation.

- **Primary (#6366F1):** Main accent and emphasis color.
- **Secondary (#4338CA):** Supporting accent for secondary emphasis.
- **Tertiary (#818CF8):** Reserved accent for supporting contrast moments.
- **Neutral (#111111):** Neutral foundation for backgrounds, surfaces, and supporting chrome.

- **Usage:** Background: #111111; Surface: #262626; Text Primary: #A3A3A3; Text Secondary: #D4D4D4; Border: #000000; Accent: #6366F1

- **Gradients:** bg-gradient-to-b from-neutral-600/40 to-neutral-800/30 via-neutral-700/10, bg-gradient-to-b from-[#252525] to-[#1a1a1a], bg-gradient-to-b from-[#222] to-[#181818], bg-gradient-to-r from-indigo-600 to-indigo-400

## Typography

Typography relies on Inter across display, body, and utility text.

- **Display (`display-lg`):** Inter, 96px, weight 300, line-height 96px, letter-spacing -0.025em.
- **Body (`body-md`):** Inter, 10px, weight 500, line-height 15px, uppercase.

## Layout

Layout follows a grid composition with reusable spacing tokens. Preserve the grid, full bleed structural frame before changing ornament or component styling. Use 4px as the base rhythm and let larger gaps step up from that cadence instead of introducing unrelated spacing values.

Treat the page as a grid / full bleed composition, and keep that framing stable when adding or remixing sections.

- **Layout type:** Grid
- **Content width:** Full Bleed
- **Base unit:** 4px
- **Scale:** 1px, 2px, 4px, 6px, 8px, 10px, 12px, 16px
- **Section padding:** 32px, 128px
- **Card padding:** 8px, 9px, 10px, 12px
- **Gaps:** 4px, 8px, 10px, 12px

## Elevation & Depth

Depth is communicated through glass, border contrast, and reusable shadow or blur treatments. Keep those recipes consistent across hero panels, cards, and controls so the page reads as one material system.

Surfaces should read as glass first, with borders, shadows, and blur only reinforcing that material choice.

- **Surface style:** Glass
- **Borders:** 1px #000000; 1px #0F0F0F; 1px #525252; 1px #737373
- **Shadows:** rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(255, 255, 255, 0.02) 0px 1px 0px 0px; rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0.6) 0px 2px 4px 0px inset, rgba(255, 255, 255, 0.05) 0px 1px 0px 0px; rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0.7) 0px 20px 40px -10px
- **Blur:** 12px

### Techniques
- **Gradient border shell:** Use a thin gradient border shell around the main card. Wrap the surface in an outer shell with 1px padding and a 16px radius. Drive the shell with linear-gradient(rgba(82, 82, 82, 0.5), rgba(38, 38, 38, 0.3), rgba(23, 23, 23, 0.5)) so the edge reads like premium depth instead of a flat stroke. Keep the actual stroke understated so the gradient shell remains the hero edge treatment. Inset the real content surface inside the wrapper with a slightly smaller radius so the gradient only appears as a hairline frame.

## Shapes

Shapes rely on a tight radius system anchored by 4px and scaled across cards, buttons, and supporting surfaces. Icon geometry should stay compatible with that soft-to-controlled silhouette.

Use the radius family intentionally: larger surfaces can open up, but controls and badges should stay within the same rounded DNA instead of inventing sharper or pill-only exceptions.

- **Corner radii:** 4px, 6px, 11px, 12px, 16px, 9999px
- **Icon treatment:** Linear
- **Icon sets:** Solar

## Components

Anchor interactions to the detected button styles. Reuse the existing card surface recipe for content blocks.

### Buttons
- **Primary:** background #262626, text #818CF8, radius 4px, padding 6px, border 1px solid rgb(23, 23, 23).
- **Links:** text #737373, radius 0px, padding 6px, border 0px solid rgb(229, 231, 235).

### Cards and Surfaces
- **Card surface:** border 0px solid rgb(229, 231, 235), radius 11px, padding 16px, shadow rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(255, 255, 255, 0.06) 0px 1px 0px 0px inset.
- **Card surface:** background #111111, border 1px solid rgba(0, 0, 0, 0.5), radius 4px, padding 16px, shadow rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0.8) 0px 2px 6px 0px inset, rgba(255, 255, 255, 0.05) 0px 1px 0px 0px.
- **Card surface:** border 0px solid rgb(229, 231, 235), radius 11px, padding 20px, shadow rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(255, 255, 255, 0.06) 0px 1px 0px 0px inset.

### Iconography
- **Treatment:** Linear.
- **Sets:** Solar.

## Do's and Don'ts

Use these constraints to keep future generations aligned with the current system instead of drifting into adjacent styles.

### Do
- Do use the primary palette as the main accent for emphasis and action states.
- Do keep spacing aligned to the detected 4px rhythm.
- Do reuse the Glass surface treatment consistently across cards and controls.
- Do keep corner radii within the detected 4px, 6px, 11px, 12px, 16px, 9999px family.

### Don't
- Don't introduce extra accent colors outside the core palette roles unless the page needs a new semantic state.
- Don't mix unrelated shadow or blur recipes that break the current depth system.
- Don't exceed the detected moderate motion intensity without a deliberate reason.

## Motion

Motion feels controlled and interface-led across text, layout, and section transitions. Timing clusters around 150ms. Easing favors ease and cubic-bezier(0.4. Hover behavior focuses on text and stroke changes. Scroll choreography uses GSAP ScrollTrigger for section reveals and pacing.

**Motion Level:** moderate

**Durations:** 150ms

**Easings:** ease, cubic-bezier(0.4, 0, 0.2, 1)

**Hover Patterns:** text, stroke, color

**Scroll Patterns:** gsap-scrolltrigger

## WebGL

Reconstruct the graphics as a centered hero scene using webgl, renderer, alpha, antialias. The effect should read as retro-futurist, technical, and meditative: perspective grid field with green on black and sparse spacing. Build it from grid lines + depth fade so the effect reads clearly. Animate it as slow breathing pulse. Interaction can react to the pointer, but only as a subtle drift. Preserve dom fallback.

**Id:** webgl

**Label:** WebGL

**Stack:** ThreeJS, WebGL

**Insights:**
  - **Scene:**
    - **Value:** Centered hero scene
  - **Effect:**
    - **Value:** Perspective grid field
  - **Primitives:**
    - **Value:** Grid lines + depth fade
  - **Motion:**
    - **Value:** Slow breathing pulse
  - **Interaction:**
    - **Value:** Pointer-reactive drift
  - **Render:**
    - **Value:** WebGL, Renderer, alpha, antialias

**Techniques:** Perspective grid, Breathing pulse, Pointer parallax, Noise fields, DOM fallback

**Code Evidence:**
  - **HTML reference:**
    - **Language:** html
    - **Snippet:**
      ```html
      <canvas width="1206" height="1722" style="display: block; width: 603px; height: 861px;"></canvas>
      ```
  - **JS reference:**
    - **Language:** html
    - **Snippet:**
      ```html
      <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
      ```

## ThreeJS

Reconstruct the Three.js layer as a centered hero scene with layered spatial depth that feels retro-futurist, volumetric, and technical. Use alpha, antialias renderer settings, perspective, ~75deg fov, custom buffer geometry geometry, pointsmaterial materials, and ambient + key + rim lighting. Motion should read as timeline-led reveals, with poster frame + dom fallback.

**Id:** threejs

**Label:** ThreeJS

**Stack:** ThreeJS, WebGL

**Insights:**
  - **Scene:**
    - **Value:** Centered hero scene with layered spatial depth
  - **Render:**
    - **Value:** alpha, antialias
  - **Camera:**
    - **Value:** Perspective, ~75deg FOV
  - **Lighting:**
    - **Value:** ambient + key + rim
  - **Materials:**
    - **Value:** PointsMaterial
  - **Geometry:**
    - **Value:** custom buffer geometry
  - **Motion:**
    - **Value:** Timeline-led reveals

**Techniques:** Particle depth, Timeline beats, alpha, antialias, Poster frame + DOM fallback

**Code Evidence:**
  - **HTML reference:**
    - **Language:** html
    - **Snippet:**
      ```html
      <canvas width="1206" height="1722" style="display: block; width: 603px; height: 861px;"></canvas>
      ```
  - **JS reference:**
    - **Language:** html
    - **Snippet:**
      ```html
      <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
      ```