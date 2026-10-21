# Repository Guidelines

> **Agent instruction:** Whatever action you can do yourself, do yourself. This includes starting applications and performing verifications.

## Project Structure & Module Organization

This repository contains the Next.js frontend POC for **Sherklock Honed**, a CTI report-to-TTP attribution product. Keep route-level UI in `src/app/`, reusable components in `src/components/`, feature logic in `src/features/`, and shared utilities and types in `src/lib/` and `src/types/`. Store static assets in `public/`. Co-locate small component tests with their source; place cross-feature and end-to-end tests in `tests/`.

Organize domain code by capability, for example `src/features/incidents`, `src/features/attribution`, `src/features/attack-graph`, and `src/features/actor-profiles`. Use mock data under `src/mocks/`; never place real or sensitive CTI reports in the repository.

## Build, Test, and Development Commands

After the Next.js application is scaffolded, use the scripts declared in `package.json`:

- `npm install` installs locked dependencies.
- `npm run dev` starts the local development server.
- `npm run build` creates a production build and catches integration errors.
- `npm run start` serves the production build locally.
- `npm run lint` runs the configured ESLint checks.
- `npm test` runs the automated test suite once configured.

Do not document or rely on a command until its corresponding package script exists.

## Coding Style & Naming Conventions

Use TypeScript, React function components, and two-space indentation. Prefer small, typed components with explicit props. Name components in PascalCase (`AttributionTable.tsx`), hooks with a `use` prefix (`useIncident.ts`), and utilities in camelCase (`parseStix.ts`). Use kebab-case for route directories. Keep browser-only components minimal and add `"use client"` only when required.

Run ESLint and the configured formatter before submitting changes. Avoid `any`; model IOC, TTP, attribution, and timeline data with shared domain types.

## Testing Guidelines

Use Vitest and React Testing Library for unit and component tests, with Playwright for critical user flows when configured. Name tests `*.test.ts(x)` and end-to-end specs `*.spec.ts`. Cover report upload validation, temporal graph rendering, attribution ranking, and explainability calculations. Every bug fix should include a regression test.

## Commit & Pull Request Guidelines

No commit history exists yet. Use Conventional Commit subjects such as `feat: add incident upload form` or `fix: preserve timeline ordering`. Keep commits focused. Pull requests should include a concise summary, verification steps, linked issue when applicable, and screenshots or recordings for visual changes. Call out mock-data assumptions and any security-relevant handling of uploaded reports.

<!-- BEGIN:nextjs-agent-rules -->

# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->
