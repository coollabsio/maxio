# MaxIO web console

React single-page app served by the MaxIO binary at `/ui/`. It talks to the console API under `/api/`
(cookie session, not SigV4). The release build embeds the files from `dist/` into the binary.

## Stack

React 19 + React Compiler, Vite 8, TypeScript 6, Tailwind CSS 4, shadcn (`base-nova`) on `@base-ui/react`,
TanStack Query 5, React Router 8, `lucide-react` icons, `sonner` toasts. The visual design follows the Coolify
design system: see [`DESIGN_SYSTEM.md`](DESIGN_SYSTEM.md) and the tokens in `src/index.css`.

## Scripts (use bun)

```bash
bun install
bun run dev           # Vite on http://127.0.0.1:${MAXIO_DEV_WEB_PORT:-5190}/ui/, proxies /api to 127.0.0.1:${PORT:-9000}
bun run build         # type-check + production build into dist/
bun run lint          # oxlint
bun run test          # unit/component tests (bun test + happy-dom + Testing Library)
bun run e2e           # Playwright against a running server (MAXIO_E2E_URL, default http://127.0.0.1:9876)
bun run api:generate  # regenerate src/api/generated from src/api/generated/openapi.json (hey-api)
```

For e2e, install the browser once with `bunx playwright install chromium` and start a server, e.g.
`cargo run -- --data-dir /tmp/maxio-e2e --port 9876`.

## Layout

- `src/app/` — providers, routes, and the shell (sidebar, header/breadcrumbs)
- `src/features/` — auth, buckets, objects, settings, versions (pages + API wrappers)
- `src/components/ui/` — Coolify-styled primitives (button, dialog, table, switch, …)
- `src/api/` — generated OpenAPI client (`generated/`), client setup, query keys
- `src/lib/` — pure helpers (paths, formatting, theme)
- `e2e/` — Playwright specs
