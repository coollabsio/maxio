import { defineConfig, type Plugin } from 'vite'
import react, { reactCompilerPreset } from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import babel from '@rolldown/plugin-babel'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { fileURLToPath } from 'node:url'

const backendPort = process.env.PORT ?? '9000'
const backendTarget = `http://127.0.0.1:${backendPort}`
const webPort = Number(process.env.MAXIO_DEV_WEB_PORT ?? 5190)

/** Dev server: `/ui` -> `/ui/` (keeps the query), like the Rust server. Vite would answer 404 otherwise. */
const redirectUiRoot: Plugin = {
  name: 'maxio-redirect-ui-root',
  configureServer: (server) => void server.middlewares.use(uiRootRedirect),
  configurePreviewServer: (server) => void server.middlewares.use(uiRootRedirect),
}

function uiRootRedirect(req: IncomingMessage, res: ServerResponse, next: () => void) {
  const url = new URL(req.url ?? '/', 'http://localhost')
  if (url.pathname !== '/ui') return next()
  res.statusCode = 308
  res.setHeader('Location', `/ui/${url.search}`)
  res.end()
}

// https://vite.dev/config/
export default defineConfig({
  base: '/ui/',
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  plugins: [redirectUiRoot, react(), tailwindcss(), babel({ presets: [reactCompilerPreset()] })],
  build: {
    outDir: 'dist',
  },
  server: {
    host: '127.0.0.1',
    port: webPort,
    strictPort: true,
    // Reachable on the tailnet through `tailscale serve` (see CLAUDE.md).
    allowedHosts: ['.ts.net'],
    // Keep the browser's Host header: the console CSRF check compares it with Origin.
    proxy: {
      '/api': { target: backendTarget, changeOrigin: false },
      '/healthz': { target: backendTarget, changeOrigin: false },
      '/readyz': { target: backendTarget, changeOrigin: false },
    },
  },
})
