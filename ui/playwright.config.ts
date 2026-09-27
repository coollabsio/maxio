import { defineConfig, devices } from '@playwright/test'

// Runs against an already running MaxIO server (the UI is served at /ui/).
// Start one with e.g. `cargo run -- --data-dir /tmp/maxio-e2e --port 9876`.
export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  use: {
    baseURL: process.env.MAXIO_E2E_URL ?? 'http://127.0.0.1:9876',
    permissions: ['clipboard-read', 'clipboard-write'],
    trace: 'retain-on-failure',
    launchOptions: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE
      ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE }
      : undefined,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
