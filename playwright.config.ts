import { defineConfig, devices } from '@playwright/test'

/**
 * THE PORT IS ONE CONSTANT, read by all three places that need it.
 *
 * Vite's default is 4173 and labs across this fleet collide on it. Because
 * `reuseExistingServer` is true outside CI, a server already answering on the port
 * is reused and `webServer.command` never runs at all -- so a sibling lab's preview
 * gets handed this repo's suites and the gates run green or red against a page this
 * repo never produced. It has really happened here.
 *
 * 4681 was chosen after sweeping every sibling `playwright.config.ts` AND the
 * catalog's own `tools/playwright-ports.json` registry (178 entries). Worth
 * recording: the grep the template suggests, `localhost:[0-9]+`, is NOT sufficient
 * -- configs that build the URL from a template literal (`const PORT = 4649` with
 * `http://localhost:${PORT}`) are invisible to it, and crypto-lab-hpke-envelope
 * holds 4649 exactly that way. Sweep for `PORT =` and `--port` too.
 */
const PORT = 4681
const BASE = '/crypto-lab-adaptor-gate/'
const URL = `http://localhost:${PORT}${BASE}`

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  timeout: 90_000,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: URL,
    colorScheme: 'dark', // dark is the only theme
  },
  projects: [
    {
      name: 'a11y',
      testMatch: /a11y\.spec\.ts/,
      use: { ...devices['Desktop Chrome'], colorScheme: 'dark' },
    },
    { name: 'claims', testMatch: /claims\.spec\.ts/, use: { ...devices['Desktop Chrome'] } },
    { name: 'flows-chromium', testMatch: /flows\.spec\.ts/, use: { ...devices['Desktop Chrome'] } },
    { name: 'flows-firefox', testMatch: /flows\.spec\.ts/, use: { ...devices['Desktop Firefox'] } },
    { name: 'flows-webkit', testMatch: /flows\.spec\.ts/, use: { ...devices['Desktop Safari'] } },
    { name: 'flows-mobile', testMatch: /flows\.spec\.ts/, use: { ...devices['Pixel 5'] } },
  ],
  webServer: {
    // BUILD before serving. `vite preview` serves whatever is already in dist/, so
    // without the build in front a run tests a stale bundle -- and a build that
    // FAILS leaves the previous good bundle in place, so the whole suite passes
    // green against source that no longer compiles. That silently invalidates
    // mutation checking, which is the only way a test is proved to have teeth.
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: URL,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
