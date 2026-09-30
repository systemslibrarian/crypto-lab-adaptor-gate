import { defineConfig } from 'vitest/config'

export default defineConfig({
  // Read the real repo name; Pages serves the lab under this subpath.
  base: '/crypto-lab-adaptor-gate/',
  test: {
    // e2e/ holds Playwright specs. Collecting them as unit tests makes Vitest
    // import @playwright/test and fail, so scope the run to src.
    include: ['src/**/*.test.ts'],
  },
})
