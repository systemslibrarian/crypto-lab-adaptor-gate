// The Playwright container tag in CI must match the installed @playwright/test.
//
// The browser gate runs inside mcr.microsoft.com/playwright:<tag> so the visual
// snapshots compare against the rendering environment they were baselined in. That
// only holds while the image tag and the npm package agree. Dependabot bumps the
// package; nothing bumps the tag. Without this test the two drift silently and the
// next snapshot failure looks like a UI regression instead of a version skew.

import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import pkg from '../package.json' with { type: 'json' }

describe('CI pins', () => {
  it('the Playwright container tag matches the installed @playwright/test version', () => {
    const wf = readFileSync(new URL('../.github/workflows/deploy.yml', import.meta.url), 'utf8')
    const m = wf.match(/mcr\.microsoft\.com\/playwright:v(\d+\.\d+\.\d+)-/)
    expect(m, 'the workflow must pin a Playwright container image').not.toBeNull()
    const declared = pkg.devDependencies['@playwright/test'].replace(/^[\^~]/, '')
    expect(m![1], 'container tag vs @playwright/test in package.json').toBe(declared)
  })

  it('the preview port is held in exactly one place', () => {
    // §4.1 asks for one constant that baseURL, webServer.command and webServer.url
    // all read. A second literal is how two of the three drift apart.
    //
    // Comments are stripped first: the config's own header discusses other labs'
    // ports by number, and counting those made this test fail on its own prose.
    const cfg = readFileSync(new URL('../playwright.config.ts', import.meta.url), 'utf8')
    const code = cfg
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .split('\n')
      .filter((l) => !l.trim().startsWith('//'))
      .join('\n')
    const literals = code.match(/\b\d{4}\b/g) ?? []
    expect(literals.length, `port literals in code: ${literals.join(', ')}`).toBe(1)
    // and the three places that need it all read that one constant
    expect(code).toMatch(/baseURL:\s*URL/)
    expect(code).toMatch(/--port \$\{PORT\}/)
    expect(code).toMatch(/url:\s*URL/)
  })
})
