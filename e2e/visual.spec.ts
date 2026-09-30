// Focused visual regression snapshots.
//
// DELIBERATELY NARROW. Snapshots are a blunt oracle: a wide one fails on every
// harmless reflow and gets re-baselined until it means nothing. So these cover
// exactly the states whose LOOK carries meaning and which the behavioural suites
// cannot see:
//
//   - the opening state, where the whole time-to-insight argument lives;
//   - the mechanism in each of its three readings (off, equal, mismatched), since
//     the colour of the subtraction IS the claim;
//   - the three swap outcomes, whose tones differ while their text is similar;
//   - the nonce panel safe vs compromised;
//   - PTLC settlement at its first and final transitions, including the break.
//
// The giant vector and fixture tables are NOT snapshotted: they are 19 and 6 rows of
// hex that the claims suite already checks value by value, and a snapshot of them
// would fail on any content change while proving nothing about appearance.
//
// Animations are disabled through the reduced-motion media query rather than by
// injecting CSS, for the same reason the a11y gate does it that way.

import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'

const DESKTOP = { width: 1280, height: 900 }
const PHONE = { width: 390, height: 844 }

async function boot(page: Page): Promise<void> {
  page.setDefaultTimeout(20_000)
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.goto('.')
  await expect(page.locator('#btn-run')).toBeVisible()
}

/** Snapshot one element, not the whole page: less to break, more to read. */
async function shot(page: Page, selector: string, name: string): Promise<void> {
  await expect(page.locator(selector)).toHaveScreenshot(name, {
    // Tight on purpose. At 0.01 a semantic tone change -- swapping t's violet for
    // the pre-signature's amber -- moved fewer pixels than the tolerance allowed and
    // all 13 snapshots still passed, which is a gate that proves nothing. Measured
    // and tightened until that mutation fails.
    maxDiffPixelRatio: 0.0005,
    animations: 'disabled',
  })
}

test.describe('opening states', () => {
  test('desktop opening', async ({ page }) => {
    await page.setViewportSize(DESKTOP)
    await boot(page)
    await shot(page, '#panel-relation .opening', 'opening-desktop.png')
  })

  test('phone opening, first viewport', async ({ page }) => {
    await page.setViewportSize(PHONE)
    await boot(page)
    // The whole point of this one: the primary action is in frame.
    await expect(page.locator('#btn-run')).toBeInViewport()
    await expect(page).toHaveScreenshot('opening-phone-first-viewport.png', {
      maxDiffPixelRatio: 0.0005,
      animations: 'disabled',
      clip: { x: 0, y: 0, width: PHONE.width, height: PHONE.height },
    })
  })
})

test.describe('the mechanism carries the claim in its colour', () => {
  test('off — nothing run', async ({ page }) => {
    await page.setViewportSize(DESKTOP)
    await boot(page)
    await shot(page, '#panel-relation .mech-card', 'mechanism-off.png')
  })

  test('equal — the real t', async ({ page }) => {
    await page.setViewportSize(DESKTOP)
    await boot(page)
    await page.locator('#btn-run').click()
    await expect(page.locator('.mech-sub.is-equal')).toHaveCount(1)
    await shot(page, '#panel-relation .mech-card', 'mechanism-equal.png')
  })

  test('mismatched — a wrong t', async ({ page }) => {
    await page.setViewportSize(DESKTOP)
    await boot(page)
    await page.locator('#btn-wrong-t').click()
    await expect(page.locator('.mech-sub.not-equal')).toHaveCount(1)
    await shot(page, '#panel-relation .mech-card', 'mechanism-mismatch.png')
  })
})

test.describe('swap outcomes', () => {
  const go = async (page: Page, cheat: boolean, skip: boolean) => {
    await page.setViewportSize(DESKTOP)
    await boot(page)
    await page.getByRole('tab', { name: /^Swap$/ }).click()
    if (cheat) await page.locator('#swap-cheat').check()
    if (skip) await page.locator('#swap-skip').check()
    await page.locator('#btn-swap-all').click()
  }

  test('honest — both paid', async ({ page }) => {
    await go(page, false, false)
    await expect(page.locator('#panel-swap')).toContainText('Both sides paid, in order')
    await shot(page, '#panel-swap .card:last-of-type', 'swap-honest.png')
  })

  test('caught — fraud stopped before anyone paid', async ({ page }) => {
    await go(page, true, false)
    await expect(page.locator('#panel-swap')).toContainText('Fraud caught before anyone paid')
    await shot(page, '#panel-swap .card:last-of-type', 'swap-caught.png')
  })

  test('loss — every check green, funds gone', async ({ page }) => {
    await go(page, true, true)
    await expect(page.locator('#swap-negative-claim')).toBeVisible()
    await shot(page, '#panel-swap .card:last-of-type', 'swap-loss.png')
  })
})

test.describe('nonce modes', () => {
  test('safe default', async ({ page }) => {
    await page.setViewportSize(DESKTOP)
    await boot(page)
    await page.getByRole('tab', { name: /^Break It$/ }).click()
    await expect(page.locator('#panel-break')).toContainText('No shared nonce')
    await shot(page, '#panel-break .opening', 'nonce-safe.png')
  })

  test('compromised', async ({ page }) => {
    await page.setViewportSize(DESKTOP)
    await boot(page)
    await page.getByRole('tab', { name: /^Break It$/ }).click()
    await page.locator('#btn-break-go').click()
    await expect(page.locator('#panel-break')).toContainText('PRIVATE KEY RECOVERED')
    await shot(page, '#panel-break .callout-danger', 'nonce-compromised.png')
  })
})

test.describe('PTLC settlement transitions', () => {
  const table = '#panel-ptlc .table-wrap'

  test('first transition — only the last hop has settled', async ({ page }) => {
    await page.setViewportSize(DESKTOP)
    await boot(page)
    await page.getByRole('tab', { name: /^PTLC$/ }).click()
    await page.locator('#btn-ptlc-next').click()
    await shot(page, table, 'ptlc-first-transition.png')
  })

  test('final transition — every hop settled', async ({ page }) => {
    await page.setViewportSize(DESKTOP)
    await boot(page)
    await page.getByRole('tab', { name: /^PTLC$/ }).click()
    await page.locator('#btn-ptlc-all').click()
    await expect(page.locator('#panel-ptlc')).toContainText('Every hop settled')
    await shot(page, table, 'ptlc-final-transition.png')
  })

  test('broken chain — upstream hops stalled', async ({ page }) => {
    await page.setViewportSize(DESKTOP)
    await boot(page)
    await page.getByRole('tab', { name: /^PTLC$/ }).click()
    await page.locator('#ptlc-corrupt-2').check()
    await page.locator('#btn-ptlc-all').click()
    await shot(page, table, 'ptlc-broken.png')
  })
})
