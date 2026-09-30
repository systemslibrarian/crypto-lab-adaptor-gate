// Functional browser tests -- every act driven end to end, in every browser.
//
// These are role-based and behavioural: they check the lab WORKS for a user, where
// claims.spec.ts checks it tells the truth and a11y.spec.ts checks it is usable.

import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'

/** Open the "Change the inputs" disclosure, which ships shut. */
async function openInputs(page: Page): Promise<void> {
  const sum = page.locator('#panel-relation details.inspect > summary').last()
  if (!(await sum.evaluate((e) => (e.parentElement as HTMLDetailsElement).open))) await sum.click()
}

async function boot(page: Page): Promise<void> {
  page.setDefaultTimeout(20_000)
  await page.goto('.')
  await expect(page.locator('#panel-relation .card').first()).toBeVisible()
}

test.describe('tabs', () => {
  test('every exhibit opens and renders content', async ({ page }) => {
    await boot(page)
    const tabs = [
      ['Relation', '#panel-relation'],
      ['Swap', '#panel-swap'],
      ['PTLC', '#panel-ptlc'],
      ['Break It', '#panel-break'],
      ['Vectors', '#panel-vectors'],
      ['Honesty', '#panel-honesty'],
    ] as const
    for (const [name, sel] of tabs) {
      await page.getByRole('tab', { name }).click()
      await expect(page.getByRole('tab', { name })).toHaveAttribute('aria-selected', 'true')
      await expect(page.locator(sel)).toBeVisible()
      await expect(page.locator(sel)).not.toBeEmpty()
    }
  })

  test('the tablist is keyboard operable with arrow keys', async ({ page }) => {
    await boot(page)
    const first = page.getByRole('tab', { name: 'Relation' })
    await first.focus()
    await expect(first).toBeFocused()
    await page.keyboard.press('ArrowRight')
    await expect(page.getByRole('tab', { name: 'Swap' })).toBeFocused()
    await expect(page.locator('#panel-swap')).toBeVisible()
    await page.keyboard.press('End')
    await expect(page.getByRole('tab', { name: 'Honesty' })).toBeFocused()
    await page.keyboard.press('Home')
    await expect(first).toBeFocused()
  })

  test('only the selected tab is a tab stop', async ({ page }) => {
    await boot(page)
    const stops = await page
      .locator('.tab-btn')
      .evaluateAll((els) => els.filter((e) => e.getAttribute('tabindex') !== '-1').length)
    expect(stops).toBe(1)
  })
})

test.describe('The Relation, end to end', () => {
  test('one action runs all four stages', async ({ page }) => {
    await boot(page)
    await expect(page.locator('#panel-relation .stage-card')).toHaveCount(1)
    await page.getByRole('button', { name: 'Run the relation' }).click()
    await expect(page.locator('#panel-relation .stage-card')).toHaveCount(4)
    await expect(page.locator('#panel-relation .mech-sub.is-equal')).toHaveCount(1)
    await expect(
      page.locator('#panel-relation .verdict').filter({ hasText: 'Secret recovered' }),
    ).toHaveCount(1)
  })

  test('stepping reveals one stage at a time', async ({ page }) => {
    await boot(page)
    await page.getByRole('button', { name: 'Step through it' }).click()
    await expect(page.locator('#panel-relation .stage-card')).toHaveCount(1)
    await expect(page.locator('#panel-relation .mech-t.is-on')).toHaveCount(1)
    await page.getByRole('button', { name: 'Next step' }).click()
    await expect(page.locator('#panel-relation .stage-card')).toHaveCount(2)
    await page.getByRole('button', { name: 'Next step' }).click()
    await expect(page.locator('#panel-relation .stage-card')).toHaveCount(3)
    await page.getByRole('button', { name: 'Next step' }).click()
    await expect(page.locator('#panel-relation .stage-card')).toHaveCount(4)
    await expect(page.locator('#panel-relation .mech-sub.is-equal')).toHaveCount(1)
  })

  test('Reset returns the exhibit to nothing-run', async ({ page }) => {
    await boot(page)
    await page.getByRole('button', { name: 'Run the relation' }).click()
    await expect(page.locator('#panel-relation .stage-card')).toHaveCount(4)
    await page.getByRole('button', { name: /^Reset$/ }).click()
    await expect(page.locator('#panel-relation .stage-card')).toHaveCount(1)
    await expect(page.locator('#panel-relation .mech-sub.is-off')).toHaveCount(1)
  })

  test('a custom t and message flow through the whole panel', async ({ page }) => {
    await boot(page)
    await openInputs(page)
    await page.locator('#t-input').fill('2b')
    await page.locator('#msg-input').fill('a different message entirely')
    await page.getByRole('button', { name: 'Lock and pre-sign' }).click()
    await expect(page.locator('#panel-relation .stage-card')).toHaveCount(2)
    await page.getByRole('button', { name: 'Run the relation' }).click()
    await expect(page.locator('#panel-relation .mech-sub.is-equal')).toHaveCount(1)
  })

  test('rejects t = 0 with an explanation rather than crashing', async ({ page }) => {
    await boot(page)
    await openInputs(page)
    await page.locator('#t-input').fill('0')
    await page.getByRole('button', { name: 'Lock and pre-sign' }).click()
    await expect(page.locator('#panel-relation .verdict-fail')).toContainText('Rejected')
    await expect(page.locator('#panel-relation .verdict-fail')).toContainText('[1, n-1]')
  })

  test('rejects a non-hex key with an explanation', async ({ page }) => {
    await boot(page)
    await openInputs(page)
    await page.locator('#sk-input').fill('zzzz')
    await page.getByRole('button', { name: 'Lock and pre-sign' }).click()
    await expect(page.locator('#panel-relation .verdict-fail')).toContainText('Rejected')
  })

  test('supplying a wrong t is allowed, and the verifier refuses the result', async ({ page }) => {
    await boot(page)
    await openInputs(page)
    await page.locator('#supply-t').fill('01')
    await page.getByRole('button', { name: 'Add this t and verify' }).click()
    await expect(page.locator('#panel-relation .mech-sub.not-equal')).toHaveCount(1)
    await expect(page.locator('#panel-relation')).not.toContainText('VALID BIP-340 signature')
  })

  test('the one-click wrong-t control also turns the headline red', async ({ page }) => {
    await boot(page)
    await page.getByRole('button', { name: 'Try a wrong t' }).click()
    await expect(page.locator('#panel-relation .mech-sub.not-equal')).toHaveCount(1)
  })
})

test.describe('Swap, end to end', () => {
  test('the toggles drive all four combinations', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: 'Swap' }).click()
    const runOut = async () => page.locator('#btn-swap-all').click()
    // honest
    await runOut()
    await expect(page.locator('#panel-swap')).toContainText('Both sides paid, in order')
    // skip only
    await page.locator('#swap-skip').check()
    await runOut()
    await expect(page.locator('#panel-swap')).toContainText('Both sides paid, in order')
    // skip + cheat
    await page.locator('#swap-cheat').check()
    await runOut()
    await expect(page.locator('#panel-swap')).toContainText('BOB LOST HIS COINS')
    // cheat only
    await page.locator('#swap-skip').uncheck()
    await runOut()
    await expect(page.locator('#panel-swap')).toContainText('Fraud caught before anyone paid')
    // reset returns the documented safe state
    await page.locator('#btn-swap-reset').click()
    await runOut()
    await expect(page.locator('#panel-swap')).toContainText('Both sides paid, in order')
  })
})

test.describe('Break It, end to end', () => {
  test('the naive toggle produces a recovered key and a verified forgery', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: 'Break It' }).click()
    await expect(page.locator('#panel-break')).toContainText('No shared nonce')
    await page.locator('#btn-break-go').click()
    await expect(page.locator('#panel-break')).toContainText('PRIVATE KEY RECOVERED')
    await expect(page.locator('#panel-break')).toContainText('FORGERY ACCEPTED')
    await page.locator('#btn-break-reset').click()
    await expect(page.locator('#panel-break')).toContainText('No shared nonce')
  })
})

test.describe('layout', () => {
  test('no horizontal scrolling at 380px on any exhibit', async ({ page }) => {
    await page.setViewportSize({ width: 380, height: 800 })
    await boot(page)
    const tabs = ['Relation', 'Swap', 'PTLC', 'Break It', 'Vectors', 'Honesty']
    for (const name of tabs) {
      await page.getByRole('tab', { name }).click()
      const overflow = await page.evaluate(() => {
        const d = document.documentElement
        return d.scrollWidth - d.clientWidth
      })
      expect(overflow, `${name} must not scroll horizontally at 380px`).toBeLessThanOrEqual(0)
    }
  })
})

test.describe('PTLC, end to end', () => {
  test('settles backward and the break controls stall the upstream hops', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: 'PTLC' }).click()
    await page.locator('#btn-ptlc-all').click()
    await expect(page.locator('#panel-ptlc')).toContainText('Every hop settled')
    await page.locator('#ptlc-corrupt-3').check()
    await page.locator('#btn-ptlc-all').click()
    await expect(page.locator('#panel-ptlc')).toContainText('chain is broken')
    await expect(page.locator('#panel-ptlc .pill-fail').filter({ hasText: 'BLOCKED' })).toHaveCount(3)
    await page.locator('#btn-ptlc-reset').click()
    await expect(page.locator('#panel-ptlc .pill-fail').filter({ hasText: 'BLOCKED' })).toHaveCount(0)
  })
})
