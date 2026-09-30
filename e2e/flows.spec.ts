// Functional browser tests -- every act driven end to end, in every browser.
//
// These are role-based and behavioural: they check the lab WORKS for a user, where
// claims.spec.ts checks it tells the truth and a11y.spec.ts checks it is usable.

import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'

async function boot(page: Page): Promise<void> {
  page.setDefaultTimeout(20_000)
  await page.goto('.')
  await expect(page.locator('#panel-relation .card').first()).toBeVisible()
}

test.describe('tabs', () => {
  test('every exhibit opens and renders content', async ({ page }) => {
    await boot(page)
    const tabs = [
      ['The Relation', '#panel-relation'],
      ['Cross-Ledger Swap', '#panel-swap'],
      ['PTLC vs HTLC', '#panel-ptlc'],
      ['Break It', '#panel-break'],
      ['Vectors & Fixtures', '#panel-vectors'],
      ["What This Is & Isn't", '#panel-honesty'],
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
    const first = page.getByRole('tab', { name: 'The Relation' })
    await first.focus()
    await expect(first).toBeFocused()
    await page.keyboard.press('ArrowRight')
    await expect(page.getByRole('tab', { name: 'Cross-Ledger Swap' })).toBeFocused()
    await expect(page.locator('#panel-swap')).toBeVisible()
    await page.keyboard.press('End')
    await expect(page.getByRole('tab', { name: "What This Is & Isn't" })).toBeFocused()
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
  test('lock, pre-sign, complete and extract', async ({ page }) => {
    await boot(page)
    await expect(page.locator('#panel-relation')).toContainText('Step 1')
    await expect(page.locator('#panel-relation')).toContainText('Step 2')
    // step 4 does not exist before a t is supplied
    await expect(page.locator('#panel-relation')).not.toContainText('Step 4')

    await page.getByRole('button', { name: 'Use the real t' }).click()
    await expect(page.locator('#panel-relation')).toContainText('Step 4')
    await expect(page.locator('#panel-relation .diff-strip.is-equal')).toHaveCount(1)
    await expect(
      page.locator('#panel-relation .verdict').filter({ hasText: 'Secret recovered' }),
    ).toHaveCount(1)
  })

  test('a custom t and message flow through the whole panel', async ({ page }) => {
    await boot(page)
    await page.locator('#t-input').fill('2b')
    await page.locator('#msg-input').fill('a different message entirely')
    await page.getByRole('button', { name: 'Lock and pre-sign' }).click()
    await expect(page.locator('#panel-relation')).toContainText('Step 2')
    await page.getByRole('button', { name: 'Use the real t' }).click()
    await expect(page.locator('#panel-relation .diff-strip.is-equal')).toHaveCount(1)
  })

  test('rejects t = 0 with an explanation rather than crashing', async ({ page }) => {
    await boot(page)
    await page.locator('#t-input').fill('0')
    await page.getByRole('button', { name: 'Lock and pre-sign' }).click()
    await expect(page.locator('#panel-relation .verdict-fail')).toContainText('Rejected')
    await expect(page.locator('#panel-relation .verdict-fail')).toContainText('[1, n-1]')
  })

  test('rejects a non-hex key with an explanation', async ({ page }) => {
    await boot(page)
    await page.locator('#sk-input').fill('zzzz')
    await page.getByRole('button', { name: 'Lock and pre-sign' }).click()
    await expect(page.locator('#panel-relation .verdict-fail')).toContainText('Rejected')
  })

  test('supplying a wrong t is allowed, and the verifier refuses the result', async ({ page }) => {
    await boot(page)
    await page.locator('#supply-t').fill('01')
    await page.getByRole('button', { name: 'Add t and verify' }).click()
    await expect(page.locator('#panel-relation .diff-strip.not-equal')).toHaveCount(1)
    await expect(page.locator('#panel-relation')).not.toContainText('VALID BIP-340 signature')
  })
})

test.describe('Swap, end to end', () => {
  test('the toggles drive all four combinations', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: 'Cross-Ledger Swap' }).click()
    // honest
    await expect(page.locator('#panel-swap')).toContainText('Both sides paid, in order')
    // skip only
    await page.locator('#swap-skip').check()
    await expect(page.locator('#panel-swap')).toContainText('Both sides paid, in order')
    // skip + cheat
    await page.locator('#swap-cheat').check()
    await expect(page.locator('#panel-swap')).toContainText('BOB LOST HIS COINS')
    // cheat only
    await page.locator('#swap-skip').uncheck()
    await expect(page.locator('#panel-swap')).toContainText('Fraud caught before anyone paid')
    // back to honest
    await page.locator('#swap-cheat').uncheck()
    await expect(page.locator('#panel-swap')).toContainText('Both sides paid, in order')
  })
})

test.describe('Break It, end to end', () => {
  test('the naive toggle produces a recovered key and a verified forgery', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: 'Break It' }).click()
    await expect(page.locator('#panel-break')).toContainText('No shared nonce')
    await page.locator('#naive-nonce').check()
    await expect(page.locator('#panel-break')).toContainText('PRIVATE KEY RECOVERED')
    await expect(page.locator('#panel-break')).toContainText('FORGERY ACCEPTED')
    await page.locator('#naive-nonce').uncheck()
    await expect(page.locator('#panel-break')).toContainText('No shared nonce')
  })
})

test.describe('layout', () => {
  test('no horizontal scrolling at 380px on any exhibit', async ({ page }) => {
    await page.setViewportSize({ width: 380, height: 800 })
    await boot(page)
    const tabs = [
      'The Relation',
      'Cross-Ledger Swap',
      'PTLC vs HTLC',
      'Break It',
      'Vectors & Fixtures',
      "What This Is & Isn't",
    ]
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
