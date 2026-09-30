// THE CLAIMS SUITE (template section 4.1b / 4.1d).
//
// This is the suite that checks the page tells the TRUTH, as opposed to a11y.spec.ts
// which checks it is usable and the Vitest suites which check the cryptography.
//
// THE RULE THAT MAKES THESE WORTH ANYTHING: compare two values the PAGE PRINTED,
// rather than asserting against a hardcoded string. A test that re-derives the same
// expression the source uses will happily agree with a bug.
//
// BUT INTERNAL CONSISTENCY IS NOT ENOUGH -- a page can be consistently wrong, and a
// corrupted value reported consistently everywhere passes any self-agreement check.
// So this file mixes three kinds:
//
//   * cross-checks          -- two surfaces that must agree (a counter against the
//                              rows it counts; a caption's numbers against the rows).
//   * independent re-derivation -- recompute the claim from the page's own raw
//                              inputs by a DIFFERENT route than the source takes.
//                              Here that is a self-contained affine BigInt
//                              secp256k1 evaluated in the browser, sharing no code
//                              with the bundle.
//   * parts-sum-to-whole    -- the three vector classes must sum to the total; the
//                              passing and failing fixture rows must sum to all rows.
//
// Every §4.1c mutation target is named in a comment on the claim that owns it.

import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'

async function boot(page: Page): Promise<void> {
  page.setDefaultTimeout(20_000)
  await page.goto('.')
  await expect(page.locator('#panel-relation .card').first()).toBeVisible()
}

/**
 * Open every progressive-disclosure block in a panel.
 *
 * Exact values live behind "Inspect exact values" now, and a closed <details>
 * reports empty innerText -- so a claim that reads a rendered value has to open the
 * disclosure the way a reader would, through its summary, rather than by stripping
 * the attribute from script.
 */
async function openAllInspects(page: Page, panel: string): Promise<void> {
  const sums = page.locator(`${panel} details.inspect > summary`)
  const n = await sums.count()
  for (let i = 0; i < n; i++) {
    const d = sums.nth(i)
    if (!(await d.evaluate((e) => (e.parentElement as HTMLDetailsElement).open))) await d.click()
  }
}

/** The abbreviated text of a labelled field row, as a reader sees it. */
async function fieldValue(page: Page, panel: string, label: string): Promise<string> {
  return page
    .locator(`${panel} .field`, { has: page.locator('.field-label', { hasText: label }) })
    .first()
    .locator('.field-value')
    .innerText()
}

/**
 * The EXACT value behind an abbreviated field, from its `data-full`.
 *
 * Also asserts the abbreviation is an honest rendering of the full value -- its
 * visible head and tail must really be that value's head and tail. Otherwise a
 * page could print one number and carry another, and every check below would be
 * measuring the wrong thing.
 */
async function fieldFull(page: Page, panel: string, label: string): Promise<string> {
  const node = page
    .locator(`${panel} .field`, { has: page.locator('.field-label', { hasText: label }) })
    .first()
    .locator('.field-value')
  const full = (await node.getAttribute('data-full')) ?? ''
  expect(full, `${label} must carry its exact value`).not.toBe('')
  const shown = (await node.innerText()).trim()
  if (shown.includes('\u2026')) {
    const [head, tail] = shown.split('\u2026')
    expect(full.startsWith(head), `${label} displayed head must match the exact value`).toBe(true)
    expect(full.endsWith(tail), `${label} displayed tail must match the exact value`).toBe(true)
  } else {
    expect(shown).toBe(full)
  }
  return full
}

// ---------------------------------------------------------------------------
// An INDEPENDENT secp256k1, evaluated inside the page but sharing no code with
// the bundle. This is the "different route" the template asks for.
// ---------------------------------------------------------------------------
const INDEPENDENT_CHECK = `(() => {
  const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
  const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
  const m = (a, n) => ((a % n) + n) % n;
  function inv(a, n) {
    let [r0, r1] = [m(a, n), n], [s0, s1] = [1n, 0n];
    while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
    if (r0 !== 1n) throw new Error('not invertible');
    return m(s0, n);
  }
  function add(p, q) {
    if (!p) return q; if (!q) return p;
    if (p.x === q.x && m(p.y + q.y, P) === 0n) return null;
    const lam = (p.x === q.x && p.y === q.y)
      ? m(3n * p.x * p.x * inv(2n * p.y, P), P)
      : m((q.y - p.y) * inv(q.x - p.x, P), P);
    const x = m(lam * lam - p.x - q.x, P);
    return { x, y: m(lam * (p.x - x) - p.y, P) };
  }
  function mul(k, p) { let acc = null, b = p, n = m(k, N); while (n > 0n) { if (n & 1n) acc = add(acc, b); b = add(b, b); n >>= 1n; } return acc; }
  const G = { x: GX, y: GY };
  function sqrt(a) { let r = 1n, b = m(a, P), e = (P + 1n) / 4n; while (e > 0n) { if (e & 1n) r = m(r * b, P); b = m(b * b, P); e >>= 1n; } if (m(r * r, P) !== m(a, P)) throw new Error('no sqrt'); return r; }
  function liftX(x) { const y = sqrt(m(x * x * x + 7n, P)); return { x, y: y % 2n === 0n ? y : m(-y, P) }; }
  return { P, N, G, add, mul, liftX, m, inv };
})()`

test.describe('The Relation — the headline claim', () => {
  test('the difference printed on screen really is s minus s-hat, re-derived independently', async ({
    page,
  }) => {
    await boot(page)
    await page.locator('#btn-run').click()
    await expect(page.locator('#panel-relation .mech-sub.is-equal')).toHaveCount(1)
    await openAllInspects(page, '#panel-relation')

    // Everything below is parsed OFF THE PAGE -- exact values, via data-full,
    // each one checked against the abbreviation the reader actually sees.
    const sHat = await fieldFull(page, '#panel-relation', 'HELD EARLIER')
    const sPub = await fieldFull(page, '#panel-relation', 'PUBLISHED: S')
    const trueT = await fieldFull(page, '#panel-relation', 'T (THE SECRET)')
    const parity = (await fieldValue(page, '#panel-relation', 'PARITY OF R + T')).trim()

    const shown = await page.locator('#panel-relation .mech-sub-val').getAttribute('data-full')

    // CROSS-CHECK: the strip claims equality, so the value it prints must be the
    // t from stage 1.
    expect(shown).toBe(trueT)

    // INDEPENDENT RE-DERIVATION: subtract the s-hat and s the PAGE printed, by
    // the parity rule the PAGE printed, using arithmetic that shares no code
    // with the bundle -- and confirm it lands on the t the page displayed.
    const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
    const m = (a: bigint): bigint => ((a % N) + N) % N
    const recomputed =
      parity === 'even'
        ? m(BigInt('0x' + sPub) - BigInt('0x' + sHat))
        : m(BigInt('0x' + sHat) - BigInt('0x' + sPub))
    expect(recomputed.toString(16).padStart(64, '0')).toBe(trueT)

    // ...and the OTHER branch must NOT land on it, so the parity rule is doing
    // work rather than being decorative.
    const wrongWay =
      parity === 'even'
        ? m(BigInt('0x' + sHat) - BigInt('0x' + sPub))
        : m(BigInt('0x' + sPub) - BigInt('0x' + sHat))
    expect(wrongWay.toString(16).padStart(64, '0')).not.toBe(trueT)

    // MUTATION TARGET (§4.1c): flip the parity rule in adaptor.ts `adapt`
    // (swap the + and - branches). The strip reports not-equal and this fails.
  })

  test('the completed signature verifies, and the page says so by computation', async ({ page }) => {
    await boot(page)
    await page.locator('#btn-run').click()
    const verdicts = page.locator('#panel-relation .verdict')
    await expect(verdicts.filter({ hasText: 'VALID BIP-340 signature' })).toHaveCount(1)
    // and the pre-signature verdict on the same page says the opposite
    await expect(verdicts.filter({ hasText: 'BIP-340 verify REJECTS it' })).toHaveCount(1)
    // MUTATION TARGET: drop T from the nonce derivation in adaptor.ts
    // `deriveNonce` (remove Tx from the hashed input). Pre-verification still
    // passes, but invariant 6's claim in Break It collapses -- see below.
  })

  test('a wrong t turns the headline claim red and the signature is refused', async ({ page }) => {
    // The falsification. If this cannot be reached, the green badge is not evidence.
    await boot(page)
    await page.locator('#btn-wrong-t').click()
    await expect(page.locator('#panel-relation .mech-sub.not-equal')).toHaveCount(1)
    await expect(page.locator('#panel-relation .mech-sub.is-equal')).toHaveCount(0)
    await expect(
      page.locator('#panel-relation .verdict').filter({ hasText: 'REJECTED — the correct answer for a wrong t' }),
    ).toHaveCount(1)
    await expect(
      page.locator('#panel-relation .verdict').filter({ hasText: 'REJECTED — the correct answer for a wrong t' }),
    ).toHaveCount(1)
    // and it must NOT claim a valid signature anywhere
    await expect(
      page.locator('#panel-relation .verdict').filter({ hasText: 'VALID BIP-340 signature' }),
    ).toHaveCount(0)
  })

  test('RETIREMENT: changing an input clears the completed signature entirely', async ({ page }) => {
    await boot(page)
    await page.locator('#btn-run').click()
    await expect(page.locator('#panel-relation .mech-sub.is-equal')).toHaveCount(1)
    // Re-lock with a new message. The stale completion must be GONE, not stale.
    await openAllInspects(page, '#panel-relation')
    await page.locator('#msg-input').fill('Alice pays Bob 0.11 units on ledger A')
    await page.locator('#btn-lock').click()
    await expect(page.locator('#panel-relation .mech-sub.is-equal')).toHaveCount(0)
    await expect(page.locator('#panel-relation .mech-sub.is-off')).toHaveCount(1)
    // and stages 3 and 4 are gone with it: the brief's rule is that a completed
    // signature is never drawn before t is supplied, and it is structural here
    await expect(page.locator('#panel-relation .stage-card')).toHaveCount(2)
    await expect(page.locator('#panel-relation')).not.toContainText('Subtract, and the secret falls out')
  })

  test('NO-OP GUARD: re-locking with the same inputs does not destroy a fresh verdict', async ({
    page,
  }) => {
    await boot(page)
    await page.locator('#btn-run').click()
    const before = await fieldFull(page, '#panel-relation', 'T = T·G (PUBLIC)')
    await expect(page.locator('#panel-relation .mech-sub.is-equal')).toHaveCount(1)
    // Re-lock with the inputs UNCHANGED. The fresh verdict must survive.
    await openAllInspects(page, '#panel-relation')
    await page.locator('#btn-lock').click()
    const after = await fieldFull(page, '#panel-relation', 'T = T·G (PUBLIC)')
    expect(after).toBe(before)
    await expect(page.locator('#panel-relation .verdict-fail')).toHaveCount(0)
    // Stage 1 and 2 still stand; re-locking retires only the completion, which is
    // correct -- a new pre-signature has been made, so the old s no longer pairs.
    await expect(page.locator('#panel-relation .stage-card')).toHaveCount(2)
  })
})

test.describe('Vectors and fixtures — counts must agree with the rows', () => {
  test('the summary counter agrees with the rows it counts', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^Vectors$/ }).click()
    const rows = page.locator('#panel-vectors table').first().locator('tbody tr')
    const rowCount = await rows.count()
    const summary = await fieldValue(page, '#panel-vectors', 'ROWS MATCHING THE PUBLISHED RESULT')
    const [matched, total] = summary.trim().split(' of ').map((n) => Number(n.trim()))
    expect(total).toBe(rowCount)

    // INDEPENDENT RE-DERIVATION of every row's verdict from the two values that
    // row prints, rather than from the badge it prints beside them.
    //
    // This is deliberately NOT a comparison of the counter against the pills.
    // That version of this test was written first and a mutation defeated it:
    // inverting the `ok` comparison in ui/vectors.ts flips the pills AND the
    // counter together, so "0 of 19" still agreed with zero match pills and the
    // test stayed green while every row on the page was wrong. A page can be
    // consistently wrong, and a check that only asks the page to agree with
    // itself cannot see it.
    const cells = await rows.evaluateAll((trs) =>
      trs.map((tr) => ({
        expected: (tr.children[4] as HTMLElement).innerText.trim(),
        computed: (tr.children[5] as HTMLElement).innerText.trim(),
        badge: (tr.children[6] as HTMLElement).innerText.trim(),
      })),
    )
    expect(cells.length).toBe(rowCount)
    let agree = 0
    for (const [i, c] of cells.entries()) {
      expect(c.expected.length, `row ${i} must print its expected verdict`).toBeGreaterThan(0)
      expect(c.computed.length, `row ${i} must print its computed verdict`).toBeGreaterThan(0)
      const same = c.expected === c.computed
      // the badge must say what the two printed values actually say
      expect(/MISMATCH/.test(c.badge), `row ${i} badge must follow its own two values`).toBe(!same)
      if (same) agree++
    }
    // The library is correct against BIP-340, so every row's two values agree...
    expect(agree).toBe(rowCount)
    // ...and the counter must report that number.
    expect(matched).toBe(agree)
    // MUTATION TARGET: invert the `ok` comparison in ui/vectors.ts
    // (`computed !== v.expected`). Every badge then contradicts its own row.
  })

  test('PARTS SUM TO WHOLE: the three vector classes account for every row', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^Vectors$/ }).click()
    const rows = page.locator('#panel-vectors table').first().locator('tbody tr')
    const total = await rows.count()
    const signable = await rows.filter({ hasText: /^\s*\d+\s+signable/ }).count()
    const cls = await rows.evaluateAll((trs) =>
      trs.map((tr) => (tr.children[1] as HTMLElement).innerText.trim()),
    )
    const nSignable = cls.filter((c) => c === 'signable').length
    const nAccept = cls.filter((c) => c === 'verify-only (accept)').length
    const nReject = cls.filter((c) => c === 'verify-only (reject)').length
    expect(nSignable + nAccept + nReject).toBe(total)
    // The caption states these numbers in prose; they must match the rows.
    const caption = await page.locator('#kat-caption').innerText()
    expect(caption).toContain(`${nSignable} rows carry a secret key`)
    expect(caption).toContain(`${nAccept} row is a positive verify-only row`)
    expect(caption).toContain(`${nReject} rows are negative verify-only rows`)
    expect(caption).toContain(`Not all ${total} round-trip`)
    void signable
    // MUTATION TARGET: change the `cls` assignment in crypto/vectors.ts so a
    // verify-only row is classed signable. The caption and the rows disagree.
  })

  test('exactly one row reaches a fourth challenge-hash block, and it is the 100-byte one', async ({
    page,
  }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^Vectors$/ }).click()
    const rows = page.locator('#panel-vectors table').first().locator('tbody tr')
    const data = await rows.evaluateAll((trs) =>
      trs.map((tr) => ({
        row: (tr.children[0] as HTMLElement).innerText.trim(),
        msgBytes: Number((tr.children[2] as HTMLElement).innerText.trim()),
        blocks: Number((tr.children[3] as HTMLElement).innerText.trim()),
      })),
    )
    // INDEPENDENT RE-DERIVATION of the block count from the message length the
    // page printed, by the formula rather than by reading the source.
    for (const d of data) {
      expect(d.blocks).toBe(Math.ceil((128 + d.msgBytes + 9) / 64))
    }
    const four = data.filter((d) => d.blocks >= 4)
    expect(four.length).toBe(1)
    expect(four[0].msgBytes).toBe(100)
    expect(Math.min(...data.map((d) => d.blocks))).toBe(3) // no row is single-block
  })

  test('the deliberately wrong fixture row is rendered and reported as FAILING', async ({ page }) => {
    // This is what makes every other green row on the page mean something.
    await boot(page)
    await page.getByRole('tab', { name: /^Vectors$/ }).click()
    const wrong = page.locator('#panel-vectors tr.row-wrong')
    await expect(wrong).toHaveCount(1)
    await expect(wrong.locator('.pill-fail')).toHaveCount(1)
    await expect(wrong.locator('.pill-fail')).toContainText('MISMATCH')
    // It is rendered as an ordinary row: same table, same columns.
    const cols = await wrong.evaluate((tr) => tr.children.length)
    const firstRowCols = await page
      .locator('#panel-vectors table')
      .last()
      .locator('tbody tr')
      .first()
      .evaluate((tr) => tr.children.length)
    expect(cols).toBe(firstRowCols)
    // MUTATION TARGET: delete the deliberatelyWrong row from crypto/fixtures.ts.
    // This claim fails, which is the point -- the table would otherwise only ever
    // be seen agreeing.
  })

  test('BOTH values are printed on every row, not only where they differ', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^Vectors$/ }).click()
    const fixtures = page.locator('#panel-vectors table').last().locator('tbody tr')
    const n = await fixtures.count()
    expect(n).toBeGreaterThan(1)
    for (let i = 0; i < n; i++) {
      const expected = (await fixtures.nth(i).locator('td').nth(2).innerText()).trim()
      const computed = (await fixtures.nth(i).locator('td').nth(3).innerText()).trim()
      expect(expected.length, `row ${i} expected s must be printed`).toBeGreaterThan(0)
      expect(computed.length, `row ${i} computed s must be printed`).toBeGreaterThan(0)
    }
    // and on the ONE row where they differ, they really do differ on screen
    const wrongExpected = (await page.locator('tr.row-wrong td').nth(2).innerText()).trim()
    const wrongComputed = (await page.locator('tr.row-wrong td').nth(3).innerText()).trim()
    expect(wrongExpected).not.toBe(wrongComputed)
  })

  test('PARTS SUM TO WHOLE: passing plus deliberately-failing equals all fixture rows', async ({
    page,
  }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^Vectors$/ }).click()
    const rows = page.locator('#panel-vectors table').last().locator('tbody tr')
    const total = await rows.count()
    const passing = Number(
      (await fieldValue(page, '#panel-vectors', 'ROWS PASSING')).trim().split(' of ')[0],
    )
    const failing = Number(
      (await fieldValue(page, '#panel-vectors', 'ROWS EXPECTED TO FAIL')).trim().split(' ')[0],
    )
    expect(passing + failing).toBe(total)
  })
})

test.describe('Swap — atomicity and the wrong-T loss', () => {
  test('the honest run pays both sides and the order is visible', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^Swap$/ }).click()
    // The exhibit reveals one transition at a time now, so the outcome exists only
    // once the sequence has actually played out -- which is the point of stepping it.
    await expect(page.locator('#panel-swap .step')).toHaveCount(1)
    await page.locator('#btn-swap-all').click()
    await expect(page.locator('#panel-swap .verdict').filter({ hasText: 'Both sides paid, in order' })).toHaveCount(1)
    await expect(page.locator('#panel-swap .step-status.is-alarm')).toHaveCount(0)
    // the ledger B step precedes the ledger A step in the rendered order
    const titles = await page.locator('#panel-swap .step-title').allInnerTexts()
    const bIdx = titles.findIndex((t) => /publishes s_B on ledger B/.test(t))
    const aIdx = titles.findIndex((t) => /publishes s_A on ledger A/.test(t))
    expect(bIdx).toBeGreaterThanOrEqual(0)
    expect(aIdx).toBeGreaterThan(bIdx)
  })

  test("Bob's claim is not computable before Alice publishes", async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^Swap$/ }).click()
    await page.locator('#btn-swap-all').click()
    await expect(
      page.locator('#panel-swap .verdict').filter({ hasText: 'Not computable before Alice publishes' }),
    ).toHaveCount(1)
    // MUTATION TARGET: make swap.ts read the signature from Alice's side instead
    // of from readPublishedSignature(ledgerB). The early-claim guard flips.
  })

  test('NEGATIVE CLAIM: every check passes and Bob still loses the funds', async ({ page }) => {
    // Template §4.1d, all three assertions.
    await boot(page)
    await page.getByRole('tab', { name: /^Swap$/ }).click()

    // 1. REACH THE FIXTURE through the UI, and drive the sequence to its end.
    await page.locator('#swap-cheat').check()
    await page.locator('#swap-skip').check()
    await page.locator('#btn-swap-all').click()

    // 2. EVERY CHECK THE PAGE PERFORMS IN THIS STATE REPORTS SUCCESS, asserted
    //    against the rendered verdicts rather than a flag the test sets.
    await expect(
      page.locator('#panel-swap .pill-ok').filter({ hasText: 'the t Bob extracted is the correct one' }),
    ).toHaveCount(1)
    await expect(
      page.locator('#panel-swap .verdict').filter({ hasText: 'Not computable before Alice publishes' }),
    ).toHaveCount(1)
    await expect(
      page.locator('#panel-swap .pill-ok').filter({ hasText: 'Alice was paid on ledger B' }),
    ).toHaveCount(1)

    // ...and yet:
    await expect(
      page.locator('#panel-swap .verdict-alarm').filter({ hasText: 'BOB LOST HIS COINS' }),
    ).toHaveCount(1)

    // 3. THE LIMITATION IS ON SCREEN IN THAT STATE -- visible, not in the README
    //    and not behind a disclosure the reader has to open.
    const claim = page.locator('#swap-negative-claim')
    await expect(claim).toBeVisible()
    await expect(claim).toContainText('What this does NOT prove')
    await expect(claim).toContainText('Extraction working does not mean the swap is safe')
    await expect(claim).toContainText('there is no failure code for that')
    // it is not inside a closed <details>
    expect(await claim.evaluate((n) => !!n.closest('details'))).toBe(false)
    // MUTATION TARGET: delete #swap-negative-claim from ui/swap.ts -> assertion 3
    // fails. Break a check inside the fixture (force bobExtractedTCorrect false)
    // -> assertion 2 fails.
  })

  test('SCOPED: skipping the check alone is NOT the loss', async ({ page }) => {
    // The brief's discipline point: "X does not prove Y" is almost always too
    // broad. The skip is only a loss against a counterparty who cheats.
    await boot(page)
    await page.getByRole('tab', { name: /^Swap$/ }).click()
    await page.locator('#swap-skip').check()
    await page.locator('#btn-swap-all').click()
    await expect(page.locator('#panel-swap .verdict-alarm')).toHaveCount(0)
    await expect(
      page.locator('#panel-swap .pill-ok').filter({ hasText: 'Bob was paid on ledger A' }),
    ).toHaveCount(1)
  })

  test('SCOPED: cheating alone is caught and nobody pays', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^Swap$/ }).click()
    await page.locator('#swap-cheat').check()
    await page.locator('#btn-swap-all').click()
    await expect(
      page.locator('#panel-swap .verdict').filter({ hasText: 'Fraud caught before anyone paid' }),
    ).toHaveCount(1)
    await expect(page.locator('#panel-swap .step-status.is-blocked')).not.toHaveCount(0)
  })
})

test.describe('PTLC — decorrelation is measured, not drawn', () => {
  test('the counters agree with the rendered strips', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^PTLC$/ }).click()
    const ptlcVals = await page.locator('#panel-ptlc .strip-ptlc .strip-val').allInnerTexts()
    const htlcVals = await page.locator('#panel-ptlc .strip-htlc .strip-val').allInnerTexts()
    expect(ptlcVals.length).toBe(3)
    expect(htlcVals.length).toBe(3)

    // CROSS-CHECK: the distinct counts the page prints must match the rendered
    // values, computed here from what is on screen.
    const ptlcDistinct = new Set(ptlcVals.map((v) => v.trim())).size
    const htlcDistinct = new Set(htlcVals.map((v) => v.trim())).size
    expect(ptlcDistinct).toBe(3)
    expect(htlcDistinct).toBe(1)
    await expect(
      page.locator('#panel-ptlc .pill').filter({ hasText: `${ptlcDistinct} distinct of 3 hops` }),
    ).not.toHaveCount(0)

    // and the headline verdict agrees with both
    await expect(
      page.locator('#panel-ptlc .verdict').filter({ hasText: 'Per-hop decorrelation holds' }),
    ).toHaveCount(1)
    // MUTATION TARGET: zero the blinding scalars in crypto/ptlc.ts
    // defaultPtlcPath. All three points collapse to one and this fails.
  })

  test('settlement runs backward and every hop extraction matches', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^PTLC$/ }).click()
    const order = await page
      .locator('#panel-ptlc table tbody tr td:nth-child(2)')
      .allInnerTexts()
    expect(order[0]).toContain('hop 3')
    expect(order[order.length - 1]).toContain('hop 1')
    const mismatches = page.locator('#panel-ptlc table .pill-fail')
    await expect(mismatches).toHaveCount(0)
    // MUTATION TARGET: feed extraction the wrong s-hat in crypto/ptlc.ts (extract
    // against a different hop's pre-signature). The extraction column goes red.
  })
})

test.describe('Break It — the attack is real and the default is safe', () => {
  test('the shipped default does NOT reuse a nonce', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^Break It$/ }).click()
    await expect(page.locator('#naive-nonce')).not.toBeChecked()
    const r1 = (await fieldValue(page, '#panel-break', 'R FROM PRE-SIGNATURE 1')).trim()
    const r2 = (await fieldValue(page, '#panel-break', 'R FROM PRE-SIGNATURE 2')).trim()
    // CROSS-CHECK the pill against the two values it describes.
    expect(r1).not.toBe(r2)
    await expect(page.locator('#panel-break .pill').filter({ hasText: 'different nonce R' })).toHaveCount(1)
    await expect(
      page.locator('#panel-break .verdict').filter({ hasText: 'No shared nonce' }),
    ).toHaveCount(1)
    // MUTATION TARGET: drop Tx from deriveNonce's hashed input in adaptor.ts.
    // R1 and R2 become equal and this claim fails -- which is how invariant 6 is
    // proved to be doing work.
  })

  test('the naive nonce really does share R, and the key is recovered', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^Break It$/ }).click()
    await page.locator('#naive-nonce').check()
    const r1 = (await fieldValue(page, '#panel-break', 'R FROM PRE-SIGNATURE 1')).trim()
    const r2 = (await fieldValue(page, '#panel-break', 'R FROM PRE-SIGNATURE 2')).trim()
    expect(r1).toBe(r2)
    await expect(
      page.locator('#panel-break .verdict-alarm').filter({ hasText: 'PRIVATE KEY RECOVERED' }),
    ).toHaveCount(1)
    await expect(
      page.locator('#panel-break .verdict-alarm').filter({ hasText: 'FORGERY ACCEPTED' }),
    ).toHaveCount(1)
    // the forgery is on a message the signer never signed
    await expect(page.locator('#panel-break')).toContainText('transfer everything to the attacker')
  })

  test('SCOPED: a reused nonce under ONE T is still not recoverable', async ({ page }) => {
    // Precision the brief asks for: nonce reuse is not sufficient on its own here.
    // The two challenges must differ, which means the two T must differ.
    await boot(page)
    await page.getByRole('tab', { name: /^Break It$/ }).click()
    await page.locator('#naive-nonce').check()
    await page.locator('#same-t').check()
    const r1 = (await fieldValue(page, '#panel-break', 'R FROM PRE-SIGNATURE 1')).trim()
    const r2 = (await fieldValue(page, '#panel-break', 'R FROM PRE-SIGNATURE 2')).trim()
    expect(r1).toBe(r2) // the nonce IS reused
    await expect(page.locator('#panel-break .pill').filter({ hasText: 'e₁ == e₂' })).toHaveCount(1)
    // ...and it still does not yield the key
    await expect(
      page.locator('#panel-break .verdict').filter({ hasText: 'Not recoverable from these two' }),
    ).toHaveCount(1)
    await expect(page.locator('#panel-break .verdict-alarm')).toHaveCount(0)
  })

  test('a wrong-T pre-signature is well-formed and still rejected against the real T', async ({
    page,
  }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^Break It$/ }).click()
    await openAllInspects(page, '#panel-break')
    const real = (await fieldValue(page, '#panel-break', 'T YOU CARE ABOUT')).trim()
    const fake = (await fieldValue(page, '#panel-break', 'T IT ACTUALLY COMMITS TO')).trim()
    expect(real).not.toBe(fake)
    await expect(
      page.locator('#panel-break .verdict').filter({ hasText: 'Rejected against the T you care about' }),
    ).toHaveCount(1)
    await expect(
      page.locator('#panel-break .pill').filter({ hasText: 'pre-verifies against its own T*' }),
    ).toHaveCount(1)
  })
})

test.describe('Honesty — the scoping the page claims is present and specific', () => {
  test('real / modeled / not built are all populated', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^Honesty$/ }).click()
    for (const tag of ['REAL', 'MODELED', 'NOT BUILT']) {
      await expect(
        page.locator('#panel-honesty .honesty-tag').filter({ hasText: new RegExp(`^${tag}$`) }),
      ).not.toHaveCount(0)
    }
    // Template §0 principle 2: the page itself must say it is not production.
    await expect(page.locator('#panel-honesty')).toContainText(/not production/i)
    await expect(page.locator('#panel-honesty')).toContainText(/teaching demo/i)
  })

  test('the negative claims are scoped to this construction, not to the field', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^Honesty$/ }).click()
    await expect(page.locator('#negative-claim-presig')).toContainText('pin WHICH t would complete it')
    await expect(page.locator('#negative-claim-preverify')).toContainText(
      'no check on this page raises a failure code',
    )
    await expect(page.locator('#panel-honesty')).toContainText(
      'It does not make a routed payment private',
    )
  })

  test('the fixtures are never called official', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^Vectors$/ }).click()
    await expect(page.locator('#fixture-caption')).toContainText('NOT official test vectors')
    // The failure this guards against is a fixture being PRESENTED as official.
    // Saying that no official adaptor vectors exist is the opposite of that, so
    // check the claim rather than the word: no sentence may assert that these
    // fixtures are official or standard.
    const body = await page.locator('#panel-vectors').innerText()
    expect(body).not.toMatch(/these (are|fixtures are) (the )?official/i)
    expect(body).not.toMatch(/official (adaptor )?(test )?vectors (are|for) (this|these|adaptor)/i)
    expect(body).toMatch(/no standards body publishes/i)
    // and the BIP-340 table, which IS official, says so separately
    await expect(page.locator('#kat-caption')).toContainText('BIP-340 official test vectors')
  })
})

test.describe('Page-level honesty checks', () => {
  test('exactly one h1, one banner, and the scripture footer verbatim', async ({ page }) => {
    await boot(page)
    await expect(page.locator('h1')).toHaveCount(1)
    await expect(page.locator('[role="banner"]')).toHaveCount(1)
    await expect(page.locator('.scripture-footer')).toContainText(
      'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31',
    )
  })

  test('the hero three roles say three different things', async ({ page }) => {
    await boot(page)
    const sub = (await page.locator('.cl-hero-sub').innerText()).trim()
    const desc = (await page.locator('.cl-hero-desc').innerText()).trim()
    const why = (await page.locator('.cl-hero-why-text').innerText()).trim()
    expect(sub).not.toBe(desc)
    expect(desc).not.toBe(why)
    expect(sub).not.toContain('.') // a label, not a sentence
    expect(desc.length).toBeGreaterThan(40)
    expect(why.length).toBeGreaterThan(80)
    // the why-box must not merely restate the description
    const descWords = new Set(desc.toLowerCase().match(/[a-z]{5,}/g) ?? [])
    const whyWords = new Set(why.toLowerCase().match(/[a-z]{5,}/g) ?? [])
    const overlap = [...whyWords].filter((w) => descWords.has(w)).length
    expect(overlap / whyWords.size).toBeLessThan(0.5)
  })

  test('the [hidden] probe: hidden panels are really not rendered', async ({ page }) => {
    await boot(page)
    // A class rule setting `display` outranks the UA [hidden] rule, so an element
    // can paint while the code believes it is hidden. Check computed style, not
    // the attribute.
    for (const id of ['swap', 'ptlc', 'break', 'vectors', 'honesty']) {
      const shown = await page
        .locator(`#panel-${id}`)
        .evaluate((n) => getComputedStyle(n).display !== 'none' || n.getBoundingClientRect().height > 0)
      expect(shown, `#panel-${id} must not paint while hidden`).toBe(false)
    }
  })

  test('the assigned --accent is on :root, and the fallback still paints without it', async ({ page }) => {
    // The accent was assigned centrally on 2026-09-30 (#ff6b7f), so the premise of
    // this test changed: it used to assert --accent was UNSET. The half worth
    // keeping is the second one — every use site reads `var(--accent, #35d6bb)`
    // and the fallback has to actually paint, because 58 of 216 labs still define
    // no --accent and a use site that assumes one is a fleet-wide hazard. So this
    // now pins the assigned value AND re-checks the fallback with it removed.
    await boot(page)
    const accent = await page.evaluate(() =>
      getComputedStyle(document.documentElement).getPropertyValue('--accent').trim(),
    )
    expect(accent, 'the centrally assigned accent must be on :root').toBe('#ff6b7f')

    const withoutAccent = await page.evaluate(() => {
      document.documentElement.style.setProperty('--accent', 'initial')
      const el = document.querySelector('.tab-btn[aria-selected="true"]') as HTMLElement | null
      const painted = el ? getComputedStyle(el).borderTopColor : ''
      document.documentElement.style.removeProperty('--accent')
      return painted
    })
    expect(withoutAccent, 'the var() fallback must paint when --accent is absent').not.toBe('rgba(0, 0, 0, 0)')
    expect(withoutAccent).not.toBe('')
    const tabBorder = await page
      .locator('.tab-btn[aria-selected="true"]')
      .evaluate((n) => getComputedStyle(n).borderTopColor)
    expect(tabBorder).not.toBe('rgba(0, 0, 0, 0)')
    expect(tabBorder).not.toBe('')
  })

  test('the independent in-page secp256k1 agrees with the bundle on T = t*G', async ({ page }) => {
    // The strongest form available from the browser: take the t the PAGE printed,
    // recompute T = t*G with arithmetic that shares no code with the bundle, and
    // compare against the x(T) the PAGE printed.
    await boot(page)
    await page.locator('#btn-run').click()
    await openAllInspects(page, '#panel-relation')
    const tFull = await fieldFull(page, '#panel-relation', 'T (THE SECRET)')
    const TxFull = await fieldFull(page, '#panel-relation', 'T = T\u00b7G (PUBLIC)')
    const computed = await page.evaluate(
      ([code, t]) => {
        const lib = eval(code) as {
          G: { x: bigint; y: bigint }
          mul: (k: bigint, p: { x: bigint; y: bigint }) => { x: bigint; y: bigint } | null
        }
        const T = lib.mul(BigInt('0x' + t), lib.G)
        if (!T) return 'identity'
        return { x: T.x.toString(16).padStart(64, '0'), evenY: T.y % 2n === 0n }
      },
      [INDEPENDENT_CHECK, tFull] as const,
    )
    expect(computed).not.toBe('identity')
    const r = computed as { x: string; evenY: boolean }
    expect(r.x).toBe(TxFull)
    // T travels x-only, so the point behind those bytes must be the even-y one.
    expect(r.evenY).toBe(true)
  })

  test('the independent secp256k1 re-derives the whole pre-signature equation', async ({ page }) => {
    // s-hat*G == R_adj + e*P, recomputed from the four values the page printed,
    // with its own point arithmetic. This is the pre-verification claim checked
    // by a route the source does not take.
    await boot(page)
    await page.locator('#btn-run').click()
    // These values live behind "Inspect exact values", so open the disclosures the
    // way a reader would rather than stripping the attribute from script.
    await openAllInspects(page, '#panel-relation')
    // The label renders through `text-transform: uppercase`, so match on the
    // part that is unambiguous rather than on the cased s-circumflex.
    const sHat = await fieldFull(page, '#panel-relation', 'PRE-SIGNATURE)')
    const rx = await fieldFull(page, '#panel-relation', 'R (NONCE POINT, X-ONLY)')
    const e = await fieldFull(page, '#panel-relation', 'CHALLENGE E')
    const pk = await fieldFull(page, '#panel-relation', "SIGNER'S PUBLIC KEY")
    const parity = (await fieldValue(page, '#panel-relation', 'PARITY OF R + T')).trim()

    const holds = await page.evaluate(
      ([code, sHatHex, rxHex, eHex, pkHex, par]) => {
        const lib = eval(code) as any
        const P = lib.P as bigint
        const neg = (p: any) => (p ? { x: p.x, y: lib.m(-p.y, P) } : null)
        const R = lib.liftX(BigInt('0x' + rxHex))
        const Pt = lib.liftX(BigInt('0x' + pkHex))
        const lhs = lib.mul(BigInt('0x' + sHatHex), lib.G)
        const Radj = par === 'even' ? R : neg(R)
        const rhs = lib.add(Radj, lib.mul(BigInt('0x' + eHex), Pt))
        const eq = (a: any, b: any) => !!a && !!b && a.x === b.x && a.y === b.y
        // and the other branch, which must NOT hold
        const rhsWrong = lib.add(par === 'even' ? neg(R) : R, lib.mul(BigInt('0x' + eHex), Pt))
        return { correct: eq(lhs, rhs), wrong: eq(lhs, rhsWrong) }
      },
      [INDEPENDENT_CHECK, sHat, rx, e, pk, parity] as const,
    )
    expect(holds.correct).toBe(true)
    expect(holds.wrong).toBe(false)
  })
})

test.describe('PTLC — causality is on screen, not just in prose', () => {
  test('settlement starts at the LAST hop and cannot advance until it succeeds', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^PTLC$/ }).click()
    // Nothing settled on arrival.
    await expect(page.locator('#panel-ptlc .pill').filter({ hasText: 'settled' })).toHaveCount(0)
    await page.locator('#btn-ptlc-next').click()
    // Exactly one hop has settled, and it is the last one on the route.
    const settled = page.locator('#panel-ptlc tbody tr', { has: page.locator('.pill-ok', { hasText: 'settled' }) })
    await expect(settled).toHaveCount(1)
    await expect(settled.first()).toContainText('hop 3')
  })

  test('corrupting a hop BLOCKS every hop upstream and none downstream', async ({ page }) => {
    // The P0 claim: the model is causal, so a break really does stall the hops
    // that depend on it. Asserted against the rendered rows.
    await boot(page)
    await page.getByRole('tab', { name: /^PTLC$/ }).click()
    await page.locator('#ptlc-corrupt-2').check()
    await page.locator('#btn-ptlc-all').click()

    const rowText = async (hop: string) =>
      (await page.locator('#panel-ptlc tbody tr', { hasText: hop }).first().innerText()).trim()

    // hop 3 is DOWNSTREAM of the break: unaffected.
    expect(await rowText('hop 3')).toMatch(/settled/)
    // hop 2 is the break, hop 1 is upstream of it: both stop.
    expect(await rowText('hop 2')).toMatch(/BLOCKED/)
    expect(await rowText('hop 1')).toMatch(/BLOCKED/)
    await expect(page.locator('#panel-ptlc .verdict-alarm')).toContainText('chain is broken')
    // and the page names the cause for the upstream hop specifically
    await expect(page.locator('#panel-ptlc')).toContainText('no usable secret arrived from downstream')
  })

  test('a WRONG BLINDING stalls upstream even though signature and extraction are correct', async ({
    page,
  }) => {
    // THE claim that separates a causal model from a precomputed one. A corrupt
    // signature is caught by the guard that stops once nothing usable arrived; only
    // this fault reaches the case where a hop settles perfectly, its extraction
    // matches, and the value DERIVED for the hop above it is wrong. A model that
    // settled each hop from a precomputed secret would sail straight through it.
    await boot(page)
    await page.getByRole('tab', { name: /^PTLC$/ }).click()
    await page.locator('#ptlc-blind-3').check()
    await page.locator('#btn-ptlc-all').click()

    const row = (hop: string) => page.locator('#panel-ptlc tbody tr', { hasText: hop }).first()
    // hop 3 is entirely healthy: settled, and its extraction matched.
    await expect(row('hop 3')).toContainText('settled')
    await expect(row('hop 3').locator('.pill-ok', { hasText: 'matches' })).toHaveCount(1)
    // ...and the hops above it still cannot settle.
    await expect(row('hop 2')).toContainText('BLOCKED')
    await expect(row('hop 1')).toContainText('BLOCKED')
    await expect(page.locator('#panel-ptlc .verdict-alarm')).toContainText('chain is broken')
    // The page names the cause precisely: not a bad signature, not a bad extraction.
    await expect(page.locator('#panel-ptlc')).toContainText('not valid under this hop payer key')
  })

  test('corrupting the FIRST hop stalls nothing else — the break is directional', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^PTLC$/ }).click()
    await page.locator('#ptlc-corrupt-1').check()
    await page.locator('#btn-ptlc-all').click()
    const blocked = page.locator('#panel-ptlc tbody tr .pill-fail', { hasText: 'BLOCKED' })
    await expect(blocked).toHaveCount(1)
  })
})

test.describe('Time to the insight', () => {
  test('one action reaches s - s-hat = t', async ({ page }) => {
    await boot(page)
    await expect(page.locator('#panel-relation .mech-sub.is-equal')).toHaveCount(0)
    await page.locator('#btn-run').click()
    await expect(page.locator('#panel-relation .mech-sub.is-equal')).toHaveCount(1)
    await expect(
      page.locator('#panel-relation .verdict').filter({ hasText: 'Secret recovered' }),
    ).toHaveCount(1)
  })

  test('the primary action is inside the first 390x844 viewport', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await boot(page)
    const y = await page.locator('#btn-run').evaluate((e) => {
      const r = e.getBoundingClientRect()
      return r.top + window.scrollY
    })
    expect(y, 'the first meaningful action must be visible without scrolling').toBeLessThan(844)
    // and the page has not been scrolled for the reader
    expect(await page.evaluate(() => window.scrollY)).toBe(0)
  })

  test('raw hex is optional detail, not the opening experience', async ({ page }) => {
    await boot(page)
    // No 64-character hex run is visible before anything is run or disclosed.
    const visibleText = await page.locator('#panel-relation').innerText()
    expect(visibleText).not.toMatch(/[0-9a-f]{64}/)
    // and the inputs ship behind a closed disclosure
    await expect(page.locator('#panel-relation details.inspect[open]')).toHaveCount(0)
    await expect(page.locator('#sk-input')).not.toBeVisible()
  })
})

test.describe('URL state survives refresh and Back', () => {
  test('the active exhibit and its failure mode are linkable', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^Swap$/ }).click()
    await page.locator('#swap-cheat').check()
    await page.locator('#swap-skip').check()
    const hash = await page.evaluate(() => location.hash)
    expect(hash).toContain('e=swap')
    expect(hash).toContain('cheat=1')
    expect(hash).toContain('skip=1')

    // A reload restores the same state...
    await page.reload()
    await expect(page.locator('#panel-swap')).toBeVisible()
    await expect(page.locator('#swap-cheat')).toBeChecked()
    await expect(page.locator('#swap-skip')).toBeChecked()

    // ...and two people opening that link see the same proof.
    await page.locator('#btn-swap-all').click()
    await expect(page.locator('#swap-negative-claim')).toBeVisible()
  })

  test('Back returns to the previous exhibit', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^PTLC$/ }).click()
    await expect(page.locator('#panel-ptlc')).toBeVisible()
    await page.goBack()
    await expect(page.locator('#panel-relation')).toBeVisible()
  })

  test('Reset all returns the page to its documented safe state', async ({ page }) => {
    await boot(page)
    await page.getByRole('tab', { name: /^Break It$/ }).click()
    await page.locator('#btn-break-go').click()
    await expect(page.locator('#panel-break .verdict-alarm').first()).toBeVisible()
    await page.locator('#btn-reset-all').click()
    await expect(page.locator('#panel-relation')).toBeVisible()
    expect(await page.evaluate(() => location.hash)).toBe('#e=relation')
    // the deliberately broken mode is off again
    await page.getByRole('tab', { name: /^Break It$/ }).click()
    await expect(page.locator('#naive-nonce')).not.toBeChecked()
  })
})
