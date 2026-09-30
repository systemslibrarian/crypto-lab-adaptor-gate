import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where the
 * Relation panel has already pre-signed its default message and the other five
 * tabpanels are hidden and UNRENDERED; the shared skip link focused; the
 * headline difference strip in BOTH of its states, mismatched under a wrong t
 * and then carrying t's violet under the real one, with step 4 appearing for
 * the first time only once a t has been supplied; the extraction disclosure
 * opened through its summary; a malformed signing key replacing the panel below
 * step 1 with a failure verdict, and the recovery from it; the swap on its
 * honest run, on the caught-fraud branch where a step reports STOPPED HERE, and
 * on the loss where an alarm verdict and a danger callout carry the negative
 * claim; the PTLC strips and the settlement table, focused as the scroll region
 * it is; the nonce-reuse attack on its safe default, on the recovered-key alarm
 * with the forgery accepted, and on the same-T branch that reuses a nonce and
 * still cannot recover; the vector and fixture tables including the row that
 * fails on purpose; the honesty panel; three hover states; and three focus
 * rings. Every one of those states is scanned, at desktop and at 380px.
 *
 * Two tone pairings are scanned on purpose because they read as contradictions
 * and are not: a pass-toned verdict whose text reports a REJECTION, and an
 * alarm-toned verdict reporting that every check succeeded.
 *
 * See `gate.ts` for why nothing is injected into the page, why no panel is
 * revealed from script, why the lab's defaults are asserted rather than assumed,
 * and why `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
