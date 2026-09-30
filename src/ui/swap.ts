// Exhibit 2 -- the cross-ledger swap (brief act 5), driven rather than reported.
//
// The swap is never drawn as simultaneous. It is an ordered sequence, the order IS
// the lesson, and an exhibit that computes the whole run and prints its ending hands
// the reader the conclusion while hiding the thing that produced it. So the same
// deterministic state machine now advances one transition at a time, with actor lanes
// showing who knows t, who holds which pre-signature, and what each ledger has
// published at that moment.

import {
  startSwap,
  swapNext,
  swapAll,
  swapFinished,
  lanesAt,
  type SteppedSwap,
} from '../crypto/swap'
import { hex } from '../crypto/secp'
import {
  el,
  field,
  verdict,
  card,
  clear,
  short,
  pill,
  inspect,
  trustRail,
  story,
  actions,
  button,
  tableWrap,
} from './dom'

const opts = { aliceCheats: false, bobSkipsPreVerify: false }
let stepped: SteppedSwap = startSwap(opts)

export function swapUiState(): { cheat: boolean; skip: boolean; cursor: number } {
  return { cheat: opts.aliceCheats, skip: opts.bobSkipsPreVerify, cursor: stepped.cursor }
}

export function setSwapUiState(cheat: boolean, skip: boolean, cursor?: number): void {
  opts.aliceCheats = cheat
  opts.bobSkipsPreVerify = skip
  stepped = startSwap(opts)
  if (cursor !== undefined) stepped = { ...stepped, cursor: Math.min(cursor, stepped.total) }
}

let onChange: (() => void) | null = null
export function setSwapOnChange(fn: () => void): void {
  onChange = fn
}

function rerender(): void {
  const panel = document.getElementById('panel-swap')
  if (panel) renderSwap(panel)
  onChange?.()
}

function restart(): void {
  stepped = startSwap(opts)
}

export function renderSwap(root: HTMLElement): void {
  clear(root)
  const run = stepped.run

  const intro = card(null)
  intro.classList.add('intro', 'opening')
  intro.append(
    story(
      'Alice has coins on one ledger, Bob on another, and neither wants to pay first. ' +
        'Alice picks a secret and both sides pre-sign their own payment against it. The ' +
        'moment Alice claims, the signature she publishes hands Bob the secret he needs ' +
        'to claim too — so the second payment is not a promise, it is arithmetic.',
    ),
  )
  intro.append(
    actions(
      button('Next event', { id: 'btn-swap-next', primary: true, disabled: swapFinished(stepped) }, () => {
        stepped = swapNext(stepped)
        rerender()
      }),
      button('Run to the end', { id: 'btn-swap-all', disabled: swapFinished(stepped) }, () => {
        stepped = swapAll(stepped)
        rerender()
      }),
      button('Reset exhibit', { id: 'btn-swap-reset' }, () => {
        opts.aliceCheats = false
        opts.bobSkipsPreVerify = false
        restart()
        rerender()
      }),
    ),
  )
  intro.append(
    el('p', {
      class: 'note hint',
      text: `Event ${stepped.cursor} of ${stepped.total}. Each press advances exactly one ledger publication or extraction.`,
    }),
  )
  intro.append(
    trustRail(
      { kind: 'real', text: 'real BIP-340 signatures and verification' },
      { kind: 'modeled', text: 'ledgers, timelocks and coins' },
    ),
  )
  root.append(intro)

  root.append(toggles())
  root.append(lanes())
  root.append(sequence())

  // Outcome is only shown once the sequence has actually played out.
  if (swapFinished(stepped)) root.append(outcome())

  root.append(
    inspect(
      'Inspect exact values',
      field('x(T) the payment is locked to', short(hex(run.Tx), 16), 'tone-t', hex(run.Tx)),
      field('Alice pre-signed against', short(hex(run.TxAlicePreSignedAgainst), 16), 'tone-t', hex(run.TxAlicePreSignedAgainst)),
      field("Alice's public key", short(hex(run.alicePublicKey), 14), '', hex(run.alicePublicKey)),
      field("Bob's public key", short(hex(run.bobPublicKey), 14), '', hex(run.bobPublicKey)),
      field(
        't Bob used',
        run.bobExtractedT === null ? '(never obtained)' : short(run.bobExtractedT.toString(16).padStart(64, '0'), 16),
        'tone-t',
        run.bobExtractedT === null ? '' : run.bobExtractedT.toString(16).padStart(64, '0'),
      ),
      el('p', {
        class: 'note',
        text: 'Each ledger is a deterministic state machine holding one output whose spend condition is "a valid BIP-340 signature under key P over this message". The signature check is real — the library’s own verify. There is no chain, script, mempool or fee, and the timelock is a step counter rather than a consensus rule. A real deployment would lock the coins into a 2-of-2 joint key with a timelocked refund, which is MuSig territory; modelling the lock keeps the adaptor arithmetic in view.',
      }),
    ),
  )
}

function toggles(): HTMLElement {
  const mk = (id: string, label: string, checked: boolean, on: (v: boolean) => void) => {
    const input = el('input', { type: 'checkbox', id }) as HTMLInputElement
    input.checked = checked
    input.addEventListener('change', () => {
      on(input.checked)
      restart()
      rerender()
    })
    return el('label', { for: id }, input, document.createTextNode(label))
  }
  return card(
    'Break it yourself',
    el(
      'div',
      { class: 'toggle-row' },
      mk('swap-skip', ' Bob skips pre-verification', opts.bobSkipsPreVerify, (v) => {
        opts.bobSkipsPreVerify = v
      }),
      mk('swap-cheat', ' Alice pre-signs against a different T', opts.aliceCheats, (v) => {
        opts.aliceCheats = v
      }),
    ),
    el('p', {
      class: 'note',
      text: 'Turn both on to see the loss. Turn only one on to see why each alone is not enough — that distinction is the actual lesson.',
    }),
  )
}

function lanes(): HTMLElement {
  const rows = lanesAt(stepped)
  const tbl = el('table', { class: 'lanes' })
  tbl.append(
    el('caption', { id: 'lanes-caption', text: 'Who knows what, right now' }),
    el(
      'thead',
      {},
      el(
        'tr',
        {},
        el('th', { scope: 'col', text: 'actor' }),
        el('th', { scope: 'col', text: 'knows t' }),
        el('th', { scope: 'col', text: 'holds a pre-signature' }),
        el('th', { scope: 'col', text: 'has claimed' }),
      ),
    ),
  )
  const body = el('tbody')
  for (const l of rows) {
    body.append(
      el(
        'tr',
        {},
        el('th', { scope: 'row', text: l.who }),
        el('td', {}, pill(l.knowsT ? 'ok' : 'info', l.knowsT ? 'yes' : 'not yet')),
        el('td', { text: l.holdsPreSignature }),
        el('td', { text: l.claimed }),
      ),
    )
  }
  tbl.append(body)
  return card('Actors', tableWrap('lanes-caption', tbl))
}

function sequence(): HTMLElement {
  const list = el('ol', { class: 'steps reset-list' })
  const shown = stepped.run.steps.slice(0, stepped.cursor)
  for (const s of shown) {
    const item = el(
      'li',
      { class: `step ${s.n === stepped.cursor ? 'is-current' : ''}` },
      el('span', { class: 'step-n', text: String(s.n) }),
      el('span', { class: 'step-title', text: s.title }),
      el('span', { class: 'step-detail', text: s.detail }),
    )
    const word = s.status === 'ok' ? 'DONE' : s.status === 'blocked' ? 'STOPPED HERE' : 'WARNING'
    item.append(el('span', { class: `step-status is-${s.status}`, text: word }))
    list.append(item)
  }
  const c = card('The sequence, in order', list)
  if (!swapFinished(stepped)) {
    c.append(
      el('p', {
        class: 'note',
        role: 'status',
        'aria-live': 'polite',
        text: `${stepped.total - stepped.cursor} event(s) still to come.`,
      }),
    )
  }
  return c
}

function outcome(): HTMLElement {
  const run = stepped.run
  const c = card('Outcome')
  c.append(
    el(
      'p',
      { class: 'pill-row' },
      pill(run.aliceClaimedB ? 'ok' : 'info', run.aliceClaimedB ? 'Alice was paid on ledger B' : 'Alice unpaid'),
      document.createTextNode(' '),
      pill(run.bobClaimedA ? 'ok' : 'fail', run.bobClaimedA ? 'Bob was paid on ledger A' : 'Bob unpaid'),
    ),
  )

  if (run.bobLostFunds) {
    c.append(
      verdict(
        'alarm',
        'SWAP COMPLETED FOR ALICE — AND BOB LOST HIS COINS',
        'Alice took ledger B. Bob extracted the correct t and still could not claim ledger A.',
      ),
      el(
        'div',
        { class: 'callout callout-danger', id: 'swap-negative-claim' },
        el('span', { class: 'callout-label', text: 'What this does NOT prove' }),
        el('p', {
          text:
            'Extraction working does not mean the swap is safe. Every check Bob ran returned ' +
            'success: his extraction was correct, the secret he recovered was the real t, and t·G ' +
            'equalled T. What he skipped was pre-verifying which T Alice’s pre-signature ' +
            'committed to. So the failure is not that Bob got the wrong secret — he got the ' +
            'right one. It is that a pre-signature can be perfectly valid and point at a different ' +
            'secret than the payment does, and there is no failure code for that. The only thing ' +
            'that raises it is running the check.',
        }),
      ),
    )
  } else if (run.bobPreVerifyRan && !run.bobPreVerifyPassed) {
    c.append(
      verdict('pass', 'Fraud caught before anyone paid', `Bob's pre-verification refused it: ${run.bobPreVerifyReason}`),
    )
  } else if (run.aliceClaimedB && run.bobClaimedA) {
    c.append(
      verdict(
        'pass',
        'Both sides paid, in order',
        'Ledger B settled first and its signature is what let ledger A settle. Reversing the order is not possible, because the second claim is built out of the first one’s bytes.',
      ),
    )
  }

  c.append(
    el('h4', { text: 'Why Bob cannot go first' }),
    run.earlyClaimPossible
      ? verdict('alarm', 'Bob could claim early — atomicity is broken', run.earlyClaimReason)
      : verdict('pass', 'Not computable before Alice publishes', run.earlyClaimReason),
    el(
      'p',
      { class: 'pill-row' },
      pill(
        run.bobExtractedTCorrect ? 'ok' : 'info',
        run.bobExtractedTCorrect ? 'the t Bob extracted is the correct one' : 'Bob never obtained t',
      ),
    ),
  )
  return c
}
