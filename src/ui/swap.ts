// Exhibit 2 -- the cross-ledger swap (brief act 5).
//
// The swap is never drawn as simultaneous. It is an ordered sequence and the order
// is the lesson, so it renders as a numbered step list whose statuses come from the
// state machine in crypto/swap.ts.

import { runSwap } from '../crypto/swap'
import { hex } from '../crypto/secp'
import { el, field, verdict, card, clear, short, pill } from './dom'

const state = { aliceCheats: false, bobSkipsPreVerify: false }

export function renderSwap(root: HTMLElement): void {
  clear(root)
  const run = runSwap(state)

  const intro = card(
    'Two ledgers, one secret, and an order that cannot be rearranged',
    el('p', {
      text:
        'Alice has coins on ledger A. Bob has coins on ledger B. Neither wants to pay first. ' +
        'Alice picks a secret t and both sides pre-sign their own payment against the same T. ' +
        'Alice can complete Bob’s pre-signature because she knows t — and the moment she ' +
        'does, the signature she publishes hands t to Bob, who uses it to complete hers.',
    }),
    el('p', {
      class: 'note',
      text:
        'Nobody has to be trusted to hand anything over. Bob reads the published signature off ' +
        'ledger B and subtracts. If Alice never moves, nothing happens and the modeled timelock ' +
        'opens a refund path.',
    }),
  )
  intro.classList.add('intro')
  root.append(intro)
  root.append(toggles())

  root.append(
    card(
      'Setup',
      field('x(T) the payment is locked to', short(hex(run.Tx), 16), 'tone-t'),
      field('Alice pre-signed against', short(hex(run.TxAlicePreSignedAgainst), 16), 'tone-t'),
      field("Alice's public key", short(hex(run.alicePublicKey), 14)),
      field("Bob's public key", short(hex(run.bobPublicKey), 14)),
    ),
  )

  // The ordered walkthrough.
  const list = el('ol', { class: 'steps reset-list' })
  for (const s of run.steps) {
    const item = el(
      'li',
      { class: 'step' },
      el('span', { class: 'step-n', text: String(s.n) }),
      el('span', { class: 'step-title', text: s.title }),
      el('span', { class: 'step-detail', text: s.detail }),
    )
    const word = s.status === 'ok' ? 'DONE' : s.status === 'blocked' ? 'STOPPED HERE' : 'WARNING'
    item.append(el('span', { class: `step-status is-${s.status}`, text: word }))
    list.append(item)
  }
  root.append(card('The sequence, in order', list))

  // Invariant 9, rendered as a result.
  root.append(
    card(
      'Why Bob cannot go first',
      el('p', {
        class: 'note',
        text:
          'Before Alice publishes, ledger B holds no spend. Bob’s claim is not blocked by a ' +
          'rule this page enforces — there is simply nothing to subtract from.',
      }),
      run.earlyClaimPossible
        ? verdict('alarm', 'Bob could claim early — atomicity is broken', run.earlyClaimReason)
        : verdict('pass', 'Not computable before Alice publishes', run.earlyClaimReason),
      field(
        "t Bob used",
        run.bobExtractedT === null
          ? '(never obtained)'
          : short(run.bobExtractedT.toString(16).padStart(64, '0'), 16),
        'tone-t',
      ),
      el(
        'p',
        {},
        pill(
          run.bobExtractedTCorrect ? 'ok' : 'info',
          run.bobExtractedTCorrect
            ? 'the t Bob extracted is the correct one'
            : 'Bob never obtained t',
        ),
      ),
      el('p', {
        class: 'note',
        text:
          'That value was read out of ledger B’s published bytes. It is never passed across ' +
          'from Alice’s side of the model — the ledger module does not even import the ' +
          'adaptor code.',
      }),
    ),
  )

  root.append(outcome(run))
}

function toggles(): HTMLElement {
  const mk = (id: string, label: string, checked: boolean, on: (v: boolean) => void) => {
    const input = el('input', { type: 'checkbox', id }) as HTMLInputElement
    input.checked = checked
    input.addEventListener('change', () => {
      on(input.checked)
      const panel = document.getElementById('panel-swap')
      if (panel) renderSwap(panel)
    })
    return el('label', { for: id }, input, document.createTextNode(label))
  }
  const row = el(
    'div',
    { class: 'toggle-row' },
    mk('swap-skip', ' Bob skips pre-verification', state.bobSkipsPreVerify, (v) => {
      state.bobSkipsPreVerify = v
    }),
    mk('swap-cheat', ' Alice pre-signs against a different T', state.aliceCheats, (v) => {
      state.aliceCheats = v
    }),
  )
  return card(
    'Break it yourself',
    el('p', {
      class: 'note',
      text:
        'Turn both on to see the loss. Turn only one on to see why each alone is not enough — ' +
        'that distinction is the actual lesson.',
    }),
    row,
  )
}

function outcome(run: ReturnType<typeof runSwap>): HTMLElement {
  const c = card('Outcome')
  c.append(
    el(
      'p',
      {},
      pill(run.aliceClaimedB ? 'ok' : 'info', run.aliceClaimedB ? 'Alice was paid on ledger B' : 'Alice unpaid'),
      document.createTextNode(' '),
      pill(run.bobClaimedA ? 'ok' : 'fail', run.bobClaimedA ? 'Bob was paid on ledger A' : 'Bob unpaid'),
    ),
  )

  if (run.bobLostFunds) {
    // The negative-claim fixture: every check Bob ran passed, and he still lost.
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
      verdict(
        'pass',
        'Fraud caught before anyone paid',
        `Bob's pre-verification refused it: ${run.bobPreVerifyReason}`,
      ),
    )
  } else if (run.aliceClaimedB && run.bobClaimedA) {
    c.append(
      verdict(
        'pass',
        'Both sides paid, in order',
        'Ledger B settled first and its signature is what let ledger A settle. Reversing the order ' +
          'is not possible, because the second claim is built out of the first one’s bytes.',
      ),
    )
  }

  c.append(
    el(
      'details',
      {},
      el('summary', { text: 'What the ledgers here are, and are not' }),
      el('p', {
        class: 'note',
        text:
          'Each ledger is a deterministic state machine holding one output whose spend condition ' +
          'is "a valid BIP-340 signature under key P over this message". The signature check is ' +
          'real — the library’s own verify. Everything else is modeled: there is no chain, ' +
          'no script, no mempool, no fee, and the timelock is a step counter rather than a ' +
          'consensus rule. A real deployment would lock the coins into a 2-of-2 joint key with a ' +
          'timelocked refund, which is MuSig territory; modelling the lock keeps the adaptor ' +
          'arithmetic in view.',
      }),
    ),
  )
  return c
}
