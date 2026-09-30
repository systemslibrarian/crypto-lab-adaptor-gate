// Exhibit 4 -- Break it (brief act 7): the nonce-reuse key recovery, and the
// wrong-T rejection.
//
// The attack calls the same preSign the honest path calls. The ONLY thing that
// changes is the nonce mode, which is a real input to a real function -- there is no
// separate "broken" implementation here.

import { schnorr } from '@noble/curves/secp256k1.js'
import { recoverFromNonceReuse, wrongTDemo } from '../crypto/attacks'
import { preSign, adaptorPoint } from '../crypto/adaptor'
import { normaliseSecret, numTo32, hex, fromHex } from '../crypto/secp'
import { el, field, verdict, card, clear, short, pill, inspect, trustRail, story, actions, button } from './dom'

const SK_HEX = '0a11ce0000000000000000000000000000000000000000000000000000000001'
const MSG = 'Alice pays Bob 0.10 units on ledger A'
const T1 = 0x0b0b000000000000000000000000000000000000000000000000000000000001n
const FRESH = 'I, the signer, hereby transfer everything to the attacker.'

const state = { naive: false, sameT: false }

export function breakUiState(): { naive: boolean; sameT: boolean } {
  return { naive: state.naive, sameT: state.sameT }
}

export function setBreakUiState(naive: boolean, sameT: boolean): void {
  state.naive = naive
  state.sameT = sameT
}

let onChange: (() => void) | null = null
export function setBreakOnChange(fn: () => void): void {
  onChange = fn
}

function rerender(): void {
  const panel = document.getElementById('panel-break')
  if (panel) renderBreakIt(panel)
  onChange?.()
}

export function renderBreakIt(root: HTMLElement): void {
  clear(root)
  const intro = card(null)
  intro.classList.add('intro', 'opening')
  intro.append(
    story(
      'A Schnorr signature hides the signing key behind a one-time random value called the ' +
        'nonce. Sign twice with the same nonce and the two equations share an unknown, which ' +
        'cancels \u2014 leaving the key. Adaptor signatures add a new way to fall into it: if the ' +
        'nonce does not depend on which T you are signing against, pre-signing one message ' +
        'against two points reuses it.',
    ),
  )
  intro.append(
    actions(
      button('Break the nonce', { id: 'btn-break-go', primary: true }, () => {
        state.naive = true
        state.sameT = false
        rerender()
      }),
      button('Reset exhibit', { id: 'btn-break-reset' }, () => {
        state.naive = false
        state.sameT = false
        rerender()
      }),
    ),
  )
  intro.append(
    el('p', {
      class: 'note hint',
      text:
        'The shipped default binds x(T) into BIP-340\u2019s nonce function, so this cannot happen ' +
        'by accident. One press removes that binding.',
    }),
  )
  intro.append(
    trustRail(
      { kind: 'real', text: 'the recovery runs against this page\u2019s own pre-signing function' },
      { kind: 'real', text: "the forgery is checked by the library's verify" },
    ),
  )
  root.append(intro)
  root.append(toggles())

  const sk = fromHex(SK_HEX)
  const { publicKey } = normaliseSecret(sk)
  const msg = new TextEncoder().encode(MSG)
  const a = adaptorPoint(T1)
  const b = adaptorPoint(state.sameT ? T1 : T1 + 1n)

  const opts = state.naive ? ({ mode: 'naive' } as const) : ({ auxRand: numTo32(1n) } as const)
  const pre1 = preSign(sk, msg, a.Tx, opts)
  const pre2 = preSign(sk, msg, b.Tx, opts)
  const shared = hex(pre1.rx) === hex(pre2.rx)

  root.append(
    card(
      'Two pre-signatures on one message, against two points',
      field('nonce derivation', state.naive ? 'naive: H(m) only' : 'default: binds x(T)'),
      field('x(T₁)', short(hex(a.Tx), 14), 'tone-t'),
      field('x(T₂)', short(hex(b.Tx), 14), 'tone-t'),
      field('R from pre-signature 1', short(hex(pre1.rx), 14)),
      field('R from pre-signature 2', short(hex(pre2.rx), 14)),
      field('ŝ₁', short(pre1.sHat.toString(16).padStart(64, '0'), 14), 'tone-shat'),
      field('ŝ₂', short(pre2.sHat.toString(16).padStart(64, '0'), 14), 'tone-shat'),
      el(
        'p',
        {},
        pill(shared ? 'fail' : 'ok', shared ? 'SAME nonce R' : 'different nonce R'),
        document.createTextNode(' '),
        pill(pre1.e === pre2.e ? 'info' : 'ok', pre1.e === pre2.e ? 'e₁ == e₂' : 'e₁ != e₂'),
        document.createTextNode(' '),
        pill('info', `parities: ${pre1.parity} / ${pre2.parity}`),
      ),
    ),
  )

  const r = recoverFromNonceReuse({ pre1, pre2, T1x: a.Tx, T2x: b.Tx }, publicKey, FRESH)

  if (!r.ok) {
    root.append(
      card(
        'Recovery',
        verdict(
          'pass',
          shared ? 'Not recoverable from these two' : 'No shared nonce, so no equation to solve',
          r.reason,
        ),
      ),
    )
  } else {
    const forgedVerifies = schnorr.verify(
      r.forgery.signature,
      new TextEncoder().encode(r.forgery.message),
      publicKey,
    )
    root.append(
      card(
        'Recovery',
        el('p', {
          class: 'note',
          text:
            'The parity of R + T decides which equation applies, and both are real. When the two ' +
            'parities agree the nonce cancels in the difference; when they differ the nonce is ' +
            'negated in one of them, so it cancels in the SUM instead.',
        }),
        field('branch used', r.branch === 'same-parity' ? 'parities agree' : 'parities differ'),
        field('equation', r.equation, 'tone-t'),
        field('recovered key d', short(r.d.toString(16).padStart(64, '0'), 16), 'tone-t'),
        el(
          'p',
          {},
          pill(r.dMatchesPublicKey ? 'fail' : 'ok', r.dMatchesPublicKey ? 'd·G == P: the real key' : 'd·G != P'),
        ),
        r.dMatchesPublicKey
          ? verdict('alarm', 'PRIVATE KEY RECOVERED', 'Computed by comparing d·G against the public key as curve points.')
          : verdict('pass', 'Recovery produced a value that is not the key', 'd·G does not equal P.'),
      ),
    )

    root.append(
      card(
        'The proof: a forgery on a message the signer never touched',
        el('p', {
          class: 'note',
          text:
            'Recovering a number is not a result on its own. This signs a fresh message with the ' +
            'recovered key and hands it to the library’s own unmodified verifier under the ' +
            'original public key.',
        }),
        field('forged message', r.forgery.message),
        field('signature', short(hex(r.forgery.signature), 16)),
        forgedVerifies
          ? verdict(
              'alarm',
              'FORGERY ACCEPTED by BIP-340 verify',
              'The signer authorised nothing here. Two pre-signatures were enough.',
            )
          : verdict('pass', 'Forgery rejected', 'The recovered value is not the signing key.'),
      ),
    )
  }

  // Wrong-T, the other half of "break it".
  const w = wrongTDemo(sk, MSG, T1, T1 + 4242n)
  root.append(
    card(
      'The other failure: a pre-signature against the wrong point',
      el('p', {
        text:
          'This one needs no nonce bug at all. A counterparty can hand you a pre-signature that ' +
          'is entirely well-formed and commits to a different secret than you think. Only ' +
          'pre-verifying against the T you care about detects it.',
      }),
      inspect(
        'Inspect exact values',
        field('T you care about', short(hex(w.TxReal), 14), 'tone-t', hex(w.TxReal)),
        field('T it actually commits to', short(hex(w.TxAttacker), 14), 'tone-t', hex(w.TxAttacker)),
      ),
      el(
        'p',
        {},
        pill(w.verifiesAgainstAttacker ? 'info' : 'fail', 'pre-verifies against its own T*'),
        document.createTextNode(' '),
        pill(w.verifiesAgainstReal ? 'fail' : 'ok', 'pre-verify against your T rejects it'),
      ),
      w.verifiesAgainstReal
        ? verdict('alarm', 'A wrong-T pre-signature passed', 'It should not have.')
        : verdict('pass', 'Rejected against the T you care about', w.reasonAgainstReal),
      el('p', {
        class: 'note',
        text:
          'Note what it is not: the pre-signature is not malformed, and nothing about it is ' +
          'invalid in isolation. Its own pre-verification against T* succeeds. The swap exhibit ' +
          'shows what that costs when the check is skipped.',
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
      rerender()
    })
    return el('label', { for: id }, input, document.createTextNode(label))
  }
  const c = card(
    'Break it yourself',
    el(
      'div',
      { class: 'toggle-row' },
      mk('naive-nonce', ' Use the naive nonce (derived from the message only)', state.naive, (v) => {
        state.naive = v
      }),
      mk('same-t', ' Use the same T for both pre-signatures', state.sameT, (v) => {
        state.sameT = v
      }),
    ),
    el('p', {
      class: 'note',
      text:
        'The second toggle is the edge case: with one T the two challenges are equal, both ' +
        'equations collapse to 0 = 0, and the recovery correctly reports that these two ' +
        'pre-signatures cannot yield the key — even though the nonce really was reused.',
    }),
  )
  if (state.naive) {
    c.append(
      el(
        'div',
        { class: 'callout callout-danger' },
        el('span', { class: 'callout-label', text: 'Deliberately broken mode' }),
        el('p', {
          text:
            'The naive nonce is not the default and never runs unless this box is ticked. It is ' +
            'here so the failure can be caused rather than described.',
        }),
      ),
    )
  }
  return c
}
