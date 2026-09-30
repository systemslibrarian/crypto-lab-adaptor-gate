// Exhibit 1 -- the headline. Acts 1-4 of the brief (Lock, Pre-sign, Complete,
// Extract) as one four-step walkthrough, because they are one mechanism and the
// ORDER is part of what is being taught.
//
// Two rules from the brief are enforced structurally rather than by care:
//   - A completed signature is never drawn before t is supplied. Steps 3 and 4 do
//     not exist in the DOM until the learner supplies t.
//   - The difference strip wears t's colour only when the computed equality holds.
//
// Every verdict is a function return value. No string in this file says a check
// passed; the words come from comparing two computed values.

import { schnorr } from '@noble/curves/secp256k1.js'
import {
  preSign,
  preVerify,
  adapt,
  extract,
  adaptorPoint,
  preSignatureAsBytes,
} from '../crypto/adaptor'
import { normaliseSecret, numTo32, hex, fromHex, mod, N, CryptoInputError } from '../crypto/secp'
import type { PreSignature } from '../crypto/types'
import { el, field, verdict, card, clear, short, hexOf, pill } from './dom'

const DEFAULT_SK = '0a11ce0000000000000000000000000000000000000000000000000000000001'
const DEFAULT_T = '0b0b000000000000000000000000000000000000000000000000000000000001'
const DEFAULT_MSG = 'Alice pays Bob 0.10 units on ledger A'

interface State {
  secretKeyHex: string
  tHex: string
  message: string
  /** Set once step 2 has run. */
  pre: PreSignature | null
  publicKey: Uint8Array | null
  Tx: Uint8Array | null
  tNorm: bigint | null
  tNegated: boolean
  /** The t the learner typed into step 3. Null until they do. */
  suppliedT: string
  completed: boolean
  error: string
}

const state: State = {
  secretKeyHex: DEFAULT_SK,
  tHex: DEFAULT_T,
  message: DEFAULT_MSG,
  pre: null,
  publicKey: null,
  Tx: null,
  tNorm: null,
  tNegated: false,
  suppliedT: '',
  completed: false,
  error: '',
}

function lockAndPreSign(): void {
  state.error = ''
  state.pre = null
  state.completed = false
  try {
    const sk = fromHex(state.secretKeyHex)
    if (sk.length !== 32) throw new CryptoInputError('the signing key must be 32 bytes (64 hex characters)')
    const tRaw = BigInt('0x' + (state.tHex || '0'))
    const ad = adaptorPoint(tRaw)
    const { publicKey } = normaliseSecret(sk)
    const msg = new TextEncoder().encode(state.message)
    state.pre = preSign(sk, msg, ad.Tx, { auxRand: numTo32(1n) })
    state.publicKey = publicKey
    state.Tx = ad.Tx
    state.tNorm = ad.t
    state.tNegated = ad.negated
  } catch (err) {
    state.error = err instanceof Error ? err.message : 'could not pre-sign'
  }
}

export function renderRelation(root: HTMLElement): void {
  clear(root)
  root.append(intro())
  root.append(lockCard())
  if (state.error) {
    root.append(verdict('fail', 'Rejected', state.error))
    return
  }
  if (!state.pre || !state.publicKey || !state.Tx || state.tNorm === null) return
  root.append(preSignCard(state.pre, state.publicKey, state.Tx))
  root.append(completeCard(state.pre, state.publicKey, state.tNorm))
  if (state.completed) {
    root.append(extractCard(state.pre, state.Tx, state.tNorm))
  }
}

function intro(): HTMLElement {
  const c = card(
    'What an adaptor signature is',
    el('p', {
      text:
        'A normal signature says "I authorise this." An adaptor signature is a signature with a ' +
        'piece missing. The signer publishes a pre-signature that is provably tied to a public ' +
        'point T, and it is not a valid signature — the real verifier rejects it. Whoever knows ' +
        'the secret t behind that point (T is t multiplied by the curve generator) can add t and ' +
        'turn it into a real signature.',
    }),
    el('p', {
      text:
        'The twist is what happens next. Because the completed signature differs from the ' +
        'pre-signature by exactly t, anyone holding the pre-signature can subtract the two and ' +
        'read t out. So completing the signature and publishing the secret are the same act. ' +
        'Think of T as a padlock everyone can see and t as its key: opening the lock in public ' +
        'hands the key to anyone who was watching the lock.',
    }),
    el('p', {
      class: 'note',
      text:
        'Everything on this page runs real BIP-340 Schnorr arithmetic on secp256k1. The final ' +
        'signature is checked by the library’s own unmodified verifier, not by this lab.',
    }),
  )
  c.classList.add('intro')
  const legend = el('ul', { class: 'legend reset-list', 'aria-label': 'Colour legend' })
  const item = (colour: string, label: string) =>
    el(
      'li',
      {},
      el('span', { class: 'swatch', style: `background:${colour}`, 'aria-hidden': 'true' }),
      document.createTextNode(label),
    )
  legend.append(item('var(--tone-t)', 'the secret t, and anything derived from it'))
  legend.append(item('var(--tone-shat)', 'the pre-signature ŝ'))
  legend.append(item('var(--tone-s)', 'the completed signature s'))
  c.append(legend)
  return c
}

function lockCard(): HTMLElement {
  const skInput = el('input', {
    type: 'text',
    id: 'sk-input',
    spellcheck: 'false',
    autocomplete: 'off',
    value: state.secretKeyHex,
  }) as HTMLInputElement
  const tInput = el('input', {
    type: 'text',
    id: 't-input',
    spellcheck: 'false',
    autocomplete: 'off',
    value: state.tHex,
  }) as HTMLInputElement
  const msgInput = el('input', {
    type: 'text',
    id: 'msg-input',
    spellcheck: 'false',
    value: state.message,
  }) as HTMLInputElement

  const apply = () => {
    state.secretKeyHex = skInput.value.trim()
    state.tHex = tInput.value.trim()
    state.message = msgInput.value
    state.suppliedT = ''
    state.completed = false
    lockAndPreSign()
    const panel = document.getElementById('panel-relation')
    if (panel) renderRelation(panel)
  }

  const btn = el('button', { class: 'btn', type: 'button', id: 'btn-lock', text: 'Lock and pre-sign' })
  btn.addEventListener('click', apply)

  const controls = el(
    'div',
    { class: 'controls' },
    el('div', { class: 'control' }, el('label', { for: 'sk-input', text: "Signer's key (hex)" }), skInput),
    el('div', { class: 'control' }, el('label', { for: 't-input', text: 'Adaptor secret t (hex)' }), tInput),
    el('div', { class: 'control' }, el('label', { for: 'msg-input', text: 'Message' }), msgInput),
    btn,
  )

  const c = card('Step 1 — Alice locks a secret behind a point', controls)
  if (state.Tx && state.tNorm !== null && state.publicKey) {
    c.append(
      field('T = t·G, x-only', short(hex(state.Tx), 16), 'tone-t', hex(state.Tx)),
      field('t (normalised)', short(hexOf(state.tNorm), 16), 'tone-t', hexOf(state.tNorm)),
      field("signer's public key", short(hex(state.publicKey), 16), '', hex(state.publicKey)),
    )
    if (state.tNegated) {
      c.append(
        el('p', {
          class: 'note',
          text:
            'T travels as 32 x-only bytes, so it always denotes the even-y point. The t you typed ' +
            'gave an odd-y point, so it was negated to n − t — exactly the normalisation ' +
            'BIP-340 applies to a signing key. The negated value is the secret the finished ' +
            'signature will reveal.',
        }),
      )
    }
  }
  return c
}

function preSignCard(pre: PreSignature, publicKey: Uint8Array, Tx: Uint8Array): HTMLElement {
  const msg = new TextEncoder().encode(state.message)
  // COMPUTED, both of them.
  const preBytes = preSignatureAsBytes(pre)
  const libraryAcceptsPreSig = schnorr.verify(preBytes, msg, publicKey)
  const pv = preVerify(pre, publicKey, msg, Tx)

  const c = card(
    'Step 2 — Bob pre-signs against T',
    el('p', {
      text:
        'Bob produces a pre-signature. Two checks run on it, and they disagree on purpose: the ' +
        'real BIP-340 verifier rejects it, while pre-verification accepts it as a well-formed ' +
        'commitment to T.',
    }),
    field('R (nonce point, x-only)', short(hex(pre.rx), 16), '', hex(pre.rx)),
    field('x(R + T)', short(hex(pre.sumX), 16), '', hex(pre.sumX)),
    field('parity of R + T', pre.parity),
    field('challenge e', short(hexOf(pre.e), 16), '', hexOf(pre.e)),
    field('ŝ (pre-signature)', short(hexOf(pre.sHat), 16), 'tone-shat', hexOf(pre.sHat)),
  )

  c.append(
    el('h4', { text: 'What the real verifier says about the pre-signature' }),
    el('p', {
      class: 'note',
      text: `The 64 bytes x(R + T) ‖ ŝ handed to the library's own schnorr.verify:`,
    }),
    libraryAcceptsPreSig
      ? verdict(
          'alarm',
          'ACCEPTED — and it should not have been',
          'A pre-signature must not verify as a signature. Seeing this means the relation is broken.',
        )
      : verdict(
          'pass',
          'REJECTED by BIP-340 verify — correct',
          'The pre-signature is short by exactly t, so ŝ·G lands on R_adj instead of ' +
            'R_adj + T. It is not a signature and the real verifier says so.',
        ),
    el('h4', { text: 'What pre-verification says' }),
    el('p', {
      class: 'note',
      text: 'Computed as a point comparison: ŝ·G == R_adj + e·P, with R_adj = R when R + T is even-y and −R when it is odd-y.',
    }),
    pv.ok
      ? verdict(
          'pass',
          'Pre-verification ACCEPTED',
          'The pre-signature really is a commitment to this T, under this key, over this message.',
        )
      : verdict('fail', 'Pre-verification REJECTED', pv.reason),
  )
  return c
}

function completeCard(
  pre: PreSignature,
  publicKey: Uint8Array,
  tNorm: bigint,
): HTMLElement {
  const tInput = el('input', {
    type: 'text',
    id: 'supply-t',
    spellcheck: 'false',
    autocomplete: 'off',
    value: state.suppliedT,
    'aria-describedby': 'supply-t-help',
  }) as HTMLInputElement

  const go = el('button', { class: 'btn', type: 'button', id: 'btn-complete', text: 'Add t and verify' })
  go.addEventListener('click', () => {
    state.suppliedT = tInput.value.trim()
    state.completed = true
    const panel = document.getElementById('panel-relation')
    if (panel) renderRelation(panel)
  })
  const useReal = el('button', {
    class: 'btn btn-secondary',
    type: 'button',
    id: 'btn-use-real-t',
    text: 'Use the real t',
  })
  useReal.addEventListener('click', () => {
    state.suppliedT = hexOf(tNorm)
    state.completed = true
    const panel = document.getElementById('panel-relation')
    if (panel) renderRelation(panel)
  })

  const c = card(
    'Step 3 — complete it with t',
    el('p', {
      text:
        'Supply a value for t. Anything is allowed: the completion is arithmetic and always ' +
        'produces 64 bytes. Whether those bytes are a signature is the library’s decision, ' +
        'not this page’s.',
    }),
    el('p', {
      class: 'note',
      id: 'supply-t-help',
      text: 'Hex. Try a wrong value first — the arithmetic still runs, and the real verifier still refuses the result.',
    }),
    el(
      'div',
      { class: 'controls' },
      el('div', { class: 'control' }, el('label', { for: 'supply-t', text: 'Your t (hex)' }), tInput),
      go,
      useReal,
    ),
  )

  if (!state.completed) {
    c.append(
      verdict(
        'neutral',
        'Nothing completed yet',
        'The completed signature is not drawn until a t is supplied.',
      ),
    )
    return c
  }

  // Completion, computed.
  let supplied: bigint
  try {
    supplied = mod(BigInt('0x' + (state.suppliedT || '0')))
    if (supplied === 0n) throw new CryptoInputError('t = 0 is rejected: T would be the point at infinity')
  } catch (err) {
    c.append(verdict('fail', 'Rejected', err instanceof Error ? err.message : 'not a usable t'))
    return c
  }

  const msg = new TextEncoder().encode(state.message)
  const { s, signature } = adapt(pre, supplied)
  const accepted = schnorr.verify(signature, msg, publicKey)
  const isRealT = supplied === tNorm

  c.append(
    el('div', { class: 'reveal' }, field('s (completed)', short(hexOf(s), 16), 'tone-s', hexOf(s))),
    field('64-byte signature', short(hex(signature), 16), 'tone-s', hex(signature)),
  )

  // THE HEADLINE VISUAL: s - s-hat beside t, with a computed equality badge.
  //
  // The right-hand cell is the TRUE t -- the secret behind T from step 1 -- and NOT
  // the t the learner just typed. Comparing the difference against the supplied
  // value would be a tautology: adapt computes s = s-hat +/- t, so s - s-hat equals
  // whatever was supplied by construction, and the badge could never read anything
  // but "equal". A badge that cannot be false is not evidence. Against the true t it
  // is falsifiable, and supplying a wrong value is how a reader falsifies it.
  const diffRaw = pre.parity === 'even' ? mod(s - pre.sHat) : mod(pre.sHat - s)
  const equal = diffRaw === tNorm
  const strip = el('div', {
    class: `diff-strip ${equal ? 'is-equal' : 'not-equal'}`,
  })
  const cell = (label: string, value: string, full: string) =>
    el(
      'div',
      { class: 'diff-cell' },
      el('span', { class: 'diff-cell-label', text: label }),
      el('span', { class: 'diff-cell-value', 'data-full': full, text: value }),
    )
  strip.append(
    cell(pre.parity === 'even' ? 's − ŝ' : 'ŝ − s', short(hexOf(diffRaw), 14), hexOf(diffRaw)),
    el(
      'div',
      { class: 'diff-eq' },
      el('span', { 'aria-hidden': 'true', text: equal ? '=' : '≠' }),
      el('span', { class: 'sr-only', text: equal ? 'equals' : 'does not equal' }),
    ),
    cell("the true t behind T", short(hexOf(tNorm), 14), hexOf(tNorm)),
  )
  c.append(
    el('h4', { text: 'The difference between the two signatures' }),
    el('p', {
      class: 'note',
      text:
        'The parity of R + T fixes the sign, so the difference is taken as ' +
        (pre.parity === 'even' ? 's − ŝ (R + T is even-y).' : 'ŝ − s (R + T is odd-y).'),
    }),
    strip,
    equal
      ? verdict(
          'pass',
          'The difference IS the secret — computed, not asserted',
          'Both values are printed above, whether or not they match, and they were compared as ' +
            'numbers rather than as rendered strings. Supply a different t to see this go red.',
        )
      : verdict(
          'fail',
          'The difference is NOT the secret behind T',
          'The subtraction returned the value you supplied, which is not the t that T commits to. ' +
            'Both numbers are printed above.',
        ),
  )

  c.append(
    el('h4', { text: "What the library's unmodified verifier says" }),
    accepted
      ? verdict(
          'pass',
          'VALID BIP-340 signature',
          'Accepted by @noble/curves’ own schnorr.verify under the signer’s public key.',
        )
      : verdict(
          'pass',
          'REJECTED — which is the correct answer for a wrong t',
          isRealT
            ? 'Unexpected: this was the real t, so a rejection here means the relation is broken.'
            : 'The arithmetic ran and produced 64 bytes. They are not a signature, because only the t ' +
              'behind T completes this pre-signature. Nothing on this page could tell you which t that ' +
              'is; it can only tell you when you have it.',
        ),
  )
  if (!accepted && isRealT) {
    c.append(verdict('alarm', 'Contradiction', 'The real t should have produced a valid signature.'))
  }
  return c
}

function extractCard(pre: PreSignature, Tx: Uint8Array, tNorm: bigint): HTMLElement {
  // Extraction uses ONLY the pre-signature held earlier and the published signature.
  const { signature } = adapt(pre, tNorm)
  const ex = extract(pre, signature, Tx)

  const c = card(
    'Step 4 — read the secret back out (the headline)',
    el('p', {
      text:
        'This step gets two things and nothing else: the pre-signature Bob kept from step 2, and ' +
        'the completed signature as published. It does not get t. Subtracting the two recovers it.',
    }),
    field('held earlier: ŝ', short(hexOf(pre.sHat), 16), 'tone-shat', hexOf(pre.sHat)),
    field('published: s', short(hex(signature.slice(32)), 16), 'tone-s', hex(signature.slice(32))),
  )

  if (ex.ok) {
    const matches = ex.t === tNorm
    c.append(
      field('recovered t', short(hexOf(ex.t), 16), 'tone-t', hexOf(ex.t)),
      field('recovered t·G, x-only', short(hex(ex.Tx), 16), 'tone-t', hex(ex.Tx)),
      field('T from step 1', short(hex(Tx), 16), 'tone-t', hex(Tx)),
      el('h4', { text: 'Does the recovered secret match?' }),
      el('p', {
        class: 'note',
        text: 'Compared two ways: the scalar against the true t, and recovered t·G against T as curve points.',
      }),
      el(
        'p',
        {},
        pill(matches ? 'ok' : 'fail', matches ? 'scalar matches the true t' : 'scalar does NOT match'),
        document.createTextNode(' '),
        pill(
          hex(ex.Tx) === hex(Tx) ? 'ok' : 'fail',
          hex(ex.Tx) === hex(Tx) ? 'recovered t·G == T' : 'recovered t·G != T',
        ),
      ),
      matches
        ? verdict(
            'pass',
            'Secret recovered from the signature alone',
            'Publishing the completed signature published t to whoever held the pre-signature. That is ' +
              'the property every construction in the other exhibits is built on.',
          )
        : verdict('fail', 'Recovery did not reproduce t', 'Both values are printed above.'),
    )
  } else {
    c.append(verdict('fail', 'Extraction reported failure', ex.reason))
  }

  c.append(
    el(
      'details',
      {},
      el('summary', { text: 'What extraction refuses to do' }),
      el('p', {
        class: 'note',
        text:
          'Extraction never returns a wrong t quietly. If the signature’s nonce is not this ' +
          'pre-signature’s x(R + T), the two do not pair and it reports that instead of ' +
          'subtracting two unrelated numbers. If the recovered t does not satisfy t·G == T, it ' +
          'reports that too. Both refusals are exercised in the test suite.',
      }),
    ),
  )
  return c
}

export function initRelation(): void {
  lockAndPreSign()
}

export { N }
