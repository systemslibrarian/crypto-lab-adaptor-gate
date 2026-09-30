// Exhibit 1 -- the headline, rebuilt as a guided centrepiece.
//
// THE DESIGN CONSTRAINT THAT SHAPES THIS FILE: a first-time visitor must reach
// `s - s-hat = +/-t` in at most two actions, with the first action visible in a
// 390x844 viewport. An earlier version put ~290 words of prose and three forms in
// front of that moment and the primary button sat at y=1941 on mobile. The crypto
// was identical; the path to it was the defect.
//
// So: one short story, ONE primary action, four compact computed stages, and every
// raw value behind "Inspect exact values". Nothing was deleted -- the signing key,
// aux randomness, parity, challenge and full hex are all still on the page and still
// checked by the claims suite. What changed is when they appear.
//
// Two rules from the brief are still enforced structurally rather than by care:
//   - A completed signature is never drawn before t is supplied. Stages 3 and 4 do
//     not exist in the DOM until the run reaches them.
//   - The difference strip wears t's colour only when the computed equality holds,
//     and it is compared against the TRUE t, so a wrong value turns it red.

import { schnorr } from '@noble/curves/secp256k1.js'
import {
  preSign,
  preVerify,
  adapt,
  extract,
  adaptorPoint,
  preSignatureAsBytes,
} from '../crypto/adaptor'
import { normaliseSecret, numTo32, hex, fromHex, mod, CryptoInputError } from '../crypto/secp'
import type { PreSignature } from '../crypto/types'
import {
  el,
  field,
  verdict,
  card,
  clear,
  short,
  hexOf,
  pill,
  inspect,
  trustRail,
  story,
  actions,
  button,
} from './dom'

const DEFAULT_SK = '0a11ce0000000000000000000000000000000000000000000000000000000001'
const DEFAULT_T = '0b0b000000000000000000000000000000000000000000000000000000000001'
const DEFAULT_MSG = 'Alice pays Bob 0.10 units on ledger A'
const WRONG_T = 'deadbeef'.repeat(8)

/** 0 = nothing run. 1 = locked. 2 = pre-signed. 3 = completed. 4 = extracted. */
export type Stage = 0 | 1 | 2 | 3 | 4

interface State {
  secretKeyHex: string
  tHex: string
  message: string
  stage: Stage
  /** Which t the completion used. 'real' or a hex string the visitor supplied. */
  suppliedT: string
  error: string
}

const initial = (): State => ({
  secretKeyHex: DEFAULT_SK,
  tHex: DEFAULT_T,
  message: DEFAULT_MSG,
  stage: 0,
  suppliedT: '',
  error: '',
})

let state: State = initial()

export function relationState(): { stage: Stage; wrongT: boolean } {
  return { stage: state.stage, wrongT: state.suppliedT !== '' && state.suppliedT !== 'real' }
}

export function setRelationState(stage: Stage, wrongT: boolean): void {
  state.stage = stage
  state.suppliedT = stage >= 3 ? (wrongT ? WRONG_T : 'real') : ''
}

/** Everything the exhibit computes, derived fresh from the inputs each render. */
interface Computed {
  publicKey: Uint8Array
  Tx: Uint8Array
  tNorm: bigint
  tNegated: boolean
  pre: PreSignature
  preSigBytes: Uint8Array
  preSigAccepted: boolean
  preVerified: boolean
  preVerifyReason: string
  /** Present from stage 3. */
  completion: null | {
    supplied: bigint
    s: bigint
    signature: Uint8Array
    accepted: boolean
    diff: bigint
    equal: boolean
    isRealT: boolean
  }
  /** Present from stage 4. */
  recovery: null | { ok: boolean; t: bigint; Tx: Uint8Array; matches: boolean; reason: string }
}

function computeAll(): Computed | null {
  try {
    const sk = fromHex(state.secretKeyHex)
    if (sk.length !== 32) {
      throw new CryptoInputError('the signing key must be 32 bytes (64 hex characters)')
    }
    const ad = adaptorPoint(BigInt('0x' + (state.tHex || '0')))
    const { publicKey } = normaliseSecret(sk)
    const msg = new TextEncoder().encode(state.message)
    const pre = preSign(sk, msg, ad.Tx, { auxRand: numTo32(1n) })
    const preSigBytes = preSignatureAsBytes(pre)
    const pv = preVerify(pre, publicKey, msg, ad.Tx)

    let completion: Computed['completion'] = null
    let recovery: Computed['recovery'] = null

    if (state.stage >= 3 && state.suppliedT !== '') {
      const supplied = state.suppliedT === 'real' ? ad.t : mod(BigInt('0x' + state.suppliedT))
      if (supplied === 0n) throw new CryptoInputError('t = 0 is rejected: T would be the point at infinity')
      const { s, signature } = adapt(pre, supplied)
      const diff = pre.parity === 'even' ? mod(s - pre.sHat) : mod(pre.sHat - s)
      completion = {
        supplied,
        s,
        signature,
        accepted: schnorr.verify(signature, msg, publicKey),
        diff,
        // Compared against the TRUE t, never against the supplied value -- that
        // comparison would be a tautology, since adapt computes s = s-hat +/- t.
        equal: diff === ad.t,
        isRealT: supplied === ad.t,
      }
      if (state.stage >= 4) {
        const ex = extract(pre, completion.signature, ad.Tx)
        recovery = ex.ok
          ? { ok: true, t: ex.t, Tx: ex.Tx, matches: ex.t === ad.t, reason: '' }
          : { ok: false, t: 0n, Tx: new Uint8Array(32), matches: false, reason: ex.reason }
      }
    }

    return {
      publicKey,
      Tx: ad.Tx,
      tNorm: ad.t,
      tNegated: ad.negated,
      pre,
      preSigBytes,
      preSigAccepted: schnorr.verify(preSigBytes, msg, publicKey),
      preVerified: pv.ok,
      preVerifyReason: pv.ok ? '' : pv.reason,
      completion,
      recovery,
    }
  } catch (err) {
    state.error = err instanceof Error ? err.message : 'could not run the relation'
    return null
  }
}

let onChange: (() => void) | null = null
export function setRelationOnChange(fn: () => void): void {
  onChange = fn
}

function rerender(): void {
  const panel = document.getElementById('panel-relation')
  if (panel) renderRelation(panel)
  onChange?.()
}

export function renderRelation(root: HTMLElement): void {
  clear(root)
  state.error = ''
  const c = computeAll()

  root.append(openingCard())
  if (state.error || !c) {
    root.append(verdict('fail', 'Rejected', state.error))
    root.append(inputsCard())
    return
  }
  root.append(mechanism(c))
  root.append(stagesCard(c))
  root.append(inputsCard())
}

// ---------------------------------------------------------------------------
// The opening: short story + the one primary action. Both above the fold.
// ---------------------------------------------------------------------------

function openingCard(): HTMLElement {
  const c = card(null)
  c.classList.add('intro', 'opening')
  c.append(
    story(
      'A signature normally proves one thing: you authorised something. An adaptor ' +
        'signature proves that and leaks a second thing — a secret — to whoever was ' +
        'holding the unfinished version. Watch it happen, then take the secret back out.',
    ),
  )

  const run = button('Run the relation', { id: 'btn-run', primary: true }, () => {
    state.suppliedT = 'real'
    state.stage = 4
    rerender()
  })
  const stepLabel = state.stage === 0 ? 'Step through it' : 'Next step'
  const step = button('' + stepLabel, { id: 'btn-step' }, () => {
    if (state.stage < 2) state.stage = (state.stage + 1) as Stage
    else if (state.stage === 2) {
      state.suppliedT = 'real'
      state.stage = 3
    } else if (state.stage === 3) state.stage = 4
    rerender()
  })
  if (state.stage === 4) step.disabled = true

  const wrong = button('Try a wrong t', { id: 'btn-wrong-t' }, () => {
    state.suppliedT = WRONG_T
    state.stage = 4
    rerender()
  })

  const reset = button('Reset', { id: 'btn-reset-relation' }, () => {
    state = initial()
    rerender()
  })

  c.append(actions(run, step, wrong, reset))
  c.append(
    el('p', {
      class: 'note hint',
      id: 'run-hint',
      text:
        state.stage === 0
          ? 'One click runs all four stages on real BIP-340 arithmetic. Everything is already loaded.'
          : 'Try a wrong t to see the headline claim fail — that is what makes the green state evidence.',
    }),
  )
  c.append(
    trustRail(
      { kind: 'real', text: 'real secp256k1 arithmetic' },
      { kind: 'real', text: "library's unmodified BIP-340 verify" },
      { kind: 'input', text: 'deterministic teaching inputs' },
    ),
  )
  return c
}

// ---------------------------------------------------------------------------
// The mechanism: the dominant visual object on the page.
// ---------------------------------------------------------------------------

function mechanism(c: Computed): HTMLElement {
  const wrap = card('The mechanism')
  wrap.classList.add('mech-card')

  const stageOf = state.stage
  const node = (
    cls: string,
    label: string,
    value: string,
    full: string,
    on: boolean,
    mark?: { ok: boolean; text: string },
  ) => {
    const n = el(
      'div',
      { class: `mech-node ${cls} ${on ? 'is-on' : 'is-off'}` },
      el('span', { class: 'mech-label', text: label }),
      el('span', { class: 'mech-value', 'data-full': full, text: on ? value : '—' }),
    )
    if (on && mark) {
      n.append(
        el(
          'span',
          { class: `mech-mark ${mark.ok ? 'is-ok' : 'is-bad'}` },
          el('span', { 'aria-hidden': 'true', text: mark.ok ? '✓' : '✗' }),
          document.createTextNode(' ' + mark.text),
        ),
      )
    }
    return n
  }

  const lockOn = stageOf >= 1
  const preOn = stageOf >= 2
  const compOn = stageOf >= 3 && c.completion !== null
  const extOn = stageOf >= 4 && c.recovery !== null

  const grid = el('div', { class: 'mech-grid' })

  grid.append(
    node('mech-t', 'the secret t', short(hexOf(c.tNorm), 8), hexOf(c.tNorm), lockOn),
    el(
      'div',
      { class: `mech-arrow ${lockOn ? 'is-on' : 'is-off'}` },
      el('span', { 'aria-hidden': 'true', text: '×G →' }),
      el('span', { class: 'sr-only', text: 'multiplied by G gives' }),
    ),
    node('mech-tpoint', 'the point T (public)', short(hex(c.Tx), 8), hex(c.Tx), lockOn),
  )

  grid.append(
    node(
      'mech-shat',
      'pre-signature ŝ',
      short(hexOf(c.pre.sHat), 8),
      hexOf(c.pre.sHat),
      preOn,
      preOn ? { ok: !c.preSigAccepted, text: 'verifier REJECTS' } : undefined,
    ),
    el(
      'div',
      { class: `mech-arrow ${compOn ? 'is-on' : 'is-off'}` },
      el('span', { 'aria-hidden': 'true', text: '+ t →' }),
      el('span', { class: 'sr-only', text: 'plus t gives' }),
    ),
    node(
      'mech-s',
      'signature s',
      compOn ? short(hexOf(c.completion!.s), 8) : '',
      compOn ? hexOf(c.completion!.s) : '',
      compOn,
      compOn
        ? { ok: c.completion!.accepted, text: c.completion!.accepted ? 'verifier ACCEPTS' : 'verifier REJECTS' }
        : undefined,
    ),
  )

  // The subtraction, spanning both columns -- the actual headline.
  const sub = el('div', { class: `mech-sub ${extOn ? 'is-on' : 'is-off'}` })
  if (extOn && c.completion) {
    const equal = c.completion.equal
    sub.classList.add(equal ? 'is-equal' : 'not-equal')
    sub.append(
      el('span', { class: 'mech-sub-op', text: 's − ŝ' }),
      el(
        'span',
        { class: 'mech-sub-eq' },
        el('span', { 'aria-hidden': 'true', text: equal ? '=' : '≠' }),
        el('span', { class: 'sr-only', text: equal ? 'equals' : 'does not equal' }),
      ),
      el('span', {
        class: 'mech-sub-val',
        'data-full': hexOf(c.completion.diff),
        text: short(hexOf(c.completion.diff), 8),
      }),
      el('span', { class: 'mech-sub-note', text: equal ? 'the secret, recovered' : 'not the secret behind T' }),
    )
  } else {
    sub.append(el('span', { class: 'mech-sub-op', text: 's − ŝ' }), el('span', { class: 'mech-sub-note', text: 'not computed yet' }))
  }

  wrap.append(grid, sub)
  wrap.append(
    el('p', {
      class: 'note',
      text:
        'Colour is consistent everywhere on this page: violet is the secret t and anything ' +
        'derived from it, amber is the pre-signature, green is the finished signature. The ' +
        'subtraction takes t’s violet only when the computed equality holds.',
    }),
  )
  return wrap
}

// ---------------------------------------------------------------------------
// The four stages: PROOF layer. Compact, with INSPECT beneath each.
// ---------------------------------------------------------------------------

function stagesCard(c: Computed): HTMLElement {
  const wrap = el('div', { class: 'stages' })
  wrap.append(stage1(c))
  if (state.stage >= 2) wrap.append(stage2(c))
  if (state.stage >= 3 && c.completion) wrap.append(stage3(c))
  if (state.stage >= 4 && c.recovery) wrap.append(stage4(c))
  return wrap
}

function stageCard(n: number, title: string, ...children: (Node | string)[]): HTMLElement {
  const c = el('section', { class: 'card stage-card', 'aria-label': `Stage ${n}: ${title}` })
  c.append(
    el(
      'h3',
      { class: 'stage-head' },
      el('span', { class: 'stage-n', text: String(n) }),
      document.createTextNode(title),
    ),
  )
  for (const ch of children) c.append(ch)
  return c
}

function stage1(c: Computed): HTMLElement {
  const body: (Node | string)[] = [
    el('p', {
      class: 'stage-story',
      text: 'Alice picks a secret and publishes only the point it maps to. T is a padlock anyone can see; t is its key.',
    }),
  ]
  if (state.stage >= 1) {
    body.push(
      field('t (the secret)', short(hexOf(c.tNorm), 14), 'tone-t', hexOf(c.tNorm)),
      field('T = t·G (public)', short(hex(c.Tx), 14), 'tone-t', hex(c.Tx)),
      inspect(
        'Inspect exact values',
        field("signer's public key", short(hex(c.publicKey), 14), '', hex(c.publicKey)),
        el('p', {
          class: 'note',
          text: c.tNegated
            ? 'T travels as 32 x-only bytes, so it always denotes the even-y point. The t supplied gave an odd-y point, so it was negated to n − t — exactly the normalisation BIP-340 applies to a signing key. The negated value is the secret the finished signature reveals.'
            : 'This t already gives an even-y T, so no normalisation was needed. T travels x-only, so a t whose point had odd y would have been negated to n − t.',
        }),
      ),
    )
  } else {
    body.push(verdict('neutral', 'Not run yet', 'Press Run the relation, or step through it.'))
  }
  return stageCard(1, 'Lock a secret behind a point', ...body)
}

function stage2(c: Computed): HTMLElement {
  return stageCard(
    2,
    'Pre-sign against T',
    el('p', {
      class: 'stage-story',
      text: 'Bob signs, but leaves a piece out. The result is provably tied to T and is not a signature — and the two checks below disagree on purpose.',
    }),
    el(
      'div',
      { class: 'verdict-pair' },
      c.preSigAccepted
        ? verdict('alarm', 'BIP-340 verify ACCEPTED it', 'A pre-signature must not verify. The relation is broken.')
        : verdict('pass', 'BIP-340 verify REJECTS it', 'Correct. It is short by exactly t.'),
      c.preVerified
        ? verdict('pass', 'Pre-verification ACCEPTS it', 'It really is a commitment to this T, under this key, over this message.')
        : verdict('fail', 'Pre-verification REJECTS it', c.preVerifyReason),
    ),
    inspect(
      'Inspect exact values',
      field('ŝ (pre-signature)', short(hexOf(c.pre.sHat), 14), 'tone-shat', hexOf(c.pre.sHat)),
      field('R (nonce point, x-only)', short(hex(c.pre.rx), 14), '', hex(c.pre.rx)),
      field('x(R + T)', short(hex(c.pre.sumX), 14), '', hex(c.pre.sumX)),
      field('parity of R + T', c.pre.parity),
      field('challenge e', short(hexOf(c.pre.e), 14), '', hexOf(c.pre.e)),
      el('p', {
        class: 'note',
        text: 'Pre-verification is a point comparison: ŝ·G == R_adj + e·P, with R_adj = R when R + T is even-y and −R when it is odd-y. The parity of R + T fixes a sign throughout, and getting it wrong is the classic adaptor bug.',
      }),
    ),
  )
}

function stage3(c: Computed): HTMLElement {
  const k = c.completion!
  return stageCard(
    3,
    'Add t and it becomes a signature',
    el('p', {
      class: 'stage-story',
      text: 'Whoever knows t can finish it. The arithmetic always produces 64 bytes; whether they are a signature is the library’s decision, not this page’s.',
    }),
    k.accepted
      ? verdict('pass', 'VALID BIP-340 signature', "Accepted by @noble/curves' own unmodified verify.")
      : verdict(
          'pass',
          'REJECTED — the correct answer for a wrong t',
          k.isRealT
            ? 'Unexpected: this was the real t, so a rejection means the relation is broken.'
            : 'Only the t behind T completes this pre-signature. The page can tell you when you have it, never which t it is.',
        ),
    inspect(
      'Inspect exact values',
      field('t supplied', short(hexOf(k.supplied), 14), 'tone-t', hexOf(k.supplied)),
      field('s (completed)', short(hexOf(k.s), 14), 'tone-s', hexOf(k.s)),
      field('64-byte signature', short(hex(k.signature), 14), 'tone-s', hex(k.signature)),
    ),
  )
}

function stage4(c: Computed): HTMLElement {
  const r = c.recovery!
  const k = c.completion!
  const body: (Node | string)[] = [
    el('p', {
      class: 'stage-story',
      text: 'This stage gets two things and nothing else: the pre-signature held earlier, and the signature as published. It does not get t.',
    }),
  ]
  if (r.ok) {
    body.push(
      el(
        'p',
        { class: 'pill-row' },
        pill(r.matches ? 'ok' : 'fail', r.matches ? 'recovered t matches the true t' : 'recovered t does NOT match'),
        document.createTextNode(' '),
        pill(hex(r.Tx) === hex(c.Tx) ? 'ok' : 'fail', hex(r.Tx) === hex(c.Tx) ? 'recovered t·G == T' : 'recovered t·G != T'),
      ),
      r.matches
        ? verdict(
            'pass',
            'Secret recovered from the signature alone',
            'Publishing the completed signature published t to whoever held the pre-signature. Every other exhibit is built on that.',
          )
        : verdict('fail', 'Recovery did not reproduce t', 'Both values are printed under Inspect.'),
      inspect(
        'Inspect exact values',
        field('held earlier: ŝ', short(hexOf(c.pre.sHat), 14), 'tone-shat', hexOf(c.pre.sHat)),
        field('published: s', short(hex(k.signature.slice(32)), 14), 'tone-s', hex(k.signature.slice(32))),
        field('recovered t', short(hexOf(r.t), 14), 'tone-t', hexOf(r.t)),
        field('recovered t·G, x-only', short(hex(r.Tx), 14), 'tone-t', hex(r.Tx)),
        field('T from stage 1', short(hex(c.Tx), 14), 'tone-t', hex(c.Tx)),
        el('p', {
          class: 'note',
          text: 'Extraction never returns a wrong t quietly. If the signature’s nonce is not this pre-signature’s x(R + T) the two do not pair and it reports that instead of subtracting unrelated numbers; if the recovered t does not satisfy t·G == T it reports that too. Both refusals are exercised in the test suite.',
        }),
      ),
    )
  } else {
    body.push(verdict('fail', 'Extraction reported failure', r.reason))
  }
  return stageCard(4, 'Subtract, and the secret falls out', ...body)
}

// ---------------------------------------------------------------------------
// Inputs: the INSPECT layer for the whole exhibit.
// ---------------------------------------------------------------------------

function inputsCard(): HTMLElement {
  const sk = el('input', { type: 'text', id: 'sk-input', spellcheck: 'false', autocomplete: 'off', value: state.secretKeyHex }) as HTMLInputElement
  const t = el('input', { type: 'text', id: 't-input', spellcheck: 'false', autocomplete: 'off', value: state.tHex }) as HTMLInputElement
  const msg = el('input', { type: 'text', id: 'msg-input', spellcheck: 'false', value: state.message }) as HTMLInputElement
  const supply = el('input', { type: 'text', id: 'supply-t', spellcheck: 'false', autocomplete: 'off', value: state.suppliedT === 'real' ? '' : state.suppliedT }) as HTMLInputElement

  const apply = button('Lock and pre-sign', { id: 'btn-lock', primary: true }, () => {
    state.secretKeyHex = sk.value.trim()
    state.tHex = t.value.trim()
    state.message = msg.value
    state.suppliedT = ''
    state.stage = 2
    rerender()
  })
  const complete = button('Add this t and verify', { id: 'btn-complete' }, () => {
    state.suppliedT = supply.value.trim()
    state.stage = 4
    rerender()
  })

  return inspect(
    'Change the inputs',
    el('p', {
      class: 'note',
      text: 'Defaults are deterministic, so two people opening the same link see the same proof. Nothing here is persisted and no key is real.',
    }),
    el(
      'div',
      { class: 'controls' },
      el('div', { class: 'control' }, el('label', { for: 'sk-input', text: "Signer's key (hex)" }), sk),
      el('div', { class: 'control' }, el('label', { for: 't-input', text: 'Adaptor secret t (hex)' }), t),
      el('div', { class: 'control' }, el('label', { for: 'msg-input', text: 'Message' }), msg),
    ),
    actions(apply),
    el(
      'div',
      { class: 'controls' },
      el('div', { class: 'control' }, el('label', { for: 'supply-t', text: 'Complete with this t (hex)' }), supply),
    ),
    actions(complete),
  )
}

export function initRelation(): void {
  state = initial()
}
