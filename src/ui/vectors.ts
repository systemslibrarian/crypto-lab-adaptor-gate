// Exhibit 5 -- the vector and fixture tables.
//
// TWO RULES ARE STRUCTURAL HERE, not editorial.
//
// 1. Every row prints BOTH the computed value and the expected value, ALWAYS --
//    not only when they differ. A badge that is the only evidence for its own claim
//    cannot be falsified by looking at the page.
//
// 2. The fixture table contains a row that is WRONG ON PURPOSE, rendered like any
//    other row, and it must report FAIL. A checker only ever seen agreeing proves
//    nothing: if every row passed, a mutation forcing the comparison true would
//    change nothing observable here.

import { schnorr } from '@noble/curves/secp256k1.js'
import { BIP340_VECTORS, VECTOR_COUNTS, challengeBlocks } from '../crypto/vectors'
import { ADAPTOR_FIXTURES, ADAPTOR_FIXTURE_MESSAGE } from '../crypto/fixtures'
import { preSign, preVerify, adapt, extract, adaptorPoint } from '../crypto/adaptor'
import { fromHex } from '../crypto/secp'
import { el, verdict, card, clear, short, pill, tableWrap, field } from './dom'

export function renderVectors(root: HTMLElement): void {
  clear(root)

  const intro = card(
    'Checking the library before trusting it, and checking this lab against itself',
    el('p', {
      text:
        'Two tables. The first runs BIP-340’s own published test vectors through the ' +
        'cryptography library this lab is built on — because a library that is subtly wrong ' +
        'looks exactly like a lab that is subtly wrong. The second runs this lab’s adaptor ' +
        'fixtures, which are not official, because no standards body publishes adaptor vectors.',
    }),
    el('p', {
      class: 'note',
      text:
        'Every row shows the computed value beside the expected one, whether or not they match. ' +
        'One fixture row is wrong on purpose and is expected to fail.',
    }),
  )
  intro.classList.add('intro')
  root.append(intro)
  root.append(bip340Table())
  root.append(fixtureTable())
}

function bip340Table(): HTMLElement {
  let pass = 0
  let fail = 0
  const tbl = el('table')
  tbl.append(
    el('caption', {
      id: 'kat-caption',
      text:
        `BIP-340 official test vectors, ${VECTOR_COUNTS.total} rows from bip-0340/test-vectors.csv in ` +
        `bitcoin/bips. ${VECTOR_COUNTS.signable} rows carry a secret key and aux_rand and so round-trip ` +
        `through pre-sign, pre-verify, adapt and extract; ${VECTOR_COUNTS.verifyOnlyAccept} row is a ` +
        `positive verify-only row; ${VECTOR_COUNTS.verifyOnlyReject} rows are negative verify-only rows ` +
        `that exercise rejection. Not all ${VECTOR_COUNTS.total} round-trip.`,
    }),
  )
  const thead = el('thead')
  thead.append(
    el(
      'tr',
      {},
      el('th', { scope: 'col', text: 'row' }),
      el('th', { scope: 'col', text: 'class' }),
      el('th', { scope: 'col', text: 'msg bytes' }),
      el('th', { scope: 'col', text: 'hash blocks' }),
      el('th', { scope: 'col', text: 'expected' }),
      el('th', { scope: 'col', text: 'computed' }),
      el('th', { scope: 'col', text: 'result' }),
      el('th', { scope: 'col', text: 'adaptor round trip' }),
      el('th', { scope: 'col', text: 'note' }),
    ),
  )
  tbl.append(thead)
  const tbody = el('tbody')

  for (const v of BIP340_VECTORS) {
    let computed = false
    try {
      computed = schnorr.verify(v.signature, v.message, v.publicKey)
    } catch {
      computed = false
    }
    const ok = computed === v.expected
    ok ? pass++ : fail++

    // The round trip, only where the row is signable.
    let round = '— verify only'
    let roundOk: boolean | null = null
    if (v.cls === 'signable' && v.secretKey && v.auxRand) {
      try {
        const ad = adaptorPoint(0x0b0b000000000000000000000000000000000000000000000000000000000001n)
        const pre = preSign(v.secretKey, v.message, ad.Tx, { auxRand: v.auxRand })
        const pv = preVerify(pre, v.publicKey, v.message, ad.Tx)
        const { signature } = adapt(pre, ad.t)
        const accepted = schnorr.verify(signature, v.message, v.publicKey)
        const ex = extract(pre, signature, ad.Tx)
        roundOk = pv.ok && accepted && ex.ok && ex.t === ad.t
        round = roundOk ? 'pre-verify, adapt, verify, extract all agree' : 'FAILED'
      } catch (err) {
        roundOk = false
        round = `threw: ${err instanceof Error ? err.message : 'error'}`
      }
    }

    const clsLabel =
      v.cls === 'signable' ? 'signable' : v.cls === 'verify-only-accept' ? 'verify-only (accept)' : 'verify-only (reject)'

    tbody.append(
      el(
        'tr',
        {},
        el('td', { text: String(v.index) }),
        el('td', { text: clsLabel }),
        el('td', { text: String(v.messageLength) }),
        el('td', { text: String(challengeBlocks(v.messageLength)) }),
        // BOTH values, always.
        el('td', { text: v.expected ? 'accept' : 'reject' }),
        el('td', { text: computed ? 'accept' : 'reject' }),
        el('td', {}, pill(ok ? 'ok' : 'fail', ok ? 'match' : 'MISMATCH')),
        el(
          'td',
          {},
          roundOk === null ? pill('info', 'n/a') : pill(roundOk ? 'ok' : 'fail', roundOk ? 'ok' : 'FAILED'),
          document.createTextNode(' '),
          el('span', { class: 'note', text: round }),
        ),
        el('td', { class: 'note', text: v.comment || '' }),
      ),
    )
  }
  tbl.append(tbody)

  const c = card('BIP-340 official vectors', tableWrap('kat-caption', tbl))
  c.append(
    field('rows matching the published result', `${pass} of ${BIP340_VECTORS.length}`),
    fail === 0
      ? verdict(
          'pass',
          `All ${pass} published verify results reproduced`,
          'Both the expected and the computed verdict are printed on every row above, so this ' +
            'summary can be checked against the rows rather than taken on trust.',
        )
      : verdict('fail', `${fail} rows disagree with the published result`, 'See the MISMATCH rows above.'),
  )
  c.append(
    el(
      'details',
      {},
      el('summary', { text: 'On message lengths and hash blocks' }),
      el('p', {
        class: 'note',
        text:
          'BIP-340’s challenge is a tagged hash, so its input is 64 bytes of tag hashes plus ' +
          '32 for the nonce x-coordinate, 32 for the key and then the message: 128 bytes before the ' +
          'message even starts. Every row is therefore multi-block. The hash-blocks column counts ' +
          'compression blocks after padding, and row 18 at 100 message bytes is the only row that ' +
          'reaches a fourth — the only message-length-driven extra-block coverage the standard ' +
          'offers.',
      }),
    ),
  )
  return c
}

function fixtureTable(): HTMLElement {
  let pass = 0
  let fail = 0
  const tbl = el('table')
  tbl.append(
    el('caption', {
      id: 'fixture-caption',
      text:
        'Pinned adaptor fixtures. NOT official test vectors — no standards body publishes ' +
        'single-signer Schnorr adaptor vectors, so these are values this lab derived and pinned, ' +
        'cross-checked in the test suite by an independent affine re-derivation that does not ' +
        'import the adaptor code. The last row is wrong on purpose.',
    }),
  )
  const thead = el('thead')
  thead.append(
    el(
      'tr',
      {},
      el('th', { scope: 'col', text: 'fixture' }),
      el('th', { scope: 'col', text: 'covers' }),
      el('th', { scope: 'col', text: 'expected s' }),
      el('th', { scope: 'col', text: 'computed s' }),
      el('th', { scope: 'col', text: 's matches' }),
      el('th', { scope: 'col', text: 'library verify' }),
      el('th', { scope: 'col', text: 'extract == t' }),
    ),
  )
  tbl.append(thead)
  const tbody = el('tbody')

  for (const f of ADAPTOR_FIXTURES) {
    const sk = fromHex(f.secretKeyHex)
    const ad = adaptorPoint(BigInt('0x' + f.tRawHex))
    const msg = new TextEncoder().encode(ADAPTOR_FIXTURE_MESSAGE)
    const pre = preSign(sk, msg, ad.Tx, { auxRand: fromHex(f.auxRandHex) })
    const { s, signature } = adapt(pre, ad.t)
    const computedS = s.toString(16)
    const sMatches = computedS === f.expect.s
    const accepted = schnorr.verify(signature, msg, fromHex(f.expect.publicKey))
    const ex = extract(pre, signature, ad.Tx)
    const exOk = ex.ok && ex.t === ad.t

    const rowOk = sMatches && accepted && exOk
    rowOk ? pass++ : fail++

    const tr = el('tr', f.deliberatelyWrong ? { class: 'row-wrong' } : {})
    tr.append(
      el('td', { text: f.id }),
      el('td', { class: 'note', text: f.label }),
      // BOTH values, always, whether or not they differ.
      el('td', { class: 'mono', text: short(f.expect.s, 10) }),
      el('td', { class: 'mono', text: short(computedS, 10) }),
      el('td', {}, pill(sMatches ? 'ok' : 'fail', sMatches ? 'match' : 'MISMATCH')),
      el('td', {}, pill(accepted ? 'ok' : 'fail', accepted ? 'accepted' : 'REJECTED')),
      el('td', {}, pill(exOk ? 'ok' : 'fail', exOk ? 'match' : 'MISMATCH')),
    )
    tbody.append(tr)
  }
  tbl.append(tbody)

  const wrongRows = ADAPTOR_FIXTURES.filter((f) => f.deliberatelyWrong).length
  const expectedFail = wrongRows
  const c = card('This lab’s adaptor fixtures', tableWrap('fixture-caption', tbl))
  c.append(
    field('rows passing', `${pass} of ${ADAPTOR_FIXTURES.length}`),
    field('rows expected to fail', `${expectedFail} (deliberately wrong)`),
    fail === expectedFail
      ? verdict(
          'pass',
          `${pass} correct rows pass and the ${expectedFail} deliberately wrong row fails`,
          'The wrong row is what makes the passing rows meaningful. If every row agreed, this ' +
            'table would report success for a comparison that had never been seen to fail.',
        )
      : verdict(
          'alarm',
          `${fail} rows failed; ${expectedFail} were expected to`,
          'Either a correct fixture regressed or the deliberately wrong row stopped being wrong.',
        ),
  )
  c.append(
    el(
      'details',
      {},
      el('summary', { text: 'Why there are no official adaptor vectors' }),
      el('p', {
        class: 'note',
        text:
          'This was checked rather than assumed. BIP-340 specifies plain Schnorr and publishes ' +
          'vectors for it only. BIP-327 specifies MuSig2 and publishes none for adaptors. ' +
          'secp256k1-zkp ships none either. So no fixture on this page is labelled official, and ' +
          'the guard against them being self-confirming is the independent re-derivation in the ' +
          'test suite: a separate affine BigInt implementation with its own modular inverse, point ' +
          'addition and tagged hash, which agrees with every intermediate value above.',
      }),
    ),
  )
  return c
}
