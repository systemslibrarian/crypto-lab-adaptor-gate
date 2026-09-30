// Exhibit 3 -- PTLC vs HTLC (brief act 6).
//
// The two strips are computed from ONE run, so the comparison is a measurement
// rather than an illustration: the same z produces three different adaptor points
// and one repeated hash.

import { runPtlc, defaultPtlcPath } from '../crypto/ptlc'
import { hex } from '../crypto/secp'
import { el, field, verdict, card, clear, short, pill, tableWrap } from './dom'

export function renderPtlc(root: HTMLElement): void {
  clear(root)
  const { hops, z, message } = defaultPtlcPath()
  const run = runPtlc(hops, z, message)

  const intro = card(
    'Routing a payment without telling the route who else is on it',
    el('p', {
      text:
        'A routed payment passes through intermediaries. Each one needs to know that if it pays ' +
        'the next hop, it can reclaim from the previous one. Lightning’s original answer was ' +
        'a hash: every hop is conditioned on revealing the same preimage. That works, and it ' +
        'means every hop carries the same identifier — so any two hops on the route can be ' +
        'recognised as one payment by anyone who sees both.',
    }),
    el('p', {
      text:
        'Point time-locked contracts replace the hash with an adaptor point. Each hop gets a ' +
        'different point, because the sender blinds each one by a scalar only that hop knows. ' +
        'The hop can still derive what it needs — add your blinding to the secret you just ' +
        'learned — but two hops no longer look related.',
    }),
  )
  intro.classList.add('intro')
  root.append(intro)

  root.append(
    card(
      'The route',
      field('path', run.hops.map((h) => h.payer).join(' → ') + ' → ' + run.hops[run.hops.length - 1].payee),
      field('hops', String(run.hops.length)),
      field("recipient's payment point x(Z)", short(hex(run.paymentPointX), 16), 'tone-t'),
      el('p', {
        class: 'note',
        text:
          'Three hops needs four nodes. The build brief’s scope and this exhibit’s heading ' +
          'both say three hops while its example path names three parties, which is two — three ' +
          'hops is what is built, so Dave is the recipient.',
      }),
    ),
  )

  // The two strips, side by side in content order.
  const ptlcStrip = el('ul', { class: 'strip strip-ptlc reset-list' })
  const htlcStrip = el('ul', { class: 'strip strip-htlc reset-list' })
  for (const h of run.hops) {
    ptlcStrip.append(
      el(
        'li',
        { class: 'strip-row' },
        el('span', { class: 'strip-hop', text: `hop ${h.index}: ${h.payer} → ${h.payee}` }),
        el('span', { class: 'strip-val', text: short(hex(h.Tx), 18) }),
      ),
    )
    htlcStrip.append(
      el(
        'li',
        { class: 'strip-row' },
        el('span', { class: 'strip-hop', text: `hop ${h.index}: ${h.payer} → ${h.payee}` }),
        el('span', { class: 'strip-val', text: short(hex(h.htlcHash), 18) }),
      ),
    )
  }

  const grid = el(
    'div',
    { class: 'card-grid' },
    card(
      'PTLC — one adaptor point per hop',
      ptlcStrip,
      el(
        'p',
        {},
        pill(
          run.distinctPtlcPoints === run.hops.length ? 'ok' : 'fail',
          `${run.distinctPtlcPoints} distinct of ${run.hops.length} hops`,
        ),
      ),
    ),
    card(
      'HTLC — the same hash on every hop',
      htlcStrip,
      el(
        'p',
        {},
        pill(
          run.distinctHtlcHashes === 1 ? 'fail' : 'ok',
          `${run.distinctHtlcHashes} distinct of ${run.hops.length} hops`,
        ),
      ),
    ),
  )
  root.append(
    card(
      'The same payment, two ways of conditioning it',
      el('p', {
        class: 'note',
        text:
          'Both columns are derived from the same secret z in the same run. Read down each one and ' +
          'compare the values, not the labels.',
      }),
      grid,
    ),
  )

  const decorrelated = run.distinctPtlcPoints === run.hops.length && run.distinctHtlcHashes === 1
  root.append(
    decorrelated
      ? verdict(
          'pass',
          'Per-hop decorrelation holds — computed from both strips',
          `${run.distinctPtlcPoints} distinct adaptor points across ${run.hops.length} hops, against ` +
            `${run.distinctHtlcHashes} distinct hash. An observer of hop 1 and hop ${run.hops.length} ` +
            'can match the HTLC values by equality and cannot match the PTLC values at all.',
        )
      : verdict('fail', 'Decorrelation does not hold in this run', 'Counts are printed above.'),
  )

  // Settlement, backward.
  const tbl = el('table')
  tbl.append(
    el('caption', {
      id: 'ptlc-settle-caption',
      text:
        'Settlement order and per-hop extraction. Each row is a real pre-signature completed and ' +
        'then subtracted; the recovered secret is compared against the hop secret by computation.',
    }),
  )
  const thead = el('thead')
  thead.append(
    el(
      'tr',
      {},
      el('th', { scope: 'col', text: 'order' }),
      el('th', { scope: 'col', text: 'hop' }),
      el('th', { scope: 'col', text: 'x(T) for this hop' }),
      el('th', { scope: 'col', text: 'pre-verify' }),
      el('th', { scope: 'col', text: 'extracted == hop secret' }),
    ),
  )
  tbl.append(thead)
  const tbody = el('tbody')
  run.settledInOrder.forEach((label, i) => {
    const idx = run.hops.length - 1 - i
    const h = run.hops[idx]
    tbody.append(
      el(
        'tr',
        {},
        el('td', { text: String(i + 1) }),
        el('td', { text: label }),
        el('td', { class: 'mono tone-t', text: short(hex(h.Tx), 12) }),
        el('td', {}, pill(h.preVerifies ? 'ok' : 'fail', h.preVerifies ? 'accepted' : 'REJECTED')),
        el('td', {}, pill(h.extractionMatches ? 'ok' : 'fail', h.extractionMatches ? 'matches' : 'MISMATCH')),
      ),
    )
  })
  tbl.append(tbody)
  root.append(
    card(
      'Extraction propagates backward, hop by hop',
      el('p', {
        class: 'note',
        text:
          'The last hop settles first. Each intermediary extracts the secret from the hop it paid, ' +
          'adds the blinding scalar it was handed, re-normalises, and that is exactly the secret ' +
          'that claims its own incoming hop — which the test suite checks by re-deriving it the ' +
          'way the intermediary would.',
      }),
      tableWrap('ptlc-settle-caption', tbl),
    ),
  )

  root.append(
    el(
      'details',
      {},
      el('summary', { text: 'What is modeled here' }),
      el('p', {
        class: 'note',
        text:
          'Three hops, real BIP-340 pre-signatures, real extraction. No channel state, no fees, no ' +
          'network, no onion routing, and no failure or retry logic. Decorrelation here is the ' +
          'algebraic property only: it shows that the per-hop identifiers differ, not that a real ' +
          'Lightning implementation leaks nothing else. Timing, amounts and topology are all ' +
          'still correlating signals, and none of them are modeled.',
      }),
    ),
  )
}
