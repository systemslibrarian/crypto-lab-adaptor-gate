// Exhibit 3 -- PTLC vs HTLC (brief act 6), driven by the causal state machine.
//
// Two things are shown here, and the second is the one that was previously faked.
//
//   DECORRELATION: three distinct adaptor points against one repeated hash, both
//   strips computed from the same run so the comparison is a measurement.
//
//   CAUSALITY: settlement starts at the LAST hop and cannot advance upstream until
//   the hop below it has settled AND its payer has extracted a usable secret. The
//   page does not merely say so -- `settleNext` in crypto/ptlc.ts has access to one
//   secret and completes each hop with that and nothing else, so the break controls
//   below really do stall the hops above them.

import {
  startPtlc,
  settleNext,
  settleAll,
  ptlcFinished,
  defaultPtlcPath,
  type PtlcState,
  type PtlcFaults,
} from '../crypto/ptlc'
import { hex } from '../crypto/secp'
import {
  el,
  field,
  verdict,
  card,
  clear,
  short,
  pill,
  tableWrap,
  inspect,
  trustRail,
  story,
  actions,
  button,
} from './dom'

let faults: PtlcFaults = {}
let run: PtlcState = startPtlc(...routeArgs(), faults)

function routeArgs(): [ReturnType<typeof defaultPtlcPath>['hops'], bigint, string] {
  const { hops, z, message } = defaultPtlcPath()
  return [hops, z, message]
}

export function ptlcUiState(): { corrupt: number; blind: number; cursorFromEnd: number } {
  return {
    corrupt: faults.corruptSignatureAtHop ?? 0,
    blind: faults.wrongBlindingAtHop ?? 0,
    cursorFromEnd: run.hops.length - 1 - run.cursor,
  }
}

export function setPtlcUiState(corrupt: number, blind: number, settled: number): void {
  faults = {}
  if (corrupt) faults.corruptSignatureAtHop = corrupt
  if (blind) faults.wrongBlindingAtHop = blind
  run = startPtlc(...routeArgs(), faults)
  for (let i = 0; i < settled; i++) run = settleNext(run)
}

let onChange: (() => void) | null = null
export function setPtlcOnChange(fn: () => void): void {
  onChange = fn
}

function rerender(): void {
  const panel = document.getElementById('panel-ptlc')
  if (panel) renderPtlc(panel)
  onChange?.()
}

function restart(): void {
  run = startPtlc(...routeArgs(), faults)
}

export function renderPtlc(root: HTMLElement): void {
  clear(root)

  const intro = card(null)
  intro.classList.add('intro', 'opening')
  intro.append(
    story(
      'A routed payment passes through strangers. Lightning’s original answer conditioned ' +
        'every hop on the same secret hash — which works, and means any two hops on the route ' +
        'can be recognised as one payment. Point time-locked contracts give each hop a different ' +
        'point instead, and the hop can still derive what it needs.',
    ),
  )
  intro.append(
    actions(
      button('Settle next hop', { id: 'btn-ptlc-next', primary: true, disabled: ptlcFinished(run) }, () => {
        run = settleNext(run)
        rerender()
      }),
      button('Settle all', { id: 'btn-ptlc-all', disabled: ptlcFinished(run) }, () => {
        run = settleAll(run)
        rerender()
      }),
      button('Reset exhibit', { id: 'btn-ptlc-reset' }, () => {
        faults = {}
        restart()
        rerender()
      }),
    ),
  )
  const settledCount = run.hops.filter((h) => h.status !== 'waiting').length
  intro.append(
    el('p', {
      class: 'note hint',
      role: 'status',
      'aria-live': 'polite',
      text: ptlcFinished(run)
        ? 'Every hop has been attempted. Settlement ran backward, from the recipient toward the sender.'
        : `${settledCount} of ${run.hops.length} hops attempted. The next to settle is hop ${run.cursor + 1} — settlement runs backward.`,
    }),
  )
  intro.append(
    trustRail(
      { kind: 'real', text: 'real BIP-340 pre-signatures and extraction' },
      { kind: 'modeled', text: 'channels, routing and the blinding handoff' },
    ),
  )
  root.append(intro)

  root.append(breakControls())
  root.append(strips())
  root.append(settlementTable())
  root.append(
    inspect(
      'Inspect exact values and what is modeled',
      field('path', run.hops.map((h) => h.payer).join(' → ') + ' → ' + run.hops[run.hops.length - 1].payee),
      field('hops', String(run.hops.length)),
      field("recipient's payment point x(Z)", short(hex(run.paymentPointX), 16), 'tone-t', hex(run.paymentPointX)),
      field('HTLC payment hash', short(hex(run.htlcHash), 16), 'tone-shat', hex(run.htlcHash)),
      el('p', {
        class: 'note',
        text: 'Three hops needs four nodes. The build brief’s scope and this exhibit’s heading both say three hops while its example path names three parties, which is two — three hops is what is built, so Dave is the recipient.',
      }),
      el('p', {
        class: 'note',
        text: 'Real BIP-340 pre-signatures and real extraction; no channel state, no fees, no network, no onion routing, no retries. Decorrelation here is the algebraic property only: it shows the per-hop identifiers differ, not that a real Lightning implementation leaks nothing else. Timing, amounts and topology are all still correlating signals and none are modeled.',
      }),
    ),
  )
}

function breakControls(): HTMLElement {
  const c = card('Break the chain')

  const group = (
    name: string,
    legend: string,
    selected: number,
    onPick: (hop: number) => void,
    idPrefix: string,
  ) => {
    const row = el('div', { class: 'toggle-row' })
    const noneId = `${idPrefix}-none`
    const none = el('input', { type: 'radio', name, id: noneId }) as HTMLInputElement
    none.checked = selected === 0
    none.addEventListener('change', () => onPick(0))
    row.append(el('label', { for: noneId }, none, document.createTextNode(' none')))
    for (const h of run.hops) {
      const id = `${idPrefix}-${h.index}`
      const input = el('input', { type: 'radio', name, id }) as HTMLInputElement
      input.checked = selected === h.index
      input.addEventListener('change', () => onPick(h.index))
      row.append(el('label', { for: id }, input, document.createTextNode(` hop ${h.index}`)))
    }
    const fs = el('fieldset', { class: 'radio-row' })
    fs.append(el('legend', { text: legend }), row)
    return fs
  }

  c.append(
    group(
      'ptlc-corrupt',
      'Corrupt a published signature',
      faults.corruptSignatureAtHop ?? 0,
      (hop) => {
        faults = hop ? { corruptSignatureAtHop: hop } : {}
        restart()
        rerender()
      },
      'ptlc-corrupt',
    ),
    group(
      'ptlc-blind',
      'Give a payee the wrong blinding scalar',
      faults.wrongBlindingAtHop ?? 0,
      (hop) => {
        faults = hop ? { wrongBlindingAtHop: hop } : {}
        restart()
        rerender()
      },
      'ptlc-blind',
    ),
    el('p', {
      class: 'note',
      text:
        'Both faults stop the hop above and leave the hops below untouched \u2014 the break ' +
        'propagates in one direction only. They fail for DIFFERENT reasons, and the second is ' +
        'the sharper lesson: a corrupt signature is rejected by the channel, but a wrong ' +
        'blinding produces a hop whose signature is fine and whose extraction is exactly ' +
        'right, and the hop above it still cannot settle \u2014 because the value derived for ' +
        'it was not the secret its point commits to.',
    }),
  )
  return c
}

function strips(): HTMLElement {
  const ptlcStrip = el('ul', { class: 'strip strip-ptlc reset-list' })
  const htlcStrip = el('ul', { class: 'strip strip-htlc reset-list' })
  for (const h of run.hops) {
    ptlcStrip.append(
      el(
        'li',
        { class: 'strip-row' },
        el('span', { class: 'strip-hop', text: `hop ${h.index}: ${h.payer} → ${h.payee}` }),
        el('span', { class: 'strip-val', 'data-full': hex(h.Tx), text: short(hex(h.Tx), 14) }),
      ),
    )
    htlcStrip.append(
      el(
        'li',
        { class: 'strip-row' },
        el('span', { class: 'strip-hop', text: `hop ${h.index}: ${h.payer} → ${h.payee}` }),
        el('span', { class: 'strip-val', 'data-full': hex(h.htlcHash), text: short(hex(h.htlcHash), 14) }),
      ),
    )
  }

  const grid = el(
    'div',
    { class: 'card-grid' },
    card(
      'PTLC — one point per hop',
      ptlcStrip,
      el('p', { class: 'pill-row' }, pill(run.distinctPtlcPoints === run.hops.length ? 'ok' : 'fail', `${run.distinctPtlcPoints} distinct of ${run.hops.length} hops`)),
    ),
    card(
      'HTLC — the same hash every hop',
      htlcStrip,
      el('p', { class: 'pill-row' }, pill(run.distinctHtlcHashes === 1 ? 'fail' : 'ok', `${run.distinctHtlcHashes} distinct of ${run.hops.length} hops`)),
    ),
  )

  const decorrelated = run.distinctPtlcPoints === run.hops.length && run.distinctHtlcHashes === 1
  return card(
    'The same payment, conditioned two ways',
    el('p', {
      class: 'note',
      text: 'Both columns derive from the same secret in the same run. Read down each one and compare the values, not the labels.',
    }),
    grid,
    decorrelated
      ? verdict(
          'pass',
          'Per-hop decorrelation holds — computed from both strips',
          `${run.distinctPtlcPoints} distinct adaptor points across ${run.hops.length} hops, against ${run.distinctHtlcHashes} distinct hash. An observer of hop 1 and hop ${run.hops.length} can match the HTLC values by equality and cannot match the PTLC values at all.`,
        )
      : verdict('fail', 'Decorrelation does not hold in this run', 'Counts are printed above.'),
  )
}

function settlementTable(): HTMLElement {
  const tbl = el('table')
  tbl.append(
    el('caption', {
      id: 'ptlc-settle-caption',
      text: 'Settlement order. Each hop is completed with the secret its payee DERIVED from the hop below it — extracted value plus its own blinding — and with nothing else.',
    }),
  )
  tbl.append(
    el(
      'thead',
      {},
      el(
        'tr',
        {},
        el('th', { scope: 'col', text: 'order' }),
        el('th', { scope: 'col', text: 'hop' }),
        el('th', { scope: 'col', text: 'x(T) for this hop' }),
        el('th', { scope: 'col', text: 'status' }),
        el('th', { scope: 'col', text: 'extracted == expected' }),
      ),
    ),
  )
  const body = el('tbody')
  // Settlement order is last hop first.
  const ordered = [...run.hops].reverse()
  ordered.forEach((h, i) => {
    const statusCell =
      h.status === 'settled'
        ? pill('ok', 'settled')
        : h.status === 'blocked'
          ? pill('fail', 'BLOCKED')
          : pill('info', 'waiting')
    const row = el(
      'tr',
      { class: h.status === 'blocked' ? 'row-wrong' : '' },
      el('td', { text: String(i + 1) }),
      el('td', { text: `hop ${h.index}: ${h.payer} → ${h.payee}` }),
      el('td', { class: 'mono tone-t', 'data-full': hex(h.Tx), text: short(hex(h.Tx), 10) }),
      el('td', {}, statusCell),
      el(
        'td',
        {},
        h.status === 'settled'
          ? pill(h.extractionMatches ? 'ok' : 'fail', h.extractionMatches ? 'matches' : 'MISMATCH')
          : pill('info', '—'),
      ),
    )
    body.append(row)
    if (h.blockedReason) {
      body.append(
        el(
          'tr',
          { class: 'row-note' },
          el('td', { colspan: '5', class: 'note', text: `hop ${h.index}: ${h.blockedReason}` }),
        ),
      )
    }
  })
  tbl.append(body)

  const c = card('Extraction propagates backward, hop by hop', tableWrap('ptlc-settle-caption', tbl))
  if (run.broken) {
    c.append(
      verdict(
        'alarm',
        'The chain is broken — every hop upstream of the break stalled',
        run.brokenReason +
          '. Nothing upstream could settle, because each hop can only be completed with the secret derived from the hop below it.',
      ),
    )
  } else if (ptlcFinished(run) && run.hops.every((h) => h.status === 'settled')) {
    c.append(
      verdict(
        'pass',
        'Every hop settled, each from the one below it',
        'The last hop settled first. Each payer then extracted from what it published, added its own blinding, re-normalised, and that derived value — not a precomputed one — is what completed the hop above.',
      ),
    )
  }
  if (run.log.length) {
    c.append(
      inspect(
        'Transition log',
        el(
          'ul',
          { class: 'plain-list' },
          ...run.log.map((l) => el('li', { text: l })),
        ),
      ),
    )
  }
  return c
}
