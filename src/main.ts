import './styles.css'
import {
  renderRelation,
  initRelation,
  relationState,
  setRelationState,
  setRelationOnChange,
  type Stage,
} from './ui/relation'
import { renderSwap, swapUiState, setSwapUiState, setSwapOnChange } from './ui/swap'
import { renderPtlc, ptlcUiState, setPtlcUiState, setPtlcOnChange } from './ui/ptlc'
import { renderBreakIt, breakUiState, setBreakUiState, setBreakOnChange } from './ui/breakit'
import { renderVectors } from './ui/vectors'
import { renderHonesty } from './ui/honesty'

type PanelId = 'relation' | 'swap' | 'ptlc' | 'break' | 'vectors' | 'honesty'

const PANELS: PanelId[] = ['relation', 'swap', 'ptlc', 'break', 'vectors', 'honesty']

const RENDERERS: Record<PanelId, (root: HTMLElement) => void> = {
  relation: renderRelation,
  swap: renderSwap,
  ptlc: renderPtlc,
  break: renderBreakIt,
  vectors: renderVectors,
  honesty: renderHonesty,
}

const rendered = new Set<PanelId>()
let current: PanelId = 'relation'
/** Set while applying URL state, so writing back does not fight the read. */
let applying = false

// ---------------------------------------------------------------------------
// URL state.
//
// The active exhibit and the important failure modes live in the hash, so a
// presenter can link straight at "the swap, broken" and a reader who hits Back or
// refresh keeps their place. Deterministic inputs plus URL state means two people
// opening the same link see the same proof.
// ---------------------------------------------------------------------------

function readUrl(): URLSearchParams {
  return new URLSearchParams(location.hash.replace(/^#/, ''))
}

function writeUrl(push: boolean): void {
  if (applying) return
  const p = new URLSearchParams()
  p.set('e', current)
  const rel = relationState()
  if (rel.stage !== 0) p.set('stage', String(rel.stage))
  if (rel.wrongT) p.set('t', 'wrong')
  const sw = swapUiState()
  if (sw.cheat) p.set('cheat', '1')
  if (sw.skip) p.set('skip', '1')
  if (sw.cursor > 1) p.set('sc', String(sw.cursor))
  const pt = ptlcUiState()
  if (pt.corrupt) p.set('corrupt', String(pt.corrupt))
  if (pt.blind) p.set('blind', String(pt.blind))
  if (pt.cursorFromEnd > 0) p.set('hops', String(pt.cursorFromEnd))
  const br = breakUiState()
  if (br.naive) p.set('naive', '1')
  if (br.sameT) p.set('samet', '1')
  const url = `${location.pathname}${location.search}#${p.toString()}`
  if (push) history.pushState(null, '', url)
  else history.replaceState(null, '', url)
}

function applyUrl(): void {
  applying = true
  try {
    const p = readUrl()
    const e = p.get('e') as PanelId | null
    setRelationState(
      (Number(p.get('stage') ?? '0') || 0) as Stage,
      p.get('t') === 'wrong',
    )
    setSwapUiState(p.get('cheat') === '1', p.get('skip') === '1', Number(p.get('sc') ?? '1') || 1)
    setPtlcUiState(
      Number(p.get('corrupt') ?? '0') || 0,
      Number(p.get('blind') ?? '0') || 0,
      Number(p.get('hops') ?? '0') || 0,
    )
    setBreakUiState(p.get('naive') === '1', p.get('samet') === '1')
    // Re-render anything already on screen so it reflects the restored state.
    rendered.clear()
    activate(e && PANELS.includes(e) ? e : 'relation', false, false)
  } finally {
    applying = false
  }
}

// ---------------------------------------------------------------------------

function panelFor(id: PanelId): HTMLElement | null {
  return document.getElementById(`panel-${id}`)
}

function activate(id: PanelId, focusPanel: boolean, push = true): void {
  current = id
  const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('.tab-btn'))
  for (const tab of tabs) {
    const target = tab.dataset.panel as PanelId
    const selected = target === id
    tab.setAttribute('aria-selected', String(selected))
    // Tab stop follows selection so the tablist is one stop, per ARIA practice.
    if (selected) tab.removeAttribute('tabindex')
    else tab.setAttribute('tabindex', '-1')
    const panel = panelFor(target)
    if (panel) panel.hidden = !selected
  }
  const panel = panelFor(id)
  if (panel && !rendered.has(id)) {
    RENDERERS[id](panel)
    rendered.add(id)
  }
  // Keep the selected tab in view in the compact mobile scroller -- but only on a
  // user-initiated change. Doing it on first load scrolled the page 291px past the
  // hero before anyone had touched it, and it moved the sequential focus start
  // point so the first Tab press skipped the skip link.
  if (push && !applying) {
    const el = tabs.find((t) => t.dataset.panel === id)
    el?.scrollIntoView({ block: 'nearest', inline: 'nearest' })
  }
  if (panel && focusPanel) panel.focus()
  writeUrl(push)
}

function wireTabs(): void {
  const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('.tab-btn'))
  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => activate(tab.dataset.panel as PanelId, false))
    tab.addEventListener('keydown', (ev) => {
      const key = ev.key
      let next = -1
      if (key === 'ArrowRight') next = (i + 1) % tabs.length
      else if (key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length
      else if (key === 'Home') next = 0
      else if (key === 'End') next = tabs.length - 1
      else return
      ev.preventDefault()
      const target = tabs[next]
      activate(target.dataset.panel as PanelId, false)
      target.focus()
    })
  })
}

function wireResetAll(): void {
  const btn = document.getElementById('btn-reset-all')
  if (!btn) return
  btn.addEventListener('click', () => {
    history.pushState(null, '', `${location.pathname}${location.search}#e=relation`)
    applyUrl()
    const panel = panelFor('relation')
    panel?.focus()
  })
}

function boot(): void {
  wireTabs()
  wireResetAll()
  initRelation()
  // Any exhibit changing its own state keeps the URL in step (replace, not push,
  // so stepping an exhibit does not fill the history).
  setRelationOnChange(() => writeUrl(false))
  setSwapOnChange(() => writeUrl(false))
  setPtlcOnChange(() => writeUrl(false))
  setBreakOnChange(() => writeUrl(false))
  applyUrl()
  window.addEventListener('popstate', applyUrl)
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot)
} else {
  boot()
}
