import './styles.css'
import { renderRelation, initRelation } from './ui/relation'
import { renderSwap } from './ui/swap'
import { renderPtlc } from './ui/ptlc'
import { renderBreakIt } from './ui/breakit'
import { renderVectors } from './ui/vectors'
import { renderHonesty } from './ui/honesty'

type PanelId = 'relation' | 'swap' | 'ptlc' | 'break' | 'vectors' | 'honesty'

const RENDERERS: Record<PanelId, (root: HTMLElement) => void> = {
  relation: renderRelation,
  swap: renderSwap,
  ptlc: renderPtlc,
  break: renderBreakIt,
  vectors: renderVectors,
  honesty: renderHonesty,
}

const rendered = new Set<PanelId>()

function panelFor(id: PanelId): HTMLElement | null {
  return document.getElementById(`panel-${id}`)
}

function activate(id: PanelId, focusPanel: boolean): void {
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
  if (panel && focusPanel) panel.focus()
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

function boot(): void {
  wireTabs()
  initRelation()
  activate('relation', false)
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot)
} else {
  boot()
}
