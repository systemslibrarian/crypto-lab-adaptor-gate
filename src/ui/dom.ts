// Small DOM helpers. No crypto here.

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v
    else if (k === 'text') node.textContent = v
    else node.setAttribute(k, v)
  }
  for (const c of children) node.append(c)
  return node
}

/**
 * A labelled value row.
 *
 * `full` carries the UNABBREVIATED value in a `data-full` attribute. Displayed hex
 * is elided in the middle so it stays readable, but an elided value cannot be
 * checked against anything, so the exact bytes travel alongside it. The attribute
 * is inert -- no role, no label, nothing assistive technology announces -- and it
 * is what lets the claims suite re-derive the page's numbers from the page's own
 * output rather than from a constant copied out of the source.
 */
export function field(
  label: string,
  value: string | Node,
  valueClass = '',
  full?: string,
): HTMLElement {
  const attrs: Record<string, string> = { class: `field-value ${valueClass}`.trim() }
  if (full) attrs['data-full'] = full
  const v = el('div', attrs)
  if (typeof value === 'string') v.textContent = value
  else v.append(value)
  return el('div', { class: 'field' }, el('div', { class: 'field-label' }, label), v)
}

/**
 * A verdict. Always icon + text + colour -- never colour alone (WCAG 1.4.1), and
 * the word is part of the string so a grayscale or deuteranopic reader gets the
 * same information.
 */
export function verdict(
  kind: 'pass' | 'fail' | 'alarm' | 'neutral',
  headline: string,
  detail?: string,
): HTMLElement {
  const icon = kind === 'pass' ? '[OK]' : kind === 'fail' ? '[X]' : kind === 'alarm' ? '[!]' : '[-]'
  const body = el('div', {}, el('strong', { text: headline }))
  if (detail) body.append(el('div', { class: 'note', text: detail }))
  return el(
    'div',
    { class: `verdict verdict-${kind}`, role: 'status', 'aria-live': 'polite' },
    el('span', { class: 'verdict-icon', 'aria-hidden': 'true', text: icon }),
    body,
  )
}

/** A verdict that is NOT a live region, for statically rendered rows. */
export function staticVerdict(
  kind: 'pass' | 'fail' | 'alarm' | 'neutral',
  headline: string,
  detail?: string,
): HTMLElement {
  const v = verdict(kind, headline, detail)
  v.removeAttribute('role')
  v.removeAttribute('aria-live')
  return v
}

export function pill(kind: 'ok' | 'fail' | 'info', text: string): HTMLElement {
  const mark = kind === 'ok' ? '✓' : kind === 'fail' ? '✗' : '·'
  return el(
    'span',
    { class: `pill pill-${kind}` },
    el('span', { 'aria-hidden': 'true', text: mark }),
    document.createTextNode(text),
  )
}

export function card(heading: string | null, ...children: (Node | string)[]): HTMLElement {
  const c = el('div', { class: 'card' })
  if (heading) c.append(el('h3', { text: heading }))
  for (const ch of children) c.append(ch)
  return c
}

/** A horizontally scrollable table region: keyboard reachable and named. */
export function tableWrap(labelledBy: string, table: HTMLElement): HTMLElement {
  return el(
    'div',
    { class: 'table-wrap', role: 'region', tabindex: '0', 'aria-labelledby': labelledBy },
    table,
  )
}

export function clear(node: HTMLElement): void {
  node.replaceChildren()
}

/** Shorten a hex string for display while keeping it recognisable. */
export function short(hexStr: string, keep = 10): string {
  if (hexStr.length <= keep * 2 + 1) return hexStr
  return `${hexStr.slice(0, keep)}…${hexStr.slice(-keep)}`
}

export function hexOf(v: bigint): string {
  return v.toString(16).padStart(64, '0')
}

/**
 * Progressive disclosure: the third layer.
 *
 * Every exhibit is built in three layers -- STORY (actors, action, consequence),
 * PROOF (the computed equation and the verifier's verdict), and INSPECT (full hex,
 * parity, challenge, fixtures, sources). Nothing is removed from the page by this;
 * what changes is WHEN it appears. Ships shut, and the a11y gate drives it open
 * through its own summary rather than revealing it from script.
 */
export function inspect(summary: string, ...children: (Node | string)[]): HTMLElement {
  const d = el('details', { class: 'inspect' })
  d.append(el('summary', {}, el('span', { class: 'inspect-label', text: summary })))
  const body = el('div', { class: 'inspect-body' })
  for (const c of children) body.append(c)
  d.append(body)
  return d
}

/**
 * The trust rail: a quiet, persistent statement of what is real and what is modeled,
 * shown beside the mechanism rather than only in the honesty panel. It exists so the
 * implementation boundary is established once, visibly, instead of being re-explained
 * every time a verdict appears.
 */
export function trustRail(...items: { kind: 'real' | 'modeled' | 'input'; text: string }[]): HTMLElement {
  const ul = el('ul', { class: 'trust-rail reset-list', 'aria-label': 'What is real on this page' })
  for (const it of items) {
    ul.append(
      el(
        'li',
        { class: `trust-item trust-${it.kind}` },
        el('span', { class: 'trust-tag', text: it.kind === 'modeled' ? 'MODELED' : it.kind === 'real' ? 'REAL' : 'INPUT' }),
        el('span', { class: 'trust-text', text: it.text }),
      ),
    )
  }
  return ul
}

/** A short story paragraph: the first layer, plain language, no hex. */
export function story(...paras: string[]): HTMLElement {
  const box = el('div', { class: 'story' })
  for (const p of paras) box.append(el('p', { text: p }))
  return box
}

/** A row of actions, with the primary one first. */
export function actions(...btns: HTMLElement[]): HTMLElement {
  return el('div', { class: 'actionbar' }, ...btns)
}

export function button(
  label: string,
  opts: { id?: string; primary?: boolean; disabled?: boolean; describedBy?: string },
  onClick: () => void,
): HTMLButtonElement {
  const attrs: Record<string, string> = {
    type: 'button',
    class: `btn ${opts.primary ? 'btn-primary' : 'btn-secondary'}`,
  }
  if (opts.id) attrs.id = opts.id
  if (opts.describedBy) attrs['aria-describedby'] = opts.describedBy
  const b = el('button', attrs, document.createTextNode(label)) as HTMLButtonElement
  if (opts.disabled) b.disabled = true
  b.addEventListener('click', onClick)
  return b
}
