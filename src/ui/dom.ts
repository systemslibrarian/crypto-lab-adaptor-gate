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
