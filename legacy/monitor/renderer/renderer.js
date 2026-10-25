'use strict'

/**
 * Renders the live verdict stream. Driven by classified events from the main
 * process (window.monitor.onEvent). Also exposes window.__render so the same
 * pipeline can be driven manually for a visual check without Electron.
 */

const stream = document.getElementById('stream')
const statusEl = document.getElementById('status')
const hideApp = document.getElementById('hide-app')
const counts = { sealed: 0, metadata: 0, exposed: 0, confirmed: 0 }
const nEl = {
  sealed: document.getElementById('n-sealed'),
  metadata: document.getElementById('n-metadata'),
  exposed: document.getElementById('n-exposed'),
  confirmed: document.getElementById('n-confirmed'),
}

const MAX_ROWS = 500

function el(tag, cls, text) {
  const node = document.createElement(tag)
  if (cls) node.className = cls
  if (text != null) node.textContent = text
  return node
}

function fmtTime(ts) {
  const d = new Date(ts || Date.now())
  return d.toLocaleTimeString([], { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0')
}

function renderVerdict(v) {
  if (v.system) {
    const s = el('div', 'system' + (v.level === 'error' ? ' error' : ''), v.message)
    stream.prepend(s)
    if (v.message) statusEl.textContent = v.message
    return
  }

  if (counts[v.lane] != null) {
    counts[v.lane]++
    nEl[v.lane].textContent = counts[v.lane]
  }
  if (v.confirmed) {
    counts.confirmed++
    nEl.confirmed.textContent = counts.confirmed
  }

  const row = el('div', 'row ' + v.lane)
  if (v.lane === 'app' && hideApp.checked) row.style.display = 'none'
  row.dataset.lane = v.lane

  const head = el('div', 'row-head')
  if (v.source) {
    const src = el('span', 'src ' + v.source, v.source === 'wire' ? 'wire' : 'app')
    src.title = v.source === 'wire' ? 'observed independently on the wire (CDP)' : 'reported by the app'
    head.appendChild(src)
  }
  head.appendChild(el('span', 'title', v.title))
  if (v.direction) head.appendChild(el('span', 'dir', v.direction === 'in' ? '↓ in' : '↑ out'))
  const parts = []
  if (v.method) parts.push(v.method)
  if (v.host) parts.push(v.host)
  if (v.size) parts.push(v.size + ' B')
  parts.push(fmtTime(v.timestamp))
  head.appendChild(el('span', 'meta', parts.join('  ·  ')))
  row.appendChild(head)

  if (v.plain) row.appendChild(el('p', 'plain', v.plain))

  if (v.serverSees && v.serverSees.length) {
    const sees = el('div', 'sees')
    for (const s of v.serverSees) sees.appendChild(el('span', 'chip ' + s.sev, s.label))
    if (v.confirmed) {
      const c = el('span', 'chip confirmed', `✓ matches ${v.matchedSource === 'wire' ? 'the wire' : 'the app'}`)
      c.title = 'The same payload was seen on both lanes — the app did not lie about what it sent.'
      sees.appendChild(c)
    }
    row.appendChild(sees)
  }

  if (v.plaintext) {
    const p = el('div', 'plaintext')
    p.appendChild(document.createTextNode('you typed: '))
    p.appendChild(el('b', null, v.plaintext))
    row.appendChild(p)
  }

  if (v.evidence) {
    const e = el('div', 'evidence')
    e.appendChild(document.createTextNode('server receives: '))
    e.appendChild(el('b', null, v.evidence))
    row.appendChild(e)
  }

  stream.prepend(row)
  while (stream.children.length > MAX_ROWS) stream.removeChild(stream.lastChild)
}

hideApp.addEventListener('change', () => {
  for (const row of stream.querySelectorAll('.row.app')) {
    row.style.display = hideApp.checked ? 'none' : ''
  }
})

window.__render = renderVerdict
if (window.monitor && typeof window.monitor.onEvent === 'function') {
  window.monitor.onEvent(renderVerdict)
} else {
  statusEl.textContent = 'standalone preview (no capture bridge)'
}
