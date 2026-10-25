'use strict'

/**
 * LUME Monitor — Electron main process.
 *
 * Independence model: we do NOT trust the LUME client to report on itself, and
 * we do NOT break TLS. Instead we launch our OWN Chromium (via puppeteer) and
 * subscribe to Chrome DevTools Protocol Network events — i.e. we read what the
 * browser actually observed leaving the machine, then classify it. LUME loads
 * inside that controlled browser; this window renders the live verdict stream.
 */

const { app, BrowserWindow } = require('electron')
const path = require('path')
const fs = require('fs')
const puppeteer = require('puppeteer')

const { normalizeHttp, normalizeWs, normalizeApp, parseUrl } = require('./capture')
const { classify } = require('./classify')
const { makeCorrelator } = require('./correlate')
const INJECT = require('./inject')

function loadConfig() {
  const file = path.join(__dirname, '..', 'config.json')
  let cfg = { lumeUrl: 'https://lume-dev-version.vercel.app', relayHosts: ['lume-api-3dnb.onrender.com'] }
  try {
    cfg = Object.assign(cfg, JSON.parse(fs.readFileSync(file, 'utf8')))
  } catch {
    /* fall back to defaults */
  }
  if (process.env.LUME_URL) cfg.lumeUrl = process.env.LUME_URL
  if (process.env.LUME_RELAY_HOSTS) cfg.relayHosts = process.env.LUME_RELAY_HOSTS.split(',').map(s => s.trim()).filter(Boolean)
  return cfg
}

let monitorWin = null
let browser = null

async function createMonitorWindow() {
  monitorWin = new BrowserWindow({
    width: 940,
    height: 860,
    title: 'LUME Monitor',
    backgroundColor: '#0b0b0c',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  })
  await monitorWin.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'))
}

function emit(payload) {
  if (monitorWin && !monitorWin.isDestroyed()) monitorWin.webContents.send('lume:event', payload)
}

async function startCapture(cfg) {
  browser = await puppeteer.launch({
    headless: false,
    defaultViewport: null,
    args: ['--no-first-run', '--no-default-browser-check'],
  })

  const pages = await browser.pages()
  const page = pages[0] || (await browser.newPage())

  const correlator = makeCorrelator()

  // Classify one event, tag which lane it came from, and cross-check the two
  // lanes: if the same body was already seen on the other lane, mark it
  // confirmed ("the app's claim matches the wire").
  function processAndEmit(ev, source) {
    if (!ev) return
    const verdict = classify(ev, cfg)
    verdict.source = source
    const body = ev.body || ''
    if ((ev.kind === 'http' || ev.kind === 'ws') && body.length > 0) {
      const c = correlator.observe(ev, source)
      if (c.confirmed) {
        verdict.confirmed = true
        verdict.matchedSource = c.matchedSource
      }
    }
    emit(verdict)
  }

  // ── Lane 2: "reported by the app" — install BEFORE navigation so the hook is
  // present when LUME's bundle runs. The bridge receives fetch/WS.send bodies
  // and any opt-in dev telemetry.
  await page.exposeFunction('__lumeMonitorBridge', payload => {
    try {
      processAndEmit(normalizeApp(payload), 'app')
    } catch {
      /* never let reporting break the page */
    }
  })
  await page.evaluateOnNewDocument(INJECT)

  // ── Lane 1: independent wire view via CDP.
  const client = await page.target().createCDPSession()
  await client.send('Network.enable')

  // WebSocket frame events carry only a requestId, not a URL, so remember which
  // socket went where in order to resolve the host on each frame.
  const wsHostByRequestId = new Map()

  client.on('Network.webSocketCreated', p => {
    const parsed = parseUrl(p.url || '')
    if (parsed) wsHostByRequestId.set(p.requestId, parsed.host)
  })

  client.on('Network.requestWillBeSent', p => {
    processAndEmit(normalizeHttp(p), 'wire')
  })

  client.on('Network.webSocketFrameSent', p => {
    processAndEmit(normalizeWs(p, 'out', wsHostByRequestId.get(p.requestId)), 'wire')
  })

  client.on('Network.webSocketFrameReceived', p => {
    processAndEmit(normalizeWs(p, 'in', wsHostByRequestId.get(p.requestId)), 'wire')
  })

  await page.goto(cfg.lumeUrl, { waitUntil: 'domcontentloaded' }).catch(() => {})
}

app.whenReady().then(async () => {
  const cfg = loadConfig()
  await createMonitorWindow()
  emit({ system: true, message: `Watching ${cfg.lumeUrl} — relay: ${cfg.relayHosts.join(', ')}` })
  try {
    await startCapture(cfg)
  } catch (err) {
    emit({ system: true, level: 'error', message: `Could not launch the controlled browser: ${err && err.message ? err.message : err}` })
  }
})

app.on('window-all-closed', async () => {
  if (browser) {
    try {
      await browser.close()
    } catch {
      /* already gone */
    }
  }
  app.quit()
})
