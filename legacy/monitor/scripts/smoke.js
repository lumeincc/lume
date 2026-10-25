'use strict'

/**
 * Headless smoke test of the capture pipeline (no Electron GUI). Launches the
 * puppeteer Chromium, wires both lanes exactly like src/main.js, loads the
 * target, and prints a summary of the classified events. Proves the runtime
 * path end-to-end against a real page.
 *
 * Run: `npm run smoke` (or `LUME_URL=http://localhost:3000 npm run smoke`).
 */

const fs = require('fs')
const path = require('path')
const puppeteer = require('puppeteer')

const { normalizeHttp, normalizeWs, normalizeApp, parseUrl } = require('../src/capture')
const { classify } = require('../src/classify')
const { makeCorrelator } = require('../src/correlate')
const INJECT = require('../src/inject')

const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'config.json'), 'utf8'))
if (process.env.LUME_URL) cfg.lumeUrl = process.env.LUME_URL

;(async () => {
  const verdicts = []
  const correlator = makeCorrelator()

  function processAndEmit(ev, source) {
    if (!ev) return
    const v = classify(ev, cfg)
    v.source = source
    const body = ev.body || ''
    if ((ev.kind === 'http' || ev.kind === 'ws') && body.length > 0) {
      const c = correlator.observe(ev, source)
      if (c.confirmed) {
        v.confirmed = true
        v.matchedSource = c.matchedSource
      }
    }
    verdicts.push(v)
  }

  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox'] })
  const page = (await browser.pages())[0] || (await browser.newPage())

  await page.exposeFunction('__lumeMonitorBridge', p => {
    try {
      processAndEmit(normalizeApp(p), 'app')
    } catch {
      /* ignore */
    }
  })
  await page.evaluateOnNewDocument(INJECT)

  const client = await page.target().createCDPSession()
  await client.send('Network.enable')
  const wsHost = new Map()
  client.on('Network.webSocketCreated', p => {
    const u = parseUrl(p.url || '')
    if (u) wsHost.set(p.requestId, u.host)
  })
  client.on('Network.requestWillBeSent', p => processAndEmit(normalizeHttp(p), 'wire'))
  client.on('Network.webSocketFrameSent', p => processAndEmit(normalizeWs(p, 'out', wsHost.get(p.requestId)), 'wire'))
  client.on('Network.webSocketFrameReceived', p => processAndEmit(normalizeWs(p, 'in', wsHost.get(p.requestId)), 'wire'))

  console.log(`loading ${cfg.lumeUrl} …`)
  await page.goto(cfg.lumeUrl, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(e => console.log('nav note:', e.message))
  await new Promise(r => setTimeout(r, 4000))

  // Self-test probe: fire one POST from page JS so the in-page hook (app lane),
  // the CDP view (wire lane) and the correlator all exercise end-to-end. The
  // server rejects it (unsigned) — we only care that the request leaves and is
  // seen on both lanes. Not real LUME behaviour, just a live check of the tool.
  const relay = cfg.relayHosts && cfg.relayHosts[0]
  if (relay) {
    console.log('firing self-test POST /messages/send …')
    await page
      .evaluate(base => {
        return fetch(base + '/api/messages/send', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            senderId: '00000000-0000-4000-8000-000000000000',
            recipientId: '00000000-0000-4000-8000-000000000001',
            encryptedPayload: JSON.stringify({ c: 'U01PS0VURVNUQ0lQSEVSVEVYVEJMT0JMT05H' }),
          }),
        }).catch(() => {})
      }, 'https://' + relay)
      .catch(() => {})
    await new Promise(r => setTimeout(r, 2500))
  }

  await browser.close()

  const byLane = {}
  const bySrc = {}
  for (const v of verdicts) {
    byLane[v.lane] = (byLane[v.lane] || 0) + 1
    bySrc[v.source] = (bySrc[v.source] || 0) + 1
  }
  const confirmed = verdicts.filter(v => v.confirmed).length

  console.log(`\n=== ${verdicts.length} events captured ===`)
  console.log('by lane  :', byLane)
  console.log('by source:', bySrc)
  console.log('confirmed (seen on app + wire):', confirmed)
  console.log('\nnon-app sample:')
  for (const v of verdicts.filter(v => v.lane !== 'app').slice(0, 15)) {
    console.log(`  [${v.source}|${v.lane}] ${v.title}  ${v.host || ''}${v.confirmed ? '  ✓' : ''}`)
  }
  if (verdicts.length === 0) process.exit(1)
})().catch(e => {
  console.error('smoke failed:', e)
  process.exit(1)
})
