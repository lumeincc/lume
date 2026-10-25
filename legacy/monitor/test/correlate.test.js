'use strict'

/** Dependency-free test for the two-lane cross-check. Run: `node test/correlate.test.js`. */

const { makeCorrelator } = require('../src/correlate')

let passed = 0
let failed = 0
function ok(name, cond) {
  cond ? passed++ : failed++
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}`)
}

const send = (body, ts) => ({ kind: 'http', method: 'POST', path: '/messages/send', body, timestamp: ts })

// same body on both lanes → the second one is confirmed, and names the other lane
{
  const c = makeCorrelator()
  const r1 = c.observe(send('CIPHERTEXTBLOB', 1000), 'app')
  const r2 = c.observe(send('CIPHERTEXTBLOB', 1050), 'wire')
  ok('first (app) not yet confirmed', r1.confirmed === false)
  ok('second (wire) confirmed, matched=app', r2.confirmed === true && r2.matchedSource === 'app')
}

// same lane twice → not a cross-lane match
{
  const c = makeCorrelator()
  c.observe(send('X', 1000), 'wire')
  ok('same lane twice not confirmed', c.observe(send('X', 1010), 'wire').confirmed === false)
}

// different bodies → not confirmed
{
  const c = makeCorrelator()
  c.observe(send('A', 1000), 'app')
  ok('different bodies not confirmed', c.observe(send('B', 1010), 'wire').confirmed === false)
}

// outside the time window → not confirmed
{
  const c = makeCorrelator({ windowMs: 1000 })
  c.observe(send('A', 1000), 'app')
  ok('outside window not confirmed', c.observe(send('A', 3000), 'wire').confirmed === false)
}

// http vs ws with the same body → not confirmed (kind is part of the key)
{
  const c = makeCorrelator()
  c.observe({ kind: 'http', method: 'POST', path: '/x', body: 'SAME', timestamp: 1000 }, 'app')
  ok('kind mismatch not confirmed', c.observe({ kind: 'ws', direction: 'out', path: null, body: 'SAME', timestamp: 1010 }, 'wire').confirmed === false)
}

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed === 0 ? 0 : 1)
