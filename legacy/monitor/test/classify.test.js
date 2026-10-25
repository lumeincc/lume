'use strict'

/**
 * Dependency-free test for the classifier. Run: `node test/classify.test.js`.
 * Prints every verdict so the output is evidence, not just a pass/fail count.
 */

const { classify, normalizePath } = require('../src/classify')
const { normalizeHttp, normalizeWs } = require('../src/capture')

const CFG = { relayHosts: ['lume-api-3dnb.onrender.com'] }

let passed = 0
let failed = 0

function check(name, verdict, expectLane, mustSee) {
  const okLane = verdict.lane === expectLane
  const okSee = mustSee == null || (verdict.serverSees || []).some(s => s.label.includes(mustSee))
  const ok = okLane && okSee
  ok ? passed++ : failed++
  const ev = verdict.evidence ? `  evidence=${verdict.evidence}` : ''
  console.log(`${ok ? 'PASS' : 'FAIL'}  [${verdict.lane}] ${name} → "${verdict.title}"${ev}`)
  if (!ok) console.log(`      expected lane=${expectLane}${mustSee ? `, serverSees~"${mustSee}"` : ''}`)
}

// ── normalizePath ───────────────────────────────────────────────────────────
const npCases = [
  ['/api/messages/send', '/messages/send'],
  ['/api/messages/pending/2b1c9d7e-1111-4aaa-8bbb-ccccdddd0000', '/messages/pending/:id'],
  ['/api/auth/check/alice', '/auth/check/:name'],
  ['/api/auth/resolve-invite/SOME_OPAQUE_TOKEN', '/auth/resolve-invite/:token'],
  ['/api/profile/2b1c9d7e-1111-4aaa-8bbb-ccccdddd0000/', '/profile/:id'],
]
for (const [input, want] of npCases) {
  const got = normalizePath(input)
  const ok = got === want
  ok ? passed++ : failed++
  console.log(`${ok ? 'PASS' : 'FAIL'}  normalizePath("${input}") → "${got}"`)
  if (!ok) console.log(`      expected "${want}"`)
}

// ── HTTP classification (via the real normalizer) ────────────────────────────
function http(method, url, postData, type) {
  return classify(normalizeHttp({ request: { method, url, postData }, type }), CFG)
}

check(
  'send message',
  http('POST', 'https://lume-api-3dnb.onrender.com/api/messages/send', JSON.stringify({
    senderId: '11111111-1111-4111-8111-111111111111',
    recipientId: '22222222-2222-4222-8222-222222222222',
    encryptedPayload: JSON.stringify({ h: 'AAAABBBBCCCC', c: 'Zm9vYmFyYmF6cXV4Y2lwaGVydGV4dEJMT0I=' }),
  })),
  'sealed',
  'encrypted'
)

check(
  'public avatar upload',
  http('POST', 'https://lume-api-3dnb.onrender.com/api/files/upload', JSON.stringify({ data: 'rawbase64image', mimeHint: 'image/png', isPublic: true })),
  'exposed',
  'not encrypted'
)

check(
  'encrypted file upload',
  http('POST', 'https://lume-api-3dnb.onrender.com/api/files/upload', JSON.stringify({ data: 'Y2lwaGVydGV4dGJsb2Jhc2U2NGxvbmc=', mimeHint: 'application/octet-stream', recipientId: '22222222-2222-4222-8222-222222222222' })),
  'sealed',
  'encrypted'
)

check(
  'group create (plaintext name)',
  http('POST', 'https://lume-api-3dnb.onrender.com/api/groups/create', JSON.stringify({ name: 'Family', memberIds: ['22222222-2222-4222-8222-222222222222'] })),
  'exposed',
  'group name'
)

check(
  'profile update (display name)',
  http('PUT', 'https://lume-api-3dnb.onrender.com/api/profile/11111111-1111-4111-8111-111111111111', JSON.stringify({ displayName: 'Alice' })),
  'exposed',
  'display name'
)

check('prekey bundle fetch', http('POST', 'https://lume-api-3dnb.onrender.com/api/auth/bundle', JSON.stringify({ username: 'bob' })), 'metadata', 'start a chat')

check('checking for messages', http('GET', 'https://lume-api-3dnb.onrender.com/api/messages/pending/11111111-1111-4111-8111-111111111111'), 'metadata', 'fetching mail')

check('app asset from vercel', http('GET', 'https://lume-dev-version.vercel.app/_next/static/chunk.js', null, 'Script'), 'app')

check('data to unexpected host', http('POST', 'https://evil.example.com/collect', JSON.stringify({ oops: 'data' }), 'Fetch'), 'exposed', 'destination')

// ── WebSocket classification ─────────────────────────────────────────────────
function ws(dir, obj, opcode) {
  return classify(normalizeWs({ response: { opcode: opcode == null ? 1 : opcode, payloadData: typeof obj === 'string' ? obj : JSON.stringify(obj) } }, dir, 'lume-api-3dnb.onrender.com'))
}

check('typing indicator (out)', ws('out', { type: 'typing', recipientId: 'x', isTyping: true }), 'metadata', 'typing')
check('read receipt (out)', ws('out', { type: 'read', recipientId: 'x', messageIds: ['a'] }), 'metadata', 'read')
check(
  'incoming message (sealed)',
  ws('in', { type: 'new_message', message: { encryptedPayload: JSON.stringify({ c: 'aW5ib3VuZGNpcGhlcnRleHRibG9ibG9uZ2Vub3VnaA==' }) } }),
  'sealed',
  'encrypted'
)
check('ping keepalive', ws('out', { type: 'ping' }), 'app')

// ── Telemetry (optional in-app dev hook: plaintext → ciphertext narrative) ────
check('telemetry encrypt', classify({ kind: 'telemetry', event: 'encrypt', recipient: 'bob', plaintextPreview: 'Привет', ciphertextPreview: 'Zm9v…', ratchetStep: 3 }), 'sealed', 'sealed on device')
{
  const v = classify({ kind: 'telemetry', event: 'encrypt', plaintextPreview: 'hi', ciphertextPreview: 'Zm9v' })
  const good = v.lane === 'sealed' && v.plaintext === 'hi' && v.evidence === 'Zm9v'
  good ? passed++ : failed++
  console.log(`${good ? 'PASS' : 'FAIL'}  telemetry carries plaintext + ciphertext evidence`)
}

// ── Summary ──────────────────────────────────────────────────────────────────
console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed === 0 ? 0 : 1)
