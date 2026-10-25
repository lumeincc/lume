'use strict'

/**
 * Pure classifier: given ONE normalized network event, decide what the LUME
 * relay can actually see, in plain language and a traffic-light colour.
 *
 * The verdicts here are derived from the LUME server source (schemas + DB), not
 * guessed. Getting a colour wrong in EITHER direction (claiming something is
 * hidden when it is not, or vice versa) destroys the whole point of the tool, so
 * every rule maps to a real endpoint and a real field.
 *
 * Lanes:
 *   sealed   — content the relay only ever sees as ciphertext
 *   metadata — visible to the relay because delivery/registration needs it
 *   exposed  — readable by the relay in the clear (name, avatar, unexpected host)
 *   app      — loading the client itself or keepalive; not your data
 *
 * No dependencies on purpose: this module is unit-testable with plain `node`.
 */

const LANE = { APP: 'app', SEALED: 'sealed', METADATA: 'metadata', EXPOSED: 'exposed' }

const UUID = /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g

function safeJson(s) {
  try {
    return JSON.parse(s)
  } catch {
    return null
  }
}

/** Normalize a URL path so a route matches regardless of the ids it carries. */
function normalizePath(path) {
  let p = (path || '').split('?')[0].replace(/\/+$/, '') || '/'
  if (p.startsWith('/api/')) p = p.slice(4)
  else if (p === '/api') p = '/'
  p = p.replace(UUID, ':id')
  p = p.replace(/\/(check|user)\/[^/]+/g, '/$1/:name')
  p = p.replace(/\/(resolve-invite)\/[^/]+/g, '/$1/:token')
  return p
}

function sev(lane, label) {
  return { sev: lane, label }
}

/** Deepest/longest string in a value — the ciphertext is the longest field. */
function longestString(v, best) {
  best = best || ''
  if (typeof v === 'string') return v.length > best.length ? v : best
  if (v && typeof v === 'object') for (const k of Object.keys(v)) best = longestString(v[k], best)
  return best
}

/**
 * A short preview of the opaque blob the relay actually receives, so the UI can
 * show "this is all the server gets: 8f3a…" rather than just asserting it.
 */
function ciphertextPreview(body) {
  if (!body) return null
  const outer = safeJson(body)
  let candidate = body
  if (outer && typeof outer === 'object') {
    const ep = outer.encryptedPayload != null ? outer.encryptedPayload : outer.data != null ? outer.data : outer
    const inner = typeof ep === 'string' ? safeJson(ep) || ep : ep
    candidate = longestString(inner) || (typeof ep === 'string' ? ep : '')
  }
  if (typeof candidate !== 'string') return null
  const s = candidate.replace(/\s+/g, '')
  if (s.length < 12) return null
  return s.slice(0, 24) + (s.length > 24 ? '…' : '')
}

function base(ev, lane, title, plain, serverSees, extra) {
  return Object.assign(
    {
      lane,
      title,
      plain,
      serverSees: serverSees || [],
      host: ev.host || null,
      scheme: ev.scheme || null,
      method: ev.method || null,
      kind: ev.kind,
      direction: ev.direction || (ev.kind === 'http' ? 'out' : null),
      size: ev.size || 0,
      timestamp: ev.timestamp || Date.now(),
    },
    extra || {}
  )
}

// ── Relay endpoint rules (keyed by "METHOD normalizedPath") ─────────────────
const RULES = {
  'POST /messages/send': ev =>
    base(
      ev,
      LANE.SEALED,
      'Message sent',
      'Your message text leaves as a sealed blob — the relay cannot read it.',
      [
        sev(LANE.SEALED, 'message content (encrypted)'),
        sev(LANE.METADATA, 'recipient'),
        sev(LANE.METADATA, 'time'),
        sev(LANE.METADATA, `size ~${ev.size} B`),
      ],
      { evidence: ciphertextPreview(ev.body) }
    ),

  'GET /messages/pending/:id': ev =>
    base(
      ev,
      LANE.METADATA,
      'Checking for messages',
      'Asks the relay for queued messages. Reveals that you are online now.',
      [sev(LANE.METADATA, 'that you are fetching mail'), sev(LANE.METADATA, 'time')]
    ),

  'POST /messages/acknowledge': ev =>
    base(ev, LANE.METADATA, 'Acknowledging messages', 'Confirms receipt so the relay can delete them.', [
      sev(LANE.METADATA, 'which message ids'),
    ]),

  'POST /files/upload': ev => {
    const body = safeJson(ev.body) || {}
    if (body.isPublic) {
      return base(
        ev,
        LANE.EXPOSED,
        'Public file uploaded',
        'Uploaded as a PUBLIC, unencrypted file (this is how avatars work) — the relay and anyone with the id can read it.',
        [
          sev(LANE.EXPOSED, 'file contents (not encrypted)'),
          sev(LANE.METADATA, `type ${body.mimeHint || '?'}`),
          sev(LANE.METADATA, `size ~${ev.size} B`),
        ]
      )
    }
    return base(
      ev,
      LANE.SEALED,
      'File uploaded',
      'The file blob is encrypted before upload — the relay stores ciphertext.',
      [sev(LANE.SEALED, 'file contents (encrypted)'), sev(LANE.METADATA, 'size'), sev(LANE.METADATA, body.recipientId ? 'recipient' : '—')],
      { evidence: ciphertextPreview(ev.body) }
    )
  },

  'GET /files/:id': ev =>
    base(ev, LANE.METADATA, 'Downloading a file', 'Fetches a stored blob; contents are sealed unless it was a public file.', [
      sev(LANE.METADATA, 'which file id'),
    ]),

  'POST /groups/create': ev => {
    const body = safeJson(ev.body) || {}
    const count = Array.isArray(body.memberIds) ? body.memberIds.length : '?'
    return base(
      ev,
      LANE.EXPOSED,
      'Group created',
      'The group NAME is sent in plain text and the full member list is visible to the relay.',
      [sev(LANE.EXPOSED, `group name: "${typeof body.name === 'string' ? body.name : '?'}"`), sev(LANE.EXPOSED, `member list (${count})`)]
    )
  },

  'GET /groups': ev =>
    base(ev, LANE.METADATA, 'Fetching your groups', 'Returns your groups and members — the relay holds the group social graph.', [
      sev(LANE.METADATA, 'group membership'),
    ]),

  'PUT /profile/:id': ev => {
    const body = safeJson(ev.body) || {}
    const sees = []
    if ('displayName' in body) sees.push(sev(LANE.EXPOSED, `display name: "${body.displayName == null ? '—' : body.displayName}"`))
    if ('avatarFileId' in body) sees.push(sev(LANE.METADATA, 'avatar reference (image itself is a public file)'))
    return base(
      ev,
      LANE.EXPOSED,
      'Profile updated',
      'Display name is stored in plain text; the avatar image itself is a public file.',
      sees.length ? sees : [sev(LANE.EXPOSED, 'profile fields')]
    )
  },

  'GET /profile/:id': ev =>
    base(ev, LANE.METADATA, 'Fetching a profile', 'Looks up a profile (name and avatar are both public).', [sev(LANE.METADATA, 'which user')]),

  'POST /auth/register': ev =>
    base(
      ev,
      LANE.METADATA,
      'Registering identity',
      'Publishes your username and PUBLIC keys. No secret key ever leaves the device.',
      [sev(LANE.METADATA, 'username + public keys')]
    ),

  'GET /auth/check/:name': ev =>
    base(ev, LANE.METADATA, 'Checking a username', 'Asks whether a username exists / is free.', [sev(LANE.METADATA, 'a username probe')]),

  'POST /auth/bundle': ev =>
    base(
      ev,
      LANE.METADATA,
      'Fetching a prekey bundle',
      'Requests someone’s keys to start a chat — this signals your intent to talk to them.',
      [sev(LANE.METADATA, 'who you want to start a chat with')]
    ),

  'POST /auth/prekeys': ev =>
    base(ev, LANE.METADATA, 'Uploading prekeys', 'Refills your one-time prekeys. Public keys only.', [sev(LANE.METADATA, 'public prekeys')]),

  'POST /auth/keys': ev =>
    base(ev, LANE.METADATA, 'Key operation', 'A key-management request (public keys only).', [sev(LANE.METADATA, 'public key material')]),

  'GET /auth/user/:name': ev =>
    base(ev, LANE.METADATA, 'Looking up a user', 'Resolves a user by name/id.', [sev(LANE.METADATA, 'which user')]),

  'GET /auth/session': ev => base(ev, LANE.METADATA, 'Session check', 'Confirms the account still exists on the relay.', []),

  'POST /auth/block': ev =>
    base(ev, LANE.METADATA, 'Blocking a user', 'The relay learns who you blocked (to enforce it).', [sev(LANE.METADATA, 'who you blocked')]),

  'POST /auth/unblock': ev => base(ev, LANE.METADATA, 'Unblocking a user', 'The relay updates your block list.', [sev(LANE.METADATA, 'who you unblocked')]),

  'GET /auth/blocked': ev => base(ev, LANE.METADATA, 'Fetching block list', 'Returns your block list.', [sev(LANE.METADATA, 'your block list')]),

  'POST /auth/discoverable': ev =>
    base(ev, LANE.METADATA, 'Toggling discoverability', 'Sets whether others can find you by username.', [sev(LANE.METADATA, 'a privacy flag')]),

  'POST /auth/invite-token': ev =>
    base(ev, LANE.METADATA, 'Creating an invite', 'Mints an invite link tied to your account.', [sev(LANE.METADATA, 'an invite token')]),

  'GET /auth/resolve-invite/:token': ev =>
    base(ev, LANE.METADATA, 'Resolving an invite', 'Looks up who an invite link belongs to.', [sev(LANE.METADATA, 'an invite token')]),

  'GET /health': ev => base(ev, LANE.APP, 'Health check', 'Pinging the relay to see if it is up.', []),
}

const APP_RESOURCE_TYPES = new Set(['Document', 'Stylesheet', 'Script', 'Image', 'Font', 'Media', 'Manifest', 'Other'])

function classifyHttp(ev, cfg) {
  const isRelay = (cfg.relayHosts || []).includes(ev.host)

  if (!isRelay) {
    // Loading the client app itself (or CDN assets) — this is LUME's code, not your data.
    if (!ev.body && APP_RESOURCE_TYPES.has(ev.resourceType || 'Other')) {
      return base(ev, LANE.APP, 'Loading the app', `App resource from ${ev.host} — LUME's own code, not your data.`, [])
    }
    // A request carrying data to a host that is NOT the relay is exactly what an
    // independent monitor exists to catch.
    return base(
      ev,
      LANE.EXPOSED,
      'Data to an unexpected host',
      `A ${ev.method} request went to ${ev.host}, which is not the LUME relay. Worth a look.`,
      [sev(LANE.EXPOSED, `destination ${ev.host}`)]
    )
  }

  const rule = RULES[`${ev.method} ${normalizePath(ev.path)}`]
  if (rule) return rule(ev)
  return base(ev, LANE.METADATA, `${ev.method} ${normalizePath(ev.path)}`, 'A request to the LUME relay.', [sev(LANE.METADATA, 'a request to the relay')])
}

function classifyWs(ev) {
  if (ev.opcode === 9 || ev.opcode === 10) {
    return base(ev, LANE.APP, 'Keepalive', 'WebSocket ping/pong keeping the connection alive.', [])
  }
  const msg = safeJson(ev.body)
  const type = msg && typeof msg.type === 'string' ? msg.type : null
  const dir = ev.direction === 'out' ? 'sent' : 'received'
  switch (type) {
    case 'ping':
    case 'pong':
      return base(ev, LANE.APP, 'Keepalive', 'Connection keepalive.', [])
    case 'typing':
      return base(ev, LANE.METADATA, 'Typing indicator', `Typing status ${dir}. The relay learns who is typing to whom.`, [
        sev(LANE.METADATA, 'typing → recipient'),
      ])
    case 'read':
      return base(ev, LANE.METADATA, 'Read receipt', `Read receipt ${dir}.`, [sev(LANE.METADATA, 'which messages were read')])
    case 'new_message':
      return base(
        ev,
        LANE.SEALED,
        'Message received',
        'A message arrived as a sealed blob — the relay only relayed ciphertext.',
        [sev(LANE.SEALED, 'message content (encrypted)'), sev(LANE.METADATA, 'sender'), sev(LANE.METADATA, 'time')],
        { evidence: ciphertextPreview(ev.body) }
      )
    default:
      return base(ev, LANE.METADATA, `Realtime ${dir}`, 'A realtime WebSocket frame.', [sev(LANE.METADATA, 'a realtime event')])
  }
}

/**
 * Optional "reported by the app" telemetry — the plaintext → ciphertext
 * narrative, only present when a DEV build of LUME calls window.__lumeMonitorReport.
 * Always the app lane: it is the app describing itself, not an independent view.
 */
function classifyTelemetry(ev) {
  const step = ev.ratchetStep != null ? ` (ratchet #${ev.ratchetStep})` : ''
  const extra = { evidence: ev.ciphertextPreview || null, plaintext: ev.plaintextPreview || null }
  if (ev.event === 'encrypt' || ev.event === 'send') {
    return base(
      ev,
      LANE.SEALED,
      'Encrypting a message' + step,
      'The app reports it sealed your text with a unique message key before sending.',
      [sev(LANE.SEALED, 'content sealed on device'), ev.recipient ? sev(LANE.METADATA, 'recipient') : null].filter(Boolean),
      extra
    )
  }
  if (ev.event === 'decrypt' || ev.event === 'receive') {
    return base(ev, LANE.SEALED, 'Decrypting a message' + step, 'The app reports it opened a sealed blob on your device.', [sev(LANE.SEALED, 'opened on device')], extra)
  }
  return base(ev, LANE.METADATA, ev.event || 'App event', 'The app reported an internal event.', [])
}

function classify(ev, cfg) {
  cfg = cfg || { relayHosts: [] }
  if (ev.kind === 'telemetry') return classifyTelemetry(ev)
  if (ev.kind === 'ws') return classifyWs(ev)
  return classifyHttp(ev, cfg)
}

module.exports = { classify, normalizePath, ciphertextPreview, LANE }
