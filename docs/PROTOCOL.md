<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# LUME — Relay protocol

Status: **draft**.
Companion to [CRYPTO.md](CRYPTO.md), which defines every key and construction
named here.

The relay accepts sealed envelopes for an account and hands them to that
account when it connects. It verifies signatures on public keys, enforces
limits, and stores as little as delivery needs. It never holds a private key of
a user and never decrypts an envelope.

---

## 1. Transport

- **One WebSocket endpoint**, `wss://<host>/v1`, TLS terminated by the hosting
  edge. Plain `ws://` only when the relay runs in development mode.
- **Binary frames only.** A text frame, a frame that does not decode (§3), or a
  message larger than **80 KiB** closes the connection with `4400`. The limit is
  enforced by the WebSocket reader before a fragmented message is reassembled.
- **No browser access.** A handshake that carries an `Origin` header is refused
  with `4403`. Native clients send none; refusing pages stops any website from
  using its visitors' browsers as free anonymous connections.
- **Blobs** move over HTTPS on the same host (§4.7).
- Outbound data per connection is bounded (§6.3); a client that stops reading is
  closed rather than buffered without end.

### 1.1 Two kinds of connection

| | Authenticated | Anonymous |
|---|---|---|
| Proves | the account's current device key (CRYPTO §3.3) | nothing |
| Used for | receiving envelopes, keys, tokens, invites, account data, reports | sending envelopes, looking up and fetching bundles, checking and registering usernames |
| Lifetime | long-lived, one per account | short-lived |

Sending on anonymous connections is what keeps the relay from recording who
sent an envelope. To keep those connections from becoming a pseudonym of their
own, the client:

- opens anonymous connections **independently** of its authenticated one, and
  closes each after a random lifetime of 1–5 minutes or 50 requests, whichever
  comes first;
- never sends on a connection that carried `Register`: the relay closes that
  connection after answering.

---

## 2. Connection authentication

On every new connection the relay sends first:

```
Challenge { nonce: bytes[32], pow_register_bits: u8, pow_intro_bits: u8 }
```

An authenticated connection answers with

```
Authenticate {
  ik_sig:     bytes[32],
  device_key: bytes[32],
  generation: u32,
  issued_at:  u64,
  cert:       bytes[64],     CRYPTO §3.3
  signature:  bytes[64]      Sign(DK.sk, L("auth") ‖ lp(host) ‖ nonce)
}                                                                         ← Ok
```

`host` is the relay's hostname in lower-case ASCII, without port — the name the
client dialled — so a signature cannot be replayed to another relay. The relay
accepts if `cert` verifies under `ik_sig`, `generation` equals the account's
current generation, and `signature` verifies under `device_key`. The nonce is
single-use per connection: there is no replay window and nothing to store, and
there is no clock check to fail on a phone with the wrong time.

A connection whose first frame is not `Authenticate` is anonymous for its whole
life. A connection with no valid first frame within 10 seconds is closed.

---

## 3. Frame encoding

Every frame is one message in a **canonical binary encoding**, implemented once
in `core/wire` and used by the relay and by every client.

```
frame = u8(version = 1) ‖ u16(type) ‖ u32(request_id) ‖ body
```

`request_id` is chosen by the client and echoed in the response; `0` marks a
frame the relay pushes. `body` is the fields of `type` in the order listed in
§4, with no tags and no padding.

| Field kind | Encoding | Canonical rule |
|---|---|---|
| `u8 u16 u32 u64` | big-endian | — |
| `bool` | `u8` | only `0` or `1` |
| `bytes[N]` | exactly N bytes | — |
| `bytes≤M` | `u32(len) ‖ data` | `len ≤ M` |
| `text≤M` | as `bytes≤M` | valid UTF-8, no NUL |
| `list<T>≤K` | `u16(count) ‖ T…` | `count ≤ K` |
| `opt<T>` | `u8(0)` or `u8(1) ‖ T` | only `0` or `1` |

Decoding **rejects** an unknown version or type, any length or count over its
bound, a non-canonical `bool` or `opt`, invalid text, and bytes after the last
field. It never allocates more than the frame's own length. Every type has a
fuzz target and a round-trip property test.

**Identifiers** — `account_id` (16 bytes), `envelope_id` (16), `blob_id` (32) —
are random, never sequential.

### 3.1 Types

| Range | Types |
|---|---|
| `0x0001–0x000F` | `Challenge 1`, `Authenticate 2`, `Ok 3`, `Error 4`, `Ping 5`, `Pong 6`, `Notice 7` |
| `0x0010–0x001F` | `Register 16`, `Registered 17`, `UpdatePrekeys 18`, `PrekeyStock 19`, `SetDiscoverable 20`, `DeleteAccount 21`, `AccountInfo 22`, `AccountData 23` |
| `0x0020–0x002F` | `CheckUsername 32`, `UsernameStatus 33`, `LookupIdentity 34`, `Identity 35`, `FetchBundle 36`, `Bundle 37` |
| `0x0030–0x003F` | `AddTokens 48`, `RevokeTokens 49`, `CreateInvite 50`, `RevokeInvite 51` |
| `0x0040–0x004F` | `Send 64`, `SendBatch 65`, `Accepted 66`, `BatchAccepted 67`, `Deliver 68`, `Ack 69` |
| `0x0050–0x005F` | `BlobUpload 80`, `BlobTicket 81` |
| `0x0060–0x006F` | `Report 96` |

---

## 4. Messages

`→` client to relay, `←` relay to client. Every request gets exactly one
response: the type listed, or `Error` (§5). `[A]` — authenticated connections
only; `[N]` — anonymous only; `[*]` — either.

### 4.1 Common

```
→ Ping   [*] { }                              ← Pong { }
← Notice     { kind: u16, text: text≤2000 }   pushed to the account: a policy change,
                                              a notice required before a lawful disclosure,
                                              an account action taken by LUME Inc.
```

### 4.2 Account

```
PrekeyX   = { id: u32, created_at: u64, key: bytes[32], signature: opt<bytes[64]> }   absent only for OPK
PrekeyKem = { kind: u8, id: u32, created_at: u64, key: bytes[1184], signature: bytes[64] }

→ Register [N] {
    username:   text≤32,
    ik_sig:     bytes[32],  ik_dh: bytes[32],  bind: bytes[64],
    device_key: bytes[32],  generation: u32,  issued_at: u64,  cert: bytes[64],
    spk:        PrekeyX,    pqspk: PrekeyKem,  ssk: PrekeyX,
    opks:       list<PrekeyX>≤100,
    pqopks:     list<PrekeyKem>≤50,
    pow:        bytes[16],
    proof:      bytes[64]   Sign(IKsig.sk, L("register") ‖ lp(host) ‖ nonce ‖ SHA256(all fields above))
  }                                                ← Registered { account_id: bytes[16], generation: u32 }
```

The relay checks, before writing anything: the proof-of-work stamp (§6.2), the
username (§6.3), `bind`, `cert`, every prekey signature, and `proof`. It then
closes the connection.

- **New account**: an unknown `ik_sig` and `ik_dh` with a free username.
  `generation` must be 1.
- **Rebind**: a known `ik_sig` under the same username with `generation`
  greater than the current one. Keys and device are replaced, the account id is
  kept, and the relay raises the account's generation — which senders see in
  every `Accepted` (§4.5) and use to start a fresh session. A rebind is not
  counted against the registration limit (the relay knows the key, so this is
  evidence, not a claim), and is limited per identity instead (§6.3).
- A taken username under a different key, or a key that belongs to another
  account, is `USERNAME_TAKEN` / `KEY_IN_USE`.

```
→ UpdatePrekeys [A] { spk: opt<PrekeyX>, pqspk: opt<PrekeyKem>, ssk: opt<PrekeyX>,
                      opks: list<PrekeyX>≤100, pqopks: list<PrekeyKem>≤50 }   ← PrekeyStock

← PrekeyStock { opks: u16, pqopks: u16,
                handed_out: list<{ kind: u8, id: u32, at: u64 }>≤150 }
                also pushed when stock falls below 20 OPK or 10 PQOPK

→ SetDiscoverable [A] { discoverable: bool }                                    ← Ok
→ DeleteAccount   [A] { confirm: bytes[64] }    Sign(IKsig.sk, L("delete") ‖ lp(host) ‖ nonce)
                                                ← Ok, then close 4000
→ AccountInfo     [A] { }                       ← AccountData
← AccountData { username, account_id, discoverable, created_day: u32, last_seen_day: u32,
                generation: u32, tokens: u16, invites: u8, pending: u32, pending_bytes: u64,
                blobs: u32, blob_bytes: u64 }
```

`handed_out` lets the client delete one-time private keys that were given out
and never used (CRYPTO §4). `DeleteAccount` and the inactive-account sweep
remove the account's row and, in the same transaction, its prekeys, seal keys,
tokens, invites, pending envelopes and blobs, and then the blob files.
`AccountInfo` is everything the relay holds about the account, as the privacy
policy promises.

### 4.3 Directory

```
→ CheckUsername  [N] { username: text≤32 }                          ← UsernameStatus { available: bool }
→ LookupIdentity [N] { username: text≤32, invite: opt<bytes[32]> }  ← Identity
← Identity { account_id: bytes[16], ik_sig: bytes[32], ik_dh: bytes[32], bind: bytes[64] }
→ FetchBundle    [N] { username: text≤32, invite: opt<bytes[32]> }  ← Bundle
← Bundle { account_id: bytes[16], ik_sig: bytes[32], ik_dh: bytes[32], bind: bytes[64],
           spk: PrekeyX, pq: PrekeyKem, ssk: PrekeyX, opk: opt<PrekeyX> }
```

- `LookupIdentity` consumes nothing. It is how a recipient checks a name an
  introduction claims (CRYPTO §5.3).
- `FetchBundle` hands out one OPK and one PQOPK when available; `pq.kind` says
  whether `pq` is a one-time key (3) or the last-resort key (2).
- **A bundle is never refused because of who asks for it.** Once 20 one-time
  keys of an account have been handed out in an hour, further bundles that hour
  come without one-time keys. Draining an account therefore costs its keys'
  forward secrecy for that hour, not its reachability.
- A **non-discoverable** account is `NOT_FOUND` to both requests unless `invite`
  is one of its live invite secrets.

### 4.4 Delivery tokens and invites

```
→ AddTokens    [A] { hashes: list<bytes[32]>≤100 }    ← Ok    at most 1000 live per account
→ RevokeTokens [A] { hashes: list<bytes[32]>≤100 }    ← Ok
→ CreateInvite [A] { secret_hash: bytes[32] }         ← Ok    24 h, at most 5 live
→ RevokeInvite [A] { secret_hash: bytes[32] }         ← Ok
```

The relay only ever sees hashes: `SHA256(L("token") ‖ T)` (CRYPTO §9.1) and
`SHA256(L("invite") ‖ S)`.

### 4.5 Envelopes

```
Lane = tag u8, then
       1 Token { token: bytes[32] }
       2 Intro { invite: opt<bytes[32]>, pow: bytes[16] }

SendItem = { recipient: bytes[16], lane: Lane, ephemeral: bool, envelope: bytes≤69713 }

→ Send      [N] SendItem                           ← Accepted { recipient_generation: u32 }
→ SendBatch [N] { items: list<SendItem>≤64 }       ← BatchAccepted { results: list<Result>≤64 }
                Result = tag u8: 1 Accepted { recipient_generation: u32 } | 2 Error { code: u16 }

← Deliver [A] { envelope_id: bytes[16], received_at: u64, lane: LaneSeen, envelope: bytes≤69713 }
              LaneSeen = tag u8: 1 Token { hash: bytes[32] } | 2 Intro { invite_hash: opt<bytes[32]> }
→ Ack     [A] { ids: list<bytes[16]>≤256 }         ← Ok
```

- **Token lane.** Always answers `Accepted`, for a live token, a revoked one or
  one never issued — so a sender cannot tell a block from a delivery, and the
  token lane cannot be used to probe which tokens exist. Only an envelope on a
  live token is stored.
- **Introduction lane.** Accepted only if the recipient is discoverable or
  `invite` is one of their live invite secrets, and the proof-of-work stamp is
  valid (§6.2); otherwise `NOT_ACCEPTED`. Envelopes on the intro lane have their
  own quota per recipient, and invite holders a separate one per invite (§6.3),
  so strangers cannot use up the room an invited contact needs.
- **`Accepted`** carries the recipient's current generation. A sender who sees
  it rise knows the recipient rebound (recovery or a new device) and starts a
  new session from a fresh bundle; envelopes sealed to the old device can no
  longer be opened.
- The response to a `Send` is identical whether the envelope was stored, pushed
  at once, dropped as ephemeral, or dropped for a revoked token.
- **Delivery.** The relay pushes pending envelopes to the recipient's
  authenticated connection, oldest first, holding at most 64 unacknowledged
  envelopes or 4 MiB, whichever is less. `Deliver` says which lane an envelope
  arrived on, so the client can apply CRYPTO §9.2.
- **Acknowledgement.** `Ack` deletes only envelopes addressed to the
  authenticated account; other ids are ignored. The client acknowledges after
  the result is durably committed to its vault — and also when an envelope fails
  permanently (undecryptable, dropped by policy), so a bad envelope cannot stall
  delivery.
- **Ephemeral** envelopes (typing, read receipts, presence) are pushed if the
  recipient is connected and otherwise dropped, never stored.

### 4.6 Reports

```
→ Report [A] { sealed: bytes≤69713 }    ← Ok
```

`sealed` is the reported conversation excerpt and the reported username, sealed
by the reporting client to LUME Inc.'s published report key with the
construction of CRYPTO §8. The relay stores it without being able to read it
and LUME Inc. opens it offline. Twenty reports per account per day.

### 4.7 Blobs

```
→ BlobUpload [N] { recipient: bytes[16], lane: Lane, size: u32 }    ← BlobTicket
← BlobTicket     { blob_id: bytes[32], upload_key: bytes[32], expires_at: u64 }
```

The lane is checked as for `Send`. The ticket authorises one
`PUT /v1/blob/<hex blob_id>` with header `Lume-Upload-Key: <hex upload_key>` and
exactly `size` bytes, within 10 minutes. `GET /v1/blob/<hex blob_id>` returns
the blob: the id is 256 random bits that travel only inside an encrypted
message, and the content is encrypted (CRYPTO §11). Downloads are limited per
blob and per address (§6.3). Blob bytes count against the **recipient's**
quota.

---

## 5. Errors and close codes

`Error { code: u16, retry_after_ms: u32 }`; `retry_after_ms` is non-zero only
for `RATE_LIMITED` and `UNAVAILABLE`. Codes carry no internal detail.

| Code | Name | Meaning |
|---|---|---|
| 1 | `MALFORMED` | decoded, but a field is semantically invalid |
| 2 | `WRONG_CONNECTION` | not allowed on this kind of connection |
| 3 | `AUTH_FAILED` | certificate, generation or signature invalid |
| 4 | `BAD_SIGNATURE` | a key, prekey or proof signature does not verify |
| 5 | `NOT_FOUND` | no such account, or not visible to this request |
| 6 | `USERNAME_TAKEN` | |
| 7 | `USERNAME_INVALID` | malformed, reserved or barred |
| 8 | `NOT_ACCEPTED` | introduction lane closed, invite unknown or expired |
| 9 | `LIMIT_REACHED` | a count or byte bound (§6.3) would be exceeded |
| 10 | `RATE_LIMITED` | retry after `retry_after_ms` |
| 11 | `TOO_LARGE` | |
| 12 | `UNAVAILABLE` | the relay is shedding load or near its disk quota |
| 13 | `INTERNAL` | |
| 14 | `KEY_IN_USE` | the identity or exchange key belongs to another account |
| 15 | `BAD_POW` | proof-of-work stamp missing, reused or too weak |

| Close | Meaning |
|---|---|
| `4000` | normal close: after `Register`, after `DeleteAccount` |
| `4001` | no valid first frame within 10 s |
| `4002` | authentication failed |
| `4005` | replaced by a newer authenticated connection for the account |
| `4006` | connection limit for this address |
| `4008` | frame budget exceeded several times over |
| `4009` | idle timeout |
| `4400` | undecodable or oversized frame |
| `4403` | `Origin` header present |

The relay sends the close frame and waits up to one second for it to flush
before dropping the socket, so a refused client sees the code, not a bare
`1006`.

---

## 6. Limits

### 6.1 Address keys

Every address-keyed limit is applied at **three levels**: the single address
(IPv4 /32, IPv6 /64 — a host is routinely given a whole /64), and the IPv6
aggregates **/56** and **/48**, each with its own, larger budget. One helper
builds every address key; no limiter formats an address itself.

The client address is the entry `TRUSTED_PROXY_HOPS` from the right of
`X-Forwarded-For`. The setting is required (§8); when it is non-zero, a request
without enough entries is refused.

Authenticated connections are keyed by **account**, not address, so thousands
of users behind one carrier NAT are not limited as if they were one.

### 6.2 Proof of work

Registration and introduction-lane sends carry a stamp `s`:

```
SHA256(L("pow") ‖ nonce ‖ u8(purpose) ‖ u32(counter) ‖ s) has at least d leading zero bits
purpose: 1 register, 2 intro       counter: increases per stamp on the connection
```

`nonce` is the connection's challenge, so stamps cannot be precomputed or
shared; the relay remembers the counters used on the connection. The challenge
announces `d`. The base is 20 bits — under a second on a current phone — and
the relay adds one bit each time the global registration or introduction rate
doubles over its normal level. Under a flood the relay makes abuse more
expensive instead of refusing everyone.

### 6.3 Bounds

| What | Bound |
|---|---|
| Username | `^[a-z0-9_]{3,32}$`, upper case folded first; reserved and barred names refused |
| Registrations | 30 / hour per address, 200 / hour per /48; proof of work |
| Rebinds | 3 / day per identity |
| `Register` attempts | 10 / minute per address, counted before any signature is verified |
| Authenticated connections | 1 per account; 20 % of process capacity reserved for them |
| Anonymous connections | 256 concurrent per address, 1024 per /56, 4096 per /48; 60 new / minute per address |
| Process | 10 000 concurrent connections |
| Idle timeout | anonymous 60 s, authenticated 15 min (the client pings every 4 min) |
| Frames | 120 per 10 s per connection; beyond that requests get `RATE_LIMITED`; three times over closes `4008` |
| `CheckUsername`, `LookupIdentity` | 60 / minute per address, 600 / hour per /48 |
| `FetchBundle` | 20 / minute per address; one-time keys: 20 handed out per hour per target, then bundles without them |
| Token lane | 120 / minute per token; ≤ 1000 pending per token |
| Introduction lane | 10 / minute per address + proof of work; ≤ 50 pending per recipient without invite (oldest evicted when full), ≤ 20 per invite |
| Pending per recipient | ≤ 10 000 envelopes and ≤ 256 MiB |
| Envelope | ≤ 69 713 bytes (CRYPTO §7–§8: largest padded plaintext 69 632 + 81 bytes of seal encoding) |
| Retention | 30 days undelivered; deleted on acknowledgement |
| Outbound per connection | ≤ 64 unacknowledged deliveries and ≤ 4 MiB queued |
| Prekeys | ≤ 100 OPK, ≤ 50 PQOPK per account |
| Tokens / invites | ≤ 1000 live per account / ≤ 5 live, 24 h |
| Blob | ≤ 25 MiB each; ≤ 1 GiB live per recipient; uploads 200 MiB / hour per address; downloads 50 per blob and 2 GiB / day per address; 30 days |
| Disk | above 85 % of `LUME_DISK_QUOTA`, `Send` and `BlobUpload` answer `UNAVAILABLE` |
| Reports | 20 / day per account, kept 90 days |
| Inactive account | deleted after 365 days without an authenticated connection; never below 30 (boot refuses) |

Limiter state lives in memory. Nothing about who called what is written to
disk.

---

## 7. What the relay stores

| Table | Columns | Bound |
|---|---|---|
| `accounts` | id, username, ik_sig (unique), ik_dh (unique), bind, device_key, generation, discoverable, created_day, last_seen_day | inactive sweep |
| `signed_prekeys` | account, kind (SPK, PQSPK, SSK), id, created_at, key, signature | two generations per kind |
| `one_time_prekeys` | account, kind (OPK, PQOPK), id, created_at, key, signature, handed_out_at | per-account caps; deleted when handed out and reported |
| `delivery_tokens` | account, token_hash, created_day | 1000 per account |
| `invites` | account, secret_hash, expires_at | 5 per account, TTL |
| `pending` | id, recipient, lane (token hash or intro + invite hash), envelope, received_at | 30 days; per-token, per-intro, per-recipient caps |
| `blobs` | id, recipient, size, upload_key_hash, downloads, expires_at | TTL, per-recipient byte cap; file deleted with the row |
| `reports` | id, sealed, received_at | 90 days, per-account daily cap |
| `barred_usernames` | username_hash, created_day | 100 000 rows, oldest removed |

Seen-times are kept to the **day**: enough for the inactive sweep, too coarse
to be a log.

**Not stored, by design:** the sender of any envelope; group names, members or
roles; display names and avatars; typing and read state; request signatures or
nonces; IP addresses.

SQLite runs with `auto_vacuum=INCREMENTAL` (set before WAL),
`journal_mode=WAL`, `foreign_keys=ON` and **`secure_delete=ON`**, so deleted
envelopes and revoked token hashes are overwritten rather than left in free
pages; every bulk delete is followed by `incremental_vacuum` and a
`wal_checkpoint(TRUNCATE)`. Prepared statements only.

---

## 8. Configuration

Read once at boot. A missing required value, an unparseable value or a value
out of range stops the process with a message naming the setting.

| Setting | Default | Rule |
|---|---|---|
| `LUME_HOST` | required | hostname clients sign (§2) |
| `TRUSTED_PROXY_HOPS` | required | integer 0–4; must match the deployment — too high lets callers choose their own address, too low puts everyone in one |
| `LUME_DISK_QUOTA` | required | bytes the relay may use for its database and blobs |
| `LUME_LISTEN` | `0.0.0.0:3001` | |
| `LUME_DB_PATH` | `./data/relay.db` | |
| `LUME_BLOB_DIR` | `./data/blobs` | |
| `INACTIVE_ACCOUNT_DAYS` | `365` | ≥ 30 |
| `LUME_DEV` | unset | allows `ws://`; refuses to start unless `LUME_HOST` is `localhost` |

Logs carry event names, counts, durations and error codes — never usernames,
account ids, tokens, addresses or envelope bytes.

---

## 9. Versioning

The first byte of every frame is the protocol version. The relay serves one
version at a time; a frame of another version is closed with `4400`. Any change
to a layout here is a new version.
