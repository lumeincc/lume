<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# LUME — Relay protocol

Status: **draft**, revision 3.
Companion to [CRYPTO.md](CRYPTO.md), which defines every key and construction
named here.

The relay accepts sealed envelopes for an account and hands them to that
account when it connects. It verifies signatures on public keys, signs username
certificates, enforces limits, and stores as little as delivery needs. It never
holds a private key of a user and never decrypts an envelope.

---

## 1. Transport

- **One WebSocket endpoint**, `wss://<host>/v1`, TLS terminated by the hosting
  edge. Plain `ws://` only when the relay runs in development mode.
- **Binary frames only.** A text frame, a frame that does not decode (§3), or a
  message larger than **80 KiB** closes the connection with `4400`. The limit is
  enforced by the WebSocket reader before a fragmented message is reassembled,
  and a frame that is not complete within 10 seconds of its first byte closes
  the connection.
- **No browser access.** An upgrade request that carries an `Origin` header is
  refused with HTTP 403 before the WebSocket opens. Native clients send none;
  refusing pages stops any website from using its visitors as anonymous
  connections.
- **Blobs** move over HTTPS on the same host (§4.7).
- Deliveries are streamed from disk; a connection never has more than 256 KiB
  queued for it (§6.3).

### 1.1 Two kinds of connection

| | Authenticated | Anonymous |
|---|---|---|
| Proves | the account's current device key (CRYPTO §3.3) | nothing |
| Used for | receiving envelopes, keys, tokens, invites, certificates, account data, reports | sending envelopes, fetching bundles and seal keys, registering |
| Lifetime | long-lived, one per account | at most 5 minutes or 50 requests, enforced by the relay |

Sending on anonymous connections is what keeps the relay from recording who
sent an envelope. To keep those connections from becoming a pseudonym of their
own, the relay closes each after 5 minutes or 50 requests, whichever comes
first, and the client opens them independently of its authenticated one, with
random lifetimes below that. A connection that carried `Register` is closed by
the relay after the answer.

---

## 2. Connection authentication

On every new connection the relay sends first:

```
Challenge { nonce: bytes[32], pow_bits: u8 }
```

An authenticated connection answers with

```
Authenticate {
  ik_sig:     bytes[32],
  device_key: bytes[32],
  generation: u32,
  cert:       bytes[64],     CRYPTO §3.3
  signature:  bytes[64]      Sign(DK.sk, L("auth") ‖ lp(host) ‖ nonce)
}                                                                         ← Ok
```

The relay accepts if `device_key` and `generation` equal the account's record,
`cert` verifies under `ik_sig`, and `signature` verifies under `device_key`.
The nonce is single-use per connection: there is no replay window, nothing to
store, and no clock to disagree with.

`host` is the relay's hostname as the client dialled it, normalised: IDNA
A-label form, lower-case ASCII, no trailing dot, no port. A signature therefore
cannot be replayed to another relay.

A connection whose first frame is not `Authenticate` is anonymous for its whole
life. A connection with no valid first frame within 10 seconds is closed.

### 2.1 Directory key and username certificates

The relay holds an Ed25519 **directory key**. Its public half is built into
every client and pinned there. It signs one thing: username certificates.

```
UsernameCertificate { username, account_id, ik_sig, ik_dh, generation, expires_at, relay_sig }
relay_sig = Sign(directory_sk, L("certificate") ‖ enc(certificate without relay_sig))
```

A client fetches its own certificate on its authenticated connection
(`GetCertificate`, §4.2), refreshes it weekly, and presents it in its
introductions (CRYPTO §5.3) and cards (CRYPTO §11.2), where it is checked
offline. A certificate is valid for 30 days.

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
| `0x0010–0x001F` | `Register 16`, `Registered 17`, `UpdatePrekeys 18`, `PrekeyStock 19`, `SetDiscoverable 20`, `DeleteAccount 21`, `AccountInfo 22`, `AccountData 23`, `ListHandedOut 24`, `HandedOut 25`, `GetCertificate 26`, `Certificate 27` |
| `0x0020–0x002F` | `CheckUsername 32`, `UsernameStatus 33`, `LookupIdentity 34`, `Identity 35`, `FetchBundle 36`, `Bundle 37`, `FetchSealKey 38`, `SealKey 39` |
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
PrekeyX   = { kind: u8, id: u32, created_at: u64, key: bytes[32], signature: opt<bytes[64]> }
PrekeyKem = { kind: u8, id: u32, created_at: u64, key: bytes[1184], signature: bytes[64] }
Pow       = { counter: u32, solution: bytes[16] }

→ Register [N] {
    username:   text≤32,
    ik_sig:     bytes[32],  ik_dh: bytes[32],  bind: bytes[64],
    device_key: bytes[32],  generation: u32,  cert: bytes[64],
    spk:        list<PrekeyX>≤5,     pqspk: list<PrekeyKem>≤5,     ssk: list<PrekeyX>≤5,
    opks:       list<PrekeyX>≤100,   pqopks: list<PrekeyKem>≤50,
    pow:        Pow,
    proof:      bytes[64]   Sign(IKsig.sk, L("register") ‖ lp(host) ‖ nonce ‖ SHA256(enc(all fields above)))
  }                                                ← Registered { account_id: bytes[16], generation: u32 }
```

The relay checks, before writing anything: the proof of work (§6.2), the
username (§6.3), `bind`, `cert`, every prekey signature and `created_at`, and
`proof`. It then answers and closes the connection. The signed-key lists hold
the active generation and up to four pre-signed future ones (CRYPTO §4). An
`OPK` (kind 5) must carry no signature and every other `PrekeyX` must carry
one; anything else is `MALFORMED`. With that rule the largest `Register` is
about 75 KB and fits the 80 KiB frame.

- **New account**: an unknown `ik_sig` with a free username, `generation` 1.
- **Rebind** (recovery on a new device): a known `ik_sig` under the same
  username with `generation` equal to the current generation + 1. The relay
  closes the old device's connections with `4010`, replaces the device key,
  purges the old generation's prekeys, seal keys and pending envelopes, revokes
  the account's invites, keeps its delivery tokens and account id, and raises
  the generation. A rebind is not counted against the registration limit — the
  relay already holds the key, which is evidence rather than a claim — and is
  limited per identity instead (§6.3).
- Any other `generation` for a known `ik_sig` is `GENERATION_MISMATCH`, with
  the current generation in `value`, reported only after `proof` has verified.
- A taken username under a different key is `USERNAME_TAKEN`.

```
→ UpdatePrekeys [A] { spk: list<PrekeyX>≤5, pqspk: list<PrekeyKem>≤5, ssk: list<PrekeyX>≤5,
                      opks: list<PrekeyX>≤100, pqopks: list<PrekeyKem>≤50,
                      withdraw: list<{ kind: u8, id: u32 }>≤150 }               ← PrekeyStock
← PrekeyStock   { opks: u16, pqopks: u16 }     also pushed when stock falls below 20 OPK or 10 PQOPK

→ ListHandedOut [A] { after: u64 }             ← HandedOut { entries: list<{ kind: u8, id: u32, at: u64 }>≤150, more: bool }
→ GetCertificate [A] { }                       ← Certificate { certificate: UsernameCertificate }
→ SetDiscoverable [A] { discoverable: bool }   ← Ok
→ DeleteAccount  [A] { confirm: bytes[64] }    Sign(IKsig.sk, L("delete") ‖ lp(host) ‖ nonce)
                                               ← Ok, then close 4000
→ AccountInfo    [A] { }                       ← AccountData
← AccountData { username, account_id, discoverable, created_day: u32, last_seen_day: u32,
                generation: u32, tokens: u16, invites: u8, pending: u32, pending_bytes: u64,
                blobs: u32, blob_bytes: u64 }
```

`ListHandedOut` pages through one-time keys handed out since `after`, so the
client can delete the ones never used (CRYPTO §4); the relay forgets an entry 15
days after hand-out. `withdraw` removes published one-time keys before the
client evicts them locally. `DeleteAccount` and the inactive-account sweep
remove the account and, in the same transaction, everything in §7 that refers
to it, and then its blob files. `AccountInfo` is everything the relay holds
about the account.

### 4.3 Directory

```
Access = tag u8: 1 Invite { secret: bytes[32] } | 2 Token { token: bytes[32] }

→ CheckUsername  [N] { username: text≤32 }                          ← UsernameStatus { available: bool }
→ LookupIdentity [N] { username: text≤32, access: opt<Access> }     ← Identity
← Identity { certificate: UsernameCertificate, bind: bytes[64] }
→ FetchBundle    [N] { username: text≤32, access: opt<Access> }     ← Bundle
← Bundle { certificate: UsernameCertificate, bind: bytes[64],
           spk: PrekeyX, pq: PrekeyKem, ssk: PrekeyX, opk: opt<PrekeyX> }
→ FetchSealKey   [N] { recipient: bytes[16], access: Access }        ← SealKey { ssk: PrekeyX, generation: u32 }
```

- A **non-discoverable** account is `NOT_FOUND` to `LookupIdentity` and
  `FetchBundle` unless `access` is one of its live invite secrets **or one of
  its live delivery tokens** — which every contact holds, so contacts can
  re-establish a session after a recovery without the account being
  discoverable.
- `FetchBundle` hands out one OPK and one PQOPK when available; `pq.kind` says
  whether `pq` is one-time (3) or last-resort (2). **A bundle is never refused
  because of who asks for it**: once 4 of either kind have been handed out in an
  hour for a target, further bundles that hour come without one-time keys.
- `FetchSealKey` returns the recipient's current seal key to a holder of an
  invite or token (CRYPTO §8).

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
Lane = tag u8: 1 Token { token: bytes[32] } | 2 Intro { invite: opt<bytes[32]>, pow: Pow }

SendItem = { recipient: bytes[16], sealed_for_generation: u32, lane: Lane, ephemeral: bool,
             envelope: bytes≤69713 }

→ Send      [N] SendItem                           ← Accepted { }
→ SendBatch [N] { items: list<SendItem>≤64 }       ← BatchAccepted { results: list<Result>≤64 }
                Result = tag u8: 1 Accepted | 2 Error { code: u16, value: u32 }

← Deliver [A]  { envelope_id: bytes[16], received_at: u64, lane: LaneSeen, envelope: bytes≤69713 }
               LaneSeen = tag u8: 1 Token { hash: bytes[32] } | 2 Intro { invite_hash: opt<bytes[32]> }
→ Ack     [A]  { ids: list<bytes[16]>≤256 }        ← Ok
```

The relay processes a `SendItem` in this order, the same for every lane:

1. **Generation.** If `sealed_for_generation` differs from the recipient's
   current generation, the answer is `STALE_GENERATION` with the current
   generation in `value`, and nothing is stored. The sender learns of a
   recovery before an envelope sealed to the old device can be lost, fetches a
   fresh bundle (with its token as access) and starts a new session.
2. **Token lane.** The answer is `Accepted` for a live token, a revoked one or
   one never issued; only an envelope on a live token is stored. A live token
   whose queue is full has its **oldest** envelope evicted rather than
   answering differently, and the same rate limit applies to every presented
   token, live or not. A sender cannot tell a block from a delivery.
3. **Introduction lane.** Accepted only if the recipient is discoverable or
   `invite` is one of their live invite secrets, and the proof of work is valid;
   otherwise `NOT_ACCEPTED`. Intro envelopes have their own quota per
   recipient, and invite holders a separate one per invite (§6.3).

The answer is sent once the decision is made; the envelope is written to disk
within 100 ms after it. An envelope lost to a relay crash in that window is
recovered end to end: recipients return a delivery receipt inside the session,
and a sender resends an envelope with no receipt after 24 hours — the ratchet
discards the copy if the original did arrive (CRYPTO §6.5).

- **Batches.** A client adds items to a `SendBatch` only while the frame stays
  within 80 KiB; at 2 KiB envelopes that is about 35 items.
- **Delivery.** The relay pushes pending envelopes to the recipient's
  authenticated connection, oldest first, holding at most 64 unacknowledged
  envelopes and at most 256 KiB queued. `Deliver` says which lane an envelope
  arrived on, so the client can apply CRYPTO §9.2.
- **Acknowledgement.** `Ack` deletes only envelopes addressed to the
  authenticated account. The client acknowledges after the result is durably
  committed to its vault, and also when an envelope fails permanently, so a
  bad envelope cannot stall delivery.
- **Ephemeral** envelopes (typing, presence) are pushed if the recipient is
  connected and otherwise dropped, never stored. The answer to a `Send` does not
  depend on whether that happened.

### 4.6 Reports

```
→ Report [A] { sealed: bytes≤69713 }    ← Ok
```

`sealed` holds the reported messages as the reporter received them and the
reported sender's identity pair (not their username, which may since have been
reissued). It is sealed to LUME Inc.'s published report key with the
construction of CRYPTO §8, using the labels `report/key` and `report/ad`. The
relay stores it without being able to read it. A report is evidence of what the
reporter says, not proof of what was sent (CRYPTO §1). Twenty reports per
account per day.

### 4.7 Blobs

```
→ BlobUpload [N] { recipient: bytes[16], token: bytes[32], size: u32, max_downloads: u8 }    ← BlobTicket
← BlobTicket     { blob_id: bytes[32], upload_key: bytes[32], expires_at: u64 }
```

Uploads go on the token lane only — a stranger on the introduction lane cannot
store blobs against anyone. The ticket authorises one
`PUT /v1/blob/<hex blob_id>` with header `Lume-Upload-Key: <hex upload_key>` and
exactly `size` bytes, within 10 minutes. `GET /v1/blob/<hex blob_id>` returns
the blob at most `max_downloads` times (≤ 100; a group attachment asks for
twice the group size). The id is 256 random bits that travel only inside an
encrypted message, and the content is encrypted (CRYPTO §11.1). Blob bytes
count against the recipient's quota.

---

## 5. Errors and close codes

`Error { code: u16, retry_after_ms: u32, value: u32 }`. `retry_after_ms` is
non-zero only for `RATE_LIMITED` and `UNAVAILABLE`; `value` only where a code
says so. Codes carry no internal detail.

| Code | Name | Meaning |
|---|---|---|
| 1 | `MALFORMED` | decoded, but a field is semantically invalid |
| 2 | `WRONG_CONNECTION` | not allowed on this kind of connection |
| 3 | `AUTH_FAILED` | device key, generation, certificate or signature invalid |
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
| 15 | `BAD_POW` | proof of work missing, reused or too weak; `value` is the difficulty required |
| 16 | `STALE_GENERATION` | the recipient has recovered on a new device; `value` is the current generation |
| 17 | `GENERATION_MISMATCH` | a rebind with the wrong generation; `value` is the current generation |

Code 14 is reserved and unused.

| Close | Meaning |
|---|---|
| `4000` | normal close: after `Register`, after `DeleteAccount` |
| `4001` | no valid first frame within 10 s |
| `4002` | authentication failed |
| `4005` | replaced by a newer authenticated connection for the account |
| `4006` | connection limit for this address |
| `4008` | frame budget exceeded three times over |
| `4009` | idle timeout, or an anonymous connection's lifetime or request allowance used up |
| `4010` | the account recovered on another device |
| `4400` | undecodable, oversized or incomplete frame |

The relay sends the close frame and waits up to one second for it to flush
before dropping the socket, so a refused client sees the code, not a bare
`1006`.

---

## 6. Limits

### 6.1 Address keys

Every address-keyed limit is applied at **every level** of the address, each
with its budget multiplied as shown, so that rotating addresses inside one
allocation buys nothing beyond the allocation's own budget:

| Family | Levels and budget multiplier |
|---|---|
| IPv4 | /32 ×1, /24 ×16 |
| IPv6 | /64 ×1, /56 ×4, /48 ×16, /32 ×64 |

One helper builds every address key; no limiter formats an address itself. The
client address is the entry `TRUSTED_PROXY_HOPS` from the right of
`X-Forwarded-For`; when that setting is non-zero, a request without enough
entries is refused.

Authenticated connections are keyed by account, not address, so many users
behind one carrier NAT are not limited as if they were one — except accounts
younger than 7 days, which are also limited per address (§6.3), so that a crowd
of freshly made accounts cannot occupy the capacity reserved for authenticated
connections.

### 6.2 Proof of work

Registration and introduction-lane sends carry a `Pow`:

```
SHA256(L("pow") ‖ nonce ‖ u8(purpose) ‖ u32(counter) ‖ solution) has at least d leading zero bits
purpose: 1 register, 2 intro
```

`nonce` is the connection's challenge, so stamps cannot be precomputed or
shared. `counter` must be strictly greater than the last counter **accepted** on
the connection; a stamp is consumed only when it verifies, so rejected or
reordered requests do not put client and relay out of step.

`d` is set **per address**, not globally: 18 bits by default (about a second on
a phone), one more for each doubling of that address's recent rate above its
budget, at /64 and /48, up to a maximum of 24. A flood from one allocation
raises the cost for that allocation alone. `Challenge` announces the default; a
stamp that is too weak is answered with `BAD_POW` and the required `d` in
`value`.

Proof of work slows abuse but does not stop a well-funded one, and an attacker
with a GPU pays far less than a phone does. Unlinkable per-account rate-limit
tokens (a VOPRF over ristretto255, in the style of Privacy Pass) are the
planned replacement and are not part of this version.

### 6.3 Bounds

| What | Bound |
|---|---|
| Username | `^[a-z0-9_]{3,32}$`, upper case folded first; reserved and barred names refused |
| Registrations | 30 / hour per address (with the §6.1 multipliers); proof of work |
| Rebinds | 3 / day per identity |
| `Register` attempts | 10 / minute per address, counted before any signature is verified |
| Authenticated connections | 1 per account; 20 % of process capacity reserved for them; accounts younger than 7 days: 16 per address |
| Anonymous connections | 256 concurrent per address; 60 new / minute per address; 5 minutes or 50 requests each |
| Process | 10 000 concurrent connections |
| Idle timeout | anonymous 60 s, authenticated 15 min (the client pings every 4 min) |
| Frames | 120 per 10 s per connection; beyond that requests get `RATE_LIMITED`; three times over closes `4008` |
| `CheckUsername`, `LookupIdentity` | 60 / minute per address |
| `FetchBundle`, `FetchSealKey` | 20 / minute per address; one-time keys: 4 per kind handed out per hour per target |
| Token lane | 120 / minute per presented token; ≤ 1000 pending per token, oldest evicted |
| Introduction lane | 10 / minute per address + proof of work; ≤ 50 pending per recipient without invite (oldest evicted), ≤ 20 per invite |
| Pending per recipient | ≤ 10 000 envelopes and ≤ 256 MiB; accounts younger than 7 days ≤ 16 MiB |
| Stored per address | ≤ 1 GiB of envelopes and blobs per day (with the §6.1 multipliers) |
| Envelope | ≤ 69 713 bytes (CRYPTO §7–§8: largest padded plaintext 69 632 + 81 bytes of seal encoding) |
| Retention | 30 days undelivered; deleted on acknowledgement |
| Outbound per connection | ≤ 64 unacknowledged deliveries and ≤ 256 KiB queued |
| Prekeys | ≤ 100 OPK, ≤ 50 PQOPK; ≤ 5 generations of each signed kind |
| Tokens / invites | ≤ 1000 live per account / ≤ 5 live, 24 h |
| Blob | ≤ 25 MiB each; ≤ 1 GiB live per recipient (accounts younger than 7 days ≤ 64 MiB); ≤ 100 downloads each and 2 GiB / day per address; 30 days |
| Disk | from 85 % of `LUME_DISK_QUOTA`, the relay evicts the oldest envelopes and blobs of the largest and youngest accounts first; from 95 %, `Send` and `BlobUpload` answer `UNAVAILABLE` |
| Reports | 20 / day per account, kept 90 days |
| Inactive account | deleted after 365 days without an authenticated connection; never below 30 (boot refuses) |

Limiter state lives in memory. Nothing about who called what is written to
disk.

---

## 7. What the relay stores

| Table | Columns | Bound |
|---|---|---|
| `accounts` | id, username, ik_sig (unique), ik_dh, bind, device_key, generation, discoverable, created_day, last_seen_day | inactive sweep |
| `signed_prekeys` | account, kind (SPK, PQSPK, SSK), id, created_at, key, signature | ≤ 5 generations per kind; replaced ones kept for their grace period |
| `one_time_prekeys` | account, kind (OPK, PQOPK), id, created_at, key, signature | per-account caps; deleted when handed out |
| `handed_out` | account, kind, id, at | 15 days |
| `delivery_tokens` | account, token_hash, created_day | 1000 per account |
| `invites` | account, secret_hash, expires_at | 5 per account, TTL |
| `pending` | id, recipient, generation, lane (token hash or intro + invite hash), envelope, received_at | 30 days; per-token, per-intro, per-recipient caps |
| `blobs` | id, recipient, size, upload_key_hash, downloads_left, expires_at | TTL, per-recipient byte cap; file deleted with the row |
| `reports` | id, sealed, received_at | 90 days, per-account daily cap |
| `barred_usernames` | username_hash, created_day | 100 000 rows, oldest removed |

Seen-times are kept to the **day**. Certificates are signed on request and not
stored.

**Not stored, by design:** the sender of any envelope; group names, members or
roles; display names and avatars; typing and read state; request signatures or
nonces; IP addresses.

SQLite runs with `auto_vacuum=INCREMENTAL` (set before WAL),
`journal_mode=WAL`, `foreign_keys=ON` and `secure_delete=ON`; every bulk delete
is followed by `incremental_vacuum` and a `wal_checkpoint(TRUNCATE)`. Prepared
statements only.

---

## 8. Configuration

Read once at boot. A missing required value, an unparseable value or a value
out of range stops the process with a message naming the setting.

| Setting | Default | Rule |
|---|---|---|
| `LUME_HOST` | required | hostname clients sign (§2) |
| `TRUSTED_PROXY_HOPS` | required | integer 0–4; must match the deployment — too high lets callers choose their own address, too low puts everyone in one |
| `LUME_DISK_QUOTA` | required | bytes the relay may use for its database and blobs |
| `LUME_DIRECTORY_KEY_FILE` | required | the directory signing key (§2.1); readable only by the relay's user |
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
