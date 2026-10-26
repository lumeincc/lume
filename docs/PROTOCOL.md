<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# LUME — Relay protocol

Status: **draft**, revision 7.
Companion to [CRYPTO.md](CRYPTO.md), which defines every key and construction
named here.

The relay accepts sealed envelopes for an account and hands them to that
account when it connects. It verifies signatures on public keys, has username
certificates signed, enforces limits, and stores as little as delivery needs.
It never holds a private key of a user and never decrypts an envelope.

---

## 1. Transport

- **One WebSocket endpoint**, `wss://<host>/v1`. **TLS is terminated by the
  relay process itself**; a load balancer in front passes TCP through and, if
  configured, reports the client address with the PROXY protocol v2 — accepted
  only from the load balancer's own addresses (§8).
  Delivery tokens travel inside requests (§4), so whoever terminates TLS sees
  them, and that must be the relay. Plain `ws://` only in development mode.
- **Binary frames only.** A text frame, a frame that does not decode (§3), or a
  message larger than **80 KiB** closes the connection with `4400`. The limit is
  enforced by the WebSocket reader before a fragmented message is reassembled.
  A frame must arrive at an average of at least 1 KiB per second after its first
  byte, and within 120 seconds at most, or the connection is closed — slow
  enough for Tor and poor mobile links, fast enough that a connection cannot be
  held open by trickling bytes.
- **No browser access.** An upgrade request that carries an `Origin` header is
  refused with HTTP 403 before the WebSocket opens.
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
sent an envelope. The relay closes each anonymous connection after 5 minutes or
50 requests, and the client opens them independently of its authenticated one,
with random lifetimes below that. A connection that carried `Register` is closed
by the relay after the answer.

---

## 2. Connection authentication

On every new connection the relay sends first:

```
Challenge { nonce: bytes[32], pow_bits: u8 }
```

`pow_bits` is the proof-of-work difficulty that currently applies to the
connecting address (§6.2). An authenticated connection answers with

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
`cert` verifies under `ik_sig`, and `signature` verifies under `device_key`. The
nonce is single-use per connection: there is no replay window, nothing to
store, and no clock to disagree with.

`host` is the relay's hostname as the client dialled it, normalised: IDNA
A-label form, lower-case ASCII, no trailing dot, no port.

A connection whose first frame is not `Authenticate` is anonymous for its whole
life. A connection with no valid first frame within 10 seconds is closed.

### 2.1 Directory keys and username certificates

Username certificates are signed by a **directory key**. The signing key is held
by a signer separate from the relay's network-facing process — a hardware
security module, or at least a separate process reachable only over a local
socket (§8) — so that compromising the relay process does not hand out the key.

Every client is built with the **LUME root key**, an Ed25519 key kept offline
and used for one thing: signing the **directory key list**.

```
DirectoryKeys { sequence, issued_at, expires_at, keys: list<{ key_id, public_key, not_before, not_after }>,
                revoked: list<{ key_id, since }>, signature }
signature = Sign(root_sk, L("directory-keys") ‖ enc(list without signature))
```

A list expires at most 14 days after `issued_at` and is signed again every
week. The relay serves the newest one (`GetDirectoryKeys`, §4.2); a client
fetches it whenever it refreshes its own certificate and at most once a day
otherwise, keeps the list with the highest `sequence` it has verified, and
ignores one with a lower `sequence`, so it cannot be rolled back. A certificate
is accepted only from a key on a current list and inside that key's window.
Without a current list a client shows names as unverified, with the safety
number.

The list is how keys are rotated and **revoked**. A new key appears on a list
before it is used; a retired key simply leaves it. A stolen key leaves `keys`
and is named under `revoked` with the time `since` from which its certificates
are distrusted, on a list signed at once. A client records, for each contact,
which key verified the name and when it accepted it, by its own clock. When a
list revokes that key, every name the client accepted with it at or after
`since`, less a day of margin, goes back to unverified — unless the contact was
verified by safety number — until a fresh certificate arrives. The client's
own record decides, because a stolen key can write any `issued_at`. Clients
send their refreshed certificate in an `Introduction` in the next message of
each session after the weekly refresh. A relay that withholds the new list can
keep a revoked key working for at most the 14 days the old list has left.

Each release ships the list current at build time, so a fresh install has a
`sequence` floor too. A client whose newest list has expired fetches a new one
before it checks any name, and retries hourly while it cannot. The relay
verifies the list against the root public key it is configured with before
serving it, and answers `GetDirectoryKeys` with `UNAVAILABLE` while it has no
current one. Losing the root key means a client release with a new one; that is
the price of keeping it offline. A self-hosted relay builds its clients with
its own root key.

```
UsernameCertificate { key_id, username, account_id, ik_sig, ik_dh, generation, issued_at, expires_at, signature }
signature = Sign(directory_sk, L("certificate") ‖ enc(certificate without signature))
```

A certificate is valid for at most 30 days after its `issued_at`; clients
refuse one whose `issued_at` is in the future or whose `expires_at` is more
than 31 days ahead. The relay signs at most one certificate per account per day
and serves that one from its cache, so lookups never load the signer; a rebind
or a revocation of the signing key drops the cached one at once. `issued_at` is
the start of the UTC day of signing, so it does not reveal when the owner was
active. A client fetches its own certificate on
its authenticated connection (`GetCertificate`, §4.2), refreshes it weekly, and
presents it in introductions (CRYPTO §5.3) and cards (CRYPTO §11.2). A username
freed by deletion or by the inactivity sweep cannot be registered again for 31
days, so two valid certificates never name the same username.

---

## 3. Frame encoding

Every frame is one message in a **canonical binary encoding**, implemented once
in `core/wire` and used by the relay and by every client.

```
frame = u8(version = 1) ‖ u16(type) ‖ u32(request_id) ‖ body
```

`request_id` is chosen by the client and echoed in the response; `0` marks a
frame the relay pushes. `body` is the fields of `type` in the order listed, with
no tags and no padding.

| Field kind | Encoding | Canonical rule |
|---|---|---|
| `u8 u16 u32 u64` | big-endian | — |
| `bool` | `u8` | only `0` or `1` |
| `bytes[N]` | exactly N bytes | — |
| `bytes≤M` | `u32(len) ‖ data` | `len ≤ M` |
| `text≤M` | as `bytes≤M` | valid UTF-8, no NUL |
| `list<T>≤K` | `u16(count) ‖ T…` | `count ≤ K` |
| `opt<T>` | `u8(0)` or `u8(1) ‖ T` | only `0` or `1` |
| `tag` union | `u8(tag) ‖ fields of that variant` | only the listed tags |

Decoding **rejects** an unknown version, type or tag, any length or count over
its bound, a non-canonical `bool` or `opt`, invalid text, and bytes after the
last field. It never allocates more than the frame's own length. Every
structure has a fuzz target and a round-trip property test.

**Identifiers** — `account_id` (16 bytes), `envelope_id` (16), `blob_id` (32) —
are random, never sequential.

### 3.1 Types

| Range | Types |
|---|---|
| `0x0001–0x000F` | `Challenge 1`, `Authenticate 2`, `Ok 3`, `Error 4`, `Ping 5`, `Pong 6`, `Notice 7` |
| `0x0010–0x001F` | `Register 16`, `Registered 17`, `UpdatePrekeys 18`, `PrekeyStock 19`, `SetDiscoverable 20`, `DeleteAccount 21`, `AccountInfo 22`, `AccountData 23`, `ListHandedOut 24`, `HandedOut 25`, `GetCertificate 26`, `Certificate 27`, `GetDirectoryKeys 28`, `DirectoryKeys 29` |
| `0x0020–0x002F` | `CheckUsername 32`, `UsernameStatus 33`, `LookupIdentity 34`, `Identity 35`, `FetchBundle 36`, `Bundle 37`, `FetchSealKey 38`, `SealKey 39` |
| `0x0030–0x003F` | `AddTokens 48`, `RevokeTokens 49`, `CreateInvite 50`, `RevokeInvite 51`, `SinkTokens 52` |
| `0x0040–0x004F` | `Send 64`, `SendBatch 65`, `Accepted 66`, `BatchAccepted 67`, `Deliver 68`, `Ack 69` |
| `0x0050–0x005F` | `BlobUpload 80`, `BlobTicket 81` |
| `0x0060–0x006F` | `Report 96` |

### 3.2 Shared structures

Used by frames below and by CRYPTO.md. Sizes are maxima.

```
PrekeyX            = { kind: u8, id: u32, created_at: u64, key: bytes[32], signature: opt<bytes[64]> }
                     signature is absent for kind 5 (OPK) and present for every other kind
PrekeyKem          = { kind: u8, id: u32, created_at: u64, key: bytes[1184], signature: bytes[64] }
Pow                = { counter: u32, solution: bytes[16] }
Access             = tag 1 Invite { secret: bytes[32] } | tag 2 Token { token: bytes[32] }
UsernameCertificate = { key_id: u32, username: text≤32, account_id: bytes[16], ik_sig: bytes[32],
                        ik_dh: bytes[32], generation: u32, issued_at: u64, expires_at: u64,
                        signature: bytes[64] }
DirectoryKeys      = { sequence: u64, issued_at: u64, expires_at: u64,
                       keys: list<{ key_id: u32, public_key: bytes[32], not_before: u64, not_after: u64 }>≤8,
                       revoked: list<{ key_id: u32, since: u64 }>≤16, signature: bytes[64] }

InitialHeader      = { ik_sig: bytes[32], ik_dh: bytes[32], bind: bytes[64], ek: bytes[32],
                       ct: bytes[1088], spk_id: u32, pq_kind: u8, pq_id: u32, opk_id: opt<u32> }
Introduction       = { account_id: bytes[16], generation: u32, token: bytes[32], seal_key: PrekeyX,
                       certificate: opt<UsernameCertificate> }
Content            = { id: bytes[16], kind: u8, introduction: opt<Introduction>, body: bytes≤67000 }
Header             = { dh: bytes[32], pn: u32, n: u32 }
RatchetMessage     = { enc_header: bytes[80], body: bytes≤69000 }
Inner              = { sender: bytes[32], initial: opt<InitialHeader>, message: RatchetMessage }
Seal               = { version: u8, ssk_id: u32, es: bytes[32], nonce: bytes[24], box: bytes≤69648 }
Card               = { certificate: UsernameCertificate, bind: bytes[64], generation: u32,
                       spk: PrekeyX, pqspk: PrekeyKem, ssk: PrekeyX, token: bytes[32],
                       group_id: bytes[16], expires_at: u64, signature: bytes[64] }
```

`enc_header` is `24 + enc(Header) + 16 = 80` bytes. A `Seal` of the largest
padded plaintext is `1 + 4 + 32 + 24 + 4 + 69 632 + 16 = 69 713` bytes, the
envelope bound.

---

## 4. Messages

`→` client to relay, `←` relay to client. Every request gets exactly one
response: the type listed, or `Error` (§5). `[A]` — authenticated connections
only; `[N]` — anonymous only; `[*]` — either.

### 4.1 Common

```
→ Ping   [*] { }                              ← Pong { }
← Notice     { kind: u16 }                    pushed to the account: a policy change,
                                              a notice required before a lawful disclosure,
                                              an account action taken by LUME Inc.
                                              Kinds come from a fixed list and the app shows
                                              its own text for each; the relay sends no text.
```

### 4.2 Account

```
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
username (§6.3), `bind`, `cert`, every prekey signature under `generation`
(`UpdatePrekeys` under the account's current generation), every `created_at`
(not more than 31 days ahead), and `proof`. It then answers and closes the
connection. Each signed-key list holds the active generation and up to four
future ones (CRYPTO §4). The largest `Register` is about 75 KB.

- **New account**: an unknown `ik_sig` with a free username, `generation` 1.
- **Rebind** (recovery on a new device): a known `ik_sig` under the same
  username with `generation` equal to the current generation + 1. The relay
  closes the old device's connections with `4010`, replaces the device key,
  purges the old generation's prekeys, seal keys and pending envelopes, revokes
  the account's invites, keeps its account id, and marks every live delivery
  token **inherited**: an inherited token not used within 45 days is deleted.
  Sinks stay sinks, so a blocked contact stays blocked after a recovery. A rebind
  is not counted against the registration limit and is limited per identity
  instead (§6.3).
- Any other `generation` for a known `ik_sig` is `GENERATION_MISMATCH`, with
  the current generation in `value`, reported only after `proof` has verified.
- A taken username under a different key, or a name in its 31-day hold, is
  `USERNAME_TAKEN`.

```
→ UpdatePrekeys [A] { spk: list<PrekeyX>≤5, pqspk: list<PrekeyKem>≤5, ssk: list<PrekeyX>≤5,
                      opks: list<PrekeyX>≤100, pqopks: list<PrekeyKem>≤50,
                      withdraw: list<{ kind: u8, id: u32 }>≤150 }               ← PrekeyStock
← PrekeyStock   { opks: u16, pqopks: u16 }     also pushed when stock falls below 20 OPK or 10 PQOPK

→ ListHandedOut [A] { after: u64 }             ← HandedOut { entries: list<{ kind: u8, id: u32, seq: u64 }>≤150, more: bool }
→ GetCertificate [A] { }                       ← Certificate { certificate: UsernameCertificate }
→ GetDirectoryKeys [*] { }                     ← DirectoryKeys
→ SetDiscoverable [A] { discoverable: bool }   ← Ok { }
→ DeleteAccount  [A] { confirm: bytes[64] }    Sign(IKsig.sk, L("delete") ‖ lp(host) ‖ nonce)
                                               ← Ok, then close 4000
→ AccountInfo    [A] { }                       ← AccountData
← AccountData { username: text≤32, account_id: bytes[16], discoverable: bool,
                created_day: u32, last_seen_day: u32,
                generation: u32, tokens: u16, invites: u8, pending: u32, pending_bytes: u64,
                blobs: u32, blob_bytes: u64 }
```

`withdraw` removes published keys of any kind by id — not-yet-active rotating
keys on every unlock (CRYPTO §4) and one-time keys before local eviction.
`ListHandedOut` pages, by an opaque sequence number, through the one-time keys
handed out since `after`; the relay keeps the day of each hand-out, not the
time, and forgets the entry after 15 days. `DeleteAccount` and the
inactive-account sweep remove the account and, in the same transaction,
everything in §7 that refers to it, and then its blob files.

### 4.3 Directory

```
→ CheckUsername  [N] { username: text≤32 }                          ← UsernameStatus { available: bool }
→ LookupIdentity [N] { username: text≤32, access: opt<Access> }     ← Identity
← Identity { certificate: UsernameCertificate, bind: bytes[64] }
→ FetchBundle    [N] { username: text≤32, access: opt<Access> }     ← Bundle
← Bundle { certificate: UsernameCertificate, bind: bytes[64], generation: u32,
           spk: PrekeyX, pq: PrekeyKem, ssk: PrekeyX, opk: opt<PrekeyX> }
           generation is the one every prekey signature covers (CRYPTO §4); the
           certificate's own generation is informational
→ FetchSealKey   [N] { recipient: bytes[16], access: Access }        ← SealKey { ssk: PrekeyX, generation: u32 }
                 generation is the one the ssk signature covers (CRYPTO §4)
```

- A **non-discoverable** account is `NOT_FOUND` to `LookupIdentity` and
  `FetchBundle` unless `access` is one of its live invite secrets or one of its
  delivery tokens.
- **Every token that the account holds as live, sink or inherited is answered
  identically** (CRYPTO §9.4). A token that the account does not hold gets
  `NOT_FOUND`, but a contact only ever holds a token the account issued, and a
  blocked contact's token is a sink, not a deleted one.
- A bundle fetched with a token as access carries **no one-time keys**; one-time
  keys go only to fetches by username or invite, at most 4 of each kind per hour
  per target. **A bundle is never refused because of who asks for it.**
- `FetchSealKey` returns the recipient's current seal key to a holder of an
  invite or token.

### 4.4 Delivery tokens and invites

```
→ AddTokens    [A] { hashes: list<bytes[32]>≤100 }    ← Ok    at most 5000 per account, sinks included
→ RevokeTokens [A] { hashes: list<bytes[32]>≤100 }    ← Ok    deletes them; used for rotation
→ SinkTokens   [A] { hashes: list<bytes[32]>≤100 }    ← Ok    turns them into sinks; used for blocking
→ CreateInvite [A] { secret_hash: bytes[32] }         ← Ok    24 h, at most 5 live
→ RevokeInvite [A] { secret_hash: bytes[32] }         ← Ok
```

The relay stores only hashes, `SHA256(L("token") ‖ T)` (CRYPTO §9.1) and
`SHA256(L("invite") ‖ S)`, though it sees the token itself whenever a request
presents it.

### 4.5 Envelopes

```
Lane     = tag 1 Token { token: bytes[32] } | tag 2 Intro { invite: opt<bytes[32]>, pow: Pow }
LaneSeen = tag 1 Token { hash: bytes[32] } | tag 2 Intro { invite_hash: opt<bytes[32]> }
SendItem = { recipient: bytes[16], sealed_for_generation: u32, lane: Lane, ephemeral: bool,
             envelope: bytes≤69713 }

→ Send      [N] SendItem                           ← Accepted { }
→ SendBatch [N] { items: list<SendItem>≤64 }       ← BatchAccepted { results: list<Result>≤64 }
                Result = tag 1 Accepted | tag 2 Error { code: u16, retry_after_ms: u32, value: u32 }

← Deliver [A]  { envelope_id: bytes[16], received_at: u64, lane: LaneSeen, envelope: bytes≤69713 }
→ Ack     [A]  { ids: list<bytes[16]>≤256 }        ← Ok
```

The relay decides a `SendItem` in this order:

1. **Lane.**
   - *Token lane*: a token the recipient does not hold is answered `Accepted`
     and discarded, whatever the rest of the item says. A live, sink or
     inherited token continues.
   - *Introduction lane*: continues only if the recipient is discoverable or
     `invite` is one of their live invite secrets, and the proof of work is
     valid; otherwise `NOT_ACCEPTED`.
2. **Generation.** If `sealed_for_generation` differs from the recipient's
   current generation, the answer is `STALE_GENERATION`, with no `value`, and
   nothing is stored. Only a sender already authorised by step 1 learns this,
   and a sink token learns it exactly as a live one would. The sender fetches
   the recipient's seal key with its token (§4.3). If its signature proves a
   higher generation, the sender starts a new session (CRYPTO §5.4); otherwise
   the answer is treated as transient and the send is retried with backoff.
3. **Store.** An envelope on a live or inherited token, or an accepted
   introduction, is stored; one on a sink token is discarded after the same
   accounting. A token whose queue is full has its **oldest** envelope evicted.
   The answer is `Accepted`.

The answer is sent once the decision is made, and the envelope is written within
100 ms after it; the relay never delays an answer for a slow disk. An envelope
lost to a crash or to eviction is recovered end to end by the sender's resends
(CRYPTO §7.2).

- **Batches.** A client adds items to a `SendBatch` only while the frame stays
  within 80 KiB; at the 2 KiB bucket that is 37 items.
- **Delivery.** The relay pushes pending envelopes to the recipient's
  authenticated connection, oldest first, holding at most 64 unacknowledged
  envelopes and at most 256 KiB queued. `Deliver` says which lane an envelope
  arrived on, so the client can apply CRYPTO §9.2.
- **Acknowledgement.** `Ack` deletes only envelopes addressed to the
  authenticated account. The client acknowledges after the result is durably
  committed, and also when an envelope fails permanently.
- **Ephemeral** envelopes (typing, presence) are pushed if the recipient is
  connected and otherwise dropped, never stored; the answer does not depend on
  which.

### 4.6 Reports

```
→ Report [A] { sealed: bytes≤69713 }    ← Ok
```

`sealed` holds the reported message or messages, as the reporter received them
and up to the envelope size, and the reported sender's identity pair. It is
sealed to LUME Inc.'s published report key with the construction of CRYPTO §8,
using the labels `report/key` and `report/ad`. The relay stores it without being
able to read it. A report is evidence of what the reporter says, not proof of
what was sent. Twenty reports per account per day.

### 4.7 Blobs

```
→ BlobUpload [N] { recipient: bytes[16], token: bytes[32], size: u32, max_downloads: u8 }    ← BlobTicket
← BlobTicket     { blob_id: bytes[32], upload_key: bytes[32], expires_at: u64 }
```

Uploads go on the token lane only, with a token the recipient holds. Live, sink
and inherited tokens are treated the same: the blob is stored, charged and
served whatever the token's state, because an uploader that could not download
its own blob would learn that it is blocked (CRYPTO §9.4). A blob on a sink
token counts against that token's 256 MiB and the uploader's address budget,
and is reported in that token's answers as if it counted against the
recipient; it never reduces what the recipient's other tokens may store and
never raises the recipient's rank under disk pressure. A group attachment is
uploaded once, on the token of any one member the sender writes to, and every
member reaches it by its id. The ticket authorises one
`PUT /v1/blob/<hex blob_id>` with header `Lume-Upload-Key: <hex upload_key>` and
exactly `size` bytes, within 10 minutes. `GET /v1/blob/<hex blob_id>` returns
the blob at most `max_downloads` times (≤ 100). A blob for one recipient
(`max_downloads` 1–3) counts against that recipient's quota; a group blob counts
against the uploading address's stored budget only. The id is 256 random bits
that travel only inside an encrypted message, and the content is encrypted
(CRYPTO §11.1).

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
| 16 | `STALE_GENERATION` | the recipient has recovered on a new device; fetch the seal key again |
| 17 | `GENERATION_MISMATCH` | a rebind with the wrong generation; `value` is the current generation |

Code 14 is reserved and unused.

| Close | Meaning |
|---|---|
| `4000` | normal close: after `Register`, after `DeleteAccount` |
| `4001` | no valid first frame within 10 s |
| `4002` | authentication failed |
| `4005` | replaced by a newer authenticated connection for the account |
| `4006` | connection limit for this address |
| `4008` | frame budget exceeded in three consecutive windows |
| `4009` | idle timeout, or an anonymous connection's lifetime or request allowance used up |
| `4010` | the account recovered on another device |
| `4400` | undecodable, oversized or too slowly delivered frame |

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
client address is the TCP peer, or, with `LUME_CLIENT_ADDRESS=proxy-protocol`,
the address in the PROXY protocol header sent by a peer in
`LUME_TRUSTED_PROXIES` (§8). No other peer is believed about an address.

Authenticated connections are keyed by account, not address, so many users
behind one carrier NAT are not limited as if they were one — except accounts
younger than 7 days, which are also limited per address (§6.3).

Every limiter's state is bounded: per-address and per-token counters live in a
fixed-size table, so a flood of random tokens or addresses cannot grow memory.
Each table holds 2^20 entries. When it is full it forgets the least recently
used entries that are neither limited nor carrying a raised proof-of-work
level; an entry that is either is kept until its window ends. Entries that find
the table full of such entries share one overflow entry, limited as strictly as
a single address. Nobody can flush their own counters, and a flood degrades
only the newcomers who arrive during it.

Addresses are normalised before keys are built: an IPv4-mapped IPv6 address
(`::ffff:0:0/96`) counts as its IPv4 address.

### 6.2 Proof of work

Registration and introduction-lane sends carry a `Pow`:

```
SHA256(L("pow") ‖ nonce ‖ u8(purpose) ‖ u32(counter) ‖ solution) has at least d leading zero bits
purpose: 1 register, 2 intro
```

`nonce` is the connection's challenge, so stamps cannot be precomputed or
shared. `counter` must be strictly greater than the last counter **accepted** on
the connection; a stamp is consumed only when it verifies.

`d` is set **per address**: 18 bits by default (about a second on a phone), one
more for each doubling of the address's recent rate above its budget at any
level of §6.1, up to 22 (about 16 seconds). `Challenge` announces the `d` that
applies to the connecting address; a stamp that is too weak is answered with
`BAD_POW` and the required `d` in `value`. Honest users who share an allocation
with an abuser pay the raised cost too, which is the price of not identifying
anyone.

### 6.3 Bounds

| What | Bound |
|---|---|
| Username | `^[a-z0-9_]{3,32}$`, upper case folded first; reserved, barred and held names refused |
| Registrations | 30 / hour per address (with the §6.1 multipliers); proof of work |
| Rebinds | 3 / day per identity |
| `Register` attempts | 10 / minute per address, counted before any signature is verified |
| Authenticated connections | 1 per account; at least 20 % of process capacity kept for them; accounts younger than 7 days: 16 per address |
| Anonymous connections | 64 concurrent per address; 60 new / minute per address; 5 minutes or 50 requests each |
| Process | 10 000 concurrent connections |
| Idle timeout | anonymous 60 s, authenticated 15 min (the client pings every 4 min) |
| Frames | 120 per 10 s per connection; beyond that requests get `RATE_LIMITED`; three consecutive windows over close `4008` |
| `CheckUsername`, `LookupIdentity` | 60 / minute per address |
| `GetDirectoryKeys` | 10 / minute per address or account; the answer is the same file for everyone |
| `GetCertificate` | 10 / hour per account; answered from the daily cache |
| `FetchBundle`, `FetchSealKey` | 20 / minute per address; 30 / hour per presented token |
| Token lane | 120 / minute per presented token; ≤ 1000 pending per token, oldest evicted |
| Introduction lane | 10 / minute per address + proof of work; ≤ 50 pending per recipient without invite, of which at most 10 from one /48 or IPv4 /24 — a full queue evicts the oldest from the largest contributor; ≤ 20 per invite |
| Pending per recipient | ≤ 10 000 envelopes and ≤ 256 MiB; accounts younger than 7 days ≤ 16 MiB; a full recipient evicts the oldest envelope of its largest token or lane |
| Stored per address | ≤ 1 GiB of envelopes and blobs presented per day (with the §6.1 multipliers), counted whether kept or discarded |
| Envelope | ≤ 69 713 bytes (§3.2) |
| Retention | 30 days undelivered; deleted on acknowledgement |
| Outbound per connection | ≤ 64 unacknowledged deliveries and ≤ 256 KiB queued |
| Prekeys | ≤ 100 OPK, ≤ 50 PQOPK; per signed kind, the active key and ≤ 4 future ones; a replaced key is deleted |
| Tokens / invites | ≤ 5000 per account / ≤ 5 live, 24 h |
| Blob | ≤ 25 MiB each; ≤ 1 GiB live per recipient (accounts younger than 7 days ≤ 64 MiB) and ≤ 256 MiB per token; ≤ 100 downloads each and 2 GiB / day per address; 30 days |
| Disk | from 85 % of `LUME_DISK_QUOTA`, the relay evicts first from the accounts with the highest ratio of stored bytes to account age in days, oldest envelopes and blobs first; from 95 %, stores for recipients above the 90th percentile of pending bytes answer `UNAVAILABLE`, others are still accepted |
| Reports | 20 / day per account, kept 90 days |
| Inactive account | deleted after 365 days without an authenticated connection; never below 30 (boot refuses) |

These bounds make abuse expensive, not impossible (CRYPTO §1).

---

## 7. What the relay stores

| Table | Columns | Bound |
|---|---|---|
| `accounts` | id, username, ik_sig (unique), ik_dh, bind, device_key, generation, discoverable, created_day, last_seen_day | inactive sweep |
| `signed_prekeys` | account, kind (SPK, PQSPK, SSK), id, created_at, key, signature | per kind: active and ≤ 4 future; a replaced key is deleted |
| `one_time_prekeys` | account, kind (OPK, PQOPK), id, created_at, key, signature | per-account caps; deleted when handed out |
| `handed_out` | account, kind, id, seq, day | 15 days |
| `delivery_tokens` | account, token_hash, state (live, sink, inherited), created_day, last_used_day | 5000 per account; inherited ones 45 days unused |
| `invites` | account, secret_hash, expires_at | 5 per account, TTL |
| `pending` | id, recipient, generation, lane (token hash or intro + invite hash + contributor prefix), envelope, received_at | 30 days; per-token, per-intro, per-recipient caps |
| `blobs` | id, recipient, size, upload_key_hash, downloads_left, expires_at | TTL, per-recipient and per-token byte caps; file deleted with the row |
| `reports` | id, sealed, received_at | 90 days, per-account daily cap |
| `barred_usernames` | username_hash, reason (barred or held), until_day | 100 000 rows, oldest removed; held names 31 days |

The contributor prefix of an introduction (its /48 or IPv4 /24, hashed with a
key that changes daily) exists only to enforce the per-prefix share of §6.3 and
is deleted with the envelope. Seen-times are kept to the **day**. Certificates
are signed on request and not stored.

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
| `LUME_TLS_CERT_FILE`, `LUME_TLS_KEY_FILE` | required unless `LUME_DEV` | the relay terminates TLS itself (§1) |
| `LUME_CLIENT_ADDRESS` | required | `direct` (the TCP peer) or `proxy-protocol` (a PROXY v2 header on every connection, refused if absent) |
| `LUME_TRUSTED_PROXIES` | required with `proxy-protocol` | comma-separated CIDR ranges of the load balancer, each inside `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` or `fc00::/7`; anything else is refused at boot. The relay cannot tell whether a range is shared with other customers of the provider, so the operator must not list one that is. A connection from any other peer is closed before a byte of it is read |
| `LUME_DIRECTORY_KEYS_FILE` | required | the current signed directory key list (§2.1); re-read when it changes. An unverifiable list stops the process at boot; an expired one is not served (`UNAVAILABLE`) and is logged until replaced |
| `LUME_DIRECTORY_ROOT_KEY` | required | the root public key the list must verify under, hex |
| `LUME_DISK_QUOTA` | required | bytes the relay may use for its database and blobs |
| `LUME_DIRECTORY_SIGNER` | required | `pkcs11:<uri>` for a hardware module, or `unix:<path>` for a local signer process; a key file is accepted only with `LUME_DEV` |
| `LUME_LISTEN` | `0.0.0.0:443` | with `proxy-protocol` it must be set explicitly to a private address the load balancer reaches; the default, `0.0.0.0`, `::` and public addresses are refused at boot |
| `LUME_DB_PATH` | `./data/relay.db` | |
| `LUME_BLOB_DIR` | `./data/blobs` | |
| `INACTIVE_ACCOUNT_DAYS` | `365` | ≥ 30 |
| `LUME_DEV` | unset | allows `ws://` and a directory key file; refuses to start unless `LUME_HOST` is `localhost` |

Logs carry event names, counts, durations and error codes — never usernames,
account ids, tokens, addresses or envelope bytes.

---

## 9. Versioning

The first byte of every frame is the protocol version. The relay serves one
version at a time; a frame of another version is closed with `4400`. Any change
to a layout here is a new version.
