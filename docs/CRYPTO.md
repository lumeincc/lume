<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# LUME — Cryptography

Status: **draft**, revision 9.
Nothing here is implemented until this document says it is; code that
disagrees with it is a bug in one of the two.

This document specifies every key, derivation and construction LUME uses. It
composes vetted primitives from libsodium and liboqs and invents none. Where a
construction follows a published design, the design is named and the
deviations are listed. The relay protocol is in [PROTOCOL.md](PROTOCOL.md).

---

## 1. Goals and non-goals

**LUME protects:**

- **Message content** against the relay, the network and anyone who later
  obtains the relay's storage — including an adversary who records traffic now
  and has a quantum computer later.
- **Forward secrecy in transit**: once a message key has been used and its
  chain has moved on, taking the device does not decrypt the recorded envelope.
  The exceptions are listed below.
- **Post-compromise security of sessions** against a classical adversary who
  stole session state once and then lost access: the ratchet heals within one
  round trip.
- **Who sent a stored envelope**: the relay stores the recipient, never the
  sender (§9).
- **Group state**: the relay holds no groups, names or member lists (§11).
- **Local data at rest** against someone holding the device's storage but not
  the passphrase, to the degree §10 states per platform.

**LUME does not protect** — stated so it is never mistaken for a claim:

- **Network addresses and live correlation.** The relay sees the address of
  every connection. An operator watching live can correlate sending and
  receiving connections by address and timing, including the moment a delivery
  token is registered and first used (§9.5). Use Tor or a VPN if that matters.
- **Timing and volume per recipient**, and patterns such as one connection
  sending many same-sized envelopes at once, which can suggest a group fan-out.
- **Account existence.** A taken username reads as taken whether or not its
  holder is discoverable. *Non-discoverable* hides an account's keys and closes
  its introduction lane; it does not hide that the name is in use.
- **Names beyond the relay's word.** A contact's username is confirmed by a
  certificate the relay signs (§5.3). Whoever holds the relay's directory key
  can attach a name to the wrong identity until that key is dropped from the
  directory key list — up to 14 days after the drop if the relay withholds the
  new list (PROTOCOL §2.1); the safety number (§12) is the check that does not
  depend on the relay. A certificate given to a contact can also
  be shown by that contact to others as proof that a username belongs to an
  identity.
- **First flights against a later compromise.** The first envelopes of a
  session that used no one-time key are sealed to a signed prekey whose private
  half is kept up to 40 days (§4) — or, if the app is not opened in that time,
  until it is next unlocked; skipped message keys are kept up to 14 days.
  Whoever takes the device within those windows can decrypt such recordings.
  Only the newest message of a backlog travels that way (§5.4).
- **A stolen identity.** Whoever copies the identity secret or the recovery
  phrase can act as that account until its owner creates a new account. There
  is no identity rotation in this version; recovery locks out an old *device*
  (§3.3), not a thief who holds the identity key.
- **Sender identity against a later compromise of the recipient.** A recorded
  envelope reveals its sender to someone who takes the recipient's device while
  the seal key it used still exists — up to 40 days — or while the delivery
  token it arrived on is still mapped to that contact in the vault (§9.5).
- **That a block goes unnoticed.** The relay gives a blocked sender no signal
  (§9.4), but replies and delivery receipts stop, as they would for someone who
  stopped opening the app.
- **That an account recovered.** The generation of a discoverable account is in
  its public certificate, and anyone holding one of an account's delivery
  tokens — a blocked contact too, since a sink answers like a live token (§9.4)
  — can read it from a bundle or seal key. Either way they learn when it
  recovered on a new device (§3.3), and nothing else.
- **Deleted data on flash storage.** The vault overwrites what it deletes
  (§10.6), but flash memory can keep earlier copies of a block beyond any
  application's reach. Someone who later has the device *and* the passphrase may
  recover messages that were deleted.
- **Post-quantum post-compromise security.** The handshake is hybrid
  post-quantum; the ratchet's healing steps are classical X25519 (§6.7).
- **Mass abuse by a well-funded attacker.** Proof of work, per-prefix limits and
  quotas (PROTOCOL §6) make abuse cost something, not impossible. Many address
  allocations or patient account farming can still degrade the relay for
  everyone; unlinkable rate-limit tokens are planned, not built.
- **The authenticity of a report.** A report is what the reporter says they
  received; this version cannot prove that a reported message was sent.
- **A hostile local process on Windows** can exhaust the TPM's dictionary-attack
  counter and so stop the vault from unlocking until the TPM recovers (§10.2).
- **A compromised device.** Malware running as the user reads what the user
  reads.

---

## 2. Primitives

| Name in this document | Primitive | Library call |
|---|---|---|
| `SHA256`, `SHA512` | SHA-2 | `crypto_hash_sha256`, `crypto_hash_sha512` |
| `HMAC(k, m)` | HMAC-SHA256 | `crypto_auth_hmacsha256_*` |
| `HKDF(salt, ikm, info, L)` | HKDF-SHA256, RFC 5869 | `crypto_kdf_hkdf_sha256_extract` / `_expand` |
| `DH(sk, pk)` | X25519, RFC 7748 | `crypto_scalarmult`; **a non-zero return (low-order point) aborts the operation**, and **a public key that is not canonical** — top bit set, or not below 2^255 − 19 — is refused wherever one arrives from another party. That still leaves keys that differ and give the same results: X25519 multiplies by a multiple of 8, so `pk` and `pk` plus a point of small order — for the point of order 2, `1/u` — agree with every private key. No construction relies on one key having one value; each one that must tell keys apart hashes their exact bytes (§5.1) |
| `Sign`, `Verify` | Ed25519, RFC 8032 | `crypto_sign_detached`, `crypto_sign_verify_detached`; **a public key outside the prime-order subgroup is refused** (`crypto_core_ed25519_is_valid_point`), so one private key has one public key |
| `AEAD(k, n, ad, m)` | XChaCha20-Poly1305-IETF | `crypto_aead_xchacha20poly1305_ietf_encrypt` / `_decrypt` |
| `Stream` | XChaCha20-Poly1305 secretstream | `crypto_secretstream_xchacha20poly1305_*` |
| `KEM` | ML-KEM-768, FIPS 203 (final) | liboqs `OQS_KEM_ml_kem_768_*` |
| `PWHash` | Argon2id v1.3 | `crypto_pwhash`, `crypto_pwhash_ALG_ARGON2ID13` |
| `Random(n)` | OS CSPRNG | `randombytes_buf`; liboqs is configured to draw from it too |
| `Eq(a, b)` | constant-time equality | `sodium_memcmp` |

**Versions.** libsodium ≥ 1.0.19 (the HKDF-SHA256 API). liboqs **≥ 0.12.0**:
0.10.x implements the FIPS 203 *draft*, which does not interoperate with the
final standard, and 0.10.0 has a secret-dependent branch in ML-KEM
decapsulation under Clang 15–18 (CVE-2024-36405). Both versions are pinned in
the vcpkg baseline; liboqs is built with ML-KEM-768 only and without OpenSSL.

**Self-test.** At start-up the core checks SHA-2, HMAC, HKDF, X25519 (including
rejection of low-order points), Ed25519 (including rejection of a small-order
public key), the AEAD (including rejection of a forged tag) and ML-KEM-768 (key
generation from a seed, encapsulation, decapsulation and implicit rejection)
against known answers, an AEAD and an ML-KEM round trip, and that both random
generators produce fresh output. Every primitive passes through one gate that
runs the self-test once: until it has passed, nothing is generated, signed or
decrypted, and if it failed, every call fails.

**ML-KEM input check.** `Encaps` refuses an encapsulation key that fails the
FIPS 203 §7.2 modulus check; liboqs performs the check and the test suite
proves it with Wycheproof's modulus-overflow vectors.

### 2.1 Conventions

- `‖` is concatenation, used only in inputs to a hash, KDF, MAC or signature.
  Integers are unsigned big-endian: `u8 u16 u32 u64`.
- `lp(x) = u32(len(x)) ‖ x`. Every variable-length value inside a hashed,
  signed or MACed input is length-prefixed.
- `L(name) = lp("LUME/v1/" ‖ name)`. Every label is length-prefixed, so no label
  is a prefix of another input. Labels are listed in §13; each is used in
  exactly one place.
- `enc(x)` is the canonical encoding of a structured value by `core/wire`. Every
  structure named in this document has its field layout in
  [PROTOCOL.md §3.2](PROTOCOL.md#32-shared-structures); every structured value
  that crosses a trust boundary — on the wire or in storage — uses it.
- Secret material lives in `SecretBytes` (sodium_malloc, guard pages, wiped on
  release). Many keys of one kind that live together — a session's skipped
  message keys, its skipped header keys — share one `SecretBytes` each, so their
  number does not multiply the guard pages. Values that exist only inside one
  function call — a recovery-phrase word while it is looked up, its index, an
  intermediate bit buffer — sit on the stack and in registers and are not wiped.
- **Private keys are held as seeds**: Ed25519 as its 32-byte seed, ML-KEM-768 as
  its 64-byte seed `d ‖ z` (FIPS 203 §7.1). The expanded forms exist only inside
  one signing or decapsulation, so a stored key cannot be half-replaced.
- **`AEAD` always draws its own nonce**, `n = Random(24)`, and every use stores
  it next to the ciphertext — as `n ‖ AEAD(k, n, ad, m)` or in a structure's
  `nonce` field; no caller chooses a nonce. A plaintext is at most
  128 KiB, checked before anything is allocated; larger data uses `Stream`
  (§11.1).
- Times are seconds since the Unix epoch. "Now" is checked with 5 minutes of
  allowed clock skew.
- **Generation** always means the account's device generation (§3.3). The
  vault's own counter is its **epoch** (§10.5).

---

## 3. Identity

### 3.1 Recovery phrase

An account is created from **256 bits of entropy** `E = Random(32)`, shown as a
**24-word BIP39 mnemonic** (English wordlist, 8-bit checksum). BIP39 is used
only as an encoding of `E`; its PBKDF2 seed function is not run. A phrase whose
checksum fails is rejected before anything is derived.

**What a phrase may look like.** It is encoded as the 24 lowercase words
separated by single spaces. On input, ASCII letters in either case are
accepted, words are separated by any run of spaces, tabs, carriage returns or
line feeds, and leading or trailing whitespace is ignored. There must be exactly
24 words, each a whole word of the list — no four-letter abbreviations. Any
other byte, a non-breaking space or other Unicode included, is refused. Errors
are reported in a fixed order: a character outside that set, then a word count
other than 24, then a word not in the list, then a failed checksum. Looking a
word up or choosing one never branches on, or indexes memory with, its position
in the list; word lengths and spacing are not hidden.

### 3.2 Identity keys

```
root    = HKDF(salt = L("identity/salt"), ikm = E, info = L("identity/root"), 32)
IKsig   = crypto_sign_seed_keypair(HKDF(0^32, root, L("identity/ed25519"), 32))
IKdh.sk = HKDF(0^32, root, L("identity/x25519"), 32)
IKdh.pk = crypto_scalarmult_base(IKdh.sk)
bind    = Sign(IKsig.sk, L("identity/bind") ‖ IKsig.pk ‖ IKdh.pk)
```

An identity is the **pair** `(IKsig.pk, IKdh.pk)`, bound by `bind`. Every
check, pin and safety number covers both halves. The relay keeps `IKsig.pk`
unique across accounts; it does not index `IKdh.pk`, so nobody can block a
registration by claiming someone else's exchange key.

### 3.3 Device key and generation

Each installation creates a random Ed25519 **device key** `DK` and a
certificate for it:

```
cert = Sign(IKsig.sk, L("device") ‖ DK.pk ‖ u32(generation))
```

The relay authenticates connections with `DK` and accepts only the device key
and generation it has on record. A new account has generation 1. Recovering the
phrase on a new device registers **exactly the current generation + 1**
(PROTOCOL §4.2): the relay then closes the old device's connections, refuses its
key, and purges the envelopes, prekeys and seal keys of the old generation,
which the new device could not open anyway. One device per account in this
version. A recovered device starts with no contacts and no block list: contacts
reach it again on their own (§9.3). The relay keeps the tokens of blocked
contacts as sinks, but the device's own block list, by identity, has to be
rebuilt.

A client takes a peer's generation only from a signed prekey that covers it
(§4) — an `Introduction`'s generation counts only if its `seal_key` verifies
under it — and never lets it go down.

---

## 4. Prekeys

| Key | Type | Kind | Used for |
|---|---|---|---|
| `SPK` — signed prekey | X25519 | 1 | the handshake (§5) |
| `PQSPK` — last-resort KEM prekey | ML-KEM-768 | 2 | the handshake, when no one-time KEM key is left |
| `PQOPK` — one-time KEM prekey | ML-KEM-768 | 3 | one handshake |
| `SSK` — seal key | X25519 | 4 | sealed sender (§8) |
| `OPK` — one-time prekey | X25519 | 5 | one handshake; unsigned |

```
sig = Sign(IKsig.sk, L("prekey") ‖ u8(kind) ‖ u32(id) ‖ u64(created_at) ‖ u32(generation) ‖ lp(public_key))
```

The signature covers the account's generation (§3.3), so only the identity key
can say that an account recovered: the relay cannot claim a new generation for
which it was given no signed key. Wherever a signed prekey travels — a bundle,
a seal key, a card, an introduction, a group acceptance, a seal-key update
inside a session — the generation its signature covers travels with it, and
the key is checked under that generation; the relay checks uploads under the
account's current one.

**Signed rotating keys** (`SPK`, `PQSPK`, `SSK`) are each active for 7 days from
their `created_at`. A client uses one only if its `created_at` is not in the
future and not more than **9 days** past; a fetched key outside that window is
refused, and a cached `SSK` older than 7 days is refreshed before use (§8). The
private half is deleted once it is more than **40 days** past its
`created_at` — 9 days of use plus the 30-day relay retention plus a day of
margin. Time alone decides: no envelope sealed to the key can still be waiting
on the relay by then, and nothing the relay does can keep the key alive longer.
Deleting needs the unlocked vault, so a key outlives its 40 days only until the
app is next unlocked. The 9 days are judged by the sender's clock and the 40 by
the recipient's: a sender whose clock is behind by more than the day of margin
can seal to a key whose private half is gone when the envelope arrives. That
envelope cannot be opened and gets no receipt; like any unacknowledged message
it is resent (§7.2) and arrives once the sender's clock is right again. Only
delivery suffers, never secrecy.

**One-time keys** (`PQOPK`, `OPK`) have no age limit: a one-time key is valid
while it is published, as long as its `created_at` is not in the future.

**Pre-signed generations.** Rotation needs `IKsig.sk`, which exists only while
the vault is unlocked. So on every unlock the client withdraws the generations
that start more than a day later, deletes their private halves, and uploads
fresh ones up to four weeks ahead of each rotating kind. Their `created_at`
values continue the active key's schedule — `created_at` of the active key
plus 7, 14, 21 and 28 days — so frequent unlocks never stretch a rotation past
§4's 9 days; the relay serves each from its
`created_at` on and refuses uploads more than 31 days ahead. A user who opens
the app at least once every four weeks never becomes unreachable, and a device
compromise exposes only the generations created since the last unlock.

**Ids** are random 32-bit values, checked against the ids already used for that
kind in the vault.

**One-time key lifecycle.** At most 100 `OPK` and 50 `PQOPK` are published. The
relay hands out at most 4 of each per hour per target account, and never to a
request that used a delivery token as access (PROTOCOL §4.3). The client learns
which ids were handed out and:

- processes pending deliveries **before** replenishing, so a key that a waiting
  first message needs is not discarded;
- treats every one-time key it published before the last 15 days as handed
  out when it has not listed hand-outs in that time, since the relay forgets
  them after 15 days (PROTOCOL §4.2), and withdraws those still published;
- deletes a handed-out private half when a handshake uses it, or **14 days**
  after hand-out if none arrives — after 14 days without a reply the initiator
  starts over from a fresh bundle (§5.4);
- holds at most 1 500 private halves per kind, and when it must evict, evicts
  only keys already handed out, oldest first; a key still published is first
  withdrawn from the relay, then deleted. At 4 hand-outs an hour for 14 days
  plus a full published stock the cap is not reached by draining alone.

---

## 5. Handshake — PQXDH

Follows Signal's PQXDH specification, revision 3, with LUME's two-key identity.
Alice starts a session with Bob.

**Deviations from PQXDH:**

- The identity is two keys bound together (§3.2), not one XEdDSA key, so `AD`
  carries both keys of each side.
- HKDF's `info` is `L("pqxdh")` followed by the hash of the whole transcript,
  `TH`, instead of a fixed string, and `AD` ends with `TH`. A header that
  differs from Alice's in any byte therefore derives other keys, even where
  X25519 alone would not notice (§2).
- HKDF produces 96 bytes: `SK` and the two header keys the ratchet's header
  encryption starts with (§6.3).
- Bob keeps a replay guard for handshakes that used no one-time key (§5.4);
  PQXDH leaves replays to the application.
- Non-canonical X25519 keys are refused (§2).

### 5.1 Alice

1. Obtain Bob's bundle (PROTOCOL §4.3) or an introduction card from him (§11.2):
   `IKsig_B, IKdh_B, bind_B, SPK_B, PQPK_B (kind 2 or 3), SSK_B, [OPK_B]`.
2. **Verify before computing anything**: `bind_B`, every signature, every
   `created_at` against §4, and that the bundle's generation is not below the
   one Alice already holds for Bob (§3.3). If Bob is pinned, `(IKsig_B, IKdh_B)`
   must equal the pin — anything else is a refusal, not a warning.
3. `EK_A` = fresh X25519 key pair.
4. ```
   DH1 = DH(IKdh_A.sk, SPK_B)      DH2 = DH(EK_A.sk, IKdh_B)
   DH3 = DH(EK_A.sk,  SPK_B)       DH4 = DH(EK_A.sk, OPK_B)     if an OPK was given
   (CT, SS) = KEM.Encaps(PQPK_B)
   ```
5. ```
   TH              = SHA256(L("transcript") ‖ IKsig_A ‖ IKdh_A ‖ EK_A ‖ IKsig_B ‖ IKdh_B
                            ‖ SPK_B ‖ [OPK_B] ‖ PQPK_B ‖ CT)
   IKM             = 0xFF^32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ [DH4] ‖ SS
   (SK, HKa, NHKb) = HKDF(0^32, IKM, L("pqxdh") ‖ TH, 96)
   AD              = L("ad") ‖ IKsig_A ‖ IKdh_A ‖ IKsig_B ‖ IKdh_B ‖ TH
   ```
   Every key in `TH` is the exact public-key bytes, as sent or published; all
   have fixed sizes, so whether `OPK_B` is present follows from the length.
   Then wipe `EK_A.sk`, `DH1…DH4`, `SS`, `IKM`.
6. Initialise the ratchet as Alice (§6.3).

### 5.2 Initial header

```
InitialHeader { ik_sig, ik_dh, bind, ek, ct, spk_id, pq_kind, pq_id, opk_id: opt<u32> }
```

Until Alice has received a message from Bob, every envelope she sends in the
session carries it.

### 5.3 Introduction

Each side puts an `Introduction` in the content of every message it sends in a
session (§7) until it has seen an envelope arrive on the delivery token it
issued in that introduction. A lost or evicted envelope on either side
therefore strands nothing.

```
Introduction { account_id, generation, token, seal_key, certificate: opt<UsernameCertificate> }
```

`account_id` and `generation` are what the peer needs to address replies;
`token` is the delivery token issued to the peer (§9); `seal_key` is the
sender's current `SSK`. Because the introduction is inside the ratchet
plaintext, it is authenticated by the session.

**The name is checked offline.** `certificate` is signed by the relay's
directory key (PROTOCOL §2.1). Alice fetches her own on her authenticated
connection, which reveals nothing about Bob. Bob shows the username only if:
the certificate's directory key is on the client's current directory key list
(PROTOCOL §2.1) and inside that key's window; its `issued_at` is not in the
future, it has not expired and it expires no more than 31 days from now; its
`ik_sig` and `ik_dh` equal the session's peer identity; and its
`account_id` equals the introduction's. Otherwise he shows "unverified contact"
with the safety number. He makes no request to the relay to check a name, so
checking reveals nothing either.

The seal's sender hint (§8) must equal `ik_sig` of the initial header, or the
envelope is dropped.

### 5.4 Bob

1. Verify `bind_A`. If Alice is pinned, `(IKsig_A, IKdh_A)` must match.
2. If a session with Alice already holds this `(EK_A, CT)`, the envelope belongs
   to it — Alice is repeating her header — and is decrypted there under the
   ratchet's own rules.
3. Otherwise look up the private prekeys by kind and id; an unknown id aborts.
4. **Replay guard.** When no one-time key was used, reject an initial header
   whose `SHA256(EK_A ‖ CT)` was already accepted under the same `SPK`/`PQSPK`.
   The set is dropped with the key. A replay that changes `EK_A` or `CT` to get
   past the tag — even to a key that gives the same X25519 results, such as
   `1/u` (§2) — changes `TH`, so Bob derives other keys, Alice's first message
   does not authenticate in step 5, and nothing is stored.
5. Recompute `SK, HKa, NHKb, AD`, initialise the ratchet as Bob (§6.3), and
   decrypt **on a scratch copy**. Only if it authenticates: store the session,
   delete the used one-time private keys, pin Alice. Otherwise discard
   everything; no prekey is consumed by a forged envelope.

If Alice receives nothing in a session for 14 days, or learns that Bob's
generation went up (§3.3), she starts a new session from a fresh bundle and
makes the old one **receive-only**: it still decrypts what arrives for 30
days, then it is deleted. In the new session she sends only her newest
unacknowledged message until Bob has answered in it; the rest follow once his
reply has moved the ratchet on (§7.2). A backlog is therefore never sent as
first flights, whatever the relay does to provoke a restart.

### 5.5 Sessions per contact

A client sends in the **newest** session in which it has received a message
from the peer, or, if none has received yet, in the newest session it
initiated. If both sides started sessions at the same time and each has
received in the other's, the one initiated by the identity with the
lexicographically lower `IKsig.pk` is used. Every other session is receive-only
and deleted 30 days after it stopped being used. A session made receive-only by
§5.4 is never sent in again, even if it is the newest to have received. A contact has at most three
sessions; a fourth makes the oldest receive-only session go first.

### 5.6 Why hybrid

`SK` is secure if **either** X25519 **or** ML-KEM-768 is. An adversary who
records the first message today and breaks X25519 later still lacks `SS`; a
flaw in the newer KEM still leaves the classical exchange.

---

## 6. Double Ratchet with header encryption

Follows Signal's Double Ratchet specification, §4 "Double Ratchet with header
encryption", with XChaCha20-Poly1305 as the AEAD.

**Deviations from the Double Ratchet specification:**

- `ENCRYPT` uses `MK` directly as the AEAD key with a random 24-byte nonce
  (§2.1), instead of deriving a key and IV from `MK` with HKDF.
- The first header keys come from the handshake (§5.1), and `KDF_RK` is HKDF
  with the label as `info`.
- The skipped-key store has fixed bounds and a lifetime (§6.6), and expired
  keys are deleted without waiting for a message.
- Nothing is written to the state until a message's body authenticates (§6.5).

### 6.1 State

`DHs`, `DHr`, `RK`, `CKs`, `CKr`, `HKs`, `HKr`, `NHKs`, `NHKr`, `Ns`, `Nr`,
`PN`, the skipped-key store, `AD`, and whether a message has been received. The
session record that holds this state adds the handshake's `(EK_A, CT)` (§5.4)
and whether the session is receive-only (§5.5). Both are serialised only into
the vault.

The skipped-key store groups keys by receiving chain: for each chain its header
key and `DHr`, then each skipped message number with the time it was stored and
its `MK`, oldest first.

### 6.2 KDFs

```
KDF_RK(RK, dh) = HKDF(salt = RK, ikm = dh, info = L("ratchet/root"), 96) → (RK', CK, NHK)
KDF_CK(CK)     = (CK' = HMAC(CK, 0x02), MK = HMAC(CK, 0x01))
```

### 6.3 Initialisation

**Alice**, after §5.1:

```
DHs = fresh X25519 key pair          DHr = SPK_B
(RK, CKs, NHKs) = KDF_RK(SK, DH(DHs.sk, SPK_B))
HKs = HKa       NHKr = NHKb          CKr = HKr = none        Ns = Nr = PN = 0
```

**Bob**, in §5.4:

```
DHs = a copy of the SPK_B key pair   DHr = none
RK = SK         NHKs = NHKb          NHKr = HKa              CKs = CKr = HKs = HKr = none
Ns = Nr = PN = 0
```

Bob's copy of `SPK_B` lives in the session only until his first DH ratchet step
(§6.5 step 3), which Alice's first message triggers; it is then replaced and
wiped.

### 6.4 Encrypting

```
(CKs, MK)  = KDF_CK(CKs)
hn         = Random(24)
enc_header = hn ‖ AEAD(HKs, hn, AD, enc(Header { dh: DHs.pk, pn: PN, n: Ns }))
mn         = Random(24)
body       = mn ‖ AEAD(MK, mn, AD ‖ enc_header, enc(content))
message    = RatchetMessage { enc_header, body }
Ns += 1;   wipe MK
```

### 6.5 Decrypting

First, skipped keys past their lifetime are deleted (§6.6) — the one change a
failed decryption keeps. Everything after is computed on scratch values, and
nothing in the state is written until the body authenticates; memory the
commit needs is reserved before that, so the commit cannot fail halfway. Any
other failure leaves the session exactly as it was. Trying header keys writes
nothing, so a forged envelope costs at most ten AEAD attempts and no copy of
the state.

1. Try each distinct header key in the skipped store once; if one opens
   `enc_header` and holds a key for `(dh, n)`, decrypt with it and delete it.
2. Else open `enc_header` with `HKr`. If it opens and `dh = DHr`: if `n < Nr`
   and no skipped key exists, **reject**; otherwise skip to `n`.
3. Else open it with `NHKr`. If it opens: store skipped keys up to `pn` in the
   current receiving chain, then
   ```
   PN = Ns;  Ns = Nr = 0;  HKs = NHKs;  HKr = NHKr;  DHr = header.dh
   (RK, CKr, NHKr) = KDF_RK(RK, DH(DHs.sk, DHr))
   DHs = fresh X25519 key pair
   (RK, CKs, NHKs) = KDF_RK(RK, DH(DHs.sk, DHr))
   ```
4. Else reject.
5. Derive `MK`, open the body with `AD ‖ enc_header`, commit, wipe `MK`.

### 6.6 Bounds

| | Value | Why |
|---|---|---|
| Skips in one step | 256 | larger `n − Nr` or `pn − Nr` is rejected before deriving any key |
| Skipped keys per session | 1024, oldest evicted | bounds memory and vault size: about 32 KiB of keys in one locked allocation |
| Skipped keys per session the user has not accepted — a first contact on the introduction lane or a request (§9.3) | 32, oldest evicted | a stranger's envelopes cannot make the recipient hold more |
| Such unaccepted sessions | 50 in all, oldest deleted first | matches the relay's queue of pending introductions (PROTOCOL §6) |
| Distinct header keys in the skipped store | 8, oldest chain evicted | bounds trial decryptions per incoming header |
| Skipped key lifetime | 14 days | deleted at every unlock, at least once a day while the app runs, and before every decryption, whether or not messages arrive |
| Sessions per contact | 3 (§5.5) | bounds trial decryptions across sessions |

### 6.7 What the ratchet heals against

The first `RK` descends from the hybrid `SK`, and every later `RK` mixes the
previous one in, so a passive recording stays protected by the post-quantum
secret. Healing after a compromise uses fresh X25519 only. A sparse
post-quantum ratchet is a candidate for a later version, not this one.

---

## 7. Message content

### 7.1 Content

The ratchet plaintext is always

```
Content { id: bytes[16], kind: u8, introduction: opt<Introduction>, body: bytes≤67000 }
```

`id` is random and identifies the message across resends and sessions. `kind`
says what `body` is: a text message, an attachment reference, a group message, a
delivery receipt, a seal-key update, a token update, a typing indicator, and so
on — the list is in the client specification. Unknown kinds are ignored.

### 7.2 Receipts, resending and duplicates

A recipient answers with **delivery receipts**: one `Content` of kind
"receipt" listing up to 256 message ids it has durably stored, sent at most once
a minute per contact and only to the message's sender, also in groups. A
receipt is resent whenever a duplicate of an already received message arrives.

A sender keeps the content of every message without a receipt for up to 30
days. It resends it after 1 hour, 4 hours, 24 hours and 7 days; after that only
when something shows it is missing — a receipt from the contact for a later
message but not for this one, acted on at most once a day — and when a new
session starts (§5.4). A send the relay answers with a transient error is not a
resend: it is retried with backoff. Each resend is a new ratchet message, freshly
sealed, so two resends cannot be linked by their bytes. Resends that fall due
while §5.4 holds a backlog wait with it. A send the relay refuses for good —
`NOT_ACCEPTED`, `NOT_FOUND`, `TOO_LARGE`, `MALFORMED` — is not retried; the
message is marked as not delivered. While its recipient is
away a message is therefore at most five envelopes on the relay, one more for
each session restart. A recipient keeps the ids it has seen for 31 days and
discards any content whose id it already has, whatever session it arrives in.
Resending never produces a duplicate on screen, and a message lost to
eviction, a relay crash or a recovery comes back within the 30 days once the
recipient is reachable again.

### 7.3 Padding

The relay sees only sealed envelopes (§8), so padding is applied once, to the
sealed plaintext:

```
pad(m) = m ‖ 0x80 ‖ 0x00…        to the smallest bucket ≥ len(m) + 1
buckets: 2048, 4096, 8192, 16384, 32768, 65536, 69632 bytes
```

Unpadding scans from the end for `0x80` after zero bytes and rejects anything
else. Padding hides the exact length of a message, not whether it carries a
handshake: an envelope with an initial header and introduction has about 1.6 KB
more fixed overhead than an ordinary one, which lands it in a larger bucket for
some content lengths. Content above about 64 KiB goes as an attachment (§11).

---

## 8. Sealed sender

The ratchet message is sealed to the recipient's current seal key `SSK_B`, so
the relay never learns who sent it. A client seals an envelope when it sends
it: an outbox keeps content in the vault, never sealed envelopes, so the 40-day
arithmetic of §4 holds.

```
ES     = fresh X25519 key pair, one per envelope
k      = HKDF(salt = ES.pk ‖ SSK_B.pk, ikm = DH(ES.sk, SSK_B.pk), info = L("seal/key"), 32)
ad     = L("seal/ad") ‖ u8(1) ‖ u32(SSK_B.id) ‖ ES.pk ‖ SSK_B.pk
nonce  = Random(24)
sealed = enc(Seal { version: 1, ssk_id, es: ES.pk, nonce, box: AEAD(k, nonce, ad, pad(enc(inner))) })
inner  = Inner { sender: IKsig_A, initial: opt<InitialHeader>, message: RatchetMessage }
```

The recipient computes the same `k` from `DH(SSK_B.sk, ES.pk)`.

The seal **hides** the sender; it does not authenticate them. Bob finds the
session for the hinted `IKsig_A`, and the ratchet's AEAD — whose `AD` contains
both identities — fails unless the message really came from that session.

**Which seal key.** A sender uses the seal key it last received from the
recipient — from a bundle, a card, an introduction, or a seal-key update inside
the session — as long as it is within the §4 window. When the cached key is
more than 7 days past its `created_at`, the sender first fetches the current
one from the relay with its delivery token (PROTOCOL §4.3).

**Forward secrecy of the sender.** A seal key's private half is deleted 40 days
after its `created_at` (§4), so a recorded
envelope stops revealing its sender to someone who later takes Bob's device or
phrase after that. The seal is classical X25519; a quantum adversary who records
envelopes could later learn *who* sent them, not *what* they said.

---

## 9. Delivery tokens and blocking

### 9.1 Issuing and rotating

- A token is `T = Random(32)`. The relay stores only `SHA256(L("token") ‖ T)`
  under the issuer's account, but it **sees `T` itself** in every request that
  presents it, and so does whoever terminates TLS for the relay (PROTOCOL §1).
- Alice issues `T_BA` in her `Introduction`; Bob issues `T_AB` in his. Each
  sends to the other on the token the other issued.
- Clients keep a **pool of about 20 unused tokens**, registered in small batches
  at random times, and draw from it for new contacts.
- Tokens rotate every 30 days: the new one is sent inside the session, and the
  old one is revoked only after an envelope has arrived on the new one.

### 9.2 Checks the client makes

- An envelope delivered on token `T` whose authenticated sender is not the
  contact `T` was issued to is **dropped**. Nothing is revoked: revoking on a
  mismatch would let anyone who learned `T` silently cut the real contact off.
- An envelope delivered on the **introduction lane** must carry an
  `InitialHeader`; one that does not is dropped.
- Every envelope whose authenticated sender is on the local **block list**
  (identities, not usernames) is dropped, whatever lane it came on.

### 9.3 After recovery

The new vault does not know which contact a token belongs to. An envelope that
carries an `InitialHeader` on an unknown token is shown as a request — "this
identity wants to continue a conversation" — and the token is bound to that
sender only when the user accepts. Tokens the relay kept from before the
recovery and that are not used within 45 days are deleted by the relay
(PROTOCOL §4.2).

### 9.4 Blocking

Blocking turns the contact's token into a **sink** and adds their identity to
the block list. The relay answers a sink token **exactly as a live one** in
every request — sending, fetching a bundle, an identity or a seal key — and
silently discards envelopes that arrive on it; quotas are charged on the bytes
presented, whether or not they are kept. Blobs are the exception that proves
the rule: an uploader can download its own blob, so a blob uploaded on a sink
token is stored and served like any other and expires unread. It counts against
that token's own limits and in that token's answers, never against what the
recipient's other tokens may store (PROTOCOL §4.7). No cap, eviction or `UNAVAILABLE` answer
depends on whether a token is a sink. A blocked sender therefore gets
no signal from the relay. Revoking a token outright is used only for rotation
(§9.1), when the contact already holds the replacement.

### 9.5 What the relay and the vault learn

For an undelivered envelope the relay holds `(recipient, token hash or
"intro", sealed bytes, time)`: given only its database, the sender cannot be
identified. A token is a stable pseudonym for one contact of one recipient while
it lives; the relay can count envelopes per pseudonym and pseudonyms per
recipient, and a live operator can try to match pseudonyms across rotations by
timing. On the recipient's side the vault maps tokens to contacts, so whoever
unlocks the vault learns the sender of any recorded envelope that arrived on a
token still mapped.

---

## 10. Vault — data at rest

### 10.1 Keys

```
salt    = Random(16), fresh for every vault
Kpw     = PWHash(passphrase, salt, ops, mem)
Khw     = HW(Kpw)                                                  §10.2
KEK     = HKDF(salt = Khw, ikm = Kpw, info = L("vault/master"), 32)
VK      = Random(32), the vault key, stored only as AEAD(KEK, nonce, L("vault/data-key"), VK)
K_rec   = HKDF(0^32, VK, L("vault/record-key"), 32)
K_check = HKDF(0^32, KEK, L("vault/check-key"), 32)
K_man   = HKDF(0^32, VK, L("vault/manifest-key"), 32)
K_root  = HKDF(0^32, VK, L("vault/root-key"), 32)
```

Each derived key has one job. Records are encrypted under keys derived from
`VK`, which never changes; a new passphrase or a new hardware key re-wraps `VK` and re-encrypts
nothing else.

### 10.2 Hardware binding per platform

`HW` is evaluated inside hardware with a key that cannot be exported, so every
passphrase guess has to run on the original device.

| Platform | `HW(x)` | What a guess costs |
|---|---|---|
| Android, Keystore at TEE or StrongBox level | HMAC-SHA256 with a non-exportable Keystore key created with `setUnlockedDeviceRequired(true)` | a Keystore operation on this unlocked device |
| Windows with a TPM 2.0 | `SHA256(L("vault/tpm") ‖ ECDH(K_tpm, P))`, where `K_tpm` is a non-exportable P-256 key in the Microsoft Platform Crypto Provider whose TPM usage authorisation is the raw 32 bytes of `HKDF(0^32, x, L("vault/tpm-pin"), 32)`, set through `NCRYPT_PCP_USAGEAUTH_PROPERTY`, and `P` is a public point stored in the vault header | a TPM operation, and every wrong guess counts towards the TPM's dictionary-attack lockout |
| Anything else | **software only**: a DPAPI-protected random `Khw` on Windows, an app-private random `Khw` on Android | nothing beyond Argon2id once the secret is read |

**What the TPM adds.** `K_tpm` and `P` are fixed, so on Windows `HW(x)` is a
per-device constant that the TPM releases only for the right `x`. It binds the
vault to the device and makes every guess pay a TPM operation and a lockout
count; it adds no entropy, and the passphrase enters the vault key only through
`Kpw` (§10.1). That guess cost holds only because the usage authorisation is the
TPM object's own authValue, checked inside the TPM: the Windows test suite
proves that a wrong value fails with the TPM's authorisation error and advances
the dictionary-attack counter. `P` is checked to be a point on P-256 other than
the identity before the TPM sees it, and a header whose `P` fails is refused.
At setup the vault creates `K_tpm`, sets its usage authorisation and performs
one ECDH; if the provider cannot do all three, the device is treated as
software only. A passphrase change creates a new `K_tpm` and `P`, commits the
header re-wrapped under them, and only then deletes the old key — so a crash
leaves a vault that opens, and an authorisation value that leaked once is
worthless afterwards.

Android reporting a `SOFTWARE` security level, and a TPM without ECC support,
are treated as software only. Software-only mode is shown to the user, never
entered silently, and raises the passphrase minimum from 10 to 14 characters.

**TPM lockout is its own state.** When the TPM refuses because of its
dictionary-attack lockout, the app says so, shows when to try again, makes no
further TPM calls until then, and never offers recovery — a correct passphrase
would have worked, and recovery would cost the history and every contact's
session. Two caveats belong to the platform, not to LUME: the lockout counter is
shared by everything on the TPM, so a hostile local program can trigger it
(§1); and whoever holds the TPM's lockout authorisation — on managed machines
often an administrator — can reset the counter.

**Hardware key lost.** Clearing the TPM, resetting the device, or Keystore
losing its key leaves the vault unopenable. The app reports "hardware key
missing", distinct from a wrong passphrase, and the way back is the recovery
phrase.

### 10.3 Header

```
VaultHeader { version, salt, ops, mem, hw_mode, tpm_point: opt<bytes[65]>, wrapped_data_key, epoch, check }
check = HMAC(K_check, L("vault/check") ‖ enc(header without check))
```

`ops` and `mem` must lie between the floor and the ceiling; anything outside is
an integrity error. A wrong passphrase fails `check`.

| | `ops` | `mem` |
|---|---|---|
| Android default | 3 | 64 MiB |
| Desktop default | 3 | 256 MiB |
| Floor | 2 | 64 MiB |
| Ceiling | 10 | 1 GiB |

### 10.4 Records and manifest

```
record = nonce ‖ AEAD(K_rec, nonce, L("vault/record") ‖ u8(type) ‖ lp(id) ‖ u64(counter), payload)
root   = Σ HMAC(K_root, L("vault/root") ‖ u8(type) ‖ lp(id) ‖ u64(counter))  mod 2^256, over the type's live records
tag    = HMAC(K_man, L("vault/manifest") ‖ enc(Manifest { epoch, types: list<{ type, count, root }> }))
```

`root` is updated incrementally — subtract a record's term, add the new one — so
a write does not rehash the type, and because the terms are keyed, nobody
without the vault keys can produce a matching root for a different set of
records. A record holds at most 128 KiB (§2.1); collections that can grow beyond it —
the seen message ids, skipped message keys, a long history — are split into
records by contact and by day. A record write and its manifest update are
**one SQLite transaction**,
so a crash leaves both or neither. On unlock the vault recomputes every root; a
missing, extra or older record is an **integrity error**: the vault stops
writing for the session and says so, never treating a record as empty. The user
can then export everything that still authenticates and start again from the
recovery phrase.

### 10.5 Rollback

The vault **epoch** increases on every unlock. On Android the epoch is part of
the Keystore key alias: unlock creates the key for epoch `e + 1`, re-wraps `VK`
under it and commits the header, and only then deletes the key for epoch `e`. An
older copy of the vault file then finds no key for its epoch while a newer one
exists, which is reported as rollback. Restoring a full device image —
Keystore included — defeats this. On Windows rollback is not detected in this
version.

A vault belongs to one identity. Creating or recovering a different identity
opens a new vault with a new salt and never reads another's records.

### 10.6 Deletion, lock and wipe

The vault database runs with `secure_delete=ON` and in WAL mode with a
`wal_checkpoint(TRUNCATE)` after every delete, so deleted records are
overwritten in the database and the log; flash wear-levelling can still keep
older copies (§1). The vault locks after 15 minutes without interaction: the
keys of §10.1 and every decrypted key are wiped from memory. Panic wipe deletes
the vault and the hardware key; whether a copy of the vault taken earlier can
still be unlocked depends on whether the deleted hardware key survives in flash
or in a backup of the platform's key store, which LUME cannot guarantee.

---

## 11. Attachments and groups

### 11.1 Attachments

Each file gets a fresh 32-byte key. The plaintext is padded with Padmé to
`P(len)`, with zero bytes; its true length travels inside the message, and
unpadding checks that every padding byte is zero. It is encrypted with
`Stream` in 64 KiB chunks; the last chunk is tagged `FINAL` and any data after
it is rejected. The relay accepts at most 25 MiB, which bounds the plaintext to
the largest length whose padded, encrypted size — 24 bytes of stream header
plus 17 bytes per chunk — fits. Key, true length and `SHA256(ciphertext)`
travel in a normal message. A group attachment is uploaded once, with a
download allowance of twice the group's size, and referenced from every
member's envelope.

### 11.2 Groups

Groups are **client-side fan-out**: a group message is sent as one sealed
pairwise message to each member, with the group id and epoch inside the
encryption. Up to 50 members. The relay stores no group.

**Joining is a choice.** Being added to a group sends an invitation; the
person becomes a member only after accepting it.

**Introduction cards.** Members who are not contacts must be able to reach each
other without either being discoverable. When a new member accepts, each
existing member whose setting "let members of my groups reach me" is on (the
default) produces a card for the newcomer, and the newcomer produces one for
each such member:

```
Card { certificate, bind, generation, spk, pqspk, ssk, token, group_id, expires_at, signature }
signature = Sign(IKsig.sk, L("card") ‖ recipient.ik_sig ‖ group_id ‖ SHA256(token) ‖ u64(expires_at))
```

A card is sealed with the construction of §8, under the labels `card/key` and
`card/ad` instead of `seal/key` and `seal/ad`, to a **seal key** of its
recipient — never to `IKdh`. A card for the newcomer is sealed to the `SSK` the
newcomer put in their acceptance, which the inviter passes on with the
membership update; the newcomer's card for a member is sealed to the `ssk` in
that member's card. Either seal key is checked first: its signature under the
recipient's `ik_sig` (§4), and its age — for a card up to 30 days past its
`created_at` instead of the 9 days of §4, since the card lives 7 days and the
private half 40, so a member who answers late can still be introduced. So the member who forwards a card
cannot read the token, and a card has the same sender forward secrecy as a
seal (§8). It expires in 7 days. It holds everything §5.1 needs, so the
receiver opens a session over the card's token without asking the relay for
anything. The two members then rotate the token inside their new session.
Identities that arrive this way are marked "introduced by <name>" until verified
by safety number.

**Leaving.** When a member leaves or is removed, every other member revokes the
token they issued to that member, unless the two have also exchanged messages
outside the group.

---

## 12. Pinning, safety numbers and invites

**Pinning.** The first verified identity for a contact pins the **pair**
`(IKsig.pk, IKdh.pk)`. Afterwards an identity that differs in either half is
refused. Usernames can be reissued; identities cannot.

**Safety number.**

```
h = SHA512(u16(0) ‖ L("fingerprint") ‖ IKsig.pk ‖ IKdh.pk)
repeat 5199 times:  h = SHA512(h ‖ IKsig.pk ‖ IKdh.pk)
digits = the first 30 bytes of h as six 5-byte chunks; each chunk u40 mod 100000, zero-padded to 5 digits
```

30 digits per party; the safety number is the two halves ordered by `IKsig.pk`,
60 digits in 12 groups of five, also shown as a QR code.

**Invites.** An invite link carries the username, the invite secret and the
first 16 bytes of `SHA256(L("invite/fingerprint") ‖ IKsig.pk ‖ IKdh.pk)`. A
client that opens the link refuses an identity that does not match, so first
contact by invite is authenticated out of band.

---

## 13. Labels

Each is used exactly once, always as `L(name)`.

| Name | Used in |
|---|---|
| `identity/salt`, `identity/root`, `identity/ed25519`, `identity/x25519`, `identity/bind` | §3.2 |
| `device` | §3.3 |
| `prekey` | §4 |
| `pqxdh`, `transcript`, `ad` | §5.1 |
| `ratchet/root` | §6.2 |
| `seal/key`, `seal/ad` | §8 |
| `token` | §9.1 |
| `vault/master`, `vault/data-key`, `vault/record-key`, `vault/check-key`, `vault/manifest-key`, `vault/root-key` | §10.1 |
| `vault/tpm`, `vault/tpm-pin` | §10.2 |
| `vault/check` | §10.3 |
| `vault/record`, `vault/root`, `vault/manifest` | §10.4 |
| `card`, `card/key`, `card/ad` | §11.2 |
| `directory-keys` | PROTOCOL §2.1 |
| `fingerprint`, `invite/fingerprint` | §12 |
| `invite` | PROTOCOL §4.4 |
| `auth` | PROTOCOL §2 |
| `register`, `delete` | PROTOCOL §4.2 |
| `certificate` | PROTOCOL §2.1 |
| `report/key`, `report/ad` | PROTOCOL §4.6 |
| `pow` | PROTOCOL §6.2 |

---

## 14. Test vectors

Every primitive is tested against published vectors: Project Wycheproof's
X25519, Ed25519, HMAC-SHA256, HKDF-SHA256, XChaCha20-Poly1305 and ML-KEM-768
(key generation from a seed, encapsulation including keys that fail the modulus
check, and decapsulation) suites, the RFC 8032 and RFC 7748 examples, the
FIPS 180-4 SHA-2 examples, and the BIP39 English entropy-to-mnemonic vectors.
Argon2id is tested with libsodium's own `crypto_pwhash` vectors and single-lane
reference vectors, because `crypto_pwhash` has one lane and no secret or
associated-data inputs.

LUME publishes its own vectors for every construction above — identity and
device derivation, prekey signatures, PQXDH, ratchet transcripts including
skipped and out-of-order messages, contents, seals, introductions, cards,
username certificates, directory key lists, vault headers, records and
manifests, and safety numbers — generated once,
committed, and checked on every platform the core builds for.
