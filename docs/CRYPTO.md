<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# LUME — Cryptography

Status: **draft**.
Nothing here is implemented until this document says it is; code that
disagrees with it is a bug in one of the two.

This document specifies every key, derivation and construction LUME uses.
It composes vetted primitives from libsodium and liboqs and invents none.
Where a construction follows a published design, the design is named and the
deviations are listed. The relay protocol is in [PROTOCOL.md](PROTOCOL.md).

---

## 1. Goals and non-goals

**LUME protects:**

- **Message content** against the relay, the network and anyone who later
  obtains the relay's storage — including an adversary who records traffic now
  and has a quantum computer later.
- **Forward secrecy**: compromising a device today does not reveal messages
  already deleted from it.
- **Post-compromise security of sessions** against a classical adversary who
  stole session state once and then lost access: the ratchet heals within one
  round trip.
- **Who sent a stored envelope**: the relay stores the recipient, never the
  sender (§8).
- **Group state**: the relay holds no groups, names or member lists (§11).
- **Local data at rest** against someone holding the device's storage but not
  the passphrase, to the degree §10 states per platform.

**LUME does not protect** — stated so it is never mistaken for a claim:

- **Network addresses and live correlation.** The relay sees the address of
  every connection. An operator watching live can correlate sending and
  receiving connections by address and timing, including the moment a delivery
  token is registered and first used (§9.4). Use Tor or a VPN if that matters.
- **Timing and volume per recipient**, and patterns such as one connection
  sending many same-sized envelopes at once, which can suggest a group fan-out.
- **Account existence.** A taken username reads as taken whether or not its
  holder is discoverable. *Non-discoverable* hides an account's keys and closes
  its introduction lane; it does not hide that the name is in use.
- **A stolen identity.** Whoever copies the identity secret (or the recovery
  phrase) can act as that account until its owner creates a new account. There
  is no identity rotation in this version; recovery locks out an old *device* (§3.3),
  not a thief who holds the identity key.
- **Sender identity against a later compromise of the recipient**, for envelopes
  whose seal key has not yet been deleted — at most 35 days (§8).
- **Post-quantum post-compromise security.** The handshake is hybrid
  post-quantum; the ratchet's healing steps are classical X25519 (§6.7).
- **A compromised device.** Malware running as the user reads what the user
  reads.

---

## 2. Primitives

| Name in this document | Primitive | Library call |
|---|---|---|
| `SHA256`, `SHA512` | SHA-2 | `crypto_hash_sha256`, `crypto_hash_sha512` |
| `HMAC(k, m)` | HMAC-SHA256 | `crypto_auth_hmacsha256` |
| `HKDF(salt, ikm, info, L)` | HKDF-SHA256, RFC 5869 | `crypto_kdf_hkdf_sha256_extract` / `_expand` |
| `DH(sk, pk)` | X25519, RFC 7748 | `crypto_scalarmult`; **a non-zero return (low-order point) aborts the operation** |
| `Sign`, `Verify` | Ed25519, RFC 8032 | `crypto_sign_detached`, `crypto_sign_verify_detached` |
| `AEAD(k, n, ad, m)` | XChaCha20-Poly1305-IETF | `crypto_aead_xchacha20poly1305_ietf_encrypt` / `_decrypt` |
| `Stream` | XChaCha20-Poly1305 secretstream | `crypto_secretstream_xchacha20poly1305_*` |
| `KEM` | ML-KEM-768, FIPS 203 (final) | liboqs `OQS_KEM_alg_ml_kem_768` |
| `PWHash` | Argon2id v1.3 | `crypto_pwhash`, `crypto_pwhash_ALG_ARGON2ID13` |
| `Random(n)` | OS CSPRNG | `randombytes_buf` |
| `Eq(a, b)` | constant-time equality | `sodium_memcmp` |

**Versions.** libsodium ≥ 1.0.19 (the HKDF-SHA256 API). liboqs **≥ 0.12.0**:
0.10.x implements the FIPS 203 *draft*, which does not interoperate with the
final standard, and 0.10.0 has a secret-dependent branch in ML-KEM
decapsulation under Clang 15–18 (CVE-2024-36405) — the compiler the Android NDK
uses. Both versions are pinned in the vcpkg baseline.

**Self-test.** At start-up the core runs a known-answer test of ML-KEM-768
against a FIPS 203 final vector, and of X25519, Ed25519, HKDF and the AEAD
against their RFC vectors. Any mismatch stops the core from initialising; no
key is generated or used.

**ML-KEM input check.** Before `Encaps`, the encapsulation key passes the
FIPS 203 §7.2 modulus check; a key that fails aborts the handshake.

### 2.1 Conventions

- `‖` is concatenation. Integers are unsigned big-endian: `u8 u16 u32 u64`.
- `lp(x) = u32(len(x)) ‖ x`. Every variable-length value inside a hashed,
  signed or MACed input is length-prefixed.
- `L(name) = lp("LUME/v1/" ‖ name)` — every label is length-prefixed, so no
  label is a prefix of another input. Labels are listed in §13; each is used in
  exactly one place.
- Every structured value that crosses a trust boundary — on the wire or in
  storage — is encoded with the canonical codec in `core/wire`
  ([PROTOCOL.md §3](PROTOCOL.md#3-frame-encoding)). The `‖` notation here is
  only for values fed to a hash, KDF, MAC or signature.
- Secret material lives in `SecretBytes` (sodium_malloc, guard pages, wiped on
  destruction). Temporaries that held a secret are wiped before their scope
  ends.
- Times are seconds since the Unix epoch.

---

## 3. Identity

### 3.1 Recovery phrase

An account is created from **256 bits of entropy** `E = Random(32)`, shown as a
**24-word BIP39 mnemonic** (English wordlist, 8-bit checksum). 256 bits because
the phrase is the root of everything and Grover's algorithm halves the strength
of a searched secret.

BIP39 is used **only as an encoding** of `E`; its PBKDF2 seed function is not
run. A phrase whose checksum fails is rejected before anything is derived.

### 3.2 Identity keys

```
root      = HKDF(salt = L("identity/salt"), ikm = E, info = L("identity/root"), 32)
IKsig     = crypto_sign_seed_keypair(HKDF(0^32, root, L("identity/ed25519"), 32))
IKdh.sk   = HKDF(0^32, root, L("identity/x25519"), 32)
IKdh.pk   = crypto_scalarmult_base(IKdh.sk)
bind      = Sign(IKsig.sk, L("identity/bind") ‖ IKsig.pk ‖ IKdh.pk)
```

An identity is the **pair** `(IKsig.pk, IKdh.pk)`, bound by `bind`. Every
check, pin and safety number covers both halves (§12). The relay enforces that
no two accounts share either key.

### 3.3 Device key

Each installation creates a random Ed25519 **device key** `DK` and a
certificate for it:

```
cert = Sign(IKsig.sk, L("device") ‖ DK.pk ‖ u32(generation) ‖ u64(issued_at))
```

The relay authenticates connections with `DK`, not with `IKsig`, and accepts
only the certificate with the **highest generation** it has seen for the
account. Recovering the phrase on a new device registers `generation + 1`,
which locks the old device out: it can no longer connect, take deliveries or
acknowledge (delete) them. This version has one device per account.

---

## 4. Prekeys

| Key | Type | Lifetime | Kind byte |
|---|---|---|---|
| `SPK` — signed prekey | X25519 | rotated every 7 days; private half kept 48 h after rotation | 1 |
| `PQSPK` — last-resort KEM prekey | ML-KEM-768 | rotated every 7 days; kept 48 h after rotation | 2 |
| `PQOPK` — one-time KEM prekey | ML-KEM-768 | one use | 3 |
| `SSK` — seal key | X25519 | rotated every 7 days; private half kept **35 days** after rotation | 4 |
| `OPK` — one-time prekey | X25519 | one use | — (unsigned) |

Signed prekeys carry their creation time:

```
sig = Sign(IKsig.sk, L("prekey") ‖ u8(kind) ‖ u32(id) ‖ u64(created_at) ‖ lp(public_key))
```

A client refuses an `SPK`, `PQSPK` or `SSK` whose `created_at` is more than
9 days old, so a relay cannot keep serving an expired generation.

**Ids** are sequential per kind and never reused for one identity; the counter
lives in the vault.

**One-time keys.** At most 100 `OPK` and 50 `PQOPK` are published. The relay
reports which ids it has handed out (PROTOCOL §4.2). A handed-out key's private
half is deleted when a handshake uses it, or **35 days** after it was handed out
if none arrives — envelopes do not outlive 30 days. The vault never holds more
than 400 `OPK` and 200 `PQOPK` private halves; beyond that the oldest are
evicted.

---

## 5. Handshake — PQXDH

Follows Signal's PQXDH specification, revision 3, with LUME's two-key identity.
Alice starts a session with Bob.

### 5.1 Alice

1. Obtain Bob's bundle (PROTOCOL §4.3): `IKsig_B, IKdh_B, bind_B, SPK_B,
   PQPK_B (kind 2 or 3), SSK_B, [OPK_B]`, each signed key with id, time and
   signature.
2. **Verify before computing anything**: `bind_B`, every signature, every
   `created_at`. If Bob is pinned, `(IKsig_B, IKdh_B)` must equal the pin —
   anything else is a refusal, not a warning. Run the ML-KEM input check on
   `PQPK_B`.
3. `EK_A` = fresh X25519 key pair.
4. ```
   DH1 = DH(IKdh_A.sk, SPK_B)      DH2 = DH(EK_A.sk, IKdh_B)
   DH3 = DH(EK_A.sk,  SPK_B)       DH4 = DH(EK_A.sk, OPK_B)     if an OPK was given
   (CT, SS) = KEM.Encaps(PQPK_B)
   ```
5. ```
   IKM            = 0xFF^32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ [DH4] ‖ SS
   (SK, HKa, NHKb) = HKDF(0^32, IKM, L("pqxdh"), 96)            three 32-byte keys
   AD             = L("ad") ‖ IKsig_A ‖ IKdh_A ‖ IKsig_B ‖ IKdh_B ‖ SHA256(PQPK_B ‖ CT)
   ```
   Then wipe `EK_A.sk`, `DH1…DH4`, `SS`, `IKM`.
6. Initialise the ratchet as Alice (§6.3).

### 5.2 Initial header

```
InitialHeader { ik_sig, ik_dh, bind, ek, ct, spk_id, pq_kind, pq_id, opk_id: opt<u32> }
```

Alice attaches it to **every** message she sends in the session until she has
received one message from Bob. A lost first message therefore does not strand
the rest.

### 5.3 Introduction

The first ratchet message from each side carries, as its plaintext:

```
Introduction { username, account_id, token, seal_key: SSK (+id, time, sig) }
```

`token` is the delivery token the *sender* issues for the other side to use
(§9); `seal_key` is the sender's current seal key. From then on each side
learns the other's new seal keys from `SealKeyUpdate` messages inside the
session.

**Bob does not trust the claimed username.** He looks it up without consuming
anything (`LookupIdentity`, PROTOCOL §4.3). Only if the identity the relay
returns equals `(IKsig_A, IKdh_A)` does the app show the name; otherwise it
shows "unverified contact" and the safety number. The sender hint of the seal
(§8) must equal `IKsig_A` of the initial header, or the envelope is dropped.

### 5.4 Bob

1. Verify `bind_A`. If Alice is pinned, `(IKsig_A, IKdh_A)` must match.
2. If an existing session with Alice already holds this `(EK_A, CT)`, the
   message belongs to it — Alice is repeating her header — and is decrypted
   there under the ratchet's own replay rules.
3. Otherwise look up the private prekeys by kind and id; an unknown id aborts.
4. **Replay guard.** When no one-time key was used, reject an initial header
   whose `SHA256(EK_A ‖ CT)` was already accepted under the same `SPK`/`PQSPK`
   generation. The set is dropped with its generation.
5. Recompute `SK, HKa, NHKb, AD`, initialise the ratchet as Bob (§6.3), and
   decrypt the message **on a scratch copy**. Only if it authenticates: store the
   session, delete the used one-time private keys, pin Alice. Otherwise discard
   everything; no prekey is consumed by a forged message.

### 5.5 Simultaneous initiation

If both sides start a session before either receives the other's, both
sessions are kept until a message from the peer succeeds in one of them; from
then on the session **initiated by the identity with the lexicographically
lower `IKsig.pk`** is used for sending. A contact has at most two sessions; the
inactive one is deleted after 7 days or on the first successful message in the
active one.

### 5.6 Why hybrid

`SK` is secure if **either** X25519 **or** ML-KEM-768 is. An adversary who
records the first message today and breaks X25519 later still lacks `SS`; a
flaw in the newer KEM still leaves the classical exchange.

---

## 6. Double Ratchet with header encryption

Follows Signal's Double Ratchet specification, §4 "Double Ratchet with header
encryption", with XChaCha20-Poly1305 as the AEAD.

### 6.1 State

`DHs` (own ratchet key pair), `DHr`, `RK`, `CKs`, `CKr`, `HKs`, `HKr`, `NHKs`,
`NHKr`, `Ns`, `Nr`, `PN`, the skipped-key store, and `AD`. Serialised only into
the vault.

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
(§6.5, step 3), which the first message from Alice triggers; it is then
replaced and wiped. The prekey store keeps its own copy for its grace period.

### 6.4 Encrypting

```
(CKs, MK)  = KDF_CK(CKs)
header     = Header { dh: DHs.pk, pn: PN, n: Ns }                    encoded with core/wire
hn         = Random(24)
enc_header = hn ‖ AEAD(HKs, hn, AD, header)
mn         = Random(24)
body       = mn ‖ AEAD(MK, mn, AD ‖ enc_header, plaintext)
Ns += 1;   wipe MK
```

The body's associated data covers the encrypted header, so a header cannot be
moved onto another body.

### 6.5 Decrypting

Runs on a **copy** of the state; the copy replaces the state only when the body
authenticates. Any failure leaves the session exactly as it was.

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
| Skipped keys per session | 1024, oldest evicted | bounds memory and vault size |
| Distinct header keys in the skipped store | 8, oldest chain evicted | bounds trial decryptions per incoming header |
| Skipped key lifetime | 14 days | |
| Sessions per contact | 2 (§5.5) | bounds trial decryptions across sessions |

### 6.7 What the ratchet heals against

The first `RK` descends from the hybrid `SK`, and every later `RK` mixes the
previous one in, so a passive recording stays protected by the post-quantum
secret. Healing after a compromise uses fresh X25519 only. A sparse
post-quantum ratchet is a candidate for a later version, not this one.

---

## 7. Padding

The relay sees only sealed envelopes (§8), so padding is applied once, to the
sealed plaintext `inner`, which hides the size of message content and the
difference between first and later messages alike:

```
pad(m) = m ‖ 0x80 ‖ 0x00…        to the smallest bucket ≥ len(m) + 1
buckets: 1024, 2048, 4096, 8192, 16384, 32768, 65536, 69632 bytes
```

Unpadding scans from the end for `0x80` after zero bytes and rejects anything
else. Message content above 64 KiB goes as an attachment (§11).

---

## 8. Sealed sender

The ratchet message is sealed to the recipient's current seal key `SSK_B`, so
the relay never learns who sent it:

```
ES     = fresh X25519 key pair, one per envelope
k      = HKDF(salt = ES.pk ‖ SSK_B.pk, ikm = DH(ES.sk, SSK_B.pk), info = L("seal/key"), 32)
ad     = L("seal/ad") ‖ u8(1) ‖ u32(SSK_B.id) ‖ ES.pk ‖ SSK_B.pk
nonce  = Random(24)
sealed = Seal { version: 1, ssk_id, es: ES.pk, nonce, box: AEAD(k, nonce, ad, pad(inner)) }
inner  = Inner { sender: IKsig_A, initial: opt<InitialHeader>, message: enc_header ‖ body }
```

(The recipient computes the same `k` from `DH(SSK_B.sk, ES.pk)`.)

The seal **hides** the sender; it does not authenticate them. Bob finds the
session for the hinted `IKsig_A`, and the ratchet's AEAD — whose `AD` contains
both identities — fails unless the message really came from that session. A
forged hint decrypts to nothing.

**Forward secrecy of the sender.** Seal keys rotate weekly and their private
halves are deleted 35 days after rotation. Once deleted, a recorded envelope no
longer reveals its sender even to someone who later takes Bob's device or
phrase. Before that, it does (§1).

The seal is classical X25519; a quantum adversary who records envelopes could
later learn *who* sent them, not *what* they said. ML-KEM here would add 1 088
bytes to every envelope. Recorded in §1.

---

## 9. Delivery tokens and blocking

Without a sender identity the relay still has to stop floods and enforce
blocks. Each side issues **one delivery token per contact**.

### 9.1 Issuing

- A token is `T = Random(32)`; the relay stores only `SHA256(L("token") ‖ T)`
  under the issuer's account.
- Alice issues `T_BA` and puts it in her `Introduction` (§5.3); Bob issues
  `T_AB` in his. Each sends to the other on the token the other issued.
- Clients keep a **pool of about 20 unused tokens**, registered in small batches
  at random times, and draw from it for new contacts — so registering a token is
  not a signal that a conversation is starting.
- Tokens rotate every 30 days: a new one is sent inside the session and the old
  one revoked later.

### 9.2 Checks the client makes

The relay cannot see inside an envelope, so the recipient's client enforces:

- An envelope delivered on token `T` must come from the contact `T` was issued
  to. An envelope from anyone else is dropped and `T` is revoked — a contact
  who lends their token to a third party loses it.
- An envelope delivered on the **introduction lane** must carry an
  `InitialHeader`; one that does not is dropped.
- Every envelope whose authenticated sender is on the local **block list**
  (identities, not usernames) is dropped, whatever lane it came on.

### 9.3 Blocking

Blocking a contact revokes their token and adds their identity to the block
list. The relay keeps refusing the token; the client drops anything the
blocked identity sends through any other lane, including a fresh session over
the introduction lane. The relay answers a revoked token exactly as a live one
(PROTOCOL §4.5), so the sender cannot tell they are blocked.

### 9.4 What the relay learns

For an undelivered envelope it holds `(recipient, token hash or "intro",
sealed bytes, time)`: given only its database, the sender cannot be identified.
A token is still a stable pseudonym for one contact of one recipient while it
lives — the relay can count envelopes per pseudonym and pseudonyms per
recipient — and a live operator can try to match pseudonyms across rotations by
timing. That is the residual stated in §1.

---

## 10. Vault — data at rest

### 10.1 Keys

```
salt  = Random(16), fresh for every vault
Kpw   = PWHash(passphrase, salt, ops, mem)                              32 bytes
Khw   = HW(Kpw)                                                         see §10.2
MK    = HKDF(salt = Khw, ikm = Kpw, info = L("vault/master"), 32)
check = HMAC(MK, L("vault/check"))                                      stored in the header
```

`HW` is a keyed function evaluated **inside hardware** with a key that cannot be
exported, so every passphrase guess has to run on the original device.

### 10.2 Hardware binding per platform

| Platform | `HW(x)` | Protection |
|---|---|---|
| Android with StrongBox or TEE | HMAC-SHA256 with a non-exportable Keystore key, `setUnlockedDeviceRequired(true)` | guesses only on this unlocked device |
| Windows with a TPM | RSA-2048 PKCS#1 v1.5 signature (deterministic) of `SHA256(x)` with a non-exportable key in the Microsoft Platform Crypto Provider | guesses only on this machine, each one paying a TPM signing operation |
| Windows without a TPM | **software only**: DPAPI-protected random `Khw`, the same for every guess | offline guessing is possible once DPAPI is opened |

Software-only mode is **shown to the user**, never entered silently, and raises
the passphrase minimum from 10 to 14 characters. Panic wipe (§10.5) is
effective only with a hardware key; in software-only mode the app says so.

### 10.3 Header

```
VaultHeader { version, salt, ops, mem, hw_mode, check }
```

`ops` and `mem` must lie between the floor and the ceiling; anything outside is
an integrity error, not a reason to try.

| | `ops` | `mem` |
|---|---|---|
| Android default | 3 | 64 MiB |
| Desktop default | 3 | 256 MiB |
| Floor | 2 | 64 MiB |
| Ceiling | 10 | 1 GiB |

A wrong passphrase fails the `check` MAC; a record failing after a correct
`check` is tampering, and the two are reported differently.

### 10.4 Records and manifest

```
nonce  = Random(24)
record = nonce ‖ AEAD(MK, nonce, L("vault/record") ‖ u8(type) ‖ lp(id) ‖ u64(counter), payload)
```

Each record carries a counter that increases on every write. A **manifest**
record lists every record id with its current counter and the vault
generation, and is MACed under `MK`. On unlock the vault verifies that every
record named in the manifest is present with the named counter and that nothing
unnamed exists. A missing, extra or older record is an **integrity error**: the
vault stops writing for the session and says so; it never treats a record as
empty. Deleting the pin store, the block list, the replay guard or a used
prekey's deletion is therefore detected.

The vault generation is also kept in the platform key store next to the
hardware key. Restoring an entire device image — key store included — can
still roll the vault back; that is outside what software can detect.

A vault belongs to one identity. Creating or recovering a different identity
opens a new vault with a new salt and never reads another's records.

### 10.5 Lock and wipe

The vault locks after 15 minutes without interaction: `MK` and every
decrypted key are wiped from memory. Panic wipe deletes the vault and the
hardware key; with a hardware key gone, any copy of the vault file is
unreadable whatever the passphrase.

---

## 11. Attachments and groups

**Attachments.** Each file gets a fresh 32-byte key. The plaintext is padded
with Padmé (padding grows with size; the overhead never exceeds 12 %) and the
padded size is capped so that the encrypted blob stays within the relay's
limit. It is encrypted with `Stream` in 64 KiB chunks; the last chunk carries
`FINAL`, and any data after it is rejected. Key, padded size and
`SHA256(ciphertext)` travel inside a normal message.

**Groups.** Groups are **client-side fan-out**: a group message is sent as
one sealed pairwise message to each member, with the group id and epoch inside
the encryption. Up to 50 members. The relay stores no group.

**Group introductions.** Members who are not yet contacts need a way to reach
each other without either being discoverable. When Carol adds Dave to a group,
every existing member issues a token for Dave and an invite-free introduction
(identity, seal key, token), and Carol forwards each one to Dave inside her
session with him; Dave does the same in the other direction. Members then open
pairwise sessions over those tokens. The identities arrive vouched for by Carol
and are marked "introduced by Carol" until verified by safety number.

---

## 12. Pinning, safety numbers and invites

**Pinning.** The first verified identity for a contact pins the **pair**
`(IKsig.pk, IKdh.pk)` (trust on first use). Afterwards an identity that differs
in either half is refused — the contact stops working visibly instead of
silently re-pointing. Usernames can be reissued; identities cannot.

**Safety number.**

```
h = SHA512(u16(0) ‖ L("fingerprint") ‖ IKsig.pk ‖ IKdh.pk)
repeat 5199 times:  h = SHA512(h ‖ IKsig.pk ‖ IKdh.pk)
digits = the first 30 bytes of h as six 5-byte chunks; each chunk u40 mod 100000, zero-padded to 5 digits
```

30 digits per party; the safety number is the two halves ordered by `IKsig.pk`,
60 digits in 12 groups of five, also shown as a QR code.

**Invites.** An invite link carries the username, the invite secret and the
first 16 bytes of `SHA256(IKsig.pk ‖ IKdh.pk)`. A client that opens the link
refuses a bundle that does not match, so first contact by invite is
authenticated out of band rather than trusted on first use.

---

## 13. Labels

Each is used exactly once, always as `L(name)`.

| Name | Used in |
|---|---|
| `identity/salt`, `identity/root`, `identity/ed25519`, `identity/x25519` | §3.2 |
| `identity/bind` | §3.2 |
| `device` | §3.3 |
| `prekey` | §4 |
| `pqxdh` | §5.1 |
| `ad` | §5.1 |
| `ratchet/root` | §6.2 |
| `seal/key`, `seal/ad` | §8 |
| `token` | §9.1 |
| `vault/master`, `vault/check`, `vault/record` | §10 |
| `fingerprint` | §12 |
| `invite` | PROTOCOL §4.4 |
| `auth` | PROTOCOL §2 |
| `register` | PROTOCOL §4.2 |
| `delete` | PROTOCOL §4.2 |
| `report` | PROTOCOL §4.6 |
| `pow` | PROTOCOL §6.2 |

---

## 14. Test vectors

Every primitive is tested against published vectors: RFC 8032 (Ed25519),
RFC 7748 (X25519, including the low-order points that must be rejected),
RFC 5869 (HKDF-SHA256), RFC 4231 (HMAC-SHA256), the XChaCha20-Poly1305 draft
vectors, the FIPS 203 final ML-KEM-768 KATs, and the BIP39 English
entropy-to-mnemonic vectors. Argon2id is tested with libsodium's own
`crypto_pwhash` vectors and single-lane reference vectors, because
`crypto_pwhash` has one lane and no secret or associated-data inputs, which the
RFC 9106 example uses.

LUME publishes its own vectors for every construction above — identity and
device derivation, prekey signatures, PQXDH, ratchet transcripts including
skipped and out-of-order messages, seals, vault headers and records, safety
numbers — generated once, committed, and checked on every platform the core
builds for.
