<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# LUME — Cryptography

Status: **draft**, revision 3.
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
- **Forward secrecy in transit**: a key taken from a device today does not
  decrypt envelopes recorded earlier.
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
- **The username behind an identity, beyond the relay's word.** A contact's
  name is confirmed by a certificate the relay signs (§5.3). A relay that lies
  can attach a name to the wrong key; the safety number (§12) is the check that
  does not depend on the relay.
- **A stolen identity.** Whoever copies the identity secret or the recovery
  phrase can act as that account until its owner creates a new account. There
  is no identity rotation in this version; recovery locks out an old *device*
  (§3.3), not a thief who holds the identity key.
- **Sender identity against a later compromise of the recipient**, for envelopes
  whose seal key has not yet been deleted — up to 42 days (§8).
- **Deleted data on flash storage.** The vault overwrites what it deletes
  (§10.5), but flash memory can keep earlier copies of a block beyond any
  application's reach. Someone who later has the device *and* the passphrase may
  recover messages that were deleted.
- **Post-quantum post-compromise security.** The handshake is hybrid
  post-quantum; the ratchet's healing steps are classical X25519 (§6.7).
- **The authenticity of a report.** A report (PROTOCOL §4.6) is what the
  reporter says they received; this version cannot prove that a reported
  message was sent.
- **A compromised device.** Malware running as the user reads what the user
  reads.

---

## 2. Primitives

| Name in this document | Primitive | Library call |
|---|---|---|
| `SHA256`, `SHA512` | SHA-2 | `crypto_hash_sha256`, `crypto_hash_sha512` |
| `HMAC(k, m)` | HMAC-SHA256 | `crypto_auth_hmacsha256_*` |
| `HKDF(salt, ikm, info, L)` | HKDF-SHA256, RFC 5869 | `crypto_kdf_hkdf_sha256_extract` / `_expand` |
| `DH(sk, pk)` | X25519, RFC 7748 | `crypto_scalarmult`; **a non-zero return (low-order point) aborts the operation** |
| `Sign`, `Verify` | Ed25519, RFC 8032 | `crypto_sign_detached`, `crypto_sign_verify_detached` |
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
rejection of a low-order point), Ed25519, the AEAD (including rejection of a
forged tag) and ML-KEM-768 (key generation from a seed and decapsulation)
against known answers, and an ML-KEM round trip. Any mismatch stops the core
from initialising; no key is generated or used.

**ML-KEM input check.** `Encaps` refuses an encapsulation key that fails the
FIPS 203 §7.2 modulus check; liboqs performs the check and the test suite
proves it with Wycheproof's modulus-overflow vectors.

### 2.1 Conventions

- `‖` is concatenation. Integers are unsigned big-endian: `u8 u16 u32 u64`.
- `lp(x) = u32(len(x)) ‖ x`. Every variable-length value inside a hashed,
  signed or MACed input is length-prefixed.
- `L(name) = lp("LUME/v1/" ‖ name)`. Every label is length-prefixed, so no label
  is a prefix of another input. Labels are listed in §13; each is used in
  exactly one place.
- `enc(x)` is the canonical encoding of a structured value by `core/wire`
  ([PROTOCOL.md §3](PROTOCOL.md#3-frame-encoding)). Every structured value that
  crosses a trust boundary — on the wire or in storage — uses it; `‖` appears
  only in inputs to a hash, KDF, MAC or signature.
- Secret material lives in `SecretBytes` (sodium_malloc, guard pages, wiped on
  release).
- Times are seconds since the Unix epoch.

---

## 3. Identity

### 3.1 Recovery phrase

An account is created from **256 bits of entropy** `E = Random(32)`, shown as a
**24-word BIP39 mnemonic** (English wordlist, 8-bit checksum). BIP39 is used
only as an encoding of `E`; its PBKDF2 seed function is not run. A phrase whose
checksum fails is rejected before anything is derived.

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
unique across accounts; `IKdh.pk` is not a key the relay indexes, so nobody can
block a registration by claiming someone else's exchange key.

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
version.

---

## 4. Prekeys

| Key | Type | Kind | Lifetime |
|---|---|---|---|
| `SPK` — signed prekey | X25519 | 1 | active 7 days; private half kept 48 h after the next one activates |
| `PQSPK` — last-resort KEM prekey | ML-KEM-768 | 2 | active 7 days; kept 48 h after |
| `PQOPK` — one-time KEM prekey | ML-KEM-768 | 3 | one use |
| `SSK` — seal key | X25519 | 4 | active 7 days; private half kept **35 days** after the next one activates |
| `OPK` — one-time prekey | X25519 | 5 | one use; unsigned |

```
sig = Sign(IKsig.sk, L("prekey") ‖ u8(kind) ‖ u32(id) ‖ u64(created_at) ‖ lp(public_key))
```

`created_at` is when the key becomes active. A client refuses a signed key that
is more than 9 days past its `created_at`, or more than 31 days before it.

**Pre-signed generations.** Rotation needs `IKsig.sk`, which exists only while
the vault is unlocked. So whenever it is unlocked, the client uploads the next
four weekly generations of `SPK`, `PQSPK` and `SSK`, each with its future
`created_at`; the relay serves each generation from its `created_at` on. A user
who opens the app at least once every four weeks never becomes unreachable.

**Ids** are sequential per kind within a vault. A recovered device starts a new
vault, but the relay has purged the old generation's prekeys (§3.3), so ids
cannot collide.

**One-time keys.** At most 100 `OPK` and 50 `PQOPK` are published. The relay
hands out at most 4 of each per hour per target account; beyond that, bundles
come without one-time keys (PROTOCOL §4.3). The client learns which ids were
handed out (PROTOCOL §4.2) and:

- processes pending deliveries **before** replenishing, so a key that a waiting
  first message needs is not discarded;
- deletes a handed-out private half when a handshake uses it, or **14 days**
  after hand-out if none arrives — after 14 days without a reply the initiator
  starts over from a fresh bundle (§5.4);
- holds at most 1 400 private halves per kind, and when it must evict, evicts
  only keys already handed out, oldest first. A key still published is first
  withdrawn from the relay, then deleted.

At 4 hand-outs an hour for 14 days the cap is never reached by draining alone.

---

## 5. Handshake — PQXDH

Follows Signal's PQXDH specification, revision 3, with LUME's two-key identity.
Alice starts a session with Bob.

### 5.1 Alice

1. Obtain Bob's bundle (PROTOCOL §4.3), or his introduction card (§11.2):
   `IKsig_B, IKdh_B, bind_B, SPK_B, PQPK_B (kind 2 or 3), SSK_B, [OPK_B]`.
2. **Verify before computing anything**: `bind_B`, every signature, every
   `created_at`. If Bob is pinned, `(IKsig_B, IKdh_B)` must equal the pin —
   anything else is a refusal, not a warning.
3. `EK_A` = fresh X25519 key pair.
4. ```
   DH1 = DH(IKdh_A.sk, SPK_B)      DH2 = DH(EK_A.sk, IKdh_B)
   DH3 = DH(EK_A.sk,  SPK_B)       DH4 = DH(EK_A.sk, OPK_B)     if an OPK was given
   (CT, SS) = KEM.Encaps(PQPK_B)
   ```
5. ```
   IKM             = 0xFF^32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ [DH4] ‖ SS
   (SK, HKa, NHKb) = HKDF(0^32, IKM, L("pqxdh"), 96)
   AD              = L("ad") ‖ IKsig_A ‖ IKdh_A ‖ IKsig_B ‖ IKdh_B ‖ SHA256(PQPK_B ‖ CT)
   ```
   Then wipe `EK_A.sk`, `DH1…DH4`, `SS`, `IKM`.
6. Initialise the ratchet as Alice (§6.3).

### 5.2 Initial header

```
InitialHeader { ik_sig, ik_dh, bind, ek, ct, spk_id, pq_kind, pq_id, opk_id: opt<u32> }
```

### 5.3 Introduction

Until Alice has received a message from Bob, **every** envelope she sends in the
session carries both the `InitialHeader` and her `Introduction` (§8):

```
Introduction { certificate, token, seal_key: SSK (+kind, id, time, sig) }
certificate  = UsernameCertificate { username, account_id, ik_sig, ik_dh, generation, expires_at, relay_sig }
```

`token` is the delivery token Alice issues for Bob (§9); `seal_key` is her
current seal key. Bob's first reply carries his own `Introduction`. A lost or
evicted first envelope therefore strands nothing.

**The name is checked offline.** `certificate` is signed by the relay's
directory key, which every client pins (PROTOCOL §2.1); Alice fetches her own on
her authenticated connection, which reveals nothing about Bob. Bob shows the
username only if the certificate verifies, has not expired, and its `ik_sig`,
`ik_dh` and `account_id` equal those of the session. Otherwise he shows
"unverified contact" with the safety number. He makes no request to the relay
to check a name, so checking reveals nothing either.

The seal's sender hint (§8) must equal `ik_sig` of the initial header, or the
envelope is dropped.

### 5.4 Bob

1. Verify `bind_A`. If Alice is pinned, `(IKsig_A, IKdh_A)` must match.
2. If a session with Alice already holds this `(EK_A, CT)`, the envelope belongs
   to it — Alice is repeating her header — and is decrypted there under the
   ratchet's own replay rules.
3. Otherwise look up the private prekeys by kind and id; an unknown id aborts.
4. **Replay guard.** When no one-time key was used, reject an initial header
   whose `SHA256(EK_A ‖ CT)` was already accepted under the same `SPK`/`PQSPK`
   generation. The set is dropped with its generation.
5. Recompute `SK, HKa, NHKb, AD`, initialise the ratchet as Bob (§6.3), and
   decrypt **on a scratch copy**. Only if it authenticates: store the session,
   delete the used one-time private keys, pin Alice. Otherwise discard
   everything; no prekey is consumed by a forged envelope.

If Alice receives nothing for 14 days, she starts a new session from a fresh
bundle and abandons the old one.

### 5.5 Simultaneous initiation

A client sends only in a session in which it has **received** a message from the
peer, or, before that, in the one session it initiated. If both sides started a
session and each has received in the other's, the session initiated by the
identity with the lexicographically lower `IKsig.pk` is kept for sending. A
contact has at most two sessions; the unused one is deleted after 7 days. Each
side keeps one token and one seal key per contact, the most recent from a
session that has received.

### 5.6 Why hybrid

`SK` is secure if **either** X25519 **or** ML-KEM-768 is. An adversary who
records the first message today and breaks X25519 later still lacks `SS`; a
flaw in the newer KEM still leaves the classical exchange.

---

## 6. Double Ratchet with header encryption

Follows Signal's Double Ratchet specification, §4 "Double Ratchet with header
encryption", with XChaCha20-Poly1305 as the AEAD.

### 6.1 State

`DHs`, `DHr`, `RK`, `CKs`, `CKr`, `HKs`, `HKr`, `NHKs`, `NHKr`, `Ns`, `Nr`,
`PN`, the skipped-key store, `AD`, the handshake's `(EK_A, CT)` (for §5.4 step 2
and the initial header Alice repeats), and whether a message has been received.
Serialised only into the vault.

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
header     = Header { dh: DHs.pk, pn: PN, n: Ns }
hn         = Random(24)
enc_header = hn ‖ AEAD(HKs, hn, AD, enc(header))
mn         = Random(24)
body       = mn ‖ AEAD(MK, mn, AD ‖ enc_header, plaintext)
Ns += 1;   wipe MK
```

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

A message that arrives twice is rejected the second time by step 2 or by the
skipped key already being consumed, so a sender may resend an envelope it is
unsure about without creating a duplicate.

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
sealed plaintext:

```
pad(m) = m ‖ 0x80 ‖ 0x00…        to the smallest bucket ≥ len(m) + 1
buckets: 2048, 4096, 8192, 16384, 32768, 65536, 69632 bytes
```

Unpadding scans from the end for `0x80` after zero bytes and rejects anything
else. An ordinary envelope carries about 160 bytes of fixed overhead around its
content; one carrying an initial header and introduction about 1 760. With
2 048 as the smallest bucket the two are indistinguishable for content up to
about 290 bytes or above about 1.9 KB, and distinguishable in between. Content
above 64 KiB goes as an attachment (§11).

---

## 8. Sealed sender

The ratchet message is sealed to the recipient's current seal key `SSK_B`, so
the relay never learns who sent it:

```
ES     = fresh X25519 key pair, one per envelope
k      = HKDF(salt = ES.pk ‖ SSK_B.pk, ikm = DH(ES.sk, SSK_B.pk), info = L("seal/key"), 32)
ad     = L("seal/ad") ‖ u8(1) ‖ u32(SSK_B.id) ‖ ES.pk ‖ SSK_B.pk
nonce  = Random(24)
sealed = enc(Seal { version: 1, ssk_id, es: ES.pk, nonce, box: AEAD(k, nonce, ad, pad(enc(inner))) })
inner  = Inner { sender: IKsig_A, initial: opt<InitialHeader>, introduction: opt<Introduction>,
                 message: enc_header ‖ body }
```

The recipient computes the same `k` from `DH(SSK_B.sk, ES.pk)`.

The seal **hides** the sender; it does not authenticate them. Bob finds the
session for the hinted `IKsig_A`, and the ratchet's AEAD — whose `AD` contains
both identities — fails unless the message really came from that session.

**Which seal key.** A sender uses the seal key it last received from the
recipient — from the bundle, an introduction, or a `SealKeyUpdate` message,
which a client sends inside a session together with its next message after
rotating. When the cached key is more than 21 days past its `created_at`, the
sender fetches the current one from the relay with its delivery token
(PROTOCOL §4.3) before sealing.

**Forward secrecy of the sender.** A seal key is active for 7 days and its
private half is deleted 35 days after it is replaced, so a recorded envelope
reveals its sender to someone who later takes Bob's device or phrase for at
most 42 days. The seal is classical X25519; a quantum adversary who records
envelopes could later learn *who* sent them, not *what* they said. ML-KEM here
would add 1 088 bytes to every envelope.

---

## 9. Delivery tokens and blocking

### 9.1 Issuing and rotating

- A token is `T = Random(32)`; the relay stores only `SHA256(L("token") ‖ T)`
  under the issuer's account.
- Alice issues `T_BA` in her `Introduction`; Bob issues `T_AB` in his. Each
  sends to the other on the token the other issued.
- Clients keep a **pool of about 20 unused tokens**, registered in small batches
  at random times, and draw from it for new contacts.
- Tokens rotate every 30 days: the new one is sent inside the session, and the
  old one is revoked only **after an envelope has arrived on the new one** — a
  contact who was offline at rotation keeps reaching you on the old token until
  their client has switched.

### 9.2 Checks the client makes

- An envelope delivered on token `T` whose authenticated sender is not the
  contact `T` was issued to is dropped, and `T` is revoked — a contact who lends
  their token to someone else loses it. An envelope that merely fails to
  decrypt is dropped **without** revoking anything, so neither the relay nor a
  third party can cut a contact off by injecting garbage.
- An envelope delivered on the **introduction lane** must carry an
  `InitialHeader`; one that does not is dropped.
- Every envelope whose authenticated sender is on the local **block list**
  (identities, not usernames) is dropped, whatever lane it came on.
- **After recovery**, the new vault does not know which contact a token belongs
  to. An envelope that carries an `InitialHeader` on an unknown token is
  treated as an introduction, and the token is bound to that sender from then
  on.

### 9.3 Blocking

Blocking revokes the contact's token and adds their identity to the block list.
The relay answers a revoked token exactly as a live one (PROTOCOL §4.5), so the
sender cannot tell they are blocked.

### 9.4 What the relay learns

For an undelivered envelope it holds `(recipient, token hash or "intro",
sealed bytes, time)`: given only its database, the sender cannot be identified.
A token is a stable pseudonym for one contact of one recipient while it lives;
the relay can count envelopes per pseudonym and pseudonyms per recipient, and a
live operator can try to match pseudonyms across rotations by timing.

---

## 10. Vault — data at rest

### 10.1 Keys

```
salt    = Random(16), fresh for every vault
Kpw     = PWHash(passphrase, salt, ops, mem)
Khw     = HW(Kpw)                                                  §10.2
MK      = HKDF(salt = Khw, ikm = Kpw, info = L("vault/master"), 32)
K_rec   = HKDF(0^32, MK, L("vault/record-key"), 32)
K_check = HKDF(0^32, MK, L("vault/check-key"), 32)
K_man   = HKDF(0^32, MK, L("vault/manifest-key"), 32)
```

Each derived key has one job; `MK` itself encrypts and MACs nothing.

### 10.2 Hardware binding per platform

`HW` is evaluated inside hardware with a key that cannot be exported, so every
passphrase guess has to run on the original device.

| Platform | `HW(x)` | What a guess costs |
|---|---|---|
| Android, Keystore at TEE or StrongBox level | HMAC-SHA256 with a non-exportable Keystore key created with `setUnlockedDeviceRequired(true)` | a Keystore operation on this unlocked device |
| Windows with a TPM | an RSA-2048 key in the Microsoft Platform Crypto Provider whose authorisation value (`NCRYPT_PIN_PROPERTY`) is `HKDF(0^32, x, L("vault/tpm-pin"), 32)`; `HW(x)` is its PKCS#1 v1.5 signature of `SHA256(L("vault/tpm-sign"))` | a TPM operation, and every wrong guess counts towards the TPM's dictionary-attack lockout |
| Anything else | **software only**: a DPAPI-protected random `Khw` on Windows, an app-private random `Khw` on Android | nothing beyond Argon2id once the secret is read |

Android reporting a `SOFTWARE` security level, and TPM firmware affected by
ROCA (CVE-2017-15361), are treated as software only. Software-only mode is
shown to the user, never entered silently, and raises the passphrase minimum
from 10 to 14 characters.

### 10.3 Header

```
VaultHeader { version, salt, ops, mem, hw_mode, generation, check }
check = HMAC(K_check, L("vault/check") ‖ enc(header without check))
```

`ops` and `mem` must lie between the floor and the ceiling; anything outside is
an integrity error. A wrong passphrase fails `check`; a header altered by
someone without the passphrase fails it too, and is reported as tampering if the
previously recorded `check` is known.

| | `ops` | `mem` |
|---|---|---|
| Android default | 3 | 64 MiB |
| Desktop default | 3 | 256 MiB |
| Floor | 2 | 64 MiB |
| Ceiling | 10 | 1 GiB |

### 10.4 Records and manifest

```
record   = nonce ‖ AEAD(K_rec, nonce, L("vault/record") ‖ u8(type) ‖ lp(id) ‖ u64(counter), payload)
manifest = enc(Manifest { generation, counters: list<{ type, count, root }> })
           with tag HMAC(K_man, L("vault/manifest") ‖ manifest)
```

Each record type keeps a counter and a hash of its record ids and counters
(`root`). A record write and its manifest update are **one SQLite
transaction**, so a crash leaves both or neither. On unlock the vault checks
every type's root; a missing, extra or older record is an **integrity error**:
the vault stops writing for the session and says so, and never treats a record
as empty.

**Rolling the whole vault back** — restoring an older copy of the file — is
detected on Android: the vault generation is encoded in the name of the
Keystore key alias, which is replaced each time the generation advances, so an
older file finds no matching key. On Windows it is not detected in this
version.

A vault belongs to one identity. Creating or recovering a different identity
opens a new vault with a new salt and never reads another's records.

### 10.5 Deletion, lock and wipe

The vault database runs with `secure_delete=ON`, so deleted records are
overwritten in the file; flash wear-levelling can still keep older copies
(§1). The vault locks after 15 minutes without interaction: `MK`, the derived
keys and every decrypted key are wiped from memory. Panic wipe deletes the vault
and the hardware key; a copy of the vault made **after** that cannot be
unlocked. A disk image taken **before** it still holds the key blob and can be
unlocked with the passphrase on the same device.

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
travel in a normal message.

A **group attachment** is uploaded once, with a download allowance of twice the
group's size, and referenced from every member's envelope.

### 11.2 Groups

Groups are **client-side fan-out**: a group message is sent as one sealed
pairwise message to each member, with the group id and epoch inside the
encryption. Up to 50 members. The relay stores no group.

**Introduction cards.** Members who are not yet contacts must be able to reach
each other without either being discoverable. Joining a group is consent to be
reachable by its members: on joining, each member produces, for every other
member, a card

```
Card { certificate, bind, spk, pqspk, ssk, token }       every key signed as in §4
```

and the member who added them forwards each card inside their pairwise session.
A card holds everything §5.1 needs, so the receiver opens a session over the
card's token without asking the relay for anything. The forwarder can see the
token, so the two members rotate it inside their new session at once (§9.1).
Identities that arrive this way are marked "introduced by <name>" until
verified by safety number.

Tokens issued on cards are counted with every other token. A pair of members
shares one token whatever number of groups they share, so the per-account limit
is a limit on distinct contacts.

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
| `pqxdh`, `ad` | §5.1 |
| `ratchet/root` | §6.2 |
| `seal/key`, `seal/ad` | §8 |
| `token` | §9.1 |
| `vault/master`, `vault/record-key`, `vault/check-key`, `vault/manifest-key` | §10.1 |
| `vault/tpm-pin`, `vault/tpm-sign` | §10.2 |
| `vault/check` | §10.3 |
| `vault/record`, `vault/manifest` | §10.4 |
| `fingerprint` | §12 |
| `invite/fingerprint` | §12 |
| `invite` | PROTOCOL §4.4 |
| `auth` | PROTOCOL §2 |
| `register` | PROTOCOL §4.2 |
| `delete` | PROTOCOL §4.2 |
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
skipped and out-of-order messages, seals, introductions and cards, vault
headers, records and manifests, safety numbers — generated once, committed, and
checked on every platform the core builds for.
