# LUME Mobile

The native LUME client — **React Native / Expo**. A real native app, not the web PWA in a wrapper.

LUME is an end-to-end encrypted messenger whose server is a blind relay: it stores and forwards opaque encrypted blobs and never sees plaintext, keys, or message content. All cryptography runs on the client.

The rule that shapes this repo: **the cryptography is never reimplemented.** The crypto core is shared with the web client verbatim; only the UI, the delivery layer and a thin platform adapter are new. Rewriting a Double Ratchet is the most reliable way to acquire a second, original bug in the worst possible place.

## Sharing strategy — vendored core + shared test vectors

`src/crypto/` is copied **byte-identical** from the web client. The web client's crypto **test suite is copied too and runs here unchanged**, so any drift between the two copies fails a vector rather than reaching a user.

Why a copy and not a monorepo: turning the deployed web repo into a workspace would put its production build at risk, and the core is stable. If keeping the copy in sync ever gets painful, the answer is a shared `@lume/crypto` package.

**Keeping it in sync:** when the web crypto changes, re-copy `src/crypto/*` and the `crypto.*.test.ts` files, then run `npm test`. Green means the port still matches.

Where the web reaches for a browser API, a compatibility shim re-presents the same interface over the mobile vault (`src/crypto/storage.ts`), which is what lets files like `spkRotation.ts` stay byte-identical instead of being rewritten.

## Architecture

```
app/                  Expo Router screens — auth, chat list, conversation
modules/lume-crypto/  local native module: PBKDF2-HMAC-SHA256 in Kotlin
src/
  crypto/             vendored, verbatim — keys · ratchet · mnemonic · safetyNumber · keyVault
                      (+ storage.ts: a shim presenting the web's storage API over the vault)
  platform/           the OS seam — PlatformCrypto (pbkdf2, randomBytes), key/value and
                      secure stores; node.ts is the reference impl used by tests
  lib/                relay client, WebSocket schemas, wire format, small primitives
  messaging.ts        X3DH + Double Ratchet send/receive
  outbox.ts           durable delivery: retry, backoff, restart
  realtime.ts         WebSocket delivery
  session.ts          unlock/lock, ratchet-session persistence
  vault.ts            the encrypted local store
  store/              app state (a small React context; the engine owns the hard parts)
  ui/                 design tokens and primitives, transcribed from the web client
```

Everything platform-specific goes through the seam, so the vendored core stays byte-identical across web, Node (tests) and React Native.

**Key storage.** The master key is derived from the user's PIN **and** a high-entropy device secret held by the OS keystore. Mixing the device secret into the PBKDF2 password rather than using it as a salt keeps the full 600 000-iteration stretch applied to the whole input, so an attacker holding the stored blob but not the keystore has no low-entropy target to grind. Key material never enters React state.

**Native PBKDF2.** `modules/lume-crypto/` implements PBKDF2-HMAC-SHA256 directly on `javax.crypto.Mac` — deliberately not `SecretKeyFactory`/`PBEKeySpec`, which re-encodes a `char[]` and would derive a *different* key from a raw byte password, orphaning every existing vault. It is loaded with `requireOptionalNativeModule`, so a build without it falls back to pure JS instead of crashing at import. Unlock is ~0.3 s at 600 000 iterations; the same work in pure JS on Hermes takes over a minute.

## Verification

A green unit suite is not enough here: Node provides globals that React Native's Hermes runtime does not (`Buffer`, `TextEncoder`, `TextDecoder`, `atob`, `btoa`), so crypto code can pass every test on a laptop and still die on a phone.

```bash
npm run verify     # test + sim + sim:negative + expo export
```

| Layer | Command | What it proves |
|---|---|---|
| Types | `npx tsc --noEmit` | the vendored core type-checks unmodified |
| Config / deps | `npx expo-doctor` | no SDK drift, no missing native peer deps |
| Logic | `npm test` | crypto vectors shared with the web client, PBKDF2 parity |
| **Device runtime** | `npm run sim` | the real identity flow with Hermes's globals **removed** |
| Bundle | `npx expo export -p android` | Metro resolves the whole graph |

`npm run sim` ([scripts/device-sim.ts](scripts/device-sim.ts)) is the important one. It runs in its own Node process, deletes exactly the globals Hermes lacks, re-adds what RN *does* provide (`self`, `crypto.getRandomValues`), resolves modules the way Metro does, and then creates and recovers a real identity. `npm run sim:negative` asserts the inverse — with the polyfills disabled the flow **must** fail — so they can never silently stop being load-bearing.

What the simulation cannot catch is performance: Node's JIT compiles the tight PBKDF2 loop that Hermes interprets, which is why a pure-JS derivation taking a second here took over a minute on the device.

Three scripts drive the real relay from Node, which catches integration faults in seconds instead of a build cycle:

```bash
npm run relay:check     # registration + a signed authenticated request
npm run e2e:message     # two accounts, real messages, asserts the relay stored only ciphertext
npm run e2e:realtime    # a live socket, measures push latency end to end
```

## CI

Every push and pull request runs the same gates, so `npm run verify` is no
longer something that only happens on one laptop:

| Job | What it proves |
|---|---|
| Type-check | `tsc --noEmit` |
| Tests | the 184-case suite |
| Crypto — unchanged from the web client | the vendored crypto suites on their own, so drift in the copied core is its own red job rather than noise inside a larger run |
| Full verify | tests + device simulation + its negative case + a real Expo export |
| Secrets | gitleaks across the whole history, redacted |
| Dependencies | `npm audit` — production tree fails at moderate, full tree at high |

The dependency gate was deliberately left out when CI was first added: the tree
carried 22 advisories under the Expo toolchain at the time, and a gate that is
red on the day it lands is how gates get switched off. It was turned on once
the tree was clean.

## Status

**The engine is complete and proven on real hardware** — a Galaxy S24 (Android 16), against the live relay: account creation, registration, encrypted messaging (X3DH + Double Ratchet), real-time delivery, persistence across restarts, and silent identity rebind when the relay loses its user row.

Delivery is built for a phone rather than a desktop. A message becomes durable state the moment it is written and is delivered across backoff, reconnects and app restarts; only transport failures are retried, so a signature or identity-pinning refusal fails immediately and stays visible instead of looping. Ratchet operations are serialised per contact, because on a phone sends and receives genuinely overlap and an unguarded read-advance-write loses messages silently.

Currently: **184 tests**, device simulation and its negative case passing, Metro export clean.

**Not built yet:** settings screen, safety-number verification UI, push notifications, attachments, groups. Screens exist for auth, the chat list and a conversation.

**No third-party security audit has been performed.**

## Build

Requires a dev build — not Expo Go, since the app uses local native modules.

```bash
npm install
npm run verify                  # always, before a build
npx expo prebuild -p android
cd android && ./gradlew :app:assembleRelease
```

Use `assembleRelease`, not `assembleDebug`: `expo-modules-core` only declares the release variant, so debug fails at configuration.

The relay URL and the app's declared origin come from `src/lib/config.ts` and can be overridden with `EXPO_PUBLIC_API_URL`, `EXPO_PUBLIC_WS_URL` and `EXPO_PUBLIC_APP_ORIGIN`. The origin matters: the relay refuses state-changing requests carrying no `Origin` header, and React Native sends none unless asked, so the app's origin must be in the relay's allowlist.

## Licence

Source-available, **view-only** — the same terms as LUME. You may read and reference the source; running, copying, modifying or distributing it requires a separate written licence. This is **not** an open-source or free-software licence. See [LICENSE](LICENSE), and the full terms in the [main LUME repository](https://github.com/lumeincc/lume).
