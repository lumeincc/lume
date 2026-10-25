// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Device-runtime simulation, run in its own Node process (see `npm run sim`).
 *
 * React Native's Hermes runtime does not provide Buffer, TextEncoder,
 * TextDecoder, atob or btoa — verified by reading RN 0.76's polyfillGlobal list.
 * Node does provide them, which is exactly how a unit suite can be green while
 * the app dies on a phone. This script deletes precisely those globals, then
 * runs the real identity flow, so the on-device path is exercised before
 * spending ~15 minutes on a cloud build.
 *
 * A separate process is deliberate: stripping globals inside the test runner
 * breaks the runner's own serialization.
 *
 * Pass `--no-polyfills` to assert the failure case (the flow MUST break).
 */

const g = globalThis as unknown as Record<string, unknown>
const withoutPolyfills = process.argv.includes('--no-polyfills')

// 1. Remove what Hermes does not have.
for (const name of ['Buffer', 'TextEncoder', 'TextDecoder', 'atob', 'btoa']) {
  delete g[name]
}

// 2. Add what React Native DOES have, so the simulation is faithful rather than
//    merely hostile. RN's setUpGlobals aliases `self` to the global object, and
//    react-native-get-random-values installs crypto.getRandomValues. Together
//    these make tweetnacl take its browser branch at import time; without `self`
//    it would fall back to `require('crypto')`, which is a Node-only path that
//    never runs on device.
g.self = g

// Everything below is dynamically imported so it evaluates AFTER the globals are
// stripped — mirroring a cold app start on device.
async function main(): Promise<void> {
  if (!withoutPolyfills) {
    await import('../src/polyfills.core')
    for (const name of ['Buffer', 'TextEncoder', 'TextDecoder']) {
      if (typeof g[name] !== 'function') throw new Error(`polyfill missing: ${name}`)
    }
    console.log('polyfills installed: Buffer, TextEncoder, TextDecoder')
  } else {
    console.log('running WITHOUT polyfills (expecting failure)')
  }

  const { createIdentity, recoverIdentity } = await import('../src/onboarding')
  const { reactNativePlatform } = await import('../src/platform/reactNative')

  const started = Date.now()
  const created = await createIdentity(reactNativePlatform, '123456')
  const elapsed = Date.now() - started

  const words = created.mnemonic.split(' ')
  if (words.length !== 12) throw new Error(`expected 12 words, got ${words.length}`)
  if (created.masterKeyLength !== 32) throw new Error('master key is not 32 bytes')
  if (!created.identity.signing.publicKey) throw new Error('no signing public key')

  const recovered = await recoverIdentity(created.mnemonic)
  if (recovered.signing.publicKey !== created.identity.signing.publicKey) {
    throw new Error('recovery produced a different signing key')
  }
  if (recovered.exchange.publicKey !== created.identity.exchange.publicKey) {
    throw new Error('recovery produced a different exchange key')
  }

  // Identity creation is deterministic (keys derived from the seed), so it never
  // touches TweetNaCl's PRNG. Screens that come next — prekey bundles, ratchet
  // ephemerals — do, and TweetNaCl only fails at CALL time ("no PRNG") if it
  // could not find a CSPRNG when it was imported. Exercise that here so the gap
  // surfaces on a laptop rather than on a phone.
  const { generateSigningKeyPair, generatePreKeyBundle } = await import('../src/crypto/keys')
  const random = generateSigningKeyPair()
  if (!random.publicKey || random.publicKey === created.identity.signing.publicKey) {
    throw new Error('TweetNaCl PRNG produced no fresh key')
  }
  const bundle = generatePreKeyBundle(created.identity.exchange, created.identity.signing, 2)
  if (!bundle.signedPreKey.publicKey || !bundle.signature || bundle.oneTimePreKeys.length !== 2) {
    throw new Error('prekey bundle generation failed')
  }

  console.log(`identity created in ${elapsed}ms (600k PBKDF2, pure JS)`)
  console.log('  TweetNaCl PRNG : working (fresh keypair + prekey bundle)')
  console.log(`  mnemonic words : ${words.length}`)
  console.log(`  signing pub    : ${created.identity.signing.publicKey.slice(0, 24)}…`)
  console.log(`  exchange pub   : ${created.identity.exchange.publicKey.slice(0, 24)}…`)
  console.log(`  master key     : ${created.masterKeyLength} bytes`)
  console.log('  recovery       : matches')
  console.log('\nDEVICE SIMULATION PASSED')
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err)
  if (withoutPolyfills) {
    console.log(`failed as expected without polyfills: ${message}`)
    console.log('\nNEGATIVE CASE CONFIRMED (the polyfills are load-bearing)')
    process.exit(0)
  }
  console.error(`DEVICE SIMULATION FAILED: ${message}`)
  process.exit(1)
})
