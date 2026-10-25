// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Exercises the ported network layer against the real relay from Node, so an API
 * mismatch surfaces in seconds instead of after a device build. It registers a
 * throwaway account, so the username is randomised and clearly marked.
 *
 * Run: npm run relay:check
 */

import '../src/polyfills.core'
import { webcrypto } from 'node:crypto'

// The vendored crypto core expects a global CSPRNG, which React Native provides
// via react-native-get-random-values and Node exposes under webcrypto.
if (!globalThis.crypto) (globalThis as { crypto?: Crypto }).crypto = webcrypto as unknown as Crypto

async function main() {
  const { API_URL } = await import('../src/lib/config')
  const { healthApi, authApi } = await import('../src/lib/api')
  const { registerNewAccount } = await import('../src/registration')
  const { createNodeTestPlatform } = await import('../src/platform/node')

  console.log(`relay: ${API_URL}`)

  const health = await healthApi.check()
  if (health.error) {
    console.error(`FAIL health: ${health.error}`)
    process.exit(1)
  }
  console.log(`health: ${health.data?.status}`)

  const username = `t_${Math.random().toString(36).slice(2, 10)}`
  const platform = createNodeTestPlatform()

  const t0 = Date.now()
  const res = await registerNewAccount(platform, username, '123456')
  if (!res.ok) {
    console.error(`FAIL register: ${res.error}`)
    process.exit(1)
  }
  console.log(`registered @${res.account.username} as ${res.account.userId} in ${Date.now() - t0}ms`)

  // The relay should now report the name as taken, and hand back a prekey bundle.
  const check = await authApi.checkUsername(username)
  console.log(`username still available? ${check.data?.available} (expected false)`)

  // A second account, so the bundle fetch is a real X3DH precondition: the relay
  // (correctly) refuses to hand you your own bundle.
  const platformB = createNodeTestPlatform()
  const usernameB = `t_${Math.random().toString(36).slice(2, 10)}`
  const resB = await registerNewAccount(platformB, usernameB, '123456')
  if (!resB.ok) {
    console.error(`FAIL register B: ${resB.error}`)
    process.exit(1)
  }
  console.log(`registered @${resB.account.username} (second account)`)

  // The key vault now holds B's keys, so this call is signed as B asking for A.
  const bundle = await authApi.getBundle(username)
  if (bundle.error) {
    console.error(`FAIL bundle: ${bundle.error}`)
    process.exit(1)
  }
  const identityMatches = bundle.data?.identityKey === res.account.identity.signing.publicKey
  console.log(`B fetched A's bundle; identityKey matches what A published? ${identityMatches}`)
  console.log(`bundle carries a one-time prekey? ${bundle.data?.oneTimePrekey ? 'yes' : 'no'}`)

  // The vault must hold the account locally after a successful registration, and
  // re-opening it must restore the ability to sign requests.
  const { closeSession, openSession } = await import('../src/session')
  const { loadPreKeyMaterial } = await import('../src/vault')

  await closeSession()
  const opened = await openSession(platform, '123456')
  console.log(`vault re-opens after registration? ${opened.ok}`)

  let prekeysStored = false
  let signedCallWorks = false
  if (opened.ok) {
    const { vaultGetMasterKey } = await import('../src/crypto/keyVault')
    const material = await loadPreKeyMaterial(platform, vaultGetMasterKey())
    prekeysStored = !!material && material.oneTimePreKeys.length > 0
    console.log(`prekey secrets stored? ${material ? material.oneTimePreKeys.length + ' one-time keys' : 'NO'}`)

    // A signed request only works if the reopened session populated the key vault.
    const session = await authApi.getSession(res.account.userId)
    signedCallWorks = !session.error
    console.log(`signed request after reopen? ${signedCallWorks ? 'OK' : session.error}`)
  }

  const allGood =
    check.data?.available === false && identityMatches && opened.ok && prekeysStored && signedCallWorks
  console.log(allGood ? '\nRELAY CHECK PASSED' : '\nRELAY CHECK FAILED')
  process.exit(allGood ? 0 : 1)
}

main().catch(e => {
  console.error('relay check crashed:', e)
  process.exit(1)
})
