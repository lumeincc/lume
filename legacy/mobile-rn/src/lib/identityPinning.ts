// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * X3DH identity trust-pinning (SEC-20260621-002).
 *
 * The signed-prekey signature only proves a bundle is internally consistent with
 * the identity key the SAME server response carried. A malicious/compromised
 * relay could therefore hand us a fully self-consistent bundle for an identity it
 * controls. To stop that MITM, first-contact X3DH (outbound bundle and inbound
 * X3DH header) MUST be pinned to the identity we already trust for that contact.
 *
 * Trust-on-first-use: when no trusted identity is known yet (brand-new contact),
 * there is nothing to pin against, so the bundle/sender is accepted and becomes
 * the trust anchor. Pinning only rejects a *mismatch* against a known identity.
 */

export interface TrustedIdentity {
  /** Ed25519 signing identity key (base64). */
  publicKey?: string;
  /** X25519 exchange identity key (base64). */
  exchangeKey?: string;
}

/**
 * Outbound: does a fetched prekey bundle match the trusted contact identity?
 * `bundleSigningKey` is the bundle's Ed25519 identity key; `bundleExchangeKey`
 * is its X25519 exchange identity key.
 */
export function bundleMatchesTrustedIdentity(
  bundleSigningKey: string,
  bundleExchangeKey: string,
  trusted: TrustedIdentity | null | undefined,
): boolean {
  if (!trusted) return true; // trust on first use
  if (trusted.publicKey && trusted.publicKey !== bundleSigningKey) return false;
  if (trusted.exchangeKey && trusted.exchangeKey !== bundleExchangeKey) return false;
  return true;
}

/**
 * Inbound: does an initial X3DH header's sender exchange identity
 * (`x3dh.senderIdentityKey`, an X25519 key) match the trusted contact?
 */
export function inboundSenderMatchesTrustedIdentity(
  senderExchangeKey: string,
  trusted: TrustedIdentity | null | undefined,
): boolean {
  if (!trusted || !trusted.exchangeKey) return true; // trust on first use
  return trusted.exchangeKey === senderExchangeKey;
}
