// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SPK (Signed PreKey) periodic rotation for X3DH protocol.
 *
 * Checks the age of the current SPK and rotates it if older than
 * SPK_ROTATION_INTERVAL_MS. The previous SPK is kept for a grace period
 * (PREVIOUS_SPK_GRACE_PERIOD_MS) so that in-flight X3DH sessions referencing
 * the old SPK can still complete.
 */

import { generateSignedPreKey, type KeyPair } from "./keys";
import { vaultGetSigningKeyPair } from "./keyVault";
import {
  loadPreKeyMaterial,
  savePreKeyMaterial,
  type LocalPreKeyMaterial,
} from "./storage";
import { authApi } from "@/lib/api";

/** Rotate SPK every 7 days. */
export const SPK_ROTATION_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000;

/** Keep the previous SPK for 48 hours after retirement. */
export const PREVIOUS_SPK_GRACE_PERIOD_MS = 48 * 60 * 60 * 1000;

interface SpkRotationResult {
  rotated: boolean;
  error?: string;
}

/**
 * Checks whether the current SPK needs rotation and performs it if so.
 * Also cleans up the previous SPK after the grace period expires.
 *
 * Should be called on unlock and during periodic sync.
 */
let inProcessRotationChain: Promise<unknown> = Promise.resolve();

/**
 * Serialises rotation so overlapping calls — unlock and periodic sync, or two PWA
 * tabs sharing this origin's IndexedDB — cannot each save from a stale load and
 * clobber the freshly-rotated key (losing an SPK that in-flight X3DH still needs).
 * Web Locks serialise across tabs; the in-process chain covers same-tab overlap
 * and environments without the Web Locks API. SEC-20260721-032.
 */
async function withRotationLock<T>(fn: () => Promise<T>): Promise<T> {
  const locks = typeof navigator !== "undefined" ? navigator.locks : undefined;
  if (locks && typeof locks.request === "function") {
    return locks.request("lume-spk-rotation", fn) as Promise<T>;
  }
  const run = inProcessRotationChain.then(fn, fn);
  inProcessRotationChain = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

export async function checkAndRotateSpk(
  masterKey: Uint8Array,
  userId: string,
): Promise<SpkRotationResult> {
  // The load-modify-save below is not safe to interleave; serialise it so a
  // second overlapping call re-reads the rotated state instead of clobbering it.
  return withRotationLock(() => performSpkRotation(masterKey, userId));
}

async function performSpkRotation(
  masterKey: Uint8Array,
  userId: string,
): Promise<SpkRotationResult> {
  const material = await loadPreKeyMaterial(masterKey);
  if (!material) {
    return { rotated: false, error: "No prekey material found" };
  }

  const now = Date.now();
  let changed = false;

  // --- Clean up expired previous SPK ---
  if (material.previousSignedPreKey && material.previousSpkRetiredAt) {
    if (now - material.previousSpkRetiredAt > PREVIOUS_SPK_GRACE_PERIOD_MS) {
      material.previousSignedPreKey = undefined;
      material.previousSpkRetiredAt = undefined;
      changed = true;
    }
  }

  // --- Check if current SPK needs rotation ---
  const spkAge = material.spkCreatedAt ? now - material.spkCreatedAt : Infinity;

  if (spkAge < SPK_ROTATION_INTERVAL_MS) {
    // SPK is still fresh — only persist if we cleaned up previous SPK above
    if (changed) {
      await savePreKeyMaterial(material, masterKey);
    }
    return { rotated: false };
  }

  // --- Rotate SPK ---
  // 1. Save current SPK as previous (grace period for in-flight X3DH)
  material.previousSignedPreKey = material.signedPreKey;
  material.previousSpkRetiredAt = now;

  // 2. Generate new SPK
  const { signedPreKey, signature } = generateSignedPreKey(vaultGetSigningKeyPair());
  material.signedPreKey = signedPreKey;
  material.spkCreatedAt = now;
  material.updatedAt = now;

  // 3. Persist locally first (so we don't lose the key if upload fails)
  await savePreKeyMaterial(material, masterKey);

  // 4. Upload to server
  const { error } = await authApi.updateSignedPrekey(
    userId,
    signedPreKey.publicKey,
    signature,
  );

  if (error) {
    // Upload failed — local state is already updated so the next sync will retry.
    // The server still has the old SPK which is fine because we kept it as previousSignedPreKey.
    return { rotated: true, error: `SPK upload failed: ${error}` };
  }

  return { rotated: true };
}

/**
 * Ensures spkCreatedAt is set on existing prekey material that was
 * created before the rotation feature was added.
 * Call this once during unlock to backfill the field.
 */
export function backfillSpkCreatedAt(
  material: LocalPreKeyMaterial,
): LocalPreKeyMaterial {
  if (material.spkCreatedAt === undefined) {
    // Use updatedAt as a reasonable approximation
    return { ...material, spkCreatedAt: material.updatedAt };
  }
  return material;
}

/**
 * Selects which recipient signed prekey to use when responding to an inbound
 * X3DH, based on the SPK public key the sender addressed. Returns the current
 * SPK (default, or on match), the previous SPK if it matches and is still within
 * its grace window, or null when the addressed SPK is unknown or its grace
 * window has expired (the caller then fails closed). SEC-20260621-022.
 */
export function selectRespondSpk(
  material: LocalPreKeyMaterial,
  addressedSpkPublicKey: string | undefined,
  now: number,
): KeyPair | null {
  if (
    !addressedSpkPublicKey ||
    addressedSpkPublicKey === material.signedPreKey.publicKey
  ) {
    return material.signedPreKey;
  }
  const prev = material.previousSignedPreKey;
  const withinGrace =
    material.previousSpkRetiredAt !== undefined &&
    now - material.previousSpkRetiredAt <= PREVIOUS_SPK_GRACE_PERIOD_MS;
  if (prev && prev.publicKey === addressedSpkPublicKey && withinGrace) {
    return prev;
  }
  return null;
}
