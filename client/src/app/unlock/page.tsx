// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { t } from "@/lib/i18n";
import { useRouter } from "next/navigation";
import { errorFeedback, successFeedback } from "@/lib/haptics";
import {
  loadIdentityKeys,
  loadSettings,
  saveSettings,
  hasAccount,
  loadPreKeyMaterial,
  savePreKeyMaterial,
  deriveMasterKeyFromPin,
  checkPinLockout,
  recordPinFailure,
  resetPinFailures,
} from "@/crypto/storage";
import { useAuthStore } from "@/stores";
import { vaultSetAuth, vaultClear } from "@/crypto/keyVault";
import { authApi, profileApi } from "@/lib/api";
import { generatePreKeyBundle } from "@/crypto/keys";
import { checkAndRotateSpk, backfillSpkCreatedAt } from "@/crypto/spkRotation";
import { MIN_PIN_LENGTH, MAX_PIN_LENGTH } from "@/lib/pinPolicy";

export default function UnlockPage() {
  const router = useRouter();
  const setAuth = useAuthStore((s) => s.setAuth);

  const [pin, setPin] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [attempts, setAttempts] = useState(0);
  const [shaking, setShaking] = useState(false);
  const [bouncingDot, setBouncingDot] = useState<number | null>(null);
  const hiddenInputRef = useRef<HTMLInputElement>(null);

  const focusHiddenInput = useCallback(() => {
    hiddenInputRef.current?.focus();
  }, []);

  const handlePinChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    // Allow any characters: the secret is now an alphanumeric passphrase, not a
    // numeric PIN. SEC-20260721-020.
    const value = e.target.value.slice(0, MAX_PIN_LENGTH);
    if (value.length > pin.length) {
      setBouncingDot(value.length - 1);
    }
    setPin(value);
  }, [pin.length]);

  useEffect(() => {
    async function check() {
      const exists = await hasAccount();
      if (!exists) {
        router.replace("/");
      }
    }

    check();
  }, [router]);

  const handleUnlock = async () => {
    setError("");
    setLoading(true);

    try {
      // Check persistent lockout before attempting
      await checkPinLockout();

      // Derive the master key from the entered PIN — PIN is discarded after this
      const masterKey = await deriveMasterKeyFromPin(pin);
      const identity = await loadIdentityKeys(masterKey, pin);

      if (!identity) {
        await recordPinFailure();
        const nextAttempts = attempts + 1;
        setAttempts(nextAttempts);
        errorFeedback();
        setShaking(true);
        if (nextAttempts >= 5) {
          setError(t("auth.unlock.errorTooManyAttempts"));
          return;
        }
        setError(t("auth.unlock.errorInvalidPin"));
        return;
      }

      await resetPinFailures();

      // Set vault keys early so API calls (which sign via vault) work
      vaultSetAuth(identity, masterKey);

      const settings = await loadSettings();
      let resolvedUserId = settings.userId;
      let resolvedUsername = settings.username?.replace(/^@+/, "").trim();

      // Always try to reconcile stored userId with the server's current record.
      // This prevents "User not found" loops after DB resets or stale local settings.
      if (resolvedUsername) {
        const { data: serverUser, error: serverError } = await authApi.getUser(
          resolvedUsername,
        );

        if (serverUser) {
          if (serverUser.identityKey !== identity.signing.publicKey) {
            vaultClear();
            errorFeedback();
            setShaking(true);
            setError(
              t("auth.unlock.errorIdentityMismatch"),
            );
            return;
          }

          resolvedUserId = serverUser.id;
          resolvedUsername = serverUser.username;

          if (
            resolvedUserId !== settings.userId ||
            resolvedUsername !== settings.username
          ) {
            await saveSettings({
              ...settings,
              userId: resolvedUserId,
              username: resolvedUsername,
            });
          }
        } else if (serverError === "User not found") {
          // Server DB reset — rebind silently. Vault still holds keys from
          // vaultSetAuth above, so authApi.register will auto-sign.
          const bundle = generatePreKeyBundle(identity.exchange, identity.signing, 20);
          const { data: rebound, error: rebindError } = await authApi.register({
            username: resolvedUsername,
            identityKey: identity.signing.publicKey,
            exchangeIdentityKey: identity.exchange.publicKey,
            signedPrekey: bundle.signedPreKey.publicKey,
            signedPrekeySignature: bundle.signature,
            oneTimePrekeys: bundle.oneTimePreKeys.map((key, i) => ({
              id: `${resolvedUsername}-prekey-${Date.now()}-${i}`,
              publicKey: key.publicKey,
            })),
          });
          if (!rebound || rebindError) {
            vaultClear();
            errorFeedback();
            setShaking(true);
            setError(t("auth.unlock.errorUnreachable"));
            return;
          }
          await savePreKeyMaterial(
            {
              signedPreKey: bundle.signedPreKey,
              oneTimePreKeys: bundle.oneTimePreKeys,
              updatedAt: Date.now(),
            },
            masterKey,
          );
          resolvedUserId = rebound.id;
          resolvedUsername = rebound.username;
          await saveSettings({ ...settings, userId: resolvedUserId, username: resolvedUsername });
          // fall through to the existing success path (SPK rotation, setAuth, etc.)
        }
      }

      if (!resolvedUserId || !resolvedUsername) {
        vaultClear();
        errorFeedback();
        setShaking(true);
        setError(t("auth.unlock.errorProfileMissing"));
        return;
      }

      // Backfill spkCreatedAt for prekey material created before rotation feature
      const existingMaterial = await loadPreKeyMaterial(masterKey);
      if (existingMaterial) {
        const backfilled = backfillSpkCreatedAt(existingMaterial);
        if (backfilled !== existingMaterial) {
          await savePreKeyMaterial(backfilled, masterKey);
        }
      }

      // Rotate SPK only if older than the rotation interval (7 days)
      const spkResult = await checkAndRotateSpk(
        masterKey,
        resolvedUserId,
      );
      if (spkResult.error) {
        if (process.env.NODE_ENV !== "production")
          console.warn("SPK rotation issue during unlock:", spkResult.error);
      }

      successFeedback();
      setAuth(resolvedUserId, resolvedUsername);

      // Fetch discoverable state
      void profileApi.get(resolvedUserId).then((profileResult) => {
        if (profileResult.data?.discoverable !== undefined) {
          useAuthStore.getState().setDiscoverable(profileResult.data.discoverable);
        }
      });

      const pendingInvite = sessionStorage.getItem("lume:pending-invite");
      if (pendingInvite) {
        sessionStorage.removeItem("lume:pending-invite");
        router.replace(`/invite/${pendingInvite}`);
      } else {
        router.replace("/chats");
      }
    } catch (unlockError) {
      if (process.env.NODE_ENV !== "production")
        console.error("Unlock error:", unlockError);
      errorFeedback();
      setShaking(true);
      const msg =
        unlockError instanceof Error ? unlockError.message : t("auth.unlock.errorGeneric");
      setError(msg.startsWith("Too many") ? msg : t("auth.unlock.errorGeneric"));
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && pin.length >= MIN_PIN_LENGTH) {
      handleUnlock();
    }
  };

  return (
    <main className="auth-shell">
      <div className="auth-hero animate-fade-in">
        <h1 className="auth-title">{t("auth.unlock.title")}</h1>

        <div className="mt-8">
          <label htmlFor="unlock-pin" className="sr-only">
            {t("auth.unlock.pinLabel")}
          </label>

          {/*
            Hidden input captures keyboard entry.

            `new-password`, not `current-password`: this field is not a login
            credential the server checks, it is the KDF input for the at-rest master
            key. Asking the browser to save it would put the only secret protecting
            the encrypted store beside that store — often synced to a vendor cloud —
            and make the passphrase-strength floor irrelevant to anyone holding the
            profile. SEC-20260805-002.

            The finding's required validation is "no save prompt appears", and
            browsers honour `new-password` more consistently than `off` on
            password fields — so this uses the variant that meets the criterion.
          */}
          <input
            ref={hiddenInputRef}
            id="unlock-pin"
            type="password"
            inputMode="text"
            autoComplete="new-password"
            value={pin}
            onChange={handlePinChange}
            onKeyDown={handleKeyDown}
            autoFocus
            className="sr-only"
            aria-label={t("auth.unlock.pinAria")}
            maxLength={MAX_PIN_LENGTH}
          />

          {/* Visual PIN dots */}
          <button
            type="button"
            onClick={focusHiddenInput}
            className={`flex items-center justify-center gap-3 w-full py-4 cursor-text${shaking ? " pin-shake" : ""}`}
            onAnimationEnd={() => setShaking(false)}
            aria-hidden="true"
            tabIndex={-1}
          >
            {pin.length === 0 ? (
              <span className="text-sm text-[var(--text-muted)] tracking-[0.08em]">
                {t("auth.unlock.pinAria")}
              </span>
            ) : (
              Array.from({ length: pin.length }, (_, i) => (
                <span
                  key={i}
                  className={`w-3 h-3 rounded-full bg-[var(--accent)] transition-colors duration-150${bouncingDot === i ? " pin-dot-bounce" : ""}`}
                  onAnimationEnd={() => setBouncingDot(null)}
                />
              ))
            )}
          </button>

          {error && (
            <p className="mt-1 text-sm text-[var(--text-secondary)] text-center">
              {error}
            </p>
          )}
        </div>

        <div className="mt-6 flex flex-col gap-3">
          <button
            onClick={handleUnlock}
            disabled={pin.length < MIN_PIN_LENGTH || loading}
            className="auth-pill"
          >
            {loading ? (
              <span className="flex items-center justify-center gap-2">
                <span className="w-5 h-5 border-2 mono-spinner rounded-full animate-spin" />
                {t("auth.unlock.checking")}
              </span>
            ) : (
              t("auth.login")
            )}
          </button>

          <div className="auth-or">{t("auth.or")}</div>

          <button
            onClick={() => router.push("/recover")}
            className="auth-pill-secondary"
          >
            {t("auth.recoverWithPhrase")}
          </button>
        </div>

        <p className="auth-foot mt-7">
          {t("auth.unlock.newHere")}{" "}
          <button
            className="auth-foot-link"
            onClick={() => router.push("/setup")}
          >
            {t("auth.createAccount")}
          </button>
        </p>
      </div>

    </main>
  );
}
