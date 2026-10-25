// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useState } from "react";
import { t } from "@/lib/i18n";
import { useRouter } from "next/navigation";
import {
  validateMnemonic,
  recoverIdentityFromMnemonic,
} from "@/crypto/mnemonic";
import {
  saveIdentityKeys,
  loadSettings,
  saveSettings,
  savePreKeyMaterial,
  deriveMasterKeyFromPin,
  savePinHash,
  resetVaultForNewAccount,
} from "@/crypto/storage";
import { useAuthStore } from "@/stores";
import { vaultSetAuth, vaultClear } from "@/crypto/keyVault";
import { authApi } from "@/lib/api";
import { MIN_PIN_LENGTH } from "@/lib/pinPolicy";
import { generatePreKeyBundle } from "@/crypto/keys";

export default function RecoverPage() {
  const router = useRouter();
  const setAuth = useAuthStore((s) => s.setAuth);

  const [mnemonic, setMnemonic] = useState("");
  const [username, setUsername] = useState("");
  const [pin, setPin] = useState("");
  const [pinConfirm, setPinConfirm] = useState("");
  const [step, setStep] = useState<"phrase" | "pin">("phrase");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleValidatePhrase = async () => {
    if (!username || !/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
      setError(t("auth.recover.errorUsername"));
      return;
    }

    const trimmed = mnemonic.trim().toLowerCase();
    const words = trimmed.split(/\s+/);

    if (words.length !== 12 && words.length !== 24) {
      setError(t("auth.recover.errorWordCount"));
      return;
    }

    if (!(await validateMnemonic(trimmed))) {
      setError(t("auth.recover.errorInvalidPhrase"));
      return;
    }

    setError("");
    setStep("pin");
  };

  const handleRecover = async () => {
    if (pin.length < MIN_PIN_LENGTH) {
      setError(t("auth.recover.errorPinTooShort"));
      return;
    }

    if (pin !== pinConfirm) {
      setError(t("auth.recover.errorPinMismatch"));
      return;
    }

    setLoading(true);
    setError("");

    try {
      const trimmed = mnemonic.trim().toLowerCase();
      const identity = await recoverIdentityFromMnemonic(trimmed);

      // Recovery replaces whatever account this device held, so its records go
      // first. Left in place they would be re-read under the recovered account:
      // with the same PIN the old contacts and chats decrypt into it, and with a
      // different PIN they fail to open and latch persistence off.
      await resetVaultForNewAccount();

      // Derive master key from PIN early — needed for vault before API calls
      const masterKey = await deriveMasterKeyFromPin(pin);

      // Set vault early so API calls can sign requests via vault
      vaultSetAuth(identity, masterKey);

      // Generate prekey bundle early — needed for both happy path and rebind
      const preKeyBundle = generatePreKeyBundle(
        identity.exchange,
        identity.signing,
        20,
      );

      const { data, error: getUserError } = await authApi.getUser(
        username,
      );

      let wasRebind = false;
      let resolvedUserId: string;
      let resolvedUsername: string;

      if (getUserError === "User not found" || (!getUserError && !data)) {
        // Server DB reset or account missing — rebind silently.
        // Vault holds keys from vaultSetAuth above, so authApi.register will auto-sign.
        const { data: rebound, error: rebindError } = await authApi.register({
          username,
          identityKey: identity.signing.publicKey,
          exchangeIdentityKey: identity.exchange.publicKey,
          signedPrekey: preKeyBundle.signedPreKey.publicKey,
          signedPrekeySignature: preKeyBundle.signature,
          oneTimePrekeys: preKeyBundle.oneTimePreKeys.map((key, i) => ({
            id: `${username}-prekey-${Date.now()}-${i}`,
            publicKey: key.publicKey,
          })),
        });
        if (!rebound || rebindError) {
          vaultClear();
          setError(t("auth.recover.errorUnreachable"));
          return;
        }
        wasRebind = true;
        resolvedUserId = rebound.id;
        resolvedUsername = rebound.username;
      } else if (getUserError) {
        vaultClear();
        setError(getUserError);
        return;
      } else {
        // Narrowed rather than asserted: the branch above only rules out the
        // "not found" shape, so a response with neither error nor body reached
        // here and threw after the vault had already been reset.
        if (!data) {
          vaultClear();
          setError(t("auth.recover.errorUnreachable"));
          return;
        }
        if (data.identityKey !== identity.signing.publicKey) {
          vaultClear();
          setError(t("auth.recover.errorNoMatch"));
          return;
        }
        resolvedUserId = data.id;
        resolvedUsername = data.username;
      }

      await saveIdentityKeys(identity, masterKey);
      await savePinHash(pin);

      const settings = await loadSettings();
      await saveSettings({
        ...settings,
        username: resolvedUsername,
        userId: resolvedUserId,
      });

      await savePreKeyMaterial(
        {
          signedPreKey: preKeyBundle.signedPreKey,
          oneTimePreKeys: preKeyBundle.oneTimePreKeys,
          updatedAt: Date.now(),
        },
        masterKey,
      );

      if (!wasRebind) {
        const { error: rotateError } = await authApi.updateSignedPrekey(
          resolvedUserId,
          preKeyBundle.signedPreKey.publicKey,
          preKeyBundle.signature,
        );
        if (rotateError) {
          if (process.env.NODE_ENV !== "production")
            console.warn(
              "Signed prekey rotation skipped during recovery:",
              rotateError,
            );
        }

        try {
          await authApi.uploadPrekeys(
            resolvedUserId,
            preKeyBundle.oneTimePreKeys.map((key, i) => ({
              id: `recovery-prekey-${Date.now()}-${i}`,
              publicKey: key.publicKey,
            })),
          );
        } catch (uploadError) {
          if (process.env.NODE_ENV !== "production")
            console.warn("Prekey refill failed after recovery:", uploadError);
        }
      }

      setMnemonic("");
      setPin("");
      setPinConfirm("");
      setAuth(resolvedUserId, resolvedUsername);
      router.replace("/chats");
    } catch (recoverError) {
      vaultClear();
      if (process.env.NODE_ENV !== "production")
        console.error("Recovery error:", recoverError);
      setError(t("auth.recover.errorGeneric"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="auth-shell">
      <div className="auth-hero animate-fade-in">
        <h1 className="auth-title">{t("auth.recover.title")}</h1>

        {step === "phrase" && (
          <div className="mt-8 flex flex-col gap-4">
            <div>
              <label htmlFor="recover-username" className="auth-field-label">
                {t("auth.usernameLabel")}
              </label>
              <div className="relative">
                <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[var(--text-muted)]">
                  @
                </span>
                <input
                  id="recover-username"
                  value={username}
                  onChange={(e) =>
                    setUsername(e.target.value.replace(/^@+/, "").trim())
                  }
                  placeholder={t("auth.usernamePlaceholder")}
                  className="apple-input apple-input-icon"
                />
              </div>
            </div>

            <div>
              <label htmlFor="recover-mnemonic" className="auth-field-label">
                {t("auth.recover.phraseLabel")}
              </label>
              <textarea
                id="recover-mnemonic"
                value={mnemonic}
                onChange={(e) => setMnemonic(e.target.value)}
                placeholder={t("auth.recover.phrasePlaceholder")}
                rows={4}
                className="apple-textarea"
              />
            </div>

            {error && (
              <p className="text-sm text-[var(--text-secondary)] text-center">
                {error}
              </p>
            )}

            <div className="flex flex-col gap-3 mt-1">
              <button
                onClick={handleValidatePhrase}
                disabled={!mnemonic.trim() || !username.trim()}
                className="auth-pill"
              >
                {t("auth.continue")}
              </button>
              <button
                onClick={() => router.push("/")}
                className="auth-pill-secondary"
              >
                {t("auth.back")}
              </button>
            </div>
          </div>
        )}

        {step === "pin" && (
          <div className="mt-8 flex flex-col gap-4">
            <div>
              <label htmlFor="recover-pin" className="auth-field-label">
                {t("auth.recover.newPin")}
              </label>
              <input
                id="recover-pin"
                type="password"
                // See Input.tsx: a local KDF input, not a saved credential.
                autoComplete="new-password"
                value={pin}
                onChange={(e) => setPin(e.target.value)}
                placeholder="••••"
                className="apple-input"
              />
            </div>

            <div>
              <label htmlFor="recover-pin-confirm" className="auth-field-label">
                {t("auth.repeatPin")}
              </label>
              <input
                id="recover-pin-confirm"
                type="password"
                autoComplete="new-password"
                value={pinConfirm}
                onChange={(e) => setPinConfirm(e.target.value)}
                placeholder="••••"
                className="apple-input"
              />
            </div>

            {error && (
              <p className="text-sm text-[var(--text-secondary)] text-center">
                {error}
              </p>
            )}

            <div className="flex flex-col gap-3 mt-1">
              <button
                onClick={handleRecover}
                disabled={!pin || !pinConfirm || loading}
                className="auth-pill"
              >
                {loading ? (
                  <span className="flex items-center justify-center gap-2">
                    <span className="w-4 h-4 border-2 mono-spinner rounded-full animate-spin" />
                    {t("auth.recover.recovering")}
                  </span>
                ) : (
                  "Recover"
                )}
              </button>
              <button
                onClick={() => setStep("phrase")}
                className="auth-pill-secondary"
              >
                Back
              </button>
            </div>
          </div>
        )}
      </div>

    </main>
  );
}
