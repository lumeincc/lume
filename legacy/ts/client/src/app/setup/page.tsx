// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useState, useEffect, useRef } from "react";
import { t } from "@/lib/i18n";
import { useRouter } from "next/navigation";
import {
  createAccountWithMnemonic,
  getMnemonicWords,
} from "@/crypto/mnemonic";
import {
  saveIdentityKeys,
  saveSettings,
  loadSettings,
  savePreKeyMaterial,
  deriveMasterKeyFromPin,
  savePinHash,
  resetVaultForNewAccount,
} from "@/crypto/storage";
import { generatePreKeyBundle } from "@/crypto/keys";
import { authApi } from "@/lib/api";
import { useAuthStore } from "@/stores";
import { vaultSetAuth } from "@/crypto/keyVault";
import { MIN_PIN_LENGTH, MAX_PIN_LENGTH } from "@/lib/pinPolicy";

type Step = "username" | "pin" | "generate" | "save-seed" | "complete";

export default function SetupPage() {
  const router = useRouter();
  const setAuth = useAuthStore((s) => s.setAuth);

  const [step, setStep] = useState<Step>("username");
  // The recovery mnemonic is held in a ref (not React state) so it stays out of
  // the React DevTools state tree, and the full IdentityKeys object is never put
  // in state at all — it lives only in local scope and the encrypted vault. SEC-20260621-003.
  const mnemonicRef = useRef<string>("");
  const [username, setUsername] = useState("");
  const [usernameError, setUsernameError] = useState("");
  const [pin, setPin] = useState("");
  const [pinConfirm, setPinConfirm] = useState("");
  const [pinError, setPinError] = useState("");
  const [, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [canProceed, setCanProceed] = useState(false);
  const usernameCheckTimerRef = useRef<ReturnType<typeof setTimeout> | null>(
    null,
  );

  useEffect(() => {
    if (step === "save-seed") {
      setCanProceed(false);
      const timer = setTimeout(() => setCanProceed(true), 3000);
      return () => clearTimeout(timer);
    }

    return undefined;
  }, [step]);

  const handleCopyMnemonic = async () => {
    await navigator.clipboard.writeText(mnemonicRef.current);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    // Auto-clear clipboard after 15 seconds to prevent lingering mnemonic
    setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), 15000);
  };

  const handleDownloadRecovery = () => {
    const blob = new Blob([mnemonicRef.current], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "lume-recovery.txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  const checkUsername = (value: string) => {
    const normalized = value.replace(/^@+/, "");
    setUsername(normalized);
    setUsernameError("");

    if (usernameCheckTimerRef.current) {
      clearTimeout(usernameCheckTimerRef.current);
      usernameCheckTimerRef.current = null;
    }

    if (normalized.length < 3) {
      setUsernameError(t("auth.setup.errorUsernameShort"));
      return;
    }

    if (!/^[a-zA-Z0-9_]+$/.test(normalized)) {
      setUsernameError(t("auth.setup.errorUsernameChars"));
      return;
    }

    usernameCheckTimerRef.current = setTimeout(async () => {
      const { data } = await authApi.checkUsername(normalized);
      if (data && !data.available) {
        setUsernameError(t("auth.setup.errorUsernameTaken"));
      }
    }, 400);
  };

  const handleSetPin = () => {
    if (pin.length < MIN_PIN_LENGTH) {
      setPinError(t("auth.setup.errorPinFormat"));
      return;
    }
    if (pin !== pinConfirm) {
      setPinError(t("auth.setup.errorPinMismatch"));
      return;
    }

    setPinError("");
    setStep("generate");
    void handleGenerate();
  };

  const handleGenerate = async () => {
    setLoading(true);
    try {
      // Start from an empty store. Keeping the previous account's records here
      // reuses the salt, so the same PIN decrypts that account's contacts and
      // chats into this one — and a different PIN makes them unreadable, which
      // latches persistence off as an integrity failure.
      await resetVaultForNewAccount();

      const result = await createAccountWithMnemonic(128);
      const generatedIdentity = result.identity;
      mnemonicRef.current = result.mnemonic;

      const preKeyBundle = generatePreKeyBundle(
        generatedIdentity.exchange,
        generatedIdentity.signing,
        20,
      );

      const { data, error } = await authApi.register({
        username,
        identityKey: generatedIdentity.signing.publicKey,
        exchangeIdentityKey: generatedIdentity.exchange.publicKey,
        signedPrekey: preKeyBundle.signedPreKey.publicKey,
        signedPrekeySignature: preKeyBundle.signature,
        oneTimePrekeys: preKeyBundle.oneTimePreKeys.map((key, i) => ({
          id: `${username}-prekey-${i}`,
          publicKey: key.publicKey,
        })),
      });

      if (error || !data) {
        // `!data` was previously asserted away. A response carrying neither an
        // error nor a body would have thrown mid-registration, after the vault
        // had already been reset — leaving no account and no message saying why.
        setUsernameError(error || t("auth.setup.errorRegistration"));
        setStep("username");
        return;
      }

      // Derive master key from PIN — PIN is only used here, never stored
      const masterKey = await deriveMasterKeyFromPin(pin);

      // Store signed prekey + OPKs locally (encrypted) so we can respond to X3DH and consume OPKs.
      await savePreKeyMaterial(
        {
          signedPreKey: preKeyBundle.signedPreKey,
          oneTimePreKeys: preKeyBundle.oneTimePreKeys,
          updatedAt: Date.now(),
        },
        masterKey,
      );

      await saveIdentityKeys(generatedIdentity, masterKey);
      await savePinHash(pin);
      const existingSettings = await loadSettings();
      await saveSettings({
        ...existingSettings,
        username,
        userId: data.id,
      });
      vaultSetAuth(generatedIdentity, masterKey);
      setAuth(data.id, username);
      setStep("save-seed");
    } catch (registrationError) {
      if (process.env.NODE_ENV !== "production")
        console.error("Registration error:", registrationError);
      setUsernameError(t("auth.setup.errorRegistration"));
      setStep("username");
    } finally {
      setLoading(false);
    }
  };

  const handleSaveSeedContinue = () => {
    mnemonicRef.current = "";
    setStep("complete");
    setTimeout(() => {
      const pendingInvite = sessionStorage.getItem("lume:pending-invite");
      if (pendingInvite) {
        sessionStorage.removeItem("lume:pending-invite");
        router.replace(`/invite/${pendingInvite}`);
      } else {
        router.replace("/chats");
      }
    }, 1800);
  };

  const words = getMnemonicWords(mnemonicRef.current);

  const stepInfo =
    step === "username"
      ? { n: 1, back: () => router.push("/") }
      : step === "pin"
        ? { n: 2, back: () => setStep("username") }
        : step === "save-seed"
          ? { n: 3, back: null }
          : null;

  const progressPct =
    step === "username" ? 33 : step === "pin" || step === "generate" ? 66 : 100;

  return (
    <main className="auth-shell">
      {/* Thin progress bar across the top for the multi-step flow */}
      {step !== "complete" && (
        <div className="absolute top-0 left-0 right-0 h-1 bg-[var(--surface-alt)] overflow-hidden z-20">
          <div
            className="h-full bg-[var(--accent)] transition-all duration-700"
            style={{ width: `${progressPct}%` }}
          />
        </div>
      )}

      <div className="auth-hero animate-fade-in">
        {stepInfo && (
          <div className="auth-step-row mb-1">
            {stepInfo.back && (
              <button
                type="button"
                onClick={stepInfo.back}
                aria-label={t("auth.back")}
                className="auth-step-back"
              >
                <svg
                  className="w-4 h-4"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M15 19l-7-7 7-7"
                  />
                </svg>
              </button>
            )}
            <span>{t("auth.stepOf", { n: stepInfo.n })}</span>
          </div>
        )}

        {step === "username" && (
          <div className="stagger-2">
            <h1 className="auth-title mt-6">{t("auth.setup.title")}</h1>

            <div className="mt-8">
              <label htmlFor="setup-username" className="auth-field-label">
                {t("auth.usernameLabel")}
              </label>
              <div className="relative">
                <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[var(--text-muted)]">
                  @
                </span>
                <input
                  id="setup-username"
                  type="text"
                  value={username}
                  onChange={(e) => checkUsername(e.target.value)}
                  placeholder={t("auth.usernamePlaceholder")}
                  className="apple-input apple-input-icon"
                />
              </div>
              {usernameError && (
                <p className="mt-2 text-sm text-[var(--text-secondary)]">
                  {usernameError}
                </p>
              )}
            </div>

            <button
              onClick={() => setStep("pin")}
              disabled={!username || !!usernameError || username.length < 3}
              className="auth-pill mt-6"
            >
              {t("auth.continue")}
            </button>

            <p className="auth-foot mt-7">
              {t("auth.haveAccount")}{" "}
              <button
                className="auth-foot-link"
                onClick={() => router.push("/unlock")}
              >
                {t("auth.login")}
              </button>
            </p>
          </div>
        )}

        {step === "pin" && (
          <div className="stagger-2">
            <h1 className="auth-title mt-6">{t("auth.setup.pinTitle")}</h1>

            <div className="mt-8 flex flex-col gap-4">
              <div>
                <label htmlFor="setup-pin" className="auth-field-label">
                  PIN
                </label>
                <input
                  id="setup-pin"
                  type="password"
                  // Not a credential the browser should keep. See Input.tsx —
                  // this field is a raw <input>, so it carries it itself.
                  autoComplete="new-password"
                  inputMode="text"
                  maxLength={MAX_PIN_LENGTH}
                  value={pin}
                  onChange={(e) => setPin(e.target.value.slice(0, MAX_PIN_LENGTH))}
                  placeholder="••••••••"
                  className="apple-input text-center text-xl sm:text-display tracking-[0.36em]"
                />
              </div>
              <div>
                <label htmlFor="setup-pin-confirm" className="auth-field-label">
                  {t("auth.repeatPin")}
                </label>
                <input
                  id="setup-pin-confirm"
                  type="password"
                  autoComplete="new-password"
                  inputMode="text"
                  maxLength={MAX_PIN_LENGTH}
                  value={pinConfirm}
                  onChange={(e) => setPinConfirm(e.target.value.slice(0, MAX_PIN_LENGTH))}
                  placeholder="••••••••"
                  className="apple-input text-center text-xl sm:text-display tracking-[0.36em]"
                />
                {pinError && (
                  <p className="mt-2 text-sm text-[var(--text-secondary)] text-center">
                    {pinError}
                  </p>
                )}
              </div>
            </div>

            <button
              onClick={handleSetPin}
              disabled={!pin || !pinConfirm}
              className="auth-pill mt-6"
            >
              {t("auth.continue")}
            </button>
          </div>
        )}

        {step === "generate" && (
          <div className="mt-10 text-center" aria-busy="true">
            <div className="w-10 h-10 mx-auto mb-6 border-2 mono-spinner rounded-full animate-spin" />
            <p className="text-[var(--text-secondary)] text-sm">
              {t("auth.setup.creating")}
            </p>
          </div>
        )}

        {step === "save-seed" && (
          <div className="page-enter">
            <h1 className="auth-title mt-6">{t("auth.setup.recoveryTitle")}</h1>
            <p className="auth-hint mt-2">
              {t("auth.setup.recoveryHint")}
            </p>

            <div className="mt-8 grid grid-cols-2 gap-2">
              {words.map((word, index) => (
                <div
                  key={word + index}
                  className="rounded-[14px] border border-[var(--border)] bg-[var(--surface-strong)] px-3 py-2 text-center"
                >
                  <span className="text-caption text-[var(--text-muted)] mr-1">
                    {index + 1}.
                  </span>
                  <span className="text-sm font-medium text-[var(--text-primary)]">
                    {word}
                  </span>
                </div>
              ))}
            </div>

            <div className="mt-6 flex flex-col gap-3">
              <div className="grid grid-cols-2 gap-3">
                <button
                  onClick={handleDownloadRecovery}
                  className="auth-pill-secondary"
                  aria-label={t("auth.setup.downloadAria")}
                >
                  {t("auth.setup.download")}
                </button>
                <button
                  onClick={handleCopyMnemonic}
                  className={`auth-pill-secondary ${copied ? "!bg-[var(--accent)] !text-[var(--accent-contrast)]" : ""}`}
                  aria-label={t("auth.setup.copyAria")}
                >
                  {copied ? t("auth.setup.copied") : t("auth.setup.copy")}
                </button>
              </div>
              <button
                onClick={handleSaveSeedContinue}
                disabled={!canProceed}
                className="auth-pill"
              >
                {t("auth.setup.saved")}
              </button>
            </div>
          </div>
        )}

        {step === "complete" && (
          <div className="mt-6 text-center page-enter">
            <h1 className="auth-title">{t("auth.setup.created")}</h1>
            <p className="auth-hint mt-2">@{username}</p>
          </div>
        )}

      </div>

    </main>
  );
}
