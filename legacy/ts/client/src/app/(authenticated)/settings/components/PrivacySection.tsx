// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Settings — Privacy section:
 * self-destruct timer, discoverable toggle + invite tokens, hidden chats toggle, hidden PIN modals.
 */

"use client";

import { useState, useCallback, useEffect } from "react";
import QRCode from "qrcode";
import { Button, Input, Modal } from "@/components/ui";
import type { Settings } from "@/crypto/storage";
import {
  hashHiddenChatPin,
  saveSettings,
  verifyHiddenChatPin,
  deriveMasterKeyFromPin,
  constantTimeEqual,
} from "@/crypto/storage";
import { useAuthStore, useChatsStore, useUIStore } from "@/stores";
import { inviteApi, profileApi } from "@/lib/api";
import { SectionHeading, ToggleRow } from "./shared";
import { t } from "@/lib/i18n";
import { MIN_PIN_LENGTH } from "@/lib/pinPolicy";
import { SegmentedControl } from "@/components/ui/SegmentedControl";
import { vaultHasKeys, vaultGetMasterKey, vaultHasMasterKey } from "@/crypto/keyVault";

const APP_URL = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";

const SELF_DESTRUCT_OPTIONS: { label: string; value: number | null }[] = [
  { label: "Off", value: null },
  { label: "5 s", value: 5 },
  { label: "30 s", value: 30 },
  { label: "1 min", value: 60 },
  { label: "5 min", value: 300 },
  { label: "1 hr", value: 3600 },
];

type HiddenPinMode = "setup" | "change" | "reset";

interface PrivacySectionProps {
  settings: Settings;
  onSettingsChange: (next: Settings) => void;
  onUpdate: <K extends keyof Settings>(key: K, value: Settings[K]) => void;
  onSaveFlash: () => void;
}

export default function PrivacySection({
  settings,
  onSettingsChange,
  onUpdate,
  onSaveFlash,
}: PrivacySectionProps) {
  const setChats = useChatsStore((s) => s.setChats);
  const setShowHiddenChats = useUIStore((s) => s.setShowHiddenChats);

  // Discoverable / invite state — fetch real value on mount
  const [discoverable, setDiscoverable] = useState<boolean | null>(null);
  const [inviteToken, setInviteToken] = useState<string | null>(null);
  const [inviteExpiresAt, setInviteExpiresAt] = useState<number | null>(null);
  const [inviteQrDataUrl, setInviteQrDataUrl] = useState<string | null>(null);
  const [countdown, setCountdown] = useState("");
  const [inviteLoading, setInviteLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  // Fetch discoverable state from server on mount
  useEffect(() => {
    const { userId } = useAuthStore.getState();
    if (!userId || !vaultHasKeys()) return;
    let cancelled = false;
    void profileApi.get(userId).then((result) => {
      if (cancelled) return;
      if (result.data) {
        setDiscoverable(result.data.discoverable ?? true);
      }
    });
    return () => { cancelled = true; };
  }, []);

  const handleToggleDiscoverable = useCallback(async (enabled: boolean) => {
    const { userId } = useAuthStore.getState();
    if (!userId || !vaultHasKeys()) return;
    const result = await inviteApi.setDiscoverable(userId, enabled);
    if (result.data) {
      setDiscoverable(result.data.discoverable);
      useAuthStore.getState().setDiscoverable(result.data.discoverable);
      if (enabled) {
        setInviteToken(null);
        setInviteExpiresAt(null);
        setInviteQrDataUrl(null);
      }
    }
  }, []);

  const handleGenerateInvite = useCallback(async () => {
    const { userId } = useAuthStore.getState();
    if (!userId || !vaultHasKeys()) return;
    setInviteLoading(true);
    try {
      const result = await inviteApi.createToken(userId);
      if (result.data) {
        setInviteToken(result.data.token);
        setInviteExpiresAt(result.data.expiresAt);
        const link = `${APP_URL}/invite/${result.data.token}`;
        const qr = await QRCode.toDataURL(link, {
          width: 200,
          margin: 2,
          color: { dark: "#000000", light: "#ffffff" },
        });
        setInviteQrDataUrl(qr);
      }
    } finally {
      setInviteLoading(false);
    }
  }, []);

  const handleCopyInviteLink = useCallback(() => {
    if (!inviteToken) return;
    const link = `${APP_URL}/invite/${inviteToken}`;
    void navigator.clipboard.writeText(link);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [inviteToken]);

  // Countdown timer for invite token expiry
  useEffect(() => {
    if (!inviteExpiresAt) {
      setCountdown("");
      return;
    }

    const tick = () => {
      const remaining = inviteExpiresAt - Math.floor(Date.now() / 1000);
      if (remaining <= 0) {
        setCountdown(t("settings.privacy.expired"));
        setInviteToken(null);
        setInviteExpiresAt(null);
        setInviteQrDataUrl(null);
        return;
      }

      if (remaining <= 5 && !inviteLoading) {
        void handleGenerateInvite();
        return;
      }

      const h = Math.floor(remaining / 3600);
      const m = Math.floor((remaining % 3600) / 60);
      const s = remaining % 60;
      setCountdown(
        h > 0 ? `${h}h ${m}m ${s}s` : m > 0 ? `${m}m ${s}s` : `${s}s`,
      );
    };

    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, [inviteExpiresAt, inviteLoading, handleGenerateInvite]);

  // Hidden chats state
  const [showHiddenPinModal, setShowHiddenPinModal] = useState(false);
  const [hiddenPinMode, setHiddenPinMode] = useState<HiddenPinMode>("setup");
  const [hiddenCurrentPin, setHiddenCurrentPin] = useState("");
  const [hiddenAccountPin, setHiddenAccountPin] = useState("");
  const [hiddenPin, setHiddenPin] = useState("");
  const [hiddenPinConfirm, setHiddenPinConfirm] = useState("");
  const [hiddenPinError, setHiddenPinError] = useState<string | null>(null);

  const resetHiddenPinForm = useCallback(() => {
    setHiddenCurrentPin("");
    setHiddenAccountPin("");
    setHiddenPin("");
    setHiddenPinConfirm("");
    setHiddenPinError(null);
  }, []);

  const openHiddenPinModal = useCallback(
    (mode: HiddenPinMode) => {
      setHiddenPinMode(mode);
      resetHiddenPinForm();
      setShowHiddenPinModal(true);
    },
    [resetHiddenPinForm],
  );

  const handleSubmitHiddenPin = async () => {
    setHiddenPinError(null);

    if (hiddenPin.length < MIN_PIN_LENGTH) {
      setHiddenPinError(t("settings.hidden.errorTooShort"));
      return;
    }
    if (hiddenPin !== hiddenPinConfirm) {
      setHiddenPinError(t("settings.hidden.errorMismatch"));
      return;
    }

    try {
      if (hiddenPinMode === "change") {
        if (!settings.hiddenChatPinHash) {
          setHiddenPinError(t("settings.hidden.errorNotConfigured"));
          return;
        }
        if (hiddenCurrentPin.length < MIN_PIN_LENGTH) {
          setHiddenPinError(t("settings.hidden.errorEnterCurrent"));
          return;
        }
        const ok = await verifyHiddenChatPin(
          hiddenCurrentPin,
          settings.hiddenChatPinHash,
        );
        if (!ok) {
          setHiddenPinError(t("settings.hidden.errorWrongCurrent"));
          return;
        }
      }

      if (hiddenPinMode === "reset") {
        if (!vaultHasMasterKey()) {
          setHiddenPinError(t("settings.hidden.errorUnlockRequired"));
          return;
        }
        // Verify the entered account PIN by deriving a key and comparing with session key
        const currentMasterKey = vaultGetMasterKey();
        const derivedKey = await deriveMasterKeyFromPin(hiddenAccountPin);
        // Was an inline copy of the same loop. A constant-time comparison
        // reimplemented in a component is one that nobody reviews as crypto —
        // this now calls the audited helper, which also covers the length check.
        if (!constantTimeEqual(derivedKey, currentMasterKey)) {
          setHiddenPinError(t("settings.hidden.errorWrongAccountPin"));
          return;
        }
      }

      const hiddenChatPinHash = await hashHiddenChatPin(hiddenPin);
      const next: Settings = {
        ...settings,
        hiddenChatsEnabled: true,
        hiddenChatPinHash,
      };
      onSettingsChange(next);
      if (!vaultHasMasterKey()) {
        setHiddenPinError(t("settings.hidden.errorUnlockToSave"));
        return;
      }
      await saveSettings(next, vaultGetMasterKey());
      setShowHiddenPinModal(false);
      resetHiddenPinForm();
      onSaveFlash();
    } catch {
      setHiddenPinError(t("settings.hidden.errorSaveFailed"));
    }
  };

  const handleToggleHiddenChats = (enabled: boolean) => {
    if (!enabled) {
      setShowHiddenChats(false);
      const visibleChats = useChatsStore
        .getState()
        .chats.map((chat) => (chat.isHidden ? { ...chat, isHidden: false } : chat));
      setChats(visibleChats);
      void onUpdate("hiddenChatsEnabled", false);
      return;
    }

    if (settings.hiddenChatPinHash) {
      void onUpdate("hiddenChatsEnabled", true);
      return;
    }

    openHiddenPinModal("setup");
  };

  return (
    <>
      <section>
        <SectionHeading>{t("settings.privacy.title")}</SectionHeading>

        <div className="mb-4">
          <p className="text-body text-[var(--text-secondary)] mb-3">
            {t("settings.selfDestructDefault")}
          </p>
          <SegmentedControl<number | null>
            options={SELF_DESTRUCT_OPTIONS}
            value={settings.selfDestructDefault}
            onChange={(v) => onUpdate("selfDestructDefault", v)}
          />
        </div>

        <ToggleRow
          label={t("settings.privacy.discoverable")}
          description={t("settings.privacy.discoverableHint")}
          checked={discoverable ?? true}
          onChange={(v) => void handleToggleDiscoverable(v)}
        />

        {discoverable === false ? (
          <div
            className="rounded-xl p-4 mb-4"
            style={{ background: "var(--surface-alt)" }}
          >
            <p className="text-xs text-[var(--text-muted)] mb-3">
              {t("settings.privacy.inviteHint")}
            </p>

            {!inviteToken ? (
              <Button
                onClick={() => void handleGenerateInvite()}
                disabled={inviteLoading}
                className="w-full"
              >
                {inviteLoading ? t("settings.privacy.generating") : t("settings.privacy.generateInvite")}
              </Button>
            ) : (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <code className="flex-1 min-w-0 truncate text-xs text-[var(--text-secondary)] font-mono">
                    {`${APP_URL}/invite/${inviteToken}`}
                  </code>
                  <Button
                    onClick={handleCopyInviteLink}
                    className="shrink-0 text-xs"
                  >
                    {copied ? t("settings.privacy.copied") : t("settings.privacy.copy")}
                  </Button>
                </div>

                <p className="text-xs text-[var(--text-muted)] text-center">
                  {t("settings.privacy.expiresIn", { time: countdown })}
                </p>

                {inviteQrDataUrl ? (
                  <div className="flex justify-center">
                    {/* eslint-disable-next-line @next/next/no-img-element -- inline data: URL QR code */}
                    <img
                      src={inviteQrDataUrl}
                      alt={t("settings.privacy.qrAlt")}
                      width={180}
                      height={180}
                      className="rounded-lg"
                      style={{ background: "var(--qr-surface)" }}
                    />
                  </div>
                ) : null}

                <Button
                  onClick={() => void handleGenerateInvite()}
                  disabled={inviteLoading}
                  className="w-full"
                >
                  {inviteLoading ? t("settings.privacy.generating") : t("settings.privacy.generateNew")}
                </Button>
              </div>
            )}
          </div>
        ) : null}

        <ToggleRow
          label={t("settings.hidden.toggle")}
          description={t("settings.hidden.toggleHint")}
          checked={settings.hiddenChatsEnabled}
          onChange={handleToggleHiddenChats}
        />

        {settings.hiddenChatsEnabled ? (
          <div className="mt-3 flex gap-2">
            <button
              type="button"
              onClick={() => openHiddenPinModal("change")}
              className="flex-1 apple-button-secondary text-xs"
            >
              {t("hidden.change")}
            </button>
            <button
              type="button"
              onClick={() => openHiddenPinModal("reset")}
              className="flex-1 apple-button-secondary text-xs"
            >
              {t("hidden.reset")}
            </button>
          </div>
        ) : null}
      </section>

      <Modal
        isOpen={showHiddenPinModal}
        onClose={() => {
          setShowHiddenPinModal(false);
          resetHiddenPinForm();
        }}
        title={
          hiddenPinMode === "setup"
            ? t("settings.hidden.titleSetup")
            : hiddenPinMode === "change"
              ? t("settings.hidden.titleChange")
              : t("settings.hidden.titleReset")
        }
      >
        <div className="space-y-4">
          <p className="text-xs text-[var(--text-secondary)]">
            {hiddenPinMode === "setup"
              ? t("settings.hidden.hintSetup")
              : hiddenPinMode === "change"
                ? t("settings.hidden.hintChange")
                : t("settings.hidden.hintReset")}
          </p>

          {hiddenPinMode === "change" ? (
            <Input
              type="password"
              placeholder={t("settings.hidden.currentPin")}
              aria-label={t("settings.hidden.currentPin")}
              value={hiddenCurrentPin}
              onChange={(e) => setHiddenCurrentPin(e.target.value)}
              autoFocus
            />
          ) : null}

          {hiddenPinMode === "reset" ? (
            <Input
              type="password"
              placeholder={t("settings.hidden.accountPin")}
              aria-label={t("settings.hidden.accountPin")}
              value={hiddenAccountPin}
              onChange={(e) => setHiddenAccountPin(e.target.value)}
              autoFocus
            />
          ) : null}

          <Input
            type="password"
            placeholder={t("settings.hidden.newPin")}
            aria-label={t("settings.hidden.newPin")}
            value={hiddenPin}
            onChange={(e) => setHiddenPin(e.target.value)}
            autoFocus={hiddenPinMode === "setup"}
          />
          <Input
            type="password"
            placeholder={t("settings.hidden.confirmPin")}
            aria-label={t("settings.hidden.confirmPin")}
            value={hiddenPinConfirm}
            onChange={(e) => setHiddenPinConfirm(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void handleSubmitHiddenPin()}
          />

          {hiddenPinError ? (
            <p className="text-xs text-red-500 text-center">{hiddenPinError}</p>
          ) : null}

          <Button
            onClick={() => void handleSubmitHiddenPin()}
            disabled={!hiddenPin || !hiddenPinConfirm}
            className="w-full"
          >
            {hiddenPinMode === "setup"
              ? t("settings.hidden.enable")
              : hiddenPinMode === "change"
                ? t("settings.hidden.titleChange")
                : t("settings.hidden.titleReset")}
          </Button>
        </div>
      </Modal>
    </>
  );
}
