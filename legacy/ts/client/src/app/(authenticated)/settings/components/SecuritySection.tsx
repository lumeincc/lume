// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Settings — Security section (change PIN modal).
 */

"use client";

import { useState } from "react";
import { Button, Input, Modal } from "@/components/ui";
import { changePin } from "@/crypto/storage";
import { vaultSetMasterKey } from "@/crypto/keyVault";
import { SectionHeading } from "./shared";
import { t } from "@/lib/i18n";
import { MIN_PIN_LENGTH } from "@/lib/pinPolicy";

interface SecuritySectionProps {
  onBackupWarning: (show: boolean) => void;
}

export default function SecuritySection({
  onBackupWarning,
}: SecuritySectionProps) {
  const [showPinModal, setShowPinModal] = useState(false);
  const [currentPin, setCurrentPin] = useState("");
  const [newPin, setNewPin] = useState("");
  const [confirmPin, setConfirmPin] = useState("");
  const [pinError, setPinError] = useState<string | null>(null);
  const [pinLoading, setPinLoading] = useState(false);
  const [pinSuccess, setPinSuccess] = useState(false);

  const openModal = () => {
    setShowPinModal(true);
    setPinError(null);
    setPinSuccess(false);
    setCurrentPin("");
    setNewPin("");
    setConfirmPin("");
  };

  const handleChangePin = async () => {
    setPinError(null);

    if (newPin.length < MIN_PIN_LENGTH) {
      setPinError(t("settings.security.errorTooShort"));
      return;
    }
    if (newPin !== confirmPin) {
      setPinError(t("settings.security.errorMismatch"));
      return;
    }
    if (newPin === currentPin) {
      setPinError(t("settings.security.errorSameAsCurrent"));
      return;
    }

    setPinLoading(true);
    try {
      const newMasterKey = await changePin(currentPin, newPin);
      vaultSetMasterKey(newMasterKey);
      setPinSuccess(true);
      onBackupWarning(true);
      setTimeout(() => {
        setShowPinModal(false);
        setPinSuccess(false);
        setCurrentPin("");
        setNewPin("");
        setConfirmPin("");
      }, 1500);
    } catch {
      setPinError(t("settings.security.errorWrongCurrent"));
    } finally {
      setPinLoading(false);
    }
  };

  return (
    <>
      <section>
        <SectionHeading>{t("settings.security.title")}</SectionHeading>
        <button
          type="button"
          onClick={openModal}
          className="apple-button-secondary w-full text-center"
        >
          {t("settings.security.changePin")}
        </button>
      </section>

      <Modal
        isOpen={showPinModal}
        onClose={() => setShowPinModal(false)}
        title={t("settings.security.changePin")}
      >
        <div className="space-y-4">
          {pinSuccess ? (
            <div className="text-center py-6">
              <div className="w-12 h-12 mx-auto rounded-full bg-[var(--accent)] flex items-center justify-center mb-3">
                <svg
                  className="w-6 h-6 text-[var(--accent-contrast)]"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M5 13l4 4L19 7"
                  />
                </svg>
              </div>
              <p className="text-sm font-medium text-[var(--text-primary)]">
                {t("settings.security.changed")}
              </p>
            </div>
          ) : (
            <>
              <Input
                type="password"
                placeholder={t("settings.security.currentPin")}
                aria-label={t("settings.security.currentPin")}
                value={currentPin}
                onChange={(e) => setCurrentPin(e.target.value)}
                autoFocus
              />
              <Input
                type="password"
                placeholder={t("settings.security.newPin")}
                aria-label={t("settings.security.newPin")}
                value={newPin}
                onChange={(e) => setNewPin(e.target.value)}
              />
              <Input
                type="password"
                placeholder={t("settings.security.confirmNewPinPlaceholder")}
                aria-label={t("settings.security.confirmNewPinLabel")}
                value={confirmPin}
                onChange={(e) => setConfirmPin(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && void handleChangePin()}
              />
              {pinError ? (
                <p className="text-xs text-red-500 text-center">{pinError}</p>
              ) : null}
              <Button
                onClick={() => void handleChangePin()}
                disabled={pinLoading || !currentPin || !newPin || !confirmPin}
                className="w-full"
              >
                {pinLoading
                  ? t("settings.security.changing")
                  : t("settings.security.changePin")}
              </Button>
            </>
          )}
        </div>
      </Modal>
    </>
  );
}
