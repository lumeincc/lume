// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Settings — Danger Zone section (delete account).
 */

"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Modal } from "@/components/ui";
import { panicWipe, deriveMasterKeyFromPin, loadIdentityKeys } from "@/crypto/storage";
import { authApi } from "@/lib/api";
import { useAuthStore } from "@/stores";
import { SectionHeading } from "./shared";
import { t } from "@/lib/i18n";
import { MIN_PIN_LENGTH } from "@/lib/pinPolicy";

export default function DangerZoneSection() {
  const router = useRouter();
  const [showDeleteAccount, setShowDeleteAccount] = useState(false);
  const [deletePin, setDeletePin] = useState("");
  const [deleteError, setDeleteError] = useState("");
  const [deleteLoading, setDeleteLoading] = useState(false);

  const handleDeleteAccount = async () => {
    if (deletePin.length < MIN_PIN_LENGTH) {
      setDeleteError(t("settings.danger.enterPin"));
      return;
    }
    setDeleteError("");
    setDeleteLoading(true);
    try {
      const mk = await deriveMasterKeyFromPin(deletePin);
      const identity = await loadIdentityKeys(mk, deletePin);
      if (!identity) {
        setDeleteError(t("settings.danger.invalidPin"));
        return;
      }

      const uid = useAuthStore.getState().userId;
      if (identity && uid) {
        try {
          await authApi.deleteAccount(uid);
        } catch {
          // Best effort.
        }
      }

      await panicWipe();
      useAuthStore.getState().clearAuth();
      router.replace("/");
    } catch {
      setDeleteError(t("settings.danger.verificationFailed"));
    } finally {
      setDeleteLoading(false);
    }
  };

  return (
    <>
      <section>
        <SectionHeading>{t("settings.danger.title")}</SectionHeading>
        <button
          type="button"
          onClick={() => setShowDeleteAccount(true)}
          className="w-full py-3 px-4 rounded-[var(--radius-md)] border border-red-500/30 text-red-500 text-body font-semibold hover:bg-red-500/5 transition-colors"
        >
          {t("settings.danger.deleteAccount")}
        </button>
      </section>

      <Modal
        isOpen={showDeleteAccount}
        onClose={() => { setShowDeleteAccount(false); setDeletePin(""); setDeleteError(""); }}
        title={t("settings.danger.modalTitle")}
      >
        <div className="space-y-4">
          <p className="text-body text-[var(--text-secondary)] text-center">
            {t("settings.danger.warning")}
          </p>
          <input
            id="delete-account-pin"
            name="delete-account-pin"
            type="password"
            // `new-password`, not `off`: Chromium ignores `off` on password
            // fields and offers to save anyway. SEC-20260805-002.
            autoComplete="new-password"
            value={deletePin}
            onChange={(e) => setDeletePin(e.target.value)}
            placeholder={t("settings.danger.pinPlaceholder")}
            className="apple-input"
          />
          {deleteError && (
            <p className="text-xs text-red-500 text-center">{deleteError}</p>
          )}
          <div className="flex gap-3">
            <button
              type="button"
              onClick={() => { setShowDeleteAccount(false); setDeletePin(""); setDeleteError(""); }}
              className="apple-button-secondary flex-1"
            >
              {t("common.cancel")}
            </button>
            <button
              type="button"
              disabled={deleteLoading}
              onClick={() => void handleDeleteAccount()}
              className="flex-1 py-3 px-4 rounded-[var(--radius-md)] bg-red-500 text-white text-body font-semibold hover:bg-red-600 transition-colors disabled:opacity-50"
            >
              {deleteLoading
                ? t("settings.danger.verifying")
                : t("settings.danger.confirm")}
            </button>
          </div>
        </div>
      </Modal>
    </>
  );
}
