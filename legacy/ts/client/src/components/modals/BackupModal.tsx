// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useState, useRef } from "react";
import { t } from "@/lib/i18n";
import { Modal, Button } from "@/components/ui";
import { exportEncryptedBackup, importEncryptedBackup } from "@/crypto/storage";
import { reconcileRestoreConsistency } from "@/lib/settingsConsistency";
import { vaultGetMasterKey, vaultHasMasterKey } from "@/crypto/keyVault";

interface BackupModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function BackupModal({
  isOpen,
  onClose,
}: BackupModalProps) {
  const [backupStatus, setBackupStatus] = useState<string | null>(null);
  const [backupLoading, setBackupLoading] = useState(false);
  const [backupPin, setBackupPin] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const resetState = () => {
    setBackupPin("");
    setBackupStatus(null);
    setSelectedFile(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  return (
    <Modal isOpen={isOpen} onClose={() => {
      resetState();
      onClose();
    }} title={t("modal.backup.title")}>
      <div className="space-y-4">
        <p className="text-[var(--text-secondary)] text-sm">
          {t("modal.backup.hint")}
        </p>
        <input
          id="backup-pin"
          name="backup-pin"
          type="password"
          // `new-password`, not `off` — see DangerZoneSection. SEC-20260805-002.
          autoComplete="new-password"
          value={backupPin}
          onChange={(e) => setBackupPin(e.target.value)}
          placeholder={t("modal.backup.pinPlaceholder")}
          aria-label={t("modal.backup.pinAria")}
          className="apple-input"
        />
        <Button
          fullWidth
          loading={backupLoading}
          onClick={async () => {
            if (!vaultHasMasterKey() || !backupPin) {
              setBackupStatus(t("modal.backup.enterPinExport"));
              return;
            }
            setBackupStatus(null);
            setBackupLoading(true);
            try {
              const data = await exportEncryptedBackup(vaultGetMasterKey(), backupPin);
              const blob = new Blob([data], { type: "application/octet-stream" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              const date = new Date().toISOString().split("T")[0];
              a.download = `lume-backup-${date}.bin`;
              a.click();
              URL.revokeObjectURL(url);
              try {
                localStorage.setItem("lume:lastBackupAt", String(Date.now()));
                window.dispatchEvent(new Event("lume:backup-saved"));
              } catch {
                // localStorage unavailable — export still succeeded
              }
              setBackupStatus(
                "Backup downloaded. Save this file in a safe place \u2014 iCloud, Google Drive, or a flash drive. Without it, recovery is impossible."
              );
            } catch (e) {
              if (process.env.NODE_ENV !== "production") console.error("Backup export error:", e);
              setBackupStatus(t("modal.backup.exportFailed"));
            } finally {
              setBackupLoading(false);
            }
          }}
        >
          {t("modal.backup.export")}
        </Button>

        <div className="border-t border-[var(--border)]" />

        <div className="space-y-2">
          <input
            ref={fileInputRef}
            id="backup-file"
            name="backup-file"
            type="file"
            accept=".bin"
            className="hidden"
            aria-label={t("modal.backup.selectFileAria")}
            onChange={(e) => {
              const file = e.target.files?.[0] ?? null;
              setSelectedFile(file);
            }}
          />
          <Button
            fullWidth
            variant="secondary"
            onClick={() => fileInputRef.current?.click()}
          >
            {selectedFile ? selectedFile.name : t("modal.backup.selectFile")}
          </Button>
          <Button
            fullWidth
            variant="secondary"
            loading={backupLoading}
            disabled={!selectedFile}
            onClick={async () => {
              if (!backupPin) {
                setBackupStatus(t("modal.backup.enterPinRestore"));
                return;
              }
              if (!selectedFile) return;
              setBackupStatus(null);
              setBackupLoading(true);
              try {
                const text = await selectedFile.text();
                await importEncryptedBackup(text, backupPin);
                await reconcileRestoreConsistency();
                setBackupStatus(t("modal.backup.restored"));
              } catch (e) {
                if (process.env.NODE_ENV !== "production") console.error("Backup restore error:", e);
                setBackupStatus(t("modal.backup.restoreFailed"));
              } finally {
                setBackupLoading(false);
              }
            }}
          >
            {t("modal.backup.restore")}
          </Button>
        </div>

        {backupStatus && (
          <p className="text-xs text-[var(--text-secondary)]">
            {backupStatus}
          </p>
        )}
      </div>
    </Modal>
  );
}
