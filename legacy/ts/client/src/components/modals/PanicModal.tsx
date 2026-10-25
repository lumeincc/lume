// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { Modal } from "@/components/ui";
import { t } from "@/lib/i18n";

interface PanicModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
}

export default function PanicModal({
  isOpen,
  onClose,
  onConfirm,
}: PanicModalProps) {
  return (
    <Modal isOpen={isOpen} onClose={onClose} title={t("modal.panic.title")}>
      <div className="space-y-6">
        <p className="text-[var(--text-secondary)]">
          {t("modal.panic.warning")}
        </p>
        <div className="flex gap-3">
          <button
            onClick={onClose}
            className="flex-1 apple-button-secondary"
          >
            {t("common.cancel")}
          </button>
          <button onClick={onConfirm} className="flex-1 apple-button">
            {t("modal.panic.confirm")}
          </button>
        </div>
      </div>
    </Modal>
  );
}
