// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useState, useMemo } from "react";
import { t } from "@/lib/i18n";
import { Modal, Button } from "@/components/ui";
import { Avatar } from "@/components/ui/Avatar";
import { groupsApi } from "@/lib/api";
import type { GroupData } from "@/lib/api";
import { useContactsStore, useGroupsStore } from "@/stores";
import { vaultHasKeys } from "@/crypto/keyVault";

interface AddMemberModalProps {
  isOpen: boolean;
  onClose: () => void;
  group: GroupData;
}

export default function AddMemberModal({
  isOpen,
  onClose,
  group,
}: AddMemberModalProps) {
  const contacts = useContactsStore((s) => s.contacts);
  const updateGroup = useGroupsStore((s) => s.updateGroup);

  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const existingMemberIds = useMemo(
    () => new Set(group.members.map((m) => m.user_id)),
    [group.members]
  );

  const availableContacts = useMemo(() => {
    const q = search.trim().toLowerCase();
    return contacts.filter((c) => {
      if (existingMemberIds.has(c.id)) return false;
      if (!q) return true;
      return c.username.toLowerCase().includes(q);
    });
  }, [contacts, search, existingMemberIds]);

  const resetAndClose = () => {
    setSearch("");
    setSelectedId(null);
    setError("");
    setLoading(false);
    onClose();
  };

  const handleAdd = async () => {
    if (!selectedId) {
      setError(t("modal.group.errorSelectContact"));
      return;
    }
    if (!vaultHasKeys()) {
      setError(t("modal.group.errorAuth"));
      return;
    }

    setError("");
    setLoading(true);

    const result = await groupsApi.addMember(group.id, selectedId);

    if (result.error) {
      setError(result.error);
      setLoading(false);
      return;
    }

    if (result.data?.members) {
      updateGroup(group.id, { members: result.data.members });
    }

    setLoading(false);
    resetAndClose();
  };

  return (
    <Modal isOpen={isOpen} onClose={resetAndClose} title={t("modal.group.addMemberTitle")}>
      <div className="space-y-4">
        {availableContacts.length > 3 && (
          <div className="relative">
            <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[var(--text-muted)]">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M21 21l-4.3-4.3m1.8-5.2a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </span>
            <input
              id="add-member-search"
              name="add-member-search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t("modal.group.searchContacts")}
              className="apple-input apple-input-icon"
              aria-label={t("modal.group.searchContactsAria")}
            />
          </div>
        )}

        <div className="max-h-64 overflow-y-auto rounded-xl border border-[var(--border)] bg-[var(--surface-strong)]">
          {availableContacts.length === 0 ? (
            <p className="px-4 py-3 text-xs text-[var(--text-muted)] text-center">
              {t("modal.group.noContactsToAdd")}
            </p>
          ) : (
            availableContacts.map((contact) => {
              const isSelected = selectedId === contact.id;
              return (
                <button
                  key={contact.id}
                  type="button"
                  onClick={() => setSelectedId(isSelected ? null : contact.id)}
                  className={`
                    w-full px-4 py-2.5 text-left flex items-center gap-3
                    border-b border-[var(--border)]/40 last:border-b-0
                    transition-colors
                    ${isSelected ? "bg-[var(--surface-alt)]" : "hover:bg-[var(--surface-alt)]"}
                  `}
                >
                  <div
                    className={`
                      w-5 h-5 rounded-full border flex items-center justify-center flex-shrink-0 transition-colors
                      ${isSelected ? "bg-[var(--accent)] border-[var(--accent)]" : "border-[var(--border)] bg-[var(--surface)]"}
                    `}
                  >
                    {isSelected && (
                      <svg className="w-3 h-3 text-[var(--accent-contrast)]" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M5 13l4 4L19 7" />
                      </svg>
                    )}
                  </div>
                  <Avatar username={contact.username} size="sm" />
                  <span className="text-body text-[var(--text-primary)] truncate">
                    @{contact.username}
                  </span>
                </button>
              );
            })
          )}
        </div>

        {error && (
          <p className="text-sm text-[var(--text-secondary)]">{error}</p>
        )}

        <Button
          fullWidth
          onClick={() => void handleAdd()}
          loading={loading}
          disabled={!selectedId}
        >
          {t("modal.group.addMember")}
        </Button>
      </div>
    </Modal>
  );
}
