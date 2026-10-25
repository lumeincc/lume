// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useState, useMemo } from "react";
import { t } from "@/lib/i18n";
import { Modal, Button, Input } from "@/components/ui";
import { Avatar } from "@/components/ui/Avatar";
import { groupsApi } from "@/lib/api";
import { useContactsStore, useGroupsStore } from "@/stores";
import { vaultHasKeys } from "@/crypto/keyVault";

interface CreateGroupModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const MAX_MEMBERS = 50;

export default function CreateGroupModal({
  isOpen,
  onClose,
}: CreateGroupModalProps) {
  const contacts = useContactsStore((s) => s.contacts);
  const addGroup = useGroupsStore((s) => s.addGroup);

  const [groupName, setGroupName] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const filteredContacts = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return contacts;
    return contacts.filter((c) => c.username.toLowerCase().includes(q));
  }, [contacts, search]);

  const toggleMember = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        if (next.size >= MAX_MEMBERS) return prev;
        next.add(id);
      }
      return next;
    });
  };

  const resetAndClose = () => {
    setGroupName("");
    setSelectedIds(new Set());
    setSearch("");
    setError("");
    setLoading(false);
    onClose();
  };

  const handleCreate = async () => {
    const name = groupName.trim();
    if (!name) {
      setError(t("modal.group.errorNameRequired"));
      return;
    }
    if (selectedIds.size < 1) {
      setError(t("modal.group.errorSelectMember"));
      return;
    }
    if (!vaultHasKeys()) {
      setError(t("modal.group.errorAuth"));
      return;
    }

    setError("");
    setLoading(true);

    const result = await groupsApi.create(
      name,
      Array.from(selectedIds),
    );

    if (result.error) {
      setError(result.error);
      setLoading(false);
      return;
    }

    if (result.data) {
      addGroup(result.data);
    }

    setLoading(false);
    resetAndClose();
  };

  return (
    <Modal isOpen={isOpen} onClose={resetAndClose} title={t("modal.group.createTitle")}>
      <div className="space-y-4">
        <Input
          label={t("group.name")}
          value={groupName}
          onChange={(e) => {
            setGroupName(e.target.value.slice(0, 64));
            if (error) setError("");
          }}
          placeholder={t("modal.group.namePlaceholder")}
          error={error || undefined}
          autoFocus
        />

        <div>
          <p className="block apple-label mb-1.5">
            {t("modal.group.membersLabel", { selected: selectedIds.size, max: MAX_MEMBERS })}
          </p>

          {contacts.length > 5 && (
            <div className="relative mb-2">
              <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[var(--text-muted)]">
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M21 21l-4.3-4.3m1.8-5.2a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </span>
              <input
                id="create-group-search"
                name="create-group-search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={t("modal.group.searchContacts")}
                className="apple-input apple-input-icon"
                aria-label={t("modal.group.searchContactsAria")}
              />
            </div>
          )}

          <div className="max-h-48 overflow-y-auto rounded-xl border border-[var(--border)] bg-[var(--surface-strong)]">
            {filteredContacts.length === 0 ? (
              <p className="px-4 py-3 text-xs text-[var(--text-muted)] text-center">
                {contacts.length === 0 ? t("modal.group.noContacts") : t("modal.group.noMatches")}
              </p>
            ) : (
              filteredContacts.map((contact) => {
                const checked = selectedIds.has(contact.id);
                return (
                  <button
                    key={contact.id}
                    type="button"
                    onClick={() => toggleMember(contact.id)}
                    className={`
                      w-full px-4 py-2.5 text-left flex items-center gap-3
                      border-b border-[var(--border)]/40 last:border-b-0
                      transition-colors
                      ${checked ? "bg-[var(--surface-alt)]" : "hover:bg-[var(--surface-alt)]"}
                    `}
                  >
                    <div
                      className={`
                        w-5 h-5 rounded-md border flex items-center justify-center flex-shrink-0 transition-colors
                        ${checked ? "bg-[var(--accent)] border-[var(--accent)]" : "border-[var(--border)] bg-[var(--surface)]"}
                      `}
                    >
                      {checked && (
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
        </div>

        <Button
          fullWidth
          onClick={() => void handleCreate()}
          loading={loading}
          disabled={!groupName.trim() || selectedIds.size < 1}
        >
          {t("modal.group.create")}
        </Button>
      </div>
    </Modal>
  );
}
