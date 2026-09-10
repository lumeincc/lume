// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

// @vitest-environment jsdom
/**
 * Tests for hooks/useContactActions.ts
 * Mocks: router, stores, authApi, saveContacts.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';

// ── Hoisted state ─────────────────────────────────────────────────────────────

const mocks = vi.hoisted(() => ({
  // Kept, and asserted *not* to be called: opening a chat used to be a
  // navigation to `/chat/[id]` and is now a state change. A test that simply
  // stopped mentioning the router would not notice it coming back.
  push: vi.fn(),
  addContact: vi.fn(),
  addChat: vi.fn(),
  setActiveChat: vi.fn(),
  setActiveGroup: vi.fn(),
  getUser: vi.fn(),
  saveContacts: vi.fn().mockResolvedValue(undefined),
  contacts: [] as unknown[],
  authUsername: 'alice',
  vaultHasKeysValue: true,
  vaultMasterKey: new Uint8Array(32).fill(1) as Uint8Array | null,
  existingChats: [] as unknown[],
}));

// ── Mocks ─────────────────────────────────────────────────────────────────────

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: mocks.push }),
}));

vi.mock('@/stores', () => {
  const useContactsStore = (selector?: (s: unknown) => unknown) => {
    const state = { contacts: mocks.contacts, addContact: mocks.addContact };
    return selector ? selector(state) : state;
  };
  useContactsStore.getState = () => ({ contacts: mocks.contacts });

  const useChatsStore = (selector?: (s: unknown) => unknown) => {
    const state = { chats: mocks.existingChats, addChat: mocks.addChat, setActiveChat: mocks.setActiveChat };
    return selector ? selector(state) : state;
  };
  useChatsStore.getState = () => ({ chats: mocks.existingChats });

  const useAuthStore = (selector?: (s: unknown) => unknown) => {
    const state = { username: mocks.authUsername };
    return selector ? selector(state) : state;
  };

  const useGroupsStore = (selector?: (s: unknown) => unknown) => {
    const state = { setActiveGroup: mocks.setActiveGroup };
    return selector ? selector(state) : state;
  };

  return { useAuthStore, useContactsStore, useChatsStore, useGroupsStore };
});

vi.mock('@/crypto/keyVault', () => ({
  vaultHasKeys: () => mocks.vaultHasKeysValue,
  vaultGetMasterKey: () => {
    if (!mocks.vaultMasterKey) throw new Error('Vault: no master key');
    return mocks.vaultMasterKey;
  },
}));

vi.mock('@/lib/api', () => ({
  authApi: { getUser: mocks.getUser },
}));

vi.mock('@/crypto/storage', () => ({
  saveContacts: mocks.saveContacts,
}));

vi.mock('uuid', () => ({
  v4: () => 'test-uuid-1234',
}));

// ── Import after mocks ────────────────────────────────────────────────────────

import { useContactActions } from '@/hooks/useContactActions';

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('useContactActions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.contacts = [];
    mocks.existingChats = [];
    mocks.authUsername = 'alice';
    mocks.vaultHasKeysValue = true;
    mocks.vaultMasterKey = new Uint8Array(32).fill(1);
    mocks.saveContacts.mockResolvedValue(undefined);
  });

  // ── initial state ──────────────────────────────────────────────────────────

  describe('initial state', () => {
    it('showAddContact starts as false', () => {
      const { result } = renderHook(() => useContactActions());
      expect(result.current.showAddContact).toBe(false);
    });

    it('addContactError starts as empty string', () => {
      const { result } = renderHook(() => useContactActions());
      expect(result.current.addContactError).toBe('');
    });

    it('addContactLoading starts as false', () => {
      const { result } = renderHook(() => useContactActions());
      expect(result.current.addContactLoading).toBe(false);
    });
  });

  // ── resetAddContact ────────────────────────────────────────────────────────

  describe('resetAddContact', () => {
    it('resets showAddContact and error', async () => {
      mocks.getUser.mockResolvedValue({ data: null, error: 'not found' });
      const { result } = renderHook(() => useContactActions());

      act(() => {
        result.current.setShowAddContact(true);
      });
      // Produce an error so we can observe it being cleared.
      await act(async () => {
        await result.current.handleAddContact('ghost');
      });
      expect(result.current.addContactError).toBe('User not found');

      act(() => {
        result.current.resetAddContact();
      });

      expect(result.current.showAddContact).toBe(false);
      expect(result.current.addContactError).toBe('');
    });
  });

  // ── handleAddContact — happy path ──────────────────────────────────────────

  describe('handleAddContact — happy path', () => {
    it('fetches user, calls addContact, saves contacts, navigates to chat', async () => {
      const newUser = {
        id: 'bob-id',
        username: 'bob',
        identityKey: 'pubkey-bob',
        exchangeIdentityKey: 'exchkey-bob',
        exchangeKey: null,
        signedPrekey: null,
      };
      mocks.getUser.mockResolvedValue({ data: newUser, error: null });

      const { result } = renderHook(() => useContactActions());

      await act(async () => {
        await result.current.handleAddContact('bob');
      });

      expect(mocks.getUser).toHaveBeenCalledWith('bob');
      expect(mocks.addContact).toHaveBeenCalledWith(
        expect.objectContaining({ id: 'bob-id', username: 'bob' })
      );
      expect(mocks.saveContacts).toHaveBeenCalled();
      // Opens the conversation by selecting it, without leaving /chats.
      expect(mocks.setActiveChat).toHaveBeenCalledWith('test-uuid-1234');
      expect(mocks.push).not.toHaveBeenCalled();
    });

    it('closes the modal after successful add', async () => {
      mocks.getUser.mockResolvedValue({
        data: { id: 'bob-id', username: 'bob', identityKey: 'pk', exchangeIdentityKey: 'ek' },
        error: null,
      });

      const { result } = renderHook(() => useContactActions());
      act(() => {
        result.current.setShowAddContact(true);
      });

      await act(async () => {
        await result.current.handleAddContact('bob');
      });

      expect(result.current.showAddContact).toBe(false);
    });

    it('uses exchangeKey fallback when exchangeIdentityKey is absent', async () => {
      mocks.getUser.mockResolvedValue({
        data: { id: 'carol-id', username: 'carol', identityKey: 'pk', exchangeKey: 'ek-fallback' },
        error: null,
      });

      const { result } = renderHook(() => useContactActions());

      await act(async () => {
        await result.current.handleAddContact('carol');
      });

      expect(mocks.addContact).toHaveBeenCalledWith(
        expect.objectContaining({ exchangeKey: 'ek-fallback' })
      );
    });
  });

  // ── handleAddContact — error cases ─────────────────────────────────────────

  describe('handleAddContact — error cases', () => {
    it('sets "User not found" when API returns error', async () => {
      mocks.getUser.mockResolvedValue({ data: null, error: 'not found' });

      const { result } = renderHook(() => useContactActions());

      await act(async () => {
        await result.current.handleAddContact('ghost');
      });

      expect(result.current.addContactError).toBe('User not found');
      expect(mocks.addContact).not.toHaveBeenCalled();
    });

    it('sets "Cannot add yourself" when trying to add own username', async () => {
      mocks.getUser.mockResolvedValue({
        data: { id: 'alice-id', username: 'alice', identityKey: 'pk', exchangeIdentityKey: 'ek' },
        error: null,
      });

      const { result } = renderHook(() => useContactActions());

      await act(async () => {
        await result.current.handleAddContact('alice');
      });

      expect(result.current.addContactError).toBe('Cannot add yourself');
      expect(mocks.addContact).not.toHaveBeenCalled();
    });

    it('sets "Contact already added" for duplicate contact', async () => {
      mocks.contacts = [{ id: 'bob-id', username: 'bob' }];
      mocks.getUser.mockResolvedValue({
        data: { id: 'bob-id', username: 'bob', identityKey: 'pk', exchangeIdentityKey: 'ek' },
        error: null,
      });

      const { result } = renderHook(() => useContactActions());

      await act(async () => {
        await result.current.handleAddContact('bob');
      });

      expect(result.current.addContactError).toBe('Contact already added');
      expect(mocks.addContact).not.toHaveBeenCalled();
    });

    it('sets "Not authenticated" when vault has no keys', async () => {
      mocks.vaultHasKeysValue = false;

      const { result } = renderHook(() => useContactActions());

      await act(async () => {
        await result.current.handleAddContact('bob');
      });

      expect(result.current.addContactError).toBe('Not authenticated');
      expect(mocks.getUser).not.toHaveBeenCalled();
    });

    it('sets "Error adding contact" when API throws', async () => {
      mocks.getUser.mockRejectedValue(new Error('network error'));

      const { result } = renderHook(() => useContactActions());

      await act(async () => {
        await result.current.handleAddContact('bob');
      });

      expect(result.current.addContactError).toBe('Error adding contact');
    });

    it('trims whitespace from contact username before API call', async () => {
      mocks.getUser.mockResolvedValue({
        data: { id: 'bob-id', username: 'bob', identityKey: 'pk', exchangeIdentityKey: 'ek' },
        error: null,
      });

      const { result } = renderHook(() => useContactActions());

      await act(async () => {
        await result.current.handleAddContact('  bob  ');
      });

      expect(mocks.getUser).toHaveBeenCalledWith('bob');
    });

    it('addContactLoading is false after request completes', async () => {
      mocks.getUser.mockResolvedValue({ data: null, error: 'not found' });

      const { result } = renderHook(() => useContactActions());

      await act(async () => {
        await result.current.handleAddContact('ghost');
      });

      expect(result.current.addContactLoading).toBe(false);
    });

    it('does not call saveContacts when masterKey is null', async () => {
      mocks.vaultMasterKey = null;
      mocks.getUser.mockResolvedValue({
        data: { id: 'bob-id', username: 'bob', identityKey: 'pk', exchangeIdentityKey: 'ek' },
        error: null,
      });

      const { result } = renderHook(() => useContactActions());

      await act(async () => {
        await result.current.handleAddContact('bob');
      });

      expect(mocks.saveContacts).not.toHaveBeenCalled();
    });
  });

  // ── openChatForContact ─────────────────────────────────────────────────────

  describe('openChatForContact', () => {
    it('creates a new chat and navigates when no existing chat', () => {
      mocks.existingChats = [];
      const { result } = renderHook(() => useContactActions());

      act(() => {
        result.current.openChatForContact('bob-id');
      });

      expect(mocks.addChat).toHaveBeenCalledWith(
        expect.objectContaining({ contactId: 'bob-id', messages: [] })
      );
      expect(mocks.setActiveChat).toHaveBeenCalledWith('test-uuid-1234');
      expect(mocks.push).not.toHaveBeenCalled();
    });

    it('opens the existing chat without creating a new one', () => {
      mocks.existingChats = [{ id: 'existing-chat-id', contactId: 'bob-id' }];

      const { result } = renderHook(() => useContactActions());

      act(() => {
        result.current.openChatForContact('bob-id');
      });

      expect(mocks.addChat).not.toHaveBeenCalled();
      expect(mocks.setActiveChat).toHaveBeenCalledWith('existing-chat-id');
      expect(mocks.push).not.toHaveBeenCalled();
    });

    it('clears the open group, which would otherwise stay on screen', () => {
      // The chats page renders a group in preference to a chat, so opening a
      // contact from the contacts rail while a group is open has to put the
      // group away or nothing visible changes.
      mocks.existingChats = [{ id: 'existing-chat-id', contactId: 'bob-id' }];

      const { result } = renderHook(() => useContactActions());

      act(() => {
        result.current.openChatForContact('bob-id');
      });

      expect(mocks.setActiveGroup).toHaveBeenCalledWith(null);
    });
  });
});
