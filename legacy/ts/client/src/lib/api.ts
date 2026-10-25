// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * API клиент для взаимодействия с сервером
 */

import type { ZodType } from 'zod';

import { vaultHasKeys, vaultSignRequest } from '@/crypto/keyVault';
import {
    RegisterResponseSchema,
    CheckUsernameResponseSchema,
    UserBundleSchema,
    SessionResponseSchema,
    BlockedUsersResponseSchema,
    SendMessageResponseSchema,
    PendingMessagesResponseSchema,
    AcknowledgeResponseSchema,
    UploadFileResponseSchema,
    DownloadFileResponseSchema,
    GroupDataSchema,
    GroupListResponseSchema,
    AddMemberResponseSchema,
    RemoveMemberResponseSchema,
    ProfileDataSchema,
    InviteTokenResponseSchema,
    ResolveInviteResponseSchema,
    DiscoverableResponseSchema,
    MessageResponseSchema,
    OkResponseSchema,
    HealthResponseSchema,
    UploadPrekeysResponseSchema,
} from './schemas';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001/api';

interface ApiResponse<T = unknown> {
    data?: T;
    error?: string;
}

async function request<T>(
    endpoint: string,
    options: RequestInit = {},
    schema?: ZodType<T>
): Promise<ApiResponse<T>> {
    try {
        const response = await fetch(`${API_URL}${endpoint}`, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers,
            },
        });

        if (response.status === 429) {
            return { error: 'Too many requests. Please try again later.' };
        }

        let data;
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            try {
                data = await response.json();
            } catch (e) {
                console.error('Failed to parse JSON response:', e);
                return { error: 'Invalid server response' };
            }
        } else {
            // If not JSON, try to read text or ignore
            try {
                const text = await response.text();
                // If it's a small text error, use it, otherwise generic
                data = { error: text.length < 100 ? text : 'Server error' };
            } catch {
                data = { error: 'Unknown server error' };
            }
        }

        if (!response.ok) {
            return { error: data.error || `Request failed: ${response.status}` };
        }

        // Validate the server response shape before use (fail closed). SEC-20260621-007.
        if (schema) {
            const parsed = schema.safeParse(data);
            if (!parsed.success) {
                if (process.env.NODE_ENV !== 'production') {
                    console.error(
                        'Invalid server response shape:',
                        endpoint,
                        parsed.error.issues[0]?.message,
                    );
                }
                return { error: 'Invalid server response' };
            }
            return { data: parsed.data };
        }

        return { data };
    } catch (error) {
        console.error('API request failed:', error);
        return { error: 'Network error' };
    }
}

// ==================== Auth API ====================

export interface RegisterData {
    username: string;
    identityKey: string;
    exchangeIdentityKey?: string;
    signedPrekey: string;
    signedPrekeySignature: string;
    oneTimePrekeys: Array<{ id: string; publicKey: string }>;
}

export interface UserBundle {
    id: string;
    username: string;
    identityKey: string;
    exchangeKey?: string;
    exchangeIdentityKey?: string;
    signedPrekey: string;
    signedPrekeySignature: string;
    oneTimePrekey?: string;
}


export const authApi = {
    register: (data: RegisterData) => {
        const headers = vaultHasKeys()
            ? vaultSignRequest('POST', '/auth/register', data)
            : {};
        return request('/auth/register', {
            method: 'POST',
            body: JSON.stringify(data),
            headers,
        }, RegisterResponseSchema);
    },

    checkUsername: (username: string) =>
        request(`/auth/check/${username}`, {}, CheckUsernameResponseSchema),

    getUser: (username: string) => {
        const headers = vaultSignRequest('GET', `/auth/user/${username}`, {});
        return request(`/auth/user/${username}`, {
            headers,
        }, UserBundleSchema);
    },

    getBundle: (username: string) => {
        const body = { username };
        const headers = vaultSignRequest('POST', '/auth/bundle', body);
        return request('/auth/bundle', {
            method: 'POST',
            body: JSON.stringify(body),
            headers,
        }, UserBundleSchema);
    },

    uploadPrekeys: (userId: string, prekeys: Array<{ id: string; publicKey: string }>) => {
        const body = { userId, prekeys };
        const headers = vaultSignRequest('POST', '/auth/prekeys', body);
        return request('/auth/prekeys', {
            method: 'POST',
            body: JSON.stringify(body),
            headers,
        }, UploadPrekeysResponseSchema);
    },

    updateSignedPrekey: (
        userId: string,
        signedPrekey: string,
        signedPrekeySignature: string,
    ) => {
        const body = { userId, signedPrekey, signedPrekeySignature };
        const headers = vaultSignRequest('POST', '/auth/keys', body);
        return request('/auth/keys', {
            method: 'POST',
            body: JSON.stringify(body),
            headers,
        }, MessageResponseSchema);
    },

    deleteAccount: (userId: string) => {
        const headers = vaultSignRequest('DELETE', `/auth/user/${userId}`, {});
        return request(`/auth/user/${userId}`, {
            method: 'DELETE',
            headers,
        }, MessageResponseSchema);
    },

    getSession: (userId: string) => {
        const body = { userId };
        const headers = vaultSignRequest('POST', '/auth/session', body);
        return request('/auth/session', {
            method: 'POST',
            body: JSON.stringify(body),
            headers,
        }, SessionResponseSchema);
    },

    blockUser: (blockedId: string) => {
        const body = { blockedId };
        const headers = vaultSignRequest('POST', '/auth/block', body);
        return request('/auth/block', {
            method: 'POST',
            body: JSON.stringify(body),
            headers,
        }, OkResponseSchema);
    },

    unblockUser: (blockedId: string) => {
        const body = { blockedId };
        const headers = vaultSignRequest('POST', '/auth/unblock', body);
        return request('/auth/unblock', {
            method: 'POST',
            body: JSON.stringify(body),
            headers,
        }, OkResponseSchema);
    },

    getBlockedUsers: () => {
        const headers = vaultSignRequest('GET', '/auth/blocked', {});
        return request('/auth/blocked', {
            headers,
        }, BlockedUsersResponseSchema);
    },
};

// ==================== Messages API ====================

export interface SendMessageData {
    senderId: string;
    recipientId: string;
    encryptedPayload: string;
}

export interface PendingMessage {
    id: string;
    senderId: string;
    senderUsername: string;
    encryptedPayload: string;
    timestamp: number;
}

export const messagesApi = {
    send: (data: SendMessageData) => {
        const headers = vaultSignRequest('POST', '/messages/send', data);
        return request('/messages/send', {
            method: 'POST',
            body: JSON.stringify(data),
            headers,
        }, SendMessageResponseSchema);
    },

    getPending: (userId: string) => {
        const headers = vaultSignRequest('GET', `/messages/pending/${userId}`, {});
        return request(`/messages/pending/${userId}`, {
            headers
        }, PendingMessagesResponseSchema);
    },

    acknowledge: (messageId: string) => {
        const headers = vaultSignRequest('DELETE', `/messages/${messageId}`, {});
        return request(`/messages/${messageId}`, {
            method: 'DELETE',
            headers
        }, MessageResponseSchema);
    },

    acknowledgeBatch: (messageIds: string[]) => {
        const body = { messageIds };
        const headers = vaultSignRequest('POST', '/messages/acknowledge', body);
        return request('/messages/acknowledge', {
            method: 'POST',
            body: JSON.stringify(body),
            headers,
        }, AcknowledgeResponseSchema);
    },
};

// ==================== Files API ====================

export const filesApi = {
    upload: (
        data: string,
        mimeHint: string,
        opts?: { recipientId?: string; isPublic?: boolean },
    ) => {
        const body = {
            data,
            mimeHint,
            ...(opts?.recipientId ? { recipientId: opts.recipientId } : {}),
            ...(opts?.isPublic ? { isPublic: true } : {}),
        };
        const headers = vaultSignRequest('POST', '/files/upload', body);
        return request('/files/upload', {
            method: 'POST',
            body: JSON.stringify(body),
            headers,
        }, UploadFileResponseSchema);
    },

    download: (fileId: string) => {
        const headers = vaultSignRequest('GET', `/files/${fileId}`, {});
        return request(`/files/${fileId}`, {
            headers,
        }, DownloadFileResponseSchema);
    },
};

// ==================== Groups API ====================

export interface GroupData {
    id: string;
    name: string;
    creator_id: string;
    created_at: number;
    members: Array<{ user_id: string; username: string; role: string }>;
}

export const groupsApi = {
    create: (name: string, memberIds: string[]) => {
        const body = { name, memberIds };
        const headers = vaultSignRequest('POST', '/groups/create', body);
        return request('/groups/create', {
            method: 'POST',
            body: JSON.stringify(body),
            headers,
        }, GroupDataSchema);
    },

    list: () => {
        const headers = vaultSignRequest('GET', '/groups', {});
        return request('/groups', {
            headers,
        }, GroupListResponseSchema);
    },

    get: (groupId: string) => {
        const headers = vaultSignRequest('GET', `/groups/${groupId}`, {});
        return request(`/groups/${groupId}`, {
            headers,
        }, GroupDataSchema);
    },

    addMember: (groupId: string, userId: string) => {
        const body = { userId };
        const headers = vaultSignRequest('POST', `/groups/${groupId}/members`, body);
        return request(`/groups/${groupId}/members`, {
            method: 'POST',
            body: JSON.stringify(body),
            headers,
        }, AddMemberResponseSchema);
    },

    removeMember: (groupId: string, userId: string) => {
        const headers = vaultSignRequest('DELETE', `/groups/${groupId}/members/${userId}`, {});
        return request(`/groups/${groupId}/members/${userId}`, {
            method: 'DELETE',
            headers,
        }, RemoveMemberResponseSchema);
    },
};

// ==================== Profile API ====================

export interface ProfileData {
    id: string;
    username: string;
    displayName: string | null;
    avatarFileId: string | null;
    discoverable?: boolean;
}

function fetchProfile(userId: string) {
    const headers = vaultSignRequest('GET', `/profile/${userId}`, {});
    return request(`/profile/${userId}`, { headers }, ProfileDataSchema);
}

// De-duplicate profile GETs with a short-lived cache. A burst of components all
// reading the same profile on mount (LeftRail, ProfileSection, PrivacySection,
// StrictMode's double-invoke, route changes) used to fire ~10 identical
// /profile/:id requests; now the first shares its result for a few seconds.
// Invalidated on write (profileApi.update / inviteApi.setDiscoverable) and a
// failed response is never cached, so callers still get fresh data.
const PROFILE_TTL_MS = 10_000;
const profileCache = new Map<
    string,
    { at: number; promise: ReturnType<typeof fetchProfile> }
>();

export function invalidateProfile(userId: string) {
    profileCache.delete(userId);
}

export const profileApi = {
    get: (userId: string) => {
        const cached = profileCache.get(userId);
        if (cached && Date.now() - cached.at < PROFILE_TTL_MS) {
            return cached.promise;
        }
        const promise = fetchProfile(userId);
        profileCache.set(userId, { at: Date.now(), promise });
        void promise.then((res) => {
            if (res.error && profileCache.get(userId)?.promise === promise) {
                profileCache.delete(userId);
            }
        });
        return promise;
    },

    update: (userId: string, data: { displayName?: string | null; avatarFileId?: string | null }) => {
        invalidateProfile(userId);
        const body = data as Record<string, unknown>;
        const headers = vaultSignRequest('PUT', `/profile/${userId}`, body);
        return request(`/profile/${userId}`, {
            method: 'PUT',
            body: JSON.stringify(body),
            headers,
        }, ProfileDataSchema);
    },
};

// ==================== Invite API ====================

export const inviteApi = {
    createToken: (userId: string) => {
        const body = { userId };
        const headers = vaultSignRequest('POST', '/auth/invite-token', body);
        return request('/auth/invite-token', {
            method: 'POST',
            body: JSON.stringify(body),
            headers,
        }, InviteTokenResponseSchema);
    },

    resolveToken: (token: string) => {
        const headers = vaultSignRequest('GET', `/auth/resolve-invite/${token}`, {});
        return request(`/auth/resolve-invite/${token}`, {
            headers,
        }, ResolveInviteResponseSchema);
    },

    setDiscoverable: (userId: string, discoverable: boolean) => {
        invalidateProfile(userId);
        const body = { userId, discoverable };
        const headers = vaultSignRequest('PUT', '/auth/discoverable', body);
        return request('/auth/discoverable', {
            method: 'PUT',
            body: JSON.stringify(body),
            headers,
        }, DiscoverableResponseSchema);
    },
};

// ==================== Health API ====================

export const healthApi = {
    check: () => request('/health', {}, HealthResponseSchema),
};
