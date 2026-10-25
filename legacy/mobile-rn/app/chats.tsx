// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import '../src/polyfills'

import { useMemo, useState } from 'react'
import { FlatList, Modal, Pressable, TextInput, View } from 'react-native'
import { router } from 'expo-router'
import { useSession } from '../src/store/session'
import {
  Avatar,
  ErrorText,
  Field,
  IconButton,
  OnlineDot,
  Pill,
  Screen,
  Txt,
  usePalette,
} from '../src/ui/components'
import { fontFor, metrics, radius, space, text } from '../src/ui/theme'

/**
 * Conversation list, laid out like the web's ChatListPanel: a borderless search
 * field under the header, then rows separated by hairlines.
 */
export default function Chats() {
  const session = useSession()
  const p = usePalette()
  const [query, setQuery] = useState('')
  const [adding, setAdding] = useState(false)
  const [username, setUsername] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // `messagesWith` is an index lookup. Scanning the whole message list per
  // contact instead made this contacts × messages on every keystroke and on every
  // message that arrived — the kind of cost a cheap phone shows and a laptop hides.
  const messagesWith = session.messagesWith
  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return session.contacts
      .filter(c => !needle || c.username.toLowerCase().includes(needle))
      .map(contact => {
        const thread = messagesWith(contact.id)
        return { contact, last: thread.length ? thread[thread.length - 1]! : null }
      })
      .sort((a, b) => (b.last?.timestamp ?? 0) - (a.last?.timestamp ?? 0))
  }, [session.contacts, messagesWith, query])

  async function add() {
    setBusy(true)
    setError(null)
    const failure = await session.addContact(username).catch(e => String(e))
    setBusy(false)
    if (failure) {
      setError(failure)
      return
    }
    setUsername('')
    setAdding(false)
  }

  return (
    <Screen>
      <View style={{ paddingHorizontal: space.lg, paddingTop: space.md, paddingBottom: space.sm }}>
        <View style={{ flexDirection: 'row', alignItems: 'center', gap: space.sm }}>
          <View style={{ flex: 1 }}>
            <Txt style={{ fontSize: 19, fontWeight: '700', color: p.textPrimary, letterSpacing: -0.2 }}>
              Чаты
            </Txt>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: 6, marginTop: 3 }}>
              <OnlineDot online={session.connection === 'connected'} />
              <Txt style={{ fontSize: text.caption, color: p.textMuted }}>
                {session.profile ? `@${session.profile.username}` : ''}
                {session.connection === 'connected'
                  ? ''
                  : ` · ${connectionLabel(session.connection)}${session.connectionDetail ? ` (${session.connectionDetail})` : ''}`}
              </Txt>
            </View>
          </View>
          <IconButton glyph="＋" onPress={() => setAdding(true)} emphasis="primary" />
        </View>

        {/* .relative.mt-4 search: transparent, underlined only. */}
        <View style={{ marginTop: space.lg, borderBottomWidth: 1, borderBottomColor: p.border }}>
          <TextInput
            value={query}
            onChangeText={setQuery}
            placeholder="Поиск"
            placeholderTextColor={p.textMuted}
            style={{
              paddingVertical: space.sm,
              fontSize: 14,
              fontFamily: fontFor('400'),
              color: p.textPrimary,
            }}
          />
        </View>
      </View>

      <FlatList
        data={rows}
        keyExtractor={r => r.contact.id}
        contentContainerStyle={rows.length ? undefined : { flexGrow: 1, justifyContent: 'center' }}
        ListEmptyComponent={
          <View style={{ paddingHorizontal: space.xl }}>
            <Txt style={{ fontSize: 14, color: p.textMuted, textAlign: 'center', lineHeight: 21 }}>
              {query ? 'Ничего не найдено' : 'Пока пусто. Добавьте собеседника по имени пользователя.'}
            </Txt>
          </View>
        }
        renderItem={({ item }) => (
          <Pressable
            onPress={() => router.push(`/chat/${item.contact.id}`)}
            style={({ pressed }) => ({
              minHeight: metrics.rowMinHeight,
              paddingHorizontal: metrics.rowPaddingH,
              paddingVertical: metrics.rowPaddingV,
              borderBottomWidth: 1,
              borderBottomColor: p.border,
              backgroundColor: pressed ? p.surfaceAlt : 'transparent',
              flexDirection: 'row',
              alignItems: 'center',
              gap: space.md,
            })}
          >
            <Avatar name={item.contact.username} />
            <View style={{ flex: 1, minWidth: 0 }}>
              <Txt
                numberOfLines={1}
                style={{ fontSize: text.body, fontWeight: '600', color: p.textPrimary }}
              >
                {item.contact.username}
              </Txt>
              <Txt numberOfLines={1} style={{ fontSize: 12, color: p.textSecondary, marginTop: 2 }}>
                {item.last ? (item.last.outgoing ? `Вы: ${item.last.text}` : item.last.text) : 'Нет сообщений'}
              </Txt>
            </View>
            {item.last ? (
              <Txt style={{ fontSize: text.caption, color: p.textMuted }}>{formatTime(item.last.timestamp)}</Txt>
            ) : null}
          </Pressable>
        )}
      />

      <Modal visible={adding} transparent animationType="fade" onRequestClose={() => setAdding(false)}>
        <View style={{ flex: 1, backgroundColor: 'rgba(0,0,0,0.45)', justifyContent: 'flex-end' }}>
          <View
            style={{
              backgroundColor: p.background,
              borderTopLeftRadius: radius.lg,
              borderTopRightRadius: radius.lg,
              padding: space.lg,
              paddingBottom: space.xl,
              gap: space.md,
            }}
          >
            <Txt style={{ fontSize: 17, fontWeight: '700', color: p.textPrimary }}>Новый чат</Txt>
            <Field
              label="Имя пользователя"
              value={username}
              onChangeText={setUsername}
              autoCapitalize="none"
              autoCorrect={false}
              placeholder="alice"
              autoFocus
            />
            {error ? <ErrorText>{error}</ErrorText> : null}
            <Pill title="Добавить" busy={busy} onPress={add} />
            <Pill variant="secondary" title="Отмена" onPress={() => setAdding(false)} />
          </View>
        </View>
      </Modal>
    </Screen>
  )
}

/** A silent "offline" hides real faults, so the state is named. */
function connectionLabel(status: string) {
  switch (status) {
    case 'connecting':
      return 'подключение'
    case 'auth_error':
      return 'ошибка авторизации'
    case 'idle':
      return 'не подключено'
    default:
      return 'нет связи'
  }
}

/** Same rule as the web: time today, date otherwise. */
function formatTime(ts: number) {
  const d = new Date(ts)
  const now = new Date()
  if (d.toDateString() === now.toDateString()) {
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
  }
  return `${d.getDate()} ${['янв', 'фев', 'мар', 'апр', 'мая', 'июн', 'июл', 'авг', 'сен', 'окт', 'ноя', 'дек'][d.getMonth()]}`
}
