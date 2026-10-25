// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import '../../src/polyfills'

import { useRef, useState } from 'react'
import { FlatList, KeyboardAvoidingView, Platform, Pressable, TextInput, View } from 'react-native'
import { router, useLocalSearchParams } from 'expo-router'
import { useSession } from '../../src/store/session'
import {
  Avatar,
  ErrorText,
  IconButton,
  OnlineDot,
  Screen,
  Txt,
  usePalette,
} from '../../src/ui/components'
import { fontFor, metrics, radius, space, text } from '../../src/ui/theme'
import type { StoredMessage } from '../../src/vault'

/**
 * One conversation. Bubbles follow the web's `.message-bubble-sent` /
 * `.message-bubble-received`: asymmetric corners with the tail on the sender's
 * side, and the composer is a transparent field with round icon buttons beside
 * it — no boxed input.
 */
export default function Chat() {
  const { id } = useLocalSearchParams<{ id: string }>()
  const session = useSession()
  const p = usePalette()
  const listRef = useRef<FlatList<StoredMessage>>(null)

  const [draft, setDraft] = useState('')
  const [sending, setSending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const contact = session.contacts.find(c => c.id === id)
  const messages = session.messagesWith(id ?? '')

  /**
   * Hands the message to the outbox, which owns delivery from here — so the
   * composer clears as soon as the message is durably queued rather than waiting
   * on the network. Whether it actually arrived is shown on the bubble itself.
   */
  async function send() {
    const body = draft.trim()
    if (!body || !id) return
    setSending(true)
    setError(null)
    const failure = await session.send(id, body).catch(e => String(e))
    setSending(false)
    if (failure) {
      setError(failure)
      return
    }
    setDraft('')
    requestAnimationFrame(() => listRef.current?.scrollToEnd({ animated: true }))
  }

  return (
    <Screen>
      <View
        style={{
          flexDirection: 'row',
          alignItems: 'center',
          gap: space.md,
          paddingHorizontal: space.md,
          paddingVertical: space.sm,
          borderBottomWidth: 1,
          borderBottomColor: p.border,
        }}
      >
        <IconButton glyph="‹" onPress={() => router.back()} emphasis="primary" />
        <Avatar name={contact?.username ?? '?'} size={36} />
        <View style={{ flex: 1 }}>
          <Txt style={{ fontSize: 15, fontWeight: '600', color: p.textPrimary }}>
            {contact?.username ?? 'Неизвестный'}
          </Txt>
          <View style={{ flexDirection: 'row', alignItems: 'center', gap: 6, marginTop: 1 }}>
            <OnlineDot online={session.connection === 'connected'} />
            <Txt style={{ fontSize: text.caption, color: p.textMuted }}>сквозное шифрование</Txt>
          </View>
        </View>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
        <FlatList
          ref={listRef}
          data={messages}
          keyExtractor={m => m.id}
          contentContainerStyle={{ paddingHorizontal: space.md, paddingVertical: space.lg, gap: 6, flexGrow: 1 }}
          onContentSizeChange={() => listRef.current?.scrollToEnd({ animated: false })}
          // A long history must not be mounted in one go: the list opens at the
          // bottom, so everything above it can be rendered as the user scrolls.
          initialNumToRender={20}
          maxToRenderPerBatch={20}
          windowSize={11}
          ListEmptyComponent={
            <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center', paddingHorizontal: space.xl }}>
              <Txt style={{ fontSize: 14, color: p.textMuted, textAlign: 'center', lineHeight: 21 }}>
                Сообщений пока нет. Первое установит защищённую сессию.
              </Txt>
            </View>
          }
          renderItem={({ item }) => <Bubble message={item} onRetry={() => session.retry(item.id)} />}
        />

        <View
          style={{
            borderTopWidth: 1,
            borderTopColor: p.border,
            paddingHorizontal: space.md,
            paddingVertical: space.md,
            gap: space.sm,
          }}
        >
          {error ? <ErrorText>{error}</ErrorText> : null}
          <View style={{ flexDirection: 'row', alignItems: 'flex-end', gap: space.md }}>
            <TextInput
              value={draft}
              onChangeText={setDraft}
              placeholder="Сообщение"
              placeholderTextColor={p.textMuted}
              multiline
              style={{
                flex: 1,
                maxHeight: 120,
                paddingHorizontal: space.sm,
                paddingVertical: 10,
                color: p.textPrimary,
                fontSize: metrics.inputFontSize,
                fontFamily: fontFor('400'),
                lineHeight: 21,
              }}
            />
            <Pressable
              onPress={send}
              disabled={sending || !draft.trim()}
              style={({ pressed }) => ({
                width: 40,
                height: 40,
                borderRadius: radius.pill,
                alignItems: 'center',
                justifyContent: 'center',
                backgroundColor: draft.trim() && !sending ? p.accent : 'transparent',
                opacity: pressed ? 0.8 : 1,
              })}
            >
              <Txt
                style={{
                  fontSize: 17,
                  fontWeight: '700',
                  color: draft.trim() && !sending ? p.accentContrast : p.textMuted,
                }}
              >
                ↑
              </Txt>
            </Pressable>
          </View>
        </View>
      </KeyboardAvoidingView>
    </Screen>
  )
}

function Bubble({ message, onRetry }: { message: StoredMessage; onRetry: () => void }) {
  const p = usePalette()
  const mine = message.outgoing
  // Absent on received messages and on anything written before the outbox existed.
  const status = mine ? (message.status ?? 'sent') : null
  return (
    <View style={{ flexDirection: 'row', justifyContent: mine ? 'flex-end' : 'flex-start' }}>
      <View
        style={{
          maxWidth: '80%',
          paddingHorizontal: metrics.bubblePaddingH,
          paddingVertical: metrics.bubblePaddingV,
          backgroundColor: mine ? p.accent : p.bubbleIn,
          // A message still on its way is dimmed rather than badged: it is the
          // quietest way to say "not there yet" without decorating the screen.
          opacity: status === 'pending' ? 0.55 : 1,
          borderWidth: mine ? 0 : 1,
          borderColor: p.border,
          // The tail corner sits on the sender's side, as in the web CSS.
          borderTopLeftRadius: metrics.bubbleRadius,
          borderTopRightRadius: metrics.bubbleRadius,
          borderBottomLeftRadius: mine ? metrics.bubbleRadius : metrics.bubbleTail,
          borderBottomRightRadius: mine ? metrics.bubbleTail : metrics.bubbleRadius,
        }}
      >
        <Txt style={{ color: mine ? p.accentContrast : p.textPrimary, fontSize: 15, lineHeight: 21 }}>
          {message.text}
        </Txt>
        <Txt
          style={{
            fontSize: text.caption,
            color: mine ? p.accentContrast : p.textMuted,
            opacity: mine ? 0.45 : 1,
            alignSelf: 'flex-end',
            marginTop: 3,
          }}
        >
          {`${String(new Date(message.timestamp).getHours()).padStart(2, '0')}:${String(new Date(message.timestamp).getMinutes()).padStart(2, '0')}`}
        </Txt>
      </View>

      {status === 'failed' ? (
        <Pressable onPress={onRetry} hitSlop={8} style={{ alignSelf: 'flex-end', paddingLeft: 8, paddingBottom: 4 }}>
          <Txt style={{ fontSize: text.caption, color: p.danger, fontWeight: '600' }}>
            не отправлено · повторить
          </Txt>
        </Pressable>
      ) : null}
    </View>
  )
}
