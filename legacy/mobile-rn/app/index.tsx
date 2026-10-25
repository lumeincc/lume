// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

// Polyfills before anything crypto-adjacent. Route modules are not guaranteed to
// evaluate after _layout, and the import is idempotent, so it is repeated here.
import '../src/polyfills'

import { useEffect, useState } from 'react'
import { KeyboardAvoidingView, Platform, ScrollView, View } from 'react-native'
import { router } from 'expo-router'
import { useSession } from '../src/store/session'
import {
  AuthFoot,
  AuthHero,
  AuthHint,
  AuthTitle,
  ErrorText,
  Field,
  OrDivider,
  Pill,
  Screen,
  Txt,
  usePalette,
} from '../src/ui/components'
import { metrics, radius, space } from '../src/ui/theme'

/**
 * The auth screen, laid out like the web client's: a narrow centred column,
 * a large centred title, then pill buttons.
 */
export default function Index() {
  const session = useSession()
  const p = usePalette()

  const [mode, setMode] = useState<'unlock' | 'create' | 'restore'>('unlock')
  const [username, setUsername] = useState('')
  const [pin, setPin] = useState('')
  const [mnemonic, setMnemonic] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [recovery, setRecovery] = useState<string | null>(null)

  useEffect(() => {
    if (session.ready) setMode(session.accountExists ? 'unlock' : 'create')
  }, [session.ready, session.accountExists])

  // Navigation is deliberately explicit per action rather than an effect on
  // `unlocked`. Registration opens the session before the phrase reaches state,
  // so an effect would route away first and the user would never see the only
  // copy of their recovery phrase.

  async function run(action: () => Promise<string | null>) {
    setBusy(true)
    setError(null)
    const failure = await action().catch(e => (e instanceof Error ? e.message : String(e)))
    setBusy(false)
    if (failure) setError(failure)
  }

  if (!session.ready) {
    return (
      <Screen style={{ alignItems: 'center', justifyContent: 'center' }}>
        <AuthHint>Открываем хранилище…</AuthHint>
      </Screen>
    )
  }

  if (recovery) {
    return (
      <Screen>
        <ScrollView contentContainerStyle={styles.shell}>
          <AuthHero>
            <AuthTitle>Сохраните фразу</AuthTitle>
            <AuthHint>
              Единственный способ восстановить доступ. Запишите на бумаге — фраза не хранится на сервере.
            </AuthHint>
            <View
              style={{
                backgroundColor: p.surfaceStrong,
                borderColor: p.border,
                borderWidth: 1,
                borderRadius: radius.md,
                padding: space.lg,
                marginTop: space.xs,
              }}
            >
              <Txt style={{ color: p.textPrimary, fontSize: 16, lineHeight: 27, letterSpacing: 0.2 }}>
                {recovery}
              </Txt>
            </View>
            <Pill
              title="Я записал фразу"
              onPress={() => {
                setRecovery(null)
                router.replace('/chats')
              }}
            />
          </AuthHero>
        </ScrollView>
      </Screen>
    )
  }

  // Titles only. The web's auth screens carry a title, the fields and the
  // buttons — no strapline under the heading, no wordmark, no slogan at the
  // bottom. Each of those was added here and each one is why the screen read as
  // a different product.
  const title = mode === 'unlock' ? 'С возвращением' : mode === 'create' ? 'Создание аккаунта' : 'Восстановление доступа'

  return (
    <Screen>
      <KeyboardAvoidingView behavior={Platform.OS === 'ios' ? 'padding' : undefined} style={{ flex: 1 }}>
        <ScrollView contentContainerStyle={styles.shell} keyboardShouldPersistTaps="handled">
          <AuthHero>
            <AuthTitle>{title}</AuthTitle>

            <View style={{ gap: space.md, marginTop: space.lg }}>
              {mode !== 'unlock' && (
                <Field
                  label="Имя пользователя"
                  value={username}
                  onChangeText={setUsername}
                  autoCapitalize="none"
                  autoCorrect={false}
                  placeholder="alice"
                />
              )}

              {mode === 'restore' && (
                <Field
                  label="Фраза восстановления"
                  value={mnemonic}
                  onChangeText={setMnemonic}
                  autoCapitalize="none"
                  autoCorrect={false}
                  multiline
                  placeholder="двенадцать слов через пробел"
                  style={{ minHeight: 96, textAlignVertical: 'top' }}
                />
              )}

              <Field
                label="PIN"
                value={pin}
                onChangeText={setPin}
                keyboardType="number-pad"
                secureTextEntry
                maxLength={12}
                placeholder="••••••"
              />

              {error ? <ErrorText>{error}</ErrorText> : null}

              {mode === 'unlock' && (
                <Pill
                  title="Открыть"
                  busy={busy}
                  onPress={() =>
                    run(async () => {
                      const failure = await session.unlock(pin)
                      if (failure) return failure
                      router.replace('/chats')
                      return null
                    })
                  }
                />
              )}

              {mode === 'create' && (
                <Pill
                  title="Создать аккаунт"
                  busy={busy}
                  onPress={() =>
                    run(async () => {
                      const res = await session.register(username, pin)
                      if (!res.ok) return res.error
                      // The phrase exists only at creation time — show it before routing on.
                      setRecovery(res.mnemonic)
                      return null
                    })
                  }
                />
              )}

              {mode === 'restore' && (
                <Pill
                  title="Восстановить"
                  busy={busy}
                  onPress={() =>
                    run(async () => {
                      const failure = await session.restore(mnemonic, username, pin)
                      if (failure) return failure
                      router.replace('/chats')
                      return null
                    })
                  }
                />
              )}

              {mode !== 'restore' && (
                <>
                  <OrDivider label="или" />
                  <Pill variant="secondary" title="Восстановить по фразе" onPress={() => setMode('restore')} />
                </>
              )}
            </View>

            {/* `.auth-foot`: the way out of this screen, as on the web. */}
            <View style={{ marginTop: space.xl }}>
              {mode === 'unlock' ? (
                <AuthFoot label="Ещё нет аккаунта?" action="Создать" onPress={() => setMode('create')} />
              ) : mode === 'create' ? (
                <AuthFoot
                  label="Уже есть аккаунт?"
                  action="Войти"
                  onPress={() => setMode(session.accountExists ? 'unlock' : 'restore')}
                />
              ) : (
                <AuthFoot
                  label="Передумали?"
                  action="Назад"
                  onPress={() => setMode(session.accountExists ? 'unlock' : 'create')}
                />
              )}
            </View>

            {/*
              Build identity. On a phone there is no URL to read and no deploy
              log within reach, so an APK sideloaded last week is
              indistinguishable from one sideloaded this morning unless the build
              says so itself. Selectable, because the point of showing a commit
              is that it can be copied into a bug report.
            */}
            <Txt
              selectable
              style={{ marginTop: space.lg, textAlign: 'center', fontSize: 11, color: p.textMuted }}
            >
              {BUILD_LABEL}
            </Txt>
          </AuthHero>
        </ScrollView>
      </KeyboardAvoidingView>
    </Screen>
  )
}

const styles = {
  shell: {
    flexGrow: 1,
    justifyContent: 'center' as const,
    paddingHorizontal: space.lg,
    paddingVertical: space.xl,
  },
}
