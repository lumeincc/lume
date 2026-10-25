// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

// Polyfills FIRST — registers the native CSPRNG before any crypto is touched.
import '../src/polyfills'

import { Stack } from 'expo-router'
import { StatusBar } from 'expo-status-bar'
import { useColorScheme } from 'react-native'
import { SafeAreaProvider } from 'react-native-safe-area-context'
import { SessionProvider } from '../src/store/session'
import { dark, light } from '../src/ui/theme'

/**
 * Fonts are embedded at build time by the `expo-font` config plugin (see
 * app.json), not loaded here at runtime.
 *
 * `useFonts` was the first attempt and it failed silently on device: it resolves
 * the bundled .ttf through expo-asset, which needs expo-file-system linked, and
 * this project does not have it — `ExpoAsset.downloadAsync` was rejected with
 * "Module 'expo.modules.interfaces.filesystem.AppDirectories' not found". The
 * app then fell back to the system face and looked exactly as it had before,
 * with nothing in the log to say why.
 *
 * Embedding is the better answer regardless: the typeface is registered by
 * Android before any JavaScript runs, so there is no load to await, no splash to
 * hold, and no failure mode. The registered family name is the file's stem —
 * `Manrope_600SemiBold` — which is what theme.ts#fontFor returns.
 */
export default function RootLayout() {
  const scheme = useColorScheme()
  const palette = scheme === 'dark' ? dark : light

  return (
    <SafeAreaProvider>
      <SessionProvider>
        <StatusBar style={scheme === 'dark' ? 'light' : 'dark'} />
        {/* Screens draw their own headers, so the navigator stays out of the way. */}
        <Stack
          screenOptions={{
            headerShown: false,
            contentStyle: { backgroundColor: palette.background },
            animation: 'slide_from_right',
          }}
        />
      </SessionProvider>
    </SafeAreaProvider>
  )
}
