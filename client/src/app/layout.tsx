// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import type { Metadata, Viewport } from "next";
import Script from "next/script";
import { headers } from "next/headers";
import { Space_Grotesk, Manrope } from "next/font/google";
import "./globals.css";
import StatusBanner from "@/components/StatusBanner";
import ErrorBoundary from "@/components/ErrorBoundary";
import Dedication from "@/components/Dedication";
import OnlineStatus from "@/components/OnlineStatus";
import ServiceWorkerRegistration from "@/components/ServiceWorkerRegistration";
import LocaleLang from "@/components/LocaleLang";
import LocaleBoot from "@/components/LocaleBoot";
import LocaleShell from "@/components/LocaleShell";

// Self-hosted at build time by next/font — no request to Google, so the CSP
// stays closed and no font call leaks who is using the app.
const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-space-grotesk",
  display: "swap",
});
// Space Grotesk carries no Cyrillic. Appending a Cyrillic face after it does
// nothing — the metric-adjusted fallback next/font generates also covers
// Cyrillic and wins first. So Russian does not extend the stack, it replaces
// it: globals.css swaps --font-sans wholesale on html[lang="ru"].
//
// Manrope is the face the Russian deck uses (in the private brand repository),
// so the product and the deck now agree.
const manrope = Manrope({
  subsets: ["latin", "cyrillic"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-manrope",
  display: "swap",
});

export const metadata: Metadata = {
  title: "LUME",
  applicationName: "LUME",
  description: "LUME - private messages and privacy by default",
  keywords: ["messenger", "secure", "encrypted", "anonymous", "e2ee", "lume"],
  authors: [{ name: "Lume Team" }],
  manifest: "/manifest.json",
  appleWebApp: {
    capable: true,
    statusBarStyle: "black-translucent",
    title: "LUME",
  },
  icons: {
    // The tab icon is the SVG: it scales to whatever size the browser asks for
    // and carries its own light/dark rule. The .ico is the fallback for anything
    // that will not take an SVG, and the PNG is the home-screen tile, which needs
    // a filled background — a transparent mark disappears once iOS or Android
    // composites it onto their own.
    icon: [
      { url: "/icon.svg", type: "image/svg+xml" },
      { url: "/favicon.ico", sizes: "64x64" },
    ],
    shortcut: "/favicon.ico",
    apple: "/lume-icon.png",
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
  userScalable: false,
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f5f5f5" },
    { media: "(prefers-color-scheme: dark)", color: "#050505" },
  ],
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;

  return (
    <html lang="en" className={`${spaceGrotesk.variable} ${manrope.variable}`} suppressHydrationWarning>
      <body className="antialiased min-h-screen">
        <Script nonce={nonce} src="/theme-init.js" strategy="beforeInteractive" />
        {process.env.NODE_ENV === "development" ? (
          <Script nonce={nonce} src="/dev-sw-cleanup.js" strategy="beforeInteractive" />
        ) : null}
        <div className="min-h-screen flex flex-col">
          <LocaleLang />
          <LocaleBoot />
          <ServiceWorkerRegistration />
          <OnlineStatus />
          <Dedication />
          <ErrorBoundary>
            <StatusBanner />
            <LocaleShell>{children}</LocaleShell>
          </ErrorBoundary>
        </div>
      </body>
    </html>
  );
}
