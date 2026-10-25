// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

'use client';

import { t } from "@/lib/i18n";
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { hasAccount } from '@/crypto/storage';

export default function HomePage() {
  const router = useRouter();
  const [checking, setChecking] = useState(true);
  const [accountExists, setAccountExists] = useState(false);

  useEffect(() => {
    async function checkAccount() {
      const exists = await hasAccount();
      setAccountExists(exists);
      setChecking(false);
    }

    checkAccount();
  }, [router]);

  if (checking) {
    return (
      <div className="auth-shell" aria-busy="true">
        <div className="w-8 h-8 border-2 mono-spinner rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <main className="auth-shell">
      <div className="auth-hero auth-hero--wide animate-fade-in">
        <h1 className="auth-welcome stagger-1">
          {accountExists ? t("auth.welcomeBack") : t("auth.welcome")}
        </h1>

        <p className="auth-sub stagger-2">
          {t("auth.tagline")}
        </p>

        <div className="mt-9 w-full max-w-[320px] mx-auto flex flex-col gap-3 stagger-3">
          {accountExists ? (
            <>
              <button onClick={() => router.push('/unlock')} className="auth-pill">
                {t("auth.login")}
              </button>
              <div className="auth-or">{t("auth.or")}</div>
              <button onClick={() => router.push('/setup')} className="auth-pill-secondary">
                {t("auth.newAccount")}
              </button>
            </>
          ) : (
            <>
              <button onClick={() => router.push('/setup')} className="auth-pill">
                {t("auth.createAccount")}
              </button>
              <div className="auth-or">{t("auth.or")}</div>
              <button onClick={() => router.push('/recover')} className="auth-pill-secondary">
                {t("auth.restoreAccess")}
              </button>
            </>
          )}
        </div>
      </div>
    </main>
  );
}
