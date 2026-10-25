// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import React, { forwardRef, useId } from 'react';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  hint?: string;
  icon?: React.ReactNode;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, hint, icon, className = '', id: externalId, ...props }, ref) => {
    const generatedId = useId();
    const inputId = externalId || generatedId;

    return (
      <div className="w-full">
        {label && <label htmlFor={inputId} className="block apple-label mb-1.5">{label}</label>}
        <div className="relative">
          {icon && (
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[var(--text-muted)]">
              {icon}
            </div>
          )}
          <input
            ref={ref}
            id={inputId}
            // No password field in LUME is a login credential the server checks.
            // Every one of them is a local secret: the passphrase that derives the
            // at-rest master key, or a hidden-chat PIN. Handing those to a browser
            // password manager — which usually syncs to a vendor cloud — puts the
            // only thing protecting the encrypted store outside the device.
            // Defaulted here rather than at each call site so a new password field
            // cannot be added without it. `{...props}` spreads after, so a caller
            // that genuinely needs different behaviour still wins.
            // SEC-20260805-002.
            autoComplete={props.type === 'password' ? 'new-password' : undefined}
            className={`
              apple-input
              ${icon ? 'apple-input-icon' : ''}
              disabled:opacity-50
              ${error ? 'border-[var(--accent)] ring-1 ring-[var(--focus-ring)]' : ''}
              ${className}
            `}
            aria-invalid={error ? true : undefined}
            {...props}
          />
        </div>
        {error && <p className="mt-1.5 text-sm text-[var(--text-secondary)]">{error}</p>}
        {hint && !error && <p className="mt-1.5 text-sm text-[var(--text-muted)]">{hint}</p>}
      </div>
    );
  }
);

Input.displayName = 'Input';

export default Input;
