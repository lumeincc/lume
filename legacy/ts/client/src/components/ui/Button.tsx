// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import React from 'react';
import { tapFeedback } from '@/lib/haptics';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
  fullWidth?: boolean;
  children: React.ReactNode;
}

export function Button({
  variant = 'primary',
  size = 'md',
  loading = false,
  fullWidth = false,
  children,
  className = '',
  disabled,
  onClick,
  ...props
}: ButtonProps) {
  const handleClick = (e: React.MouseEvent<HTMLButtonElement>) => {
    if (variant === 'primary') {
      tapFeedback();
    }
    onClick?.(e);
  };
  const baseStyles = `
    inline-flex items-center justify-center
    font-semibold tracking-[0.01em]
    transition-all duration-200
    focus:outline-none focus:ring-2 focus:ring-[var(--focus-ring)] focus:ring-offset-0
    disabled:opacity-50 disabled:cursor-not-allowed
  `;

  const variants = {
    primary: `apple-button`,
    secondary: `apple-button-secondary`,
    ghost: `
      bg-transparent text-[var(--text-primary)] border border-[var(--border)] rounded-xl
      hover:bg-[var(--surface-alt)] active:bg-[var(--surface-alt)]
    `,
    danger: `
      bg-transparent text-[var(--text-primary)] border border-dashed border-[var(--border)] rounded-xl
      hover:bg-[var(--surface-alt)] active:bg-[var(--surface-alt)]
    `,
  };

  const sizes = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-5 py-3.5 text-sm rounded-2xl',
    lg: 'px-6 py-4 text-base rounded-2xl',
  };

  return (
    <button
      className={`
        ${baseStyles}
        ${variants[variant]}
        ${sizes[size]}
        ${fullWidth ? 'w-full' : ''}
        ${className}
      `}
      disabled={disabled || loading}
      onClick={handleClick}
      {...props}
    >
      {loading ? (
        <svg
          className="animate-spin -ml-1 mr-2 h-4 w-4"
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle
            className="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
          />
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          />
        </svg>
      ) : null}
      {children}
    </button>
  );
}

export default Button;
