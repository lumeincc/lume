// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

// @vitest-environment jsdom

import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';
import { Input } from '@/components/ui/Input';

describe('Input', () => {
  it('renders an input element', () => {
    render(<Input />);
    expect(screen.getByRole('textbox')).toBeDefined();
  });

  it('renders label with htmlFor association', () => {
    render(<Input label="Email" />);
    const label = screen.getByText('Email');
    const input = screen.getByRole('textbox');
    expect(label.getAttribute('for')).toBe(input.id);
  });

  it('uses external id when provided', () => {
    render(<Input label="Name" id="custom-id" />);
    const input = screen.getByRole('textbox');
    expect(input.id).toBe('custom-id');
  });

  it('does not render label when omitted', () => {
    const { container } = render(<Input />);
    expect(container.querySelector('label')).toBeNull();
  });

  it('renders error message', () => {
    render(<Input error="Required field" />);
    expect(screen.getByText('Required field')).toBeDefined();
  });

  it('sets aria-invalid when error is present', () => {
    render(<Input error="Bad value" />);
    expect(screen.getByRole('textbox').getAttribute('aria-invalid')).toBe('true');
  });

  it('does not set aria-invalid without error', () => {
    render(<Input />);
    expect(screen.getByRole('textbox').getAttribute('aria-invalid')).toBeNull();
  });

  it('renders hint text', () => {
    render(<Input hint="Enter your email" />);
    expect(screen.getByText('Enter your email')).toBeDefined();
  });

  it('hides hint when error is present', () => {
    render(<Input hint="Hint text" error="Error text" />);
    expect(screen.queryByText('Hint text')).toBeNull();
    expect(screen.getByText('Error text')).toBeDefined();
  });

  it('renders icon', () => {
    render(<Input icon={<span data-testid="icon">@</span>} />);
    expect(screen.getByTestId('icon')).toBeDefined();
  });

  it('applies icon padding class', () => {
    render(<Input icon={<span>@</span>} />);
    expect(screen.getByRole('textbox').className).toContain('apple-input-icon');
  });

  it('is disabled when disabled prop is true', () => {
    render(<Input disabled />);
    expect((screen.getByRole('textbox') as HTMLInputElement).disabled).toBe(true);
  });

  it('fires onChange handler', () => {
    const handler = vi.fn();
    render(<Input onChange={handler} />);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'test' } });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('displays value', () => {
    render(<Input value="hello" onChange={() => {}} />);
    expect((screen.getByRole('textbox') as HTMLInputElement).value).toBe('hello');
  });

  it('renders placeholder', () => {
    render(<Input placeholder="Type here..." />);
    expect(screen.getByPlaceholderText('Type here...')).toBeDefined();
  });

  it('forwards ref', () => {
    const ref = React.createRef<HTMLInputElement>();
    render(<Input ref={ref} />);
    expect(ref.current).toBeInstanceOf(HTMLInputElement);
  });

  // SEC-20260805-002. Every password field in this app holds a local secret —
  // the passphrase behind the at-rest master key, or a hidden-chat PIN — not a
  // credential the server checks. None of them should end up in a browser
  // password manager, which usually means a vendor cloud.
  describe('password fields are kept out of the password manager', () => {
    it('defaults type="password" to autoComplete="new-password"', () => {
      const { container } = render(<Input type="password" />);
      const input = container.querySelector('input');
      expect(input?.getAttribute('autocomplete')).toBe('new-password');
    });

    it('leaves non-password fields alone', () => {
      // A username or search field has no reason to opt out of autofill, and
      // blanket-disabling it would be a usability cost with no security gain.
      render(<Input type="text" />);
      expect(screen.getByRole('textbox').getAttribute('autocomplete')).toBeNull();
    });

    it('still lets a call site override it', () => {
      const { container } = render(<Input type="password" autoComplete="off" />);
      expect(container.querySelector('input')?.getAttribute('autocomplete')).toBe('off');
    });
  });
});
