// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

// @vitest-environment jsdom

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Modal } from '@/components/ui/Modal';

describe('Modal', () => {
  const onClose = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    document.body.style.overflow = '';
  });

  it('renders children when open', () => {
    render(<Modal isOpen onClose={onClose}><p>Content</p></Modal>);
    expect(screen.getByText('Content')).toBeDefined();
  });

  it('returns null when closed', () => {
    const { container } = render(<Modal isOpen={false} onClose={onClose}><p>Hidden</p></Modal>);
    expect(container.innerHTML).toBe('');
  });

  it('renders title', () => {
    render(<Modal isOpen onClose={onClose} title="Test Title"><p>Body</p></Modal>);
    expect(screen.getByText('Test Title')).toBeDefined();
  });

  it('has role="dialog" and aria-modal="true"', () => {
    render(<Modal isOpen onClose={onClose} title="Dialog"><p>Body</p></Modal>);
    const dialog = screen.getByRole('dialog');
    expect(dialog.getAttribute('aria-modal')).toBe('true');
  });

  it('sets aria-label from title', () => {
    render(<Modal isOpen onClose={onClose} title="My Modal"><p>Body</p></Modal>);
    expect(screen.getByRole('dialog').getAttribute('aria-label')).toBe('My Modal');
  });

  it('renders close button with aria-label="Close"', () => {
    render(<Modal isOpen onClose={onClose} title="X"><p>Body</p></Modal>);
    expect(screen.getByLabelText('Close')).toBeDefined();
  });

  it('applies sm size class', () => {
    render(<Modal isOpen onClose={onClose} size="sm"><p>Body</p></Modal>);
    expect(screen.getByRole('dialog').className).toContain('max-w-sm');
  });

  it('applies lg size class', () => {
    render(<Modal isOpen onClose={onClose} size="lg"><p>Body</p></Modal>);
    expect(screen.getByRole('dialog').className).toContain('max-w-lg');
  });

  it('calls onClose when close button clicked', () => {
    render(<Modal isOpen onClose={onClose} title="X"><p>Body</p></Modal>);
    fireEvent.click(screen.getByLabelText('Close'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('calls onClose when backdrop clicked', () => {
    render(<Modal isOpen onClose={onClose}><p>Body</p></Modal>);
    const backdrop = document.querySelector('.modal-backdrop-blur');
    expect(backdrop).not.toBeNull();
    fireEvent.click(backdrop!);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('calls onClose on Escape key', () => {
    render(<Modal isOpen onClose={onClose}><p>Body</p></Modal>);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('does not call onClose on non-Escape key', () => {
    render(<Modal isOpen onClose={onClose}><p>Body</p></Modal>);
    fireEvent.keyDown(document, { key: 'Enter' });
    expect(onClose).not.toHaveBeenCalled();
  });

  it('hides close button when showCloseButton=false', () => {
    render(<Modal isOpen onClose={onClose} title="No X" showCloseButton={false}><p>Body</p></Modal>);
    expect(screen.queryByLabelText('Close')).toBeNull();
  });
});
