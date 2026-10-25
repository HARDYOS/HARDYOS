import { type FormEvent, type ReactNode, useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { errorMessage } from "../api";
import { Alert, Button, Field, TextInput } from "./index";

export function Dialog({
  title,
  description,
  children,
  footer,
  onClose,
  width = 480,
  onSubmit,
}: {
  title: string;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  onClose: () => void;
  width?: number;
  onSubmit?: () => void;
}) {
  const titleId = useId();
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const first = ref.current?.querySelector<HTMLElement>("input, select, textarea, button:not(.dialog__close)");
    first?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
      if (e.key === "Tab" && ref.current) {
        const items = ref.current.querySelectorAll<HTMLElement>(
          'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea, [href], [tabindex]:not([tabindex="-1"])',
        );
        if (items.length === 0) return;
        const firstEl = items[0]!;
        const lastEl = items[items.length - 1]!;
        if (e.shiftKey && document.activeElement === firstEl) {
          e.preventDefault();
          lastEl.focus();
        } else if (!e.shiftKey && document.activeElement === lastEl) {
          e.preventDefault();
          firstEl.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey, true);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      prev?.focus?.();
    };
  }, [onClose]);

  const body = (
    <>
      <header className="dialog__head">
        <h2 id={titleId} className="dialog__title">
          {title}
        </h2>
        <button type="button" className="dialog__close" aria-label="Close" onClick={onClose}>
          ×
        </button>
      </header>
      {description && <p className="dialog__desc">{description}</p>}
      <div className="dialog__body">{children}</div>
      {footer && <footer className="dialog__foot">{footer}</footer>}
    </>
  );

  return createPortal(
    <div className="dialog-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} className="dialog glass" role="dialog" aria-modal="true" aria-labelledby={titleId} style={{ width }}>
        {onSubmit ? (
          <form
            onSubmit={(e: FormEvent) => {
              e.preventDefault();
              onSubmit();
            }}
          >
            {body}
          </form>
        ) : (
          body
        )}
      </div>
    </div>,
    document.body,
  );
}

/**
 * Confirmation for destructive actions. With `typeToConfirm`, the person must
 * type that exact text before the button enables.
 */
export function ConfirmDialog({
  title,
  children,
  confirmLabel,
  typeToConfirm,
  danger = true,
  onConfirm,
  onClose,
}: {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  typeToConfirm?: string;
  danger?: boolean;
  onConfirm: () => Promise<unknown> | void;
  onClose: () => void;
}) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ready = !typeToConfirm || typed === typeToConfirm;

  async function run() {
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      await onConfirm();
      onClose();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <Dialog
      title={title}
      onClose={onClose}
      onSubmit={run}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant={danger ? "danger" : "primary"} disabled={!ready} busy={busy}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="stack">
        <div className="dialog__text">{children}</div>
        {typeToConfirm && (
          <Field label={`Type ${typeToConfirm} to confirm`}>
            {(id) => (
              <TextInput id={id} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
            )}
          </Field>
        )}
        {error && <Alert tone="bad">{error}</Alert>}
      </div>
    </Dialog>
  );
}
