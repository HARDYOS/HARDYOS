import { useEffect } from "react";
import { create } from "zustand";

export type ToastLevel = "info" | "success" | "warning" | "error";

export interface Toast {
  id: number;
  level: ToastLevel;
  title: string;
  body?: string;
}

interface ToastState {
  toasts: Toast[];
  push(t: Omit<Toast, "id">): void;
  dismiss(id: number): void;
}

let nextId = 1;

export const useToasts = create<ToastState>((set) => ({
  toasts: [],
  push(t) {
    const toast = { ...t, id: nextId++ };
    set((s) => ({ toasts: [...s.toasts.slice(-4), toast] }));
  },
  dismiss(id) {
    set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
  },
}));

/** Shows a toast from anywhere. */
export function toast(level: ToastLevel, title: string, body?: string) {
  useToasts.getState().push({ level, title, body });
}

function ToastItem({ t }: { t: Toast }) {
  const dismiss = useToasts((s) => s.dismiss);
  useEffect(() => {
    const ms = t.level === "error" || t.level === "warning" ? 10_000 : 5_000;
    const timer = setTimeout(() => dismiss(t.id), ms);
    return () => clearTimeout(timer);
  }, [t, dismiss]);
  return (
    <div className={`toast toast--${t.level} glass`} role={t.level === "error" ? "alert" : "status"}>
      <div className="toast__text">
        <strong>{t.title}</strong>
        {t.body && <span>{t.body}</span>}
      </div>
      <button type="button" className="toast__close" aria-label="Dismiss" onClick={() => dismiss(t.id)}>
        ×
      </button>
    </div>
  );
}

export function Toasts() {
  const toasts = useToasts((s) => s.toasts);
  return (
    <div className="toasts" aria-live="polite">
      {toasts.map((t) => (
        <ToastItem key={t.id} t={t} />
      ))}
    </div>
  );
}
