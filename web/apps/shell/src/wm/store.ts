import { create } from "zustand";

/** A window on the desktop. */
export interface Win {
  id: string;
  appId: string;
  title: string;
  x: number;
  y: number;
  w: number;
  h: number;
  z: number;
  minimized: boolean;
  maximized: boolean;
  args?: Record<string, string>;
}

export interface OpenOptions {
  title: string;
  width: number;
  height: number;
  multiInstance?: boolean;
  args?: Record<string, string>;
}

interface Viewport {
  width: number;
  height: number;
}

interface WMState {
  windows: Win[];
  focusedId: string | null;
  nextZ: number;
  viewport: Viewport;
  open(appId: string, opts: OpenOptions): string;
  close(id: string): void;
  focus(id: string): void;
  minimize(id: string): void;
  toggleMaximize(id: string): void;
  move(id: string, x: number, y: number): void;
  resize(id: string, rect: { x: number; y: number; w: number; h: number }): void;
  setTitle(id: string, title: string): void;
  setViewport(v: Viewport): void;
  closeAll(): void;
}

export const MENUBAR_H = 32;
export const DOCK_RESERVE = 92;
export const MIN_W = 360;
export const MIN_H = 240;

let counter = 0;

/** Keeps at least the title bar reachable inside the viewport. */
export function clampRect(r: { x: number; y: number; w: number; h: number }, vp: Viewport) {
  const w = Math.max(MIN_W, Math.min(r.w, vp.width));
  const h = Math.max(MIN_H, Math.min(r.h, vp.height - MENUBAR_H));
  const x = Math.min(Math.max(r.x, -w + 120), vp.width - 120);
  const y = Math.min(Math.max(r.y, MENUBAR_H), vp.height - 48);
  return { x, y, w, h };
}

/** Topmost visible window, which becomes focused when another closes or minimizes. */
function topVisible(windows: Win[], exceptId?: string): string | null {
  let best: Win | null = null;
  for (const w of windows) {
    if (w.id === exceptId || w.minimized) continue;
    if (!best || w.z > best.z) best = w;
  }
  return best?.id ?? null;
}

export const useWM = create<WMState>((set, get) => ({
  windows: [],
  focusedId: null,
  nextZ: 1,
  viewport: { width: typeof window === "undefined" ? 1440 : window.innerWidth, height: typeof window === "undefined" ? 900 : window.innerHeight },

  open(appId, opts) {
    const s = get();
    if (!opts.multiInstance) {
      const existing = s.windows.find((w) => w.appId === appId);
      if (existing) {
        set((st) => ({
          windows: st.windows.map((w) =>
            w.id === existing.id ? { ...w, minimized: false, z: st.nextZ, args: opts.args ?? w.args } : w,
          ),
          focusedId: existing.id,
          nextZ: st.nextZ + 1,
        }));
        return existing.id;
      }
    }
    const vp = s.viewport;
    const offset = (s.windows.length % 6) * 28;
    const w = Math.min(opts.width, vp.width - 48);
    const h = Math.min(opts.height, vp.height - MENUBAR_H - DOCK_RESERVE - 16);
    const rect = clampRect(
      {
        x: Math.round((vp.width - w) / 2) + offset - 70,
        y: MENUBAR_H + Math.max(16, Math.round((vp.height - MENUBAR_H - DOCK_RESERVE - h) / 2)) + offset - 40,
        w,
        h,
      },
      vp,
    );
    const id = `win-${++counter}`;
    set((st) => ({
      windows: [
        ...st.windows,
        { id, appId, title: opts.title, ...rect, z: st.nextZ, minimized: false, maximized: false, args: opts.args },
      ],
      focusedId: id,
      nextZ: st.nextZ + 1,
    }));
    return id;
  },

  close(id) {
    set((st) => {
      const windows = st.windows.filter((w) => w.id !== id);
      return { windows, focusedId: st.focusedId === id ? topVisible(windows) : st.focusedId };
    });
  },

  focus(id) {
    const s = get();
    const w = s.windows.find((x) => x.id === id);
    if (!w || (s.focusedId === id && !w.minimized && w.z === s.nextZ - 1)) return;
    set((st) => ({
      windows: st.windows.map((x) => (x.id === id ? { ...x, z: st.nextZ, minimized: false } : x)),
      focusedId: id,
      nextZ: st.nextZ + 1,
    }));
  },

  minimize(id) {
    set((st) => ({
      windows: st.windows.map((w) => (w.id === id ? { ...w, minimized: true } : w)),
      focusedId: st.focusedId === id ? topVisible(st.windows, id) : st.focusedId,
    }));
  },

  toggleMaximize(id) {
    set((st) => ({ windows: st.windows.map((w) => (w.id === id ? { ...w, maximized: !w.maximized } : w)) }));
    get().focus(id);
  },

  move(id, x, y) {
    set((st) => ({
      windows: st.windows.map((w) => {
        if (w.id !== id) return w;
        const r = clampRect({ x, y, w: w.w, h: w.h }, st.viewport);
        return { ...w, x: r.x, y: r.y, maximized: false };
      }),
    }));
  },

  resize(id, rect) {
    set((st) => ({
      windows: st.windows.map((w) => (w.id === id ? { ...w, ...clampRect(rect, st.viewport), maximized: false } : w)),
    }));
  },

  setTitle(id, title) {
    set((st) => ({ windows: st.windows.map((w) => (w.id === id ? { ...w, title } : w)) }));
  },

  setViewport(viewport) {
    set((st) => ({ viewport, windows: st.windows.map((w) => ({ ...w, ...clampRect(w, viewport) })) }));
  },

  closeAll() {
    set({ windows: [], focusedId: null });
  },
}));
