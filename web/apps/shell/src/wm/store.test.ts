import { beforeEach, describe, expect, it } from "vitest";
import { MENUBAR_H, MIN_W, useWM } from "./store";

const opts = { title: "Storage Manager", width: 900, height: 600 };

beforeEach(() => {
  useWM.setState({ windows: [], focusedId: null, nextZ: 1, viewport: { width: 1440, height: 900 } });
});

describe("window manager", () => {
  it("opens, focuses and reuses single-instance windows", () => {
    const wm = useWM.getState();
    const a = wm.open("storage", opts);
    const b = useWM.getState().open("control", { ...opts, title: "Control Panel" });
    expect(useWM.getState().focusedId).toBe(b);
    const again = useWM.getState().open("storage", opts);
    expect(again).toBe(a);
    expect(useWM.getState().windows).toHaveLength(2);
    expect(useWM.getState().focusedId).toBe(a);
  });

  it("opens multiple instances when allowed", () => {
    useWM.getState().open("terminal", { ...opts, multiInstance: true });
    useWM.getState().open("terminal", { ...opts, multiInstance: true });
    expect(useWM.getState().windows).toHaveLength(2);
  });

  it("moves focus to the next window on minimize and close", () => {
    const a = useWM.getState().open("a", opts);
    const b = useWM.getState().open("b", opts);
    useWM.getState().minimize(b);
    expect(useWM.getState().focusedId).toBe(a);
    useWM.getState().focus(b);
    expect(useWM.getState().windows.find((w) => w.id === b)?.minimized).toBe(false);
    useWM.getState().close(b);
    expect(useWM.getState().focusedId).toBe(a);
  });

  it("keeps windows reachable and at least the minimum size", () => {
    const id = useWM.getState().open("a", opts);
    useWM.getState().move(id, -5000, -100);
    let w = useWM.getState().windows[0]!;
    expect(w.y).toBe(MENUBAR_H);
    expect(w.x + w.w).toBeGreaterThanOrEqual(120);
    useWM.getState().resize(id, { x: 10, y: 50, w: 10, h: 10 });
    w = useWM.getState().windows[0]!;
    expect(w.w).toBe(MIN_W);
    expect(useWM.getState().windows.find((x) => x.id === id)?.maximized).toBe(false);
  });
});
