import type { User } from "@hardy/api-client";
import { visibleApps } from "../shell";
import { openApp } from "../wm/open";
import { useWM } from "../wm/store";

export function Dock({ user }: { user: User }) {
  const windows = useWM((s) => s.windows);
  const focusedId = useWM((s) => s.focusedId);
  const apps = visibleApps(user);

  function activate(appId: string) {
    const wins = windows.filter((w) => w.appId === appId);
    const focused = wins.find((w) => w.id === focusedId && !w.minimized);
    if (focused) {
      useWM.getState().minimize(focused.id); // clicking the active app hides it, like macOS
    } else if (wins.length > 0) {
      const top = wins.reduce((a, b) => (b.z > a.z ? b : a));
      useWM.getState().focus(top.id);
    } else {
      openApp(appId, user);
    }
  }

  return (
    <nav className="dock glass" aria-label="Dock">
      {apps.map((a) => {
        const running = windows.some((w) => w.appId === a.id);
        return (
          <button key={a.id} type="button" className="dock__item" aria-label={running ? `${a.name} (open)` : a.name} onClick={() => activate(a.id)}>
            <span className="dock__label" aria-hidden="true">
              {a.name}
            </span>
            <span className="dock__tile" style={{ background: a.color }}>
              {a.glyph(26)}
            </span>
            <span className={running ? "dock__dot dock__dot--on" : "dock__dot"} aria-hidden="true" />
          </button>
        );
      })}
    </nav>
  );
}
