import type { User } from "@hardy/api-client";
import { useEffect } from "react";
import { useEvents } from "../hooks/useEvents";
import { visibleApps } from "../shell";
import { Toasts } from "../ui/toasts";
import { openApp } from "../wm/open";
import { useWM } from "../wm/store";
import { WindowLayer } from "../wm/WindowLayer";
import { Dock } from "./Dock";
import { MenuBar } from "./MenuBar";
import { Widgets } from "./Widgets";

const DESKTOP_ICONS = ["os.hardy.files", "os.hardy.storage", "os.hardy.control"];

export function Desktop({ user }: { user: User }) {
  const connection = useEvents(true);
  const apps = visibleApps(user).filter((a) => DESKTOP_ICONS.includes(a.id));

  useEffect(() => {
    const onResize = () => useWM.getState().setViewport({ width: window.innerWidth, height: window.innerHeight });
    window.addEventListener("resize", onResize);
    onResize();
    return () => window.removeEventListener("resize", onResize);
  }, []);

  return (
    <div className="desktop wallpaper">
      <MenuBar user={user} connection={connection} />
      <div className="desktop-icons">
        {apps.map((a) => (
          <button key={a.id} type="button" className="desktop-icon" onDoubleClick={() => openApp(a.id, user)} onKeyDown={(e) => e.key === "Enter" && openApp(a.id, user)}>
            <span className="app-tile" style={{ background: a.color }}>
              {a.glyph(28)}
            </span>
            <span className="desktop-icon__label">{a.name}</span>
          </button>
        ))}
      </div>
      <Widgets user={user} />
      <WindowLayer user={user} />
      <Dock user={user} />
      <Toasts />
    </div>
  );
}
