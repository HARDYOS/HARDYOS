import type { User } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, unwrap } from "../api";
import { PendingNetwork, useNetworkStatus } from "../apps/control-panel/Network";
import { useEvents } from "../hooks/useEvents";
import { openLinkFromHash } from "../links";
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
  // A link from an alert email or chat message (#open=storage/disks/sda).
  useEffect(() => openLinkFromHash(user), [user]);

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
      {user.role === "admin" && <NetworkBanner />}
      <HostnameBanner />
      <Widgets user={user} />
      <WindowLayer user={user} />
      <Dock user={user} />
      <Toasts />
    </div>
  );
}

/** A network change waiting to be kept shows on the desktop, so it can be
 * confirmed right after signing in at the server's new address. */
function NetworkBanner() {
  const net = useNetworkStatus();
  // The Control Panel's Network page shows the same prompt.
  const panelOpen = useWM((s) => s.windows.some((w) => w.appId === "os.hardy.control"));
  if (!net.data?.pending || panelOpen) return null;
  return (
    <div className="desktop-banner">
      <PendingNetwork pending={net.data.pending} />
    </div>
  );
}

/** With hostnames on (Control Panel › Hostnames), apps open on their own
 * origins only when the desktop is used at its own name: offer to move there
 * when that address answers from this device. */
function HostnameBanner() {
  const q = useQuery({ queryKey: ["hostnames", "desktop"], queryFn: () => unwrap(api.GET("/hostnames/desktop")), staleTime: 300_000, retry: false });
  const target = q.data?.url ?? "";
  const [reachable, setReachable] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  useEffect(() => {
    if (!target || window.location.origin === target) return;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 4000);
    fetch(`${target}/api/v1/health`, { mode: "no-cors", signal: ctl.signal, credentials: "omit" })
      .then(() => setReachable(true))
      .catch(() => setReachable(false))
      .finally(() => clearTimeout(timer));
    return () => ctl.abort();
  }, [target]);
  if (!reachable || dismissed || !target) return null;
  return (
    <div className="desktop-banner" role="status">
      <span className="small">
        This server has its own address: at <span className="mono">{target.replace("https://", "")}</span> every app opens in its own, separate origin.
      </span>
      <a className="btn btn--primary btn--sm" href={target + "/"}>
        Switch
      </a>
      <button type="button" className="btn btn--ghost btn--sm" onClick={() => setDismissed(true)}>
        Not now
      </button>
    </div>
  );
}
