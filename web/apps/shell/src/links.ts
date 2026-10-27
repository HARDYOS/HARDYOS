import type { User } from "@hardy/api-client";
import { openApp } from "./wm/open";

/** Where a notification's link opens: app id and arguments. Links are
 * written by hardyd ("storage/disks/sda", "storage/pool/tank", "ups",
 * "control/notifications", "apps/immich", "vms/haos", "monitor", "logs"). */
export function linkTarget(link: string): { app: string; args?: Record<string, string> } | null {
  const [head, a, b] = link.split("/");
  switch (head) {
    case "storage":
      if (a === "pool" && b) return { app: "os.hardy.storage", args: { pool: b } };
      if (a === "disks") return { app: "os.hardy.storage", args: { section: "disks", ...(b ? { disk: b } : {}) } };
      return { app: "os.hardy.storage", args: a ? { section: a } : undefined };
    case "ups":
      return { app: "os.hardy.control", args: { section: "ups" } };
    case "control":
      return { app: "os.hardy.control", args: a ? { section: a } : undefined };
    case "apps":
      return { app: "os.hardy.store" };
    case "vms":
      return { app: "os.hardy.vms" };
    case "monitor":
      return { app: "os.hardy.monitor", args: a ? { tab: a } : undefined };
    case "logs":
      return { app: "os.hardy.logs" };
  }
  return null;
}

/** Opens a notification's link; false when it has nowhere to go. */
export function openLink(link: string | undefined, user: User): boolean {
  const t = link ? linkTarget(link) : null;
  if (!t) return false;
  openApp(t.app, user, t.args);
  return true;
}

/** Opens a link handed over in the page's address (#open=storage/disks),
 * as alert emails and webhooks do, then clears it. */
export function openLinkFromHash(user: User) {
  const m = /^#open=(.+)$/.exec(window.location.hash);
  if (!m) return;
  let link = "";
  try {
    link = decodeURIComponent(m[1] ?? "");
  } catch {
    return;
  }
  history.replaceState(null, "", window.location.pathname + window.location.search);
  if (/^[a-z]+(\/[A-Za-z0-9._:@-]+){0,2}$/.test(link)) openLink(link, user);
}
