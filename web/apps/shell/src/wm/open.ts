import type { User } from "@hardy/api-client";
import { appById } from "../shell";
import { toast } from "../ui/toasts";
import { useWM } from "./store";
import { useClusterScope } from "../cluster/scope";

/** Opens (or focuses) an app window, respecting admin-only apps. */
export function openApp(appId: string, user: User | null | undefined, args?: Record<string, string>) {
  const app = appById(appId);
  if (!app) {
    toast("error", "Unknown app", appId);
    return;
  }
  if (app.adminOnly && user?.role !== "admin") {
    toast("warning", `${app.name} is for administrators`);
    return;
  }
  // In a cluster, windows open for the server picked in the switcher
  // (args.node; "" is this server) and say which in their title.
  const node = args?.node ?? useClusterScope.getState().node;
  if (node && appId !== "os.hardy.cluster") {
    args = { ...args, node };
  }
  const title = args?.title ?? app.name;
  // Installed apps share one window component; each gets its own window
  // (keyed by the full id) titled with the app's name.
  useWM.getState().open(node && appId !== "os.hardy.cluster" ? `${appId}@${node}` : appId, {
    title: node && appId !== "os.hardy.cluster" ? `${title} — ${node}` : title,
    width: app.defaultSize?.width ?? 900,
    height: app.defaultSize?.height ?? 600,
    multiInstance: app.multiInstance,
    args,
  });
}
