import type { User } from "@hardy/api-client";
import { appById } from "../shell";
import { toast } from "../ui/toasts";
import { useWM } from "./store";

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
  useWM.getState().open(app.id, {
    title: app.name,
    width: app.defaultSize?.width ?? 900,
    height: app.defaultSize?.height ?? 600,
    multiInstance: app.multiInstance,
    args,
  });
}
