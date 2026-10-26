import { CSRF_HEADER, type AppPackage, type InstalledApp, type Job } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { ApiFailure, api, unwrap } from "../../api";
import { Badge, type Tone } from "../../ui";

export const useApps = () =>
  useQuery({
    queryKey: ["apps"],
    queryFn: () => unwrap(api.GET("/apps")),
    refetchInterval: (q) => (q.state.data?.apps.some((a) => a.state === "starting" || a.state === "restarting") ? 3_000 : 15_000),
  });

export const useCatalog = (enabled: boolean) =>
  useQuery({ queryKey: ["apps", "catalog"], queryFn: () => unwrap(api.GET("/apps/catalog")), enabled, staleTime: 60_000 });

export const useImportedCatalogs = (enabled: boolean) =>
  useQuery({ queryKey: ["apps", "catalogs"], queryFn: () => unwrap(api.GET("/apps/catalogs")), enabled, staleTime: 60_000 });

export const STATE: Record<InstalledApp["state"], { tone: Tone; label: string }> = {
  running: { tone: "good", label: "Running" },
  starting: { tone: "accent", label: "Starting" },
  restarting: { tone: "warn", label: "Restarting" },
  unhealthy: { tone: "bad", label: "Unhealthy" },
  partial: { tone: "warn", label: "Partly running" },
  stopped: { tone: "neutral", label: "Stopped" },
  "not-created": { tone: "neutral", label: "Not started" },
};

export function isRunning(app: Pick<InstalledApp, "state">): boolean {
  return app.state === "running" || app.state === "starting" || app.state === "unhealthy" || app.state === "partial";
}

/** The address of an app's web page, on the host the desktop was opened at. */
export function appUrl(app: Pick<InstalledApp, "web">, hostname = window.location.hostname): string | null {
  if (!app.web) return null;
  return `${app.web.scheme}://${hostname}:${app.web.port}${app.web.path}`;
}

export function AppIcon({ src, name, size = 48 }: { src: string; name: string; size?: number }) {
  return src ? (
    <img className="app-icon" src={src} alt="" width={size} height={size} />
  ) : (
    <span className="app-icon app-icon--blank" style={{ width: size, height: size }} aria-hidden="true">
      {name.slice(0, 1)}
    </span>
  );
}

const SOURCE: Record<string, { tone: Tone; label: string } | undefined> = {
  upload: { tone: "warn", label: "Uploaded" },
  imported: { tone: "warn", label: "Third-party" },
  custom: { tone: "warn", label: "Custom" },
};

/** Labels anything that isn't from HardyOS's own catalog. */
export function SourceBadge({ source, sourceName }: { source: string; sourceName?: string }) {
  const s = SOURCE[source];
  if (!s) return null;
  return (
    <span title={source === "imported" && sourceName ? `From ${sourceName}` : undefined}>
      <Badge tone={s.tone}>{s.label}</Badge>
    </span>
  );
}

/** Whether a package's extra permissions need ticking (anything but HardyOS's catalog). */
export function untrusted(pkg: Pick<AppPackage, "source">): boolean {
  return pkg.source !== "catalog";
}

/** Notes from an install job (for example, an image that couldn't be refreshed). */
export function appNotes(j: Job): string | undefined {
  const notes = (j.result as { notes?: string[] } | null | undefined)?.notes;
  return notes && notes.length > 0 ? notes.join(" ") : undefined;
}

/** The snapshot a failed update took first, if any. */
export function jobSnapshot(j: Job): string | undefined {
  const s = (j.result as { snapshot?: string } | null | undefined)?.snapshot;
  return s || undefined;
}

// ---- shared folders --------------------------------------------------------
// The shares API (docs/plans/app-store-v2.md section 1) is built alongside;
// these calls follow its contract until its schemas are in the generated client.

/** A shared folder, as GET /shares lists it. */
export interface Share {
  id: string;
  name: string;
  description: string;
  pool: string;
  path: string;
  mounted: boolean;
  apps: { app: string; uid: number; level: string }[];
}

async function rawGet<T>(path: string): Promise<T> {
  let res: Response;
  try {
    res = await globalThis.fetch(new Request(new URL(`/api/v1${path}`, window.location.origin).toString(), {
      credentials: "same-origin",
      headers: { [CSRF_HEADER]: "1" },
    }));
  } catch {
    throw new ApiFailure(0, "network", "Can't reach the server. Check that it's on and connected.");
  }
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) throw new ApiFailure(res.status, String(body.code ?? "error"), String(body.message ?? res.statusText));
  return body as T;
}

export const useShares = (enabled = true) =>
  useQuery({
    queryKey: ["shares"],
    queryFn: async () => {
      const r = await rawGet<{ shares?: Share[] } | Share[]>("/shares");
      return Array.isArray(r) ? r : (r.shares ?? []);
    },
    enabled,
    staleTime: 30_000,
  });
