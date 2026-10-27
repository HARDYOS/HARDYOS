import type { BackupItem, BackupRestoreRequest, BackupTarget, BackupTaskInput, BackupTargetRequest, BackupMaintenance, BackupRebuildRequest } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { api, unwrap } from "../../api";

/** Query keys of the Backup app. */
export const backupKeys = {
  all: ["backup"] as const,
  overview: ["backup", "overview"] as const,
  runs: (task?: string) => ["backup", "runs", task ?? ""] as const,
  versions: (target: string) => ["backup", "versions", target] as const,
  browse: (target: string, snapshot: string, path: string) => ["backup", "browse", target, snapshot, path] as const,
};

export const useOverview = () =>
  useQuery({ queryKey: backupKeys.overview, queryFn: () => unwrap(api.GET("/backup")), refetchInterval: 15_000 });

export const useRuns = (task?: string) =>
  useQuery({
    queryKey: backupKeys.runs(task),
    queryFn: () => unwrap(api.GET("/backup/runs", { params: { query: task ? { task, limit: 100 } : { limit: 100 } } })),
    refetchInterval: 15_000,
  });

export const useVersions = (target: string | null) =>
  useQuery({
    queryKey: backupKeys.versions(target ?? ""),
    queryFn: () => unwrap(api.GET("/backup/targets/{id}/versions", { params: { path: { id: target! } } })),
    enabled: !!target,
    staleTime: 30_000,
  });

export const useBrowse = (target: string, snapshot: string | null, path: string) =>
  useQuery({
    queryKey: backupKeys.browse(target, snapshot ?? "", path),
    queryFn: () => unwrap(api.GET("/backup/targets/{id}/browse", { params: { path: { id: target }, query: { snapshot: snapshot!, path } } })),
    enabled: !!snapshot,
    staleTime: 60_000,
  });

/** What can be backed up: shared folders, apps and VMs on this server. */
export function useSources() {
  const shares = useQuery({ queryKey: ["shares"], queryFn: () => unwrap(api.GET("/shares")) });
  const apps = useQuery({ queryKey: ["apps"], queryFn: () => unwrap(api.GET("/apps")) });
  const vms = useQuery({ queryKey: ["vms"], queryFn: () => unwrap(api.GET("/vms")) });
  return {
    pending: shares.isPending,
    shares: (shares.data?.shares ?? []).map((s) => ({ id: s.id, name: s.name })),
    apps: (apps.data?.apps ?? []).map((a) => ({ id: a.id, name: a.name })),
    vms: (vms.data?.vms ?? []).map((v) => ({ id: v.id, name: v.name })),
  };
}

export const createTarget = (body: BackupTargetRequest) => unwrap(api.POST("/backup/targets", { body }));
export const updateTarget = (id: string, body: BackupTargetRequest) => unwrap(api.PUT("/backup/targets/{id}", { params: { path: { id } }, body }));
export const removeTarget = (id: string, confirm: string) => unwrap(api.DELETE("/backup/targets/{id}", { params: { path: { id } }, body: { confirm } }));
export const setMaintenance = (id: string, body: BackupMaintenance) =>
  unwrap(api.PUT("/backup/targets/{id}/maintenance", { params: { path: { id } }, body }));
export const recoveryKit = (id: string, password: string) =>
  unwrap(api.POST("/backup/targets/{id}/recovery-kit", { params: { path: { id } }, body: { password } }));
export const pruneNow = (id: string) => unwrap(api.POST("/backup/targets/{id}/prune", { params: { path: { id } } }));
export const checkNow = (id: string) => unwrap(api.POST("/backup/targets/{id}/check", { params: { path: { id } } }));
export const createTask = (body: BackupTaskInput) => unwrap(api.POST("/backup/tasks", { body }));
export const updateTask = (id: string, body: BackupTaskInput) => unwrap(api.PUT("/backup/tasks/{id}", { params: { path: { id } }, body }));
export const deleteTask = (id: string) => unwrap(api.DELETE("/backup/tasks/{id}", { params: { path: { id } } }));
export const runTask = (id: string) => unwrap(api.POST("/backup/tasks/{id}/run", { params: { path: { id } } }));
export const restore = (body: BackupRestoreRequest) => unwrap(api.POST("/backup/restore", { body }));
export const rebuild = (body: BackupRebuildRequest) => unwrap(api.POST("/backup/rebuild", { body }));
export const dismissRebuild = () => unwrap(api.DELETE("/backup/rebuild"));

/** Saves text as a file the browser downloads. */
export function saveText(fileName: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** "share:media" etc. */
export const itemKey = (it: BackupItem) => (it.kind === "system" ? "system" : `${it.kind}:${it.id}`);

export function parseItemKey(key: string): BackupItem {
  if (key === "system") return { kind: "system" };
  const i = key.indexOf(":");
  return { kind: key.slice(0, i) as BackupItem["kind"], id: key.slice(i + 1) };
}

/** A person's name for an item, from what's on the server now. */
export function itemLabel(key: string, names: Record<string, string>): string {
  if (key === "system") return "Settings and domain";
  return names[key] ?? key.slice(key.indexOf(":") + 1);
}

export const kindLabel: Record<string, string> = { share: "Shared folder", app: "App", vm: "Virtual machine", system: "Settings" };

export function targetWhere(t: BackupTarget): string {
  if (t.kind === "b2") return `Backblaze B2 · ${t.bucket}${t.prefix ? "/" + t.prefix : ""}`;
  const host = (t.endpoint ?? "").replace(/^https:\/\//, "");
  return `${host} · ${t.bucket}${t.prefix ? "/" + t.prefix : ""}`;
}

export const weekdays = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

/** Well-known S3-compatible services, to fill in the endpoint. */
export const providers: { id: string; label: string; kind: "s3" | "b2"; endpoint?: string; region?: string; hint?: string }[] = [
  { id: "aws", label: "Amazon S3", kind: "s3", endpoint: "https://s3.us-east-1.amazonaws.com", region: "us-east-1", hint: "Use your bucket's region in the endpoint." },
  { id: "wasabi", label: "Wasabi", kind: "s3", endpoint: "https://s3.wasabisys.com", region: "us-east-1" },
  { id: "r2", label: "Cloudflare R2", kind: "s3", endpoint: "https://<account-id>.r2.cloudflarestorage.com", region: "auto", hint: "Your account id is on R2's overview page." },
  { id: "b2", label: "Backblaze B2", kind: "b2" },
  { id: "minio", label: "MinIO or other S3", kind: "s3", endpoint: "https://", region: "" },
];
