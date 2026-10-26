import createClient from "openapi-fetch";
import type { components, paths } from "./schema.gen";

export type { components, paths };
type S = components["schemas"];
export type Health = S["Health"];
export type VersionInfo = S["VersionInfo"];
export type ApiError = S["Error"];
export type User = S["User"];
export type Role = S["Role"];
export type Job = S["Job"];
export type JobState = S["JobState"];
export type AuditEntry = S["AuditEntry"];
export type SetupStatus = S["SetupStatus"];
export type Hardware = S["Hardware"];
export type Disk = S["Disk"];
export type SMART = S["SMART"];
export type DiskHealth = S["DiskHealth"];
export type Pool = S["Pool"];
export type PoolStatus = S["PoolStatus"];
export type Vdev = S["Vdev"];
export type Scan = S["Scan"];
export type PoolSpec = S["PoolSpec"];
export type VdevSpec = S["VdevSpec"];
export type Recommendation = S["Recommendation"];
export type ImportablePool = S["ImportablePool"];
export type Dataset = S["Dataset"];
export type Snapshot = S["Snapshot"];
export type SnapshotPolicy = S["SnapshotPolicy"];
export type ScrubPolicy = S["ScrubPolicy"];
export type Notification = S["Notification"];
export type SystemInfo = S["SystemInfo"];
export type Metrics = S["Metrics"];
export type MetricSample = S["MetricSample"];
export type InstallerStatus = S["InstallerStatus"];
export type InstallerHardware = S["InstallerHardware"];
export type InstallerNIC = S["InstallerNIC"];
export type InstallPlan = S["InstallPlan"];
export type InstallNetwork = S["InstallNetwork"];
export type InstallCheck = S["InstallCheck"];
export type InstallRequest = S["InstallRequest"];

/** Header every state-changing request must carry (hardyd's CSRF check). */
export const CSRF_HEADER = "X-HardyOS-Request";

/** Creates a typed client for the hardyd API. */
export function createApiClient(baseUrl = "/api/v1", fetchImpl?: typeof fetch) {
  return createClient<paths>({
    baseUrl,
    credentials: "same-origin",
    headers: { [CSRF_HEADER]: "1" },
    // Resolve fetch per call so tests and service workers that replace it are honored.
    fetch: fetchImpl ?? ((req: Request) => globalThis.fetch(req)),
  });
}

export type ApiClient = ReturnType<typeof createApiClient>;

/** Builds the WebSocket URL for the event stream relative to the page. */
export function eventsUrl(origin: string = globalThis.location?.origin ?? "http://localhost"): string {
  const u = new URL("/api/v1/events", origin);
  u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
  return u.toString();
}
