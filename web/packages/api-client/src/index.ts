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
export type UpdateStatus = S["UpdateStatus"];
export type InstalledVersion = S["InstalledVersion"];
export type PendingUpdate = S["PendingUpdate"];
export type UpdateResult = S["UpdateResult"];
export type UpdateCheck = S["UpdateCheck"];
export type AvailableUpdate = S["AvailableUpdate"];
export type BackupStatus = S["BackupStatus"];
export type BackupSettings = S["BackupSettings"];
export type PoolBackup = S["PoolBackup"];
export type BackupStaged = S["BackupStaged"];
export type RestoreResult = S["RestoreResult"];
export type BackupDownload = S["BackupDownload"];
export type BootDisks = S["BootDisks"];
export type InstallerHardware = S["InstallerHardware"];
export type InstallerNIC = S["InstallerNIC"];
export type InstallPlan = S["InstallPlan"];
export type InstallNetwork = S["InstallNetwork"];
export type InstallCheck = S["InstallCheck"];
export type NetworkAddressing = S["NetworkAddressing"];
export type NetworkInterface = S["NetworkInterface"];
export type NetworkBond = S["NetworkBond"];
export type NetworkVLAN = S["NetworkVLAN"];
export type NetworkConfig = S["NetworkConfig"];
export type NetworkStatus = S["NetworkStatus"];
export type NetworkPending = S["NetworkPending"];
export type LiveInterface = S["LiveInterface"];
export type TimeConfig = S["TimeConfig"];
export type TimeStatus = S["TimeStatus"];
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
export type DomainStatus = S["DomainStatus"];
export type DomainConfig = S["DomainConfig"];
export type DomainSuggestion = S["DomainSuggestion"];
export type DomainUser = S["DomainUser"];
export type DomainGroup = S["DomainGroup"];
export type DomainController = S["DomainController"];
export type AppsOverview = S["AppsOverview"];
export type InstalledApp = S["App"];
export type AppPackage = S["AppPackage"];
export type AppPackageRef = S["AppPackageRef"];
export type AppPlan = S["AppPlan"];
export type AppInstallRequest = S["AppInstallRequest"];
// Shared folders
export type Share = S["Share"];
export type ShareRule = S["ShareRule"];
export type ShareAppGrant = S["ShareAppGrant"];
export type ShareCreateRequest = S["ShareCreateRequest"];
export type ShareUpdateRequest = S["ShareUpdateRequest"];
export type ShareStarterRequest = S["ShareStarterRequest"];
