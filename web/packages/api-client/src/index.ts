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
export type UnreadCount = S["UnreadCount"];
export type AlertChannel = S["AlertChannel"];
export type AlertChannelConfig = S["AlertChannelConfig"];
export type AlertChannelInput = S["AlertChannelInput"];
export type AlertSecretsInput = S["AlertSecretsInput"];
export type AlertRoute = S["AlertRoute"];
export type AlertSettings = S["AlertSettings"];
export type QuietHours = S["QuietHours"];
export type AlertDelivery = S["AlertDelivery"];
export type AlertCategory = S["AlertCategory"];
export type ChannelTestResult = S["ChannelTestResult"];
export type SeriesInfo = S["SeriesInfo"];
export type SeriesData = S["SeriesData"];
export type HistoryResult = S["HistoryResult"];
export type Condition = S["Condition"];
export type MonitorSettings = S["MonitorSettings"];
export type SmartSchedule = S["SmartSchedule"];
export type DiskInfo = S["DiskInfo"];
export type TestState = S["TestState"];
export type SMARTAttribute = S["SMARTAttribute"];
export type SelfTest = S["SelfTest"];
export type UPSConfig = S["UPSConfig"];
export type UPSStatus = S["UPSStatus"];
export type UPSView = S["UPSView"];
export type UPSDevice = S["UPSDevice"];
export type UPSSecretsInput = S["UPSSecretsInput"];
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
export type NetworkBridge = S["NetworkBridge"];
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
export type DomainAdminsGroup = S["DomainAdminsGroup"];
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
export type ShareServices = S["ShareServices"];
export type ShareSnapshot = S["ShareSnapshot"];
export type ShareNFS = S["ShareNFS"];
export type AppSource = S["AppSource"];
export type AppShareMount = S["AppShareMount"];
export type AppShareChoice = S["AppShareChoice"];
export type AppShare = S["AppShare"];
export type AppLimits = S["AppLimits"];
export type AppEntryGrant = S["AppEntryGrant"];
export type AppPrincipal = S["AppPrincipal"];
export type AppAccess = S["AppAccess"];
export type AppSettingValue = S["AppSettingValue"];
export type AppConfig = S["AppConfig"];
export type AppConfigUpdate = S["AppConfigUpdate"];
export type AppUpdateRequest = S["AppUpdateRequest"];
export type AppGrantsNeeded = S["AppGrantsNeeded"];
export type AppSnapshot = S["AppSnapshot"];
export type AppOpen = S["AppOpen"];
export type AppCatalog = S["AppCatalog"];
export type AppCatalogApp = S["AppCatalogApp"];
export type CustomAppRequest = S["CustomAppRequest"];
// Share links (part D)
export type ShareLink = S["ShareLink"];
export type ShareLinkRequest = S["ShareLinkRequest"];
export type ShareLinkCreated = S["ShareLinkCreated"];
// Files API as the File Manager consumes it (owned by part C)
export type FileShare = S["FileShare"];
export type FileEntry = S["FileEntry"];
export type FileVersion = S["FileVersion"];
export type FileUpload = S["FileUpload"];
export type FileTransferRequest = S["FileTransferRequest"];
export type FileServicesStatus = S["FileServicesStatus"];
export type FileServicesHomes = S["FileServicesHomes"];
export type FileServicesShare = S["FileServicesShare"];
export type FileListing = S["FileListing"];
export type FileBulkResult = S["FileBulkResult"];
export type FileItemResult = S["FileItemResult"];
export type FileUploadRequest = S["FileUploadRequest"];
// Remote access: NetBird client and publishing (part A)
export type NetBirdClientStatus = S["NetBirdClientStatus"];
export type RemoteStatus = S["RemoteStatus"];
export type RemoteSettings = S["RemoteSettings"];
export type RemoteJoinRequest = S["RemoteJoinRequest"];
export type RemotePublishingRequest = S["RemotePublishingRequest"];
export type PublishItem = S["PublishItem"];
export type PublishConfig = S["PublishConfig"];
export type PublishRequest = S["PublishRequest"];
export type AppPublish = S["AppPublish"];
export type RemoteCheck = S["RemoteCheck"];
export type RemoteCheckStep = S["RemoteCheckStep"];
export type DNSRecord = S["DNSRecord"];
export type NetBirdGroup = S["NetBirdGroup"];
export type NetBirdCluster = S["NetBirdCluster"];
// Sign-in provider (OIDC), Control Panel > Sign-in (OIDC) (remote access part B)
export type OidcStatus = S["OidcStatus"];
export type OidcKey = S["OidcKey"];
export type OidcClient = S["OidcClient"];
export type OidcClientSpec = S["OidcClientSpec"];
export type OidcClientResult = S["OidcClientResult"];
export type OidcPreset = S["OidcPreset"];
export type OidcPresetStep = S["OidcPresetStep"];
// Devices, GPUs and vGPU (part D)
export type VMDevice = S["VMDevice"];
export type DeviceProblem = S["DeviceProblem"];
export type DevicesCheckResult = S["DevicesCheckResult"];
export type DeviceInventory = S["DeviceInventory"];
export type IOMMUState = S["IOMMUState"];
export type IOMMUGroup = S["IOMMUGroup"];
export type PCIDeviceInfo = S["PCIDeviceInfo"];
export type USBDeviceInfo = S["USBDeviceInfo"];
export type GPUInfo = S["GPUInfo"];
export type GPUOwner = S["GPUOwner"];
export type DeviceUser = S["DeviceUser"];
export type StuckDevice = S["StuckDevice"];
export type VGPUInfo = S["VGPUInfo"];
export type VGPUType = S["VGPUType"];
export type VGPUInstance = S["VGPUInstance"];
export type NvidiaStatus = S["NvidiaStatus"];
export type NvidiaLicenceText = S["NvidiaLicenceText"];
export type GPUTask = S["GPUTask"];
export type VGPUUpload = S["VGPUUpload"];
// Virtual machines (phase 5 part C); VMDevice is part D's, above.
export type VM = S["VM"];
export type VMSpec = S["VMSpec"];
export type VMDisk = S["VMDisk"];
export type VMMedia = S["VMMedia"];
export type VMNIC = S["VMNIC"];
export type VMCloudInit = S["VMCloudInit"];
export type VMOverview = S["VMOverview"];
export type VMKeptDisk = S["VMKeptDisk"];
export type VMTemplate = S["VMTemplate"];
export type VMPreset = S["VMPreset"];
export type VMImage = S["VMImage"];
export type VMCapabilities = S["VMCapabilities"];
export type VMLibrary = S["VMLibrary"];
export type VMLibraryFile = S["VMLibraryFile"];
export type VMTask = S["VMTask"];
export type VMSnapshot = S["VMSnapshot"];
export type VMCreateRequest = S["VMCreateRequest"];
export type VMUpdateRequest = S["VMUpdateRequest"];
export type VMConsoleSession = S["VMConsoleSession"];

// Versioned cloud backups (phase 6 part A).
export type BackupItem = S["BackupItem"];
export type BackupSchedule = S["BackupSchedule"];
export type BackupRetention = S["BackupRetention"];
export type BackupMaintenance = S["BackupMaintenance"];
export type BackupTarget = S["BackupTarget"];
export type BackupTargetRequest = S["BackupTargetRequest"];
export type BackupRun = S["BackupRun"];
export type BackupTask = S["BackupTask"];
export type BackupTaskInput = S["BackupTaskInput"];
export type BackupRebuildOffer = S["BackupRebuildOffer"];
export type CloudBackupOverview = S["CloudBackupOverview"];
export type RecoveryKit = S["RecoveryKit"];
export type BackupVersion = S["BackupVersion"];
export type BackupVersionItem = S["BackupVersionItem"];
export type BackupEntry = S["BackupEntry"];
export type BackupRestoreRequest = S["BackupRestoreRequest"];
export type BackupRebuildRequest = S["BackupRebuildRequest"];
export type FileBackupVersion = S["FileBackupVersion"];
export type InstallRestore = S["InstallRestore"];
export type InstallBackupVersion = S["InstallBackupVersion"];

// Replication between HardyOS servers (phase 6 part B).
export type ReplicationKind = S["ReplicationKind"];
export type ReplicationItem = S["ReplicationItem"];
export type ReplicationLocalItem = S["ReplicationLocalItem"];
export type ReplicationTarget = S["ReplicationTarget"];
export type ReplicationTask = S["ReplicationTask"];
export type ReplicationTaskRequest = S["ReplicationTaskRequest"];
export type ReplicationOverview = S["ReplicationOverview"];
export type ReplicationSnapshot = S["ReplicationSnapshot"];
export type ReplicationRemoteItem = S["ReplicationRemoteItem"];
export type ReplicationBrowse = S["ReplicationBrowse"];
export type ReplicationRestoreRequest = S["ReplicationRestoreRequest"];
export type ReplicationRun = S["ReplicationRun"];
export type ReplicationPairing = S["ReplicationPairing"];
export type ReplicationPairingCode = S["ReplicationPairingCode"];
export type ReplicationSource = S["ReplicationSource"];
export type ReplicationReceive = S["ReplicationReceive"];
