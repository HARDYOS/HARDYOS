import { lazy, type ComponentType, type LazyExoticComponent } from "react";

/**
 * The Backup app's tabs. Each is a component given the app's shared state.
 * Other parts add theirs to EXTRA_TABS: replication's sending side
 * (./replication) is one; its receiving side stays in Control Panel ›
 * Replication.
 */
export interface BackupTabProps {
  /** Opens another tab (e.g. Restore after picking a task). */
  go: (tab: string, args?: Record<string, string>) => void;
  args: Record<string, string>;
}

export interface BackupTab {
  id: string;
  label: string;
  component: ComponentType<BackupTabProps> | LazyExoticComponent<ComponentType<BackupTabProps>>;
}

/** Tabs other parts of HardyOS add (see above). */
export const EXTRA_TABS: BackupTab[] = [
  { id: "replication", label: "Replication", component: lazy(() => import("./replication/ReplicationTab").then((m) => ({ default: m.ReplicationTab }))) },
];
