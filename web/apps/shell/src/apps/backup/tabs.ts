import type { ComponentType, LazyExoticComponent } from "react";

/**
 * The Backup app's tabs. Each is a component given the app's shared state.
 * Other parts add theirs here: replication (built on its own branch) lives
 * in ./replication/ReplicationTab.tsx and is added as
 *
 *   { id: "replication", label: "Replication", component: lazy(() => import("./replication/ReplicationTab")) }
 *
 * to EXTRA_TABS when it's merged.
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
export const EXTRA_TABS: BackupTab[] = [];
