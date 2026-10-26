import type { AppManifest, ShellBridge } from "@hardy/sdk";
import type { User } from "@hardy/api-client";
import { type ComponentType, type LazyExoticComponent, type ReactNode, createContext, lazy, useContext } from "react";
import { ActivityIcon, BagIcon, FolderIcon, ListIcon, SlidersIcon, StorageIcon, TerminalIcon } from "./icons";

/** Props every app window receives. */
export interface AppProps {
  windowId: string;
  args?: Record<string, string>;
}

export interface AppDef extends AppManifest {
  color: string;
  glyph: (size: number) => ReactNode;
  component: LazyExoticComponent<ComponentType<AppProps>>;
  /** Shown in the dock but opens a "coming soon" window. */
  comingIn?: string;
}

const ComingSoon = lazy(() => import("./apps/ComingSoon"));

/** Every app the desktop knows about, in dock order. */
export const APPS: AppDef[] = [
  {
    id: "os.hardy.files",
    name: "Files",
    icon: "folder",
    color: "#2F6BFF",
    glyph: (s) => <FolderIcon size={s} />,
    component: ComingSoon,
    comingIn: "the file services phase (SMB, NFS, sharing and sync)",
    defaultSize: { width: 560, height: 360 },
  },
  {
    id: "os.hardy.storage",
    name: "Storage Manager",
    icon: "storage",
    color: "#0E9F75",
    glyph: (s) => <StorageIcon size={s} />,
    component: lazy(() => import("./apps/storage/StorageManager")),
    defaultSize: { width: 1120, height: 740 },
    adminOnly: true,
  },
  {
    id: "os.hardy.control",
    name: "Control Panel",
    icon: "sliders",
    color: "#475569",
    glyph: (s) => <SlidersIcon size={s} />,
    component: lazy(() => import("./apps/control-panel/ControlPanel")),
    defaultSize: { width: 960, height: 660 },
    adminOnly: true,
  },
  {
    id: "os.hardy.store",
    name: "App Store",
    icon: "bag",
    color: "#7C5CF5",
    glyph: (s) => <BagIcon size={s} />,
    component: ComingSoon,
    comingIn: "the platform phase (Docker apps and the app store)",
    defaultSize: { width: 560, height: 360 },
  },
  {
    id: "os.hardy.terminal",
    name: "Terminal",
    icon: "terminal",
    color: "#11151F",
    glyph: (s) => <TerminalIcon size={s} color="#7CF2C4" />,
    component: lazy(() => import("./apps/terminal/Terminal")),
    defaultSize: { width: 820, height: 520 },
    adminOnly: true,
  },
  {
    id: "os.hardy.monitor",
    name: "Resource Monitor",
    icon: "activity",
    color: "#E08A12",
    glyph: (s) => <ActivityIcon size={s} />,
    component: lazy(() => import("./apps/monitor/ResourceMonitor")),
    defaultSize: { width: 900, height: 640 },
  },
  {
    id: "os.hardy.logs",
    name: "Log Center",
    icon: "list",
    color: "#D9475A",
    glyph: (s) => <ListIcon size={s} />,
    component: lazy(() => import("./apps/logs/LogCenter")),
    defaultSize: { width: 940, height: 620 },
    adminOnly: true,
  },
];

export function appById(id: string): AppDef | undefined {
  return APPS.find((a) => a.id === id);
}

/** Apps the user may open. */
export function visibleApps(user: User | null | undefined): AppDef[] {
  return APPS.filter((a) => !a.adminOnly || user?.role === "admin");
}

export interface ShellContextValue extends ShellBridge {
  user: User;
  windowId: string;
}

export const ShellContext = createContext<ShellContextValue | null>(null);

/** The shell bridge for the calling app window. */
export function useShell(): ShellContextValue {
  const ctx = useContext(ShellContext);
  if (!ctx) throw new Error("useShell must be used inside an app window");
  return ctx;
}
