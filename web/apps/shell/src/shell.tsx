import type { AppManifest, ShellBridge } from "@hardy/sdk";
import type { User } from "@hardy/api-client";
import { type ComponentType, type LazyExoticComponent, type ReactNode, createContext, lazy, useContext } from "react";
import { ActivityIcon, BagIcon, DocumentIcon, FolderIcon, ListIcon, NotesIcon, ScreenIcon, SlidersIcon, StorageIcon, TerminalIcon, VMIcon } from "./icons";

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
  /** Not in the dock or on the desktop (opened by other apps). */
  hidden?: boolean;
}

/** Installed Docker apps open in windows with this id prefix plus ":" and the app's id. */
export const APP_WINDOW = "os.hardy.appwindow";

/** Every app the desktop knows about, in dock order. */
export const APPS: AppDef[] = [
  {
    id: "os.hardy.files",
    name: "File Manager",
    icon: "folder",
    color: "#2F6BFF",
    glyph: (s) => <FolderIcon size={s} />,
    component: lazy(() => import("./apps/files/FileManager")),
    defaultSize: { width: 1080, height: 700 },
  },
  {
    id: "os.hardy.notes",
    name: "Notes",
    icon: "notes",
    color: "#0E9F75",
    glyph: (s) => <NotesIcon size={s} />,
    component: lazy(() => import("./apps/notes/Notes")),
    defaultSize: { width: 980, height: 660 },
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
    component: lazy(() => import("./apps/store/AppStore")),
    defaultSize: { width: 1040, height: 700 },
  },
  {
    id: "os.hardy.vms",
    name: "Virtual Machines",
    icon: "vm",
    color: "#0B7285",
    glyph: (s) => <VMIcon size={s} />,
    component: lazy(() => import("./apps/vms/VirtualMachines")),
    defaultSize: { width: 1140, height: 760 },
    adminOnly: true,
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

const appWindow: AppDef = {
  id: APP_WINDOW,
  name: "App",
  icon: "bag",
  color: "#7C5CF5",
  glyph: (s) => <BagIcon size={s} />,
  component: lazy(() => import("./apps/store/AppFrame")),
  defaultSize: { width: 1180, height: 760 },
  hidden: true,
};

/** A VM's screen opens in a window with this id prefix plus ":" and the VM's id. */
export const VM_CONSOLE = "os.hardy.vmconsole";

const vmConsole: AppDef = {
  id: VM_CONSOLE,
  name: "VM screen",
  icon: "screen",
  color: "#0B7285",
  glyph: (s) => <ScreenIcon size={s} />,
  component: lazy(() => import("./apps/vms/Console")),
  defaultSize: { width: 1060, height: 700 },
  hidden: true,
  adminOnly: true,
};

/** A document's editor opens in a window with this id prefix plus ":" share ":" path. */
export const OFFICE_EDITOR = "os.hardy.office";

const officeEditor: AppDef = {
  id: OFFICE_EDITOR,
  name: "Document",
  icon: "document",
  color: "#22D3EE",
  glyph: (s) => <DocumentIcon size={s} />,
  component: lazy(() => import("./apps/office/OfficeEditor")),
  defaultSize: { width: 1200, height: 800 },
  hidden: true,
};

export function appById(id: string): AppDef | undefined {
  if (id === APP_WINDOW || id.startsWith(`${APP_WINDOW}:`)) return appWindow;
  if (id === OFFICE_EDITOR || id.startsWith(`${OFFICE_EDITOR}:`)) return officeEditor;
  if (id === VM_CONSOLE || id.startsWith(`${VM_CONSOLE}:`)) return vmConsole;
  return APPS.find((a) => a.id === id);
}

/** Apps the user may open from the dock and desktop. */
export function visibleApps(user: User | null | undefined): AppDef[] {
  return APPS.filter((a) => !a.hidden && (!a.adminOnly || user?.role === "admin"));
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
