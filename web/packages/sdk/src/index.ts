/**
 * @hardy/sdk: the contract between the HardyOS web desktop and the apps
 * that open as windows inside it. Phase 1 fills in the implementation;
 * these types are the stable surface apps code against.
 */

/** Describes an app the desktop can launch. */
export interface AppManifest {
  /** Stable reverse-DNS style id, e.g. "os.hardy.storage". */
  id: string;
  name: string;
  /** Icon name from the shell's icon set. */
  icon: string;
  /** Default window size in CSS pixels. */
  defaultSize?: { width: number; height: number };
  /** Whether more than one window of the app may be open at once. */
  multiInstance?: boolean;
  /** Admin-only apps are hidden from regular users. */
  adminOnly?: boolean;
}

export type NotificationLevel = "info" | "success" | "warning" | "error";

export interface Notification {
  title: string;
  body?: string;
  level?: NotificationLevel;
}

/** What the shell offers to every app window. */
export interface ShellBridge {
  /** Open another app, optionally with launch arguments. */
  openApp(appId: string, args?: Record<string, string>): void;
  /** Show a toast and add it to the notification center. */
  notify(n: Notification): void;
  /** Change the title shown in the window's title bar and the menu bar. */
  setTitle(title: string): void;
  /** Close the calling window. */
  close(): void;
}
