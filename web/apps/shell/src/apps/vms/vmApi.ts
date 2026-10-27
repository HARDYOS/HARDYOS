import type { Job, VM, VMCapabilities, VMLibrary, VMOverview, VMSnapshot, VMTemplate } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { api, unwrap } from "../../api";
import type { Tone } from "../../ui";

export const vmKeys = {
  all: ["vms"] as const,
  one: (id: string) => ["vms", id] as const,
  snapshots: (id: string) => ["vms", id, "snapshots"] as const,
  logs: (id: string) => ["vms", id, "logs"] as const,
  templates: ["vms-templates"] as const,
  caps: ["vms-caps"] as const,
  library: ["vms-library"] as const,
};

export const useVMs = () =>
  useQuery<VMOverview>({ queryKey: vmKeys.all, queryFn: () => unwrap(api.GET("/vms")), refetchInterval: 3_000 });

export const useVM = (id: string) =>
  useQuery<VM>({ queryKey: vmKeys.one(id), queryFn: () => unwrap(api.GET("/vms/{id}", { params: { path: { id } } })), refetchInterval: 2_000 });

export const useTemplates = () =>
  useQuery<VMTemplate[]>({ queryKey: vmKeys.templates, queryFn: () => unwrap(api.GET("/vms/templates")), staleTime: Infinity });

export const useCapabilities = () =>
  useQuery<VMCapabilities>({ queryKey: vmKeys.caps, queryFn: () => unwrap(api.GET("/vms/capabilities")), staleTime: 30_000 });

export const useLibrary = (poll = false) =>
  useQuery<VMLibrary>({ queryKey: vmKeys.library, queryFn: () => unwrap(api.GET("/vms/isos")), refetchInterval: poll ? 2_000 : false });

export const useSnapshots = (id: string) =>
  useQuery<VMSnapshot[]>({ queryKey: vmKeys.snapshots(id), queryFn: () => unwrap(api.GET("/vms/{id}/snapshots", { params: { path: { id } } })) });

export type VMAction = "start" | "stop" | "force-stop" | "restart" | "reset";

/** Starts a job for an action on a VM and returns the job. */
export async function vmAction(id: string, action: VMAction): Promise<Job> {
  const r = await unwrap(api.POST("/vms/{id}/{action}", { params: { path: { id, action } } }));
  return r.job;
}

export const STATE: Record<string, { label: string; tone: Tone }> = {
  running: { label: "Running", tone: "good" },
  stopped: { label: "Off", tone: "neutral" },
  paused: { label: "Paused", tone: "warn" },
  "shutting-down": { label: "Shutting down", tone: "warn" },
  crashed: { label: "Crashed", tone: "bad" },
  suspended: { label: "Asleep", tone: "warn" },
  unknown: { label: "Unknown", tone: "neutral" },
};

export const isOn = (v: Pick<VM, "state">) => v.state === "running" || v.state === "paused" || v.state === "shutting-down";

/** "8 GB" / "512 MB" from megabytes. */
export function memory(mb: number): string {
  if (mb >= 1024) {
    const gb = mb / 1024;
    return `${Number.isInteger(gb) ? gb : gb.toFixed(1)} GB`;
  }
  return `${mb} MB`;
}

export function diskSize(gb: number): string {
  return gb >= 1024 && gb % 1024 === 0 ? `${gb / 1024} TB` : `${gb} GB`;
}

/** What the VM runs, for subtitles. */
export function osLabel(v: Pick<VM, "os" | "template">, templates?: VMTemplate[]): string {
  const t = templates?.find((x) => x.id === v.template);
  if (t) return t.name;
  return v.os === "windows" ? "Windows" : v.os === "linux" ? "Linux" : "Other system";
}

export const CONSOLE_APP = "os.hardy.vmconsole";
export const consoleWindowId = (id: string) => `${CONSOLE_APP}:${id}`;

/** Live history of a VM's CPU and memory, kept while its page is open. */
export function pushSample(history: number[], value: number, max = 60): number[] {
  const next = [...history, value];
  return next.length > max ? next.slice(next.length - max) : next;
}
