import type { ReplicationKind, ReplicationTask } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { api, unwrap } from "../../../api";
import type { Tone } from "../../../ui";

/** The sending side: identity, paired servers and tasks. */
export function useReplication() {
  return useQuery({ queryKey: ["replication"], queryFn: () => unwrap(api.GET("/replication")), refetchInterval: 10_000 });
}

/** Shared folders, apps and VMs that can be replicated. */
export function useReplicationItems(enabled = true) {
  return useQuery({ queryKey: ["replication-items"], queryFn: () => unwrap(api.GET("/replication/items")), enabled });
}

/** The receiving side: pairing code, sources and their replicas. */
export function useReceive() {
  return useQuery({ queryKey: ["replication-receive"], queryFn: () => unwrap(api.GET("/replication/receive")), refetchInterval: 15_000 });
}

/** Data pools (for where replicas or restored copies go). */
export function usePoolNames() {
  return useQuery({
    queryKey: ["pools"],
    queryFn: () => unwrap(api.GET("/storage/pools")),
    select: (pools) => pools.map((p) => p.name),
  });
}

export const KIND_LABEL: Record<ReplicationKind, string> = { share: "Shared folder", app: "App", vm: "VM" };
export const KIND_PLURAL: Record<ReplicationKind, string> = { share: "Shared folders", app: "Apps", vm: "Virtual machines" };

/** "every 15 minutes", "every 6 hours", "every day". */
export function intervalLabel(minutes: number): string {
  if (minutes % 1440 === 0) return minutes === 1440 ? "every day" : `every ${minutes / 1440} days`;
  if (minutes % 60 === 0) return minutes === 60 ? "every hour" : `every ${minutes / 60} hours`;
  return `every ${minutes} minutes`;
}

/** Splits minutes into the largest whole unit for editing. */
export function splitInterval(minutes: number): { value: number; unit: "minutes" | "hours" | "days" } {
  if (minutes % 1440 === 0) return { value: minutes / 1440, unit: "days" };
  if (minutes % 60 === 0) return { value: minutes / 60, unit: "hours" };
  return { value: minutes, unit: "minutes" };
}

export const UNIT_MINUTES = { minutes: 1, hours: 60, days: 1440 } as const;

/** The time in a replication snapshot's name (hardyos-repl-<task>-YYYYMMDDTHHMMSSZ), as ISO. */
export function snapshotTime(name: string): string | null {
  const m = /-(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(name);
  if (!m) return null;
  return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`;
}

/** How a task is doing, in a word and a tone. */
export function taskStatus(t: ReplicationTask): { tone: Tone; text: string } {
  if (t.runningJob) return { tone: "accent", text: "running" };
  if (!t.enabled) return { tone: "neutral", text: "paused" };
  if (t.stale) return { tone: "bad", text: "behind" };
  if (t.lastError) return { tone: "warn", text: "last run failed" };
  if (!t.lastSuccessAt) return { tone: "neutral", text: "not run yet" };
  return { tone: "good", text: "up to date" };
}

/** A suggested id for a restored shared folder: "media-restored", "media-restored-2"… */
export function restoredID(id: string, taken: string[]): string {
  const base = `${id}-restored`.slice(0, 32).replace(/-+$/, "");
  if (!taken.includes(base)) return base;
  for (let i = 2; i < 100; i++) {
    const c = `${base.slice(0, 29)}-${i}`;
    if (!taken.includes(c)) return c;
  }
  return base;
}
