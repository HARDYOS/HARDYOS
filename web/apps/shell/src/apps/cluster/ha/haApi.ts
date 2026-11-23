// Cluster HA and moves (Phase 8 part C): hooks and calls over the
// generated client.
import type { Job, components } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { ApiFailure, api, unwrap } from "../../../api";
import type { Tone } from "../../../ui";

type S = components["schemas"];
export type HAStatus = S["ClusterHAStatus"];
export type Placement = S["ClusterPlacement"];
export type HAPolicy = S["ClusterHAPolicy"];
export type NodeHA = S["ClusterNodeHA"];
export type MoveCandidates = S["ClusterMoveCandidates"];
export type MoveRecord = S["ClusterMoveRecord"];
export type Timings = S["ClusterTimings"];
export type WorkloadKind = "vm" | "app";

export const haKeys = {
  status: ["cluster", "ha"] as const,
  candidates: (kind: WorkloadKind, id: string) => ["cluster", "candidates", kind, id] as const,
  moves: ["cluster", "moves"] as const,
};

export const useHAStatus = (poll = 3_000) =>
  useQuery<HAStatus>({ queryKey: haKeys.status, queryFn: () => unwrap(api.GET("/cluster/ha")), refetchInterval: poll });

/** The workload's placement when this server is in a cluster and it is a cluster workload. */
export function useClusterPlacement(kind: WorkloadKind, id: string): Placement | undefined {
  const q = useHAStatus(10_000);
  if (!q.data?.member) return undefined;
  return q.data.placements.find((p) => p.workload.kind === kind && p.workload.id === id);
}

export const useMoveCandidates = (kind: WorkloadKind, id: string) =>
  useQuery<MoveCandidates>({
    queryKey: haKeys.candidates(kind, id),
    queryFn: () => unwrap(api.GET("/cluster/moves/candidates", { params: { query: { kind, id } } })),
  });

export const useMoves = () =>
  useQuery<MoveRecord[]>({ queryKey: haKeys.moves, queryFn: () => unwrap(api.GET("/cluster/moves")), refetchInterval: 10_000 });

export async function moveWorkload(req: {
  kind: WorkloadKind;
  id: string;
  to?: string;
  mode: "offline" | "live";
  generation: number;
  confirm?: string;
}): Promise<Job> {
  const r = await unwrap(api.POST("/cluster/moves", { body: req }));
  return r.job;
}

export async function setPolicy(kind: WorkloadKind, id: string, policy: HAPolicy): Promise<Job> {
  const r = await unwrap(api.PUT("/cluster/workloads/{kind}/{id}/ha", { params: { path: { kind, id } }, body: { policy } }));
  return r.job;
}

export async function requestWorkload(kind: WorkloadKind, id: string, requested: "running" | "stopped", generation: number): Promise<Job> {
  const r = await unwrap(api.POST("/cluster/workloads/{kind}/{id}/request", { params: { path: { kind, id } }, body: { requested, generation } }));
  return r.job;
}

export async function setWatchdogOverride(node: string, allow: boolean, confirm: string): Promise<Job> {
  const r = await unwrap(api.PUT("/cluster/ha/watchdog/{node}", { params: { path: { node } }, body: { allow, confirm } }));
  return r.job;
}

export async function setTimings(t: Timings): Promise<Job> {
  const r = await unwrap(api.PUT("/cluster/ha/timings", { body: t }));
  return r.job;
}

export async function drainNode(node: string, stopOthers: boolean, confirm?: string): Promise<Job> {
  const r = await unwrap(api.POST("/cluster/moves/drain", { body: { node, stopOthers, confirm } }));
  return r.job;
}

export const PLACEMENT_STATE: Record<Placement["state"], { label: string; tone: Tone }> = {
  stopped: { label: "Stopped", tone: "neutral" },
  starting: { label: "Starting", tone: "info" },
  running: { label: "Running", tone: "good" },
  stopping: { label: "Stopping", tone: "warn" },
  migrating: { label: "Moving live", tone: "info" },
  moving: { label: "Moving", tone: "info" },
  recovering: { label: "Recovering", tone: "warn" },
  pending: { label: "Waiting for a server", tone: "warn" },
  error: { label: "Failed", tone: "bad" },
};

/** Nanoseconds (the status's timings) to milliseconds for the form. */
export function timingsFromStatus(t: Record<string, number>): Timings {
  const ms = (k: string) => Math.round((t[k] ?? 0) / 1e6);
  return {
    heartbeatMs: ms("heartbeat"),
    suspectMs: ms("suspect"),
    quorumLeaseMs: ms("quorumLease"),
    selfStopMs: ms("selfStop"),
    watchdogMs: ms("watchdog"),
    deadMs: ms("dead"),
    storageIsolatedMs: ms("storageIsolated"),
    lanIsolatedMs: ms("lanIsolated"),
    fenceAckMs: ms("fenceAck"),
  };
}

/**
 * The same checks hardyd makes (decision 353), for the form; hardyd refuses
 * anything unsafe regardless.
 */
export function timingProblems(t: Timings): string[] {
  const p: string[] = [];
  if (t.heartbeatMs < 500 || t.heartbeatMs > 5000) p.push("The heartbeat is 0.5-5 s.");
  if (t.quorumLeaseMs < 5000 || t.quorumLeaseMs > 120000) p.push("The quorum lease is 5-120 s.");
  if (t.quorumLeaseMs < 5 * t.heartbeatMs) p.push("The quorum lease is at least 5 heartbeats.");
  if (t.watchdogMs < 5000 || t.watchdogMs > 60000) p.push("The watchdog timeout is 5-60 s.");
  if (t.selfStopMs < 2000 || t.selfStopMs >= t.watchdogMs) p.push("The self-stop time is at least 2 s and shorter than the watchdog timeout.");
  if (t.deadMs < t.quorumLeaseMs + t.watchdogMs + 10000)
    p.push(`A server can be declared dead no sooner than ${(t.quorumLeaseMs + t.watchdogMs + 10000) / 1000} s (quorum lease + watchdog + 10 s).`);
  if (t.deadMs > 600000) p.push("A server is declared dead within 10 minutes.");
  if (t.suspectMs < 2 * t.heartbeatMs || t.suspectMs >= t.deadMs) p.push("Suspect comes after two heartbeats and before dead.");
  if (t.storageIsolatedMs < 5000) p.push("Storage isolation takes at least 5 s.");
  if (t.lanIsolatedMs < 30000) p.push("LAN isolation takes at least 30 s.");
  if (t.fenceAckMs < 10000 || t.fenceAckMs > 300000) p.push("The fence acknowledgement wait is 10 s to 5 minutes.");
  return p;
}

export const notMember = (err: unknown) => err instanceof ApiFailure && err.code === "not_member";
