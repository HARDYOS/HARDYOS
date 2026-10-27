import { useQuery } from "@tanstack/react-query";
import { api, unwrap } from "../api";

/** Every imported pool, including the boot pool. */
export const usePools = (enabled = true) =>
  useQuery({ queryKey: ["pools"], queryFn: () => unwrap(api.GET("/storage/pools")), enabled, refetchInterval: 30_000 });

/** Pools the installer creates for the system itself; they hold no user data. */
export const isBootPool = (name: string) => name === "rpool" || name === "bpool" || name === "hardyos-boot";

/** Data pools only: what people think of as "storage". */
export const useDataPools = (enabled = true) =>
  useQuery({
    queryKey: ["pools"],
    queryFn: () => unwrap(api.GET("/storage/pools")),
    enabled,
    refetchInterval: 30_000,
    select: (pools) => pools.filter((p) => !isBootPool(p.name)),
  });

export const usePoolStatus = (pool: string, running = false) =>
  useQuery({
    queryKey: ["pool", pool],
    queryFn: () => unwrap(api.GET("/storage/pools/{pool}", { params: { path: { pool } } })),
    refetchInterval: running ? 5_000 : 30_000,
  });

export const useHardware = (enabled = true) =>
  useQuery({ queryKey: ["hardware"], queryFn: () => unwrap(api.GET("/hardware")), enabled, staleTime: 30_000 });

export const useDiskHealth = () =>
  useQuery({ queryKey: ["disk-health"], queryFn: () => unwrap(api.GET("/hardware/disk-health")), staleTime: 60_000 });

export const useSystemInfo = () =>
  useQuery({ queryKey: ["system-info"], queryFn: () => unwrap(api.GET("/system/info")), refetchInterval: 60_000 });

export const useMetrics = (intervalMs = 2_000) =>
  useQuery({ queryKey: ["metrics"], queryFn: () => unwrap(api.GET("/system/metrics")), refetchInterval: intervalMs, staleTime: 0 });

export const useNotifications = () =>
  useQuery({ queryKey: ["notifications"], queryFn: () => unwrap(api.GET("/notifications", { params: { query: { limit: 50 } } })) });

export const useJobs = (limit = 50) =>
  useQuery({ queryKey: ["jobs", limit], queryFn: () => unwrap(api.GET("/jobs", { params: { query: { limit } } })), refetchInterval: 10_000 });

export const useJob = (id: string | null) =>
  useQuery({
    queryKey: ["job", id],
    // A request that hangs (a dropped connection) would stop the polling for
    // good, since a new one only starts when the last one ends: give up after
    // 15 s and let the next poll try again.
    queryFn: ({ signal }) => {
      const ctl = new AbortController();
      const stop = () => ctl.abort();
      signal.addEventListener("abort", stop);
      const timer = setTimeout(stop, 15_000);
      return unwrap(api.GET("/jobs/{id}", { params: { path: { id: id! } }, signal: ctl.signal })).finally(() => {
        clearTimeout(timer);
        signal.removeEventListener("abort", stop);
      });
    },
    enabled: !!id,
    retry: true,
    refetchInterval: (q) => {
      const s = q.state.data?.state;
      return s === "queued" || s === "running" || (!s && q.state.status === "error") ? 2_000 : false;
    },
    // Keep following a job while the window is in the background (installs
    // take minutes; people switch away), so it isn't stuck when they return.
    refetchIntervalInBackground: true,
  });

export const useDatasets = (root?: string) =>
  useQuery({
    queryKey: ["datasets", root ?? ""],
    queryFn: () => unwrap(api.GET("/storage/datasets", { params: { query: root ? { root } : {} } })),
  });

export const useSnapshots = (root?: string) =>
  useQuery({
    queryKey: ["snapshots", root ?? ""],
    queryFn: () => unwrap(api.GET("/storage/snapshots", { params: { query: root ? { root } : {} } })),
  });
