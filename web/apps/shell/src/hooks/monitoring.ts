import { useQuery } from "@tanstack/react-query";
import { api, unwrap } from "../api";

export type HistoryRange = "1h" | "6h" | "24h" | "7d" | "30d" | "90d" | "1y" | "2y";
export const RANGES: HistoryRange[] = ["1h", "6h", "24h", "7d", "30d", "90d", "1y", "2y"];

export const useUnread = () =>
  useQuery({ queryKey: ["notifications", "unread"], queryFn: () => unwrap(api.GET("/notifications/unread")), refetchInterval: 60_000 });

/** Resource history for some series (a trailing * matches a prefix). */
export const useHistory = (series: string[], range: HistoryRange, points = 300, enabled = true) =>
  useQuery({
    queryKey: ["history", series.join(","), range, points],
    queryFn: () => unwrap(api.GET("/monitor/history", { params: { query: { series: series.join(","), range, points } } })),
    refetchInterval: range === "1h" ? 10_000 : range === "6h" || range === "24h" ? 60_000 : 300_000,
    placeholderData: (prev) => prev, // keep the frame while a new range loads
    enabled: enabled && series.length > 0,
  });

export const useConditions = (enabled = true) =>
  useQuery({ queryKey: ["conditions"], queryFn: () => unwrap(api.GET("/monitor/conditions")), refetchInterval: 30_000, enabled });

export const useMonitorSettings = () => useQuery({ queryKey: ["monitor-settings"], queryFn: () => unwrap(api.GET("/monitor/settings")) });

export const useDiskInfo = () => useQuery({ queryKey: ["disk-info"], queryFn: () => unwrap(api.GET("/monitor/disks")), refetchInterval: 60_000 });

export const useChannels = () => useQuery({ queryKey: ["alert-channels"], queryFn: () => unwrap(api.GET("/alerts/channels")) });
export const useRoutes = () => useQuery({ queryKey: ["alert-routes"], queryFn: () => unwrap(api.GET("/alerts/routes")) });
export const useCategories = () => useQuery({ queryKey: ["alert-categories"], queryFn: () => unwrap(api.GET("/alerts/categories")), staleTime: Infinity });
export const useAlertSettings = () => useQuery({ queryKey: ["alert-settings"], queryFn: () => unwrap(api.GET("/alerts/settings")) });
export const useDeliveries = () =>
  useQuery({ queryKey: ["alert-deliveries"], queryFn: () => unwrap(api.GET("/alerts/deliveries", { params: { query: { limit: 50 } } })), refetchInterval: 30_000 });

export const useUPS = () => useQuery({ queryKey: ["ups"], queryFn: () => unwrap(api.GET("/ups")), refetchInterval: 10_000 });
