import type { Health, VersionInfo } from "@hardy/api-client";
import { useEffect, useState } from "react";
import { api } from "../api";

export type SystemInfo =
  | { state: "loading" }
  | { state: "error"; message: string }
  | { state: "ok"; health: Health; version: VersionInfo };

/** Polls hardyd's health and version endpoints. */
export function useSystemInfo(intervalMs = 10_000): SystemInfo {
  const [info, setInfo] = useState<SystemInfo>({ state: "loading" });

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const [h, v] = await Promise.all([api.GET("/health"), api.GET("/version")]);
        if (cancelled) return;
        if (h.data && v.data) setInfo({ state: "ok", health: h.data, version: v.data });
        else setInfo({ state: "error", message: "hardyd returned an error" });
      } catch {
        if (!cancelled) setInfo({ state: "error", message: "Can't reach hardyd" });
      }
    }
    void load();
    const t = setInterval(load, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, [intervalMs]);

  return info;
}

/** Formats seconds as "3 days", "5 hours" or "12 minutes". */
export function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86_400);
  if (d >= 1) return `${d} day${d === 1 ? "" : "s"}`;
  const h = Math.floor(seconds / 3_600);
  if (h >= 1) return `${h} hour${h === 1 ? "" : "s"}`;
  const m = Math.max(1, Math.floor(seconds / 60));
  return `${m} minute${m === 1 ? "" : "s"}`;
}
