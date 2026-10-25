import { eventsUrl, type Job, type Notification } from "@hardy/api-client";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { toast } from "../ui/toasts";

export type Connection = "connecting" | "open" | "closed";

/**
 * Subscribes to hardyd's event stream: keeps job and storage queries fresh
 * and turns notifications into toasts. Reconnects with backoff.
 */
export function useEvents(enabled: boolean): Connection {
  const qc = useQueryClient();
  const [state, setState] = useState<Connection>("connecting");
  const retry = useRef(0);

  useEffect(() => {
    if (!enabled || typeof WebSocket === "undefined") return;
    let ws: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;

    const connect = () => {
      setState("connecting");
      ws = new WebSocket(eventsUrl());
      ws.onopen = () => {
        retry.current = 0;
        setState("open");
      };
      ws.onmessage = (msg) => {
        let e: { type?: string; data?: unknown };
        try {
          e = JSON.parse(String(msg.data));
        } catch {
          return;
        }
        if (e.type === "job.updated") {
          const job = e.data as Job;
          qc.setQueryData(["job", job.id], job);
          void qc.invalidateQueries({ queryKey: ["jobs"] });
          if (job.state === "succeeded" || job.state === "failed") {
            if (job.kind.startsWith("storage.")) {
              for (const key of ["pools", "pool", "datasets", "snapshots", "hardware", "snapshot-policies", "scrub-policies"]) {
                void qc.invalidateQueries({ queryKey: [key] });
              }
            }
            if (job.state === "failed") toast("error", `${job.title} failed`, job.error);
          }
        } else if (e.type === "notification") {
          const n = e.data as Notification;
          toast(n.level, n.title, n.body || undefined);
          void qc.invalidateQueries({ queryKey: ["notifications"] });
        } else if (e.type === "audit.created") {
          void qc.invalidateQueries({ queryKey: ["audit"] });
        }
      };
      ws.onclose = () => {
        setState("closed");
        if (stopped) return;
        const delay = Math.min(30_000, 1_000 * 2 ** retry.current++);
        timer = setTimeout(connect, delay);
      };
    };
    connect();
    return () => {
      stopped = true;
      clearTimeout(timer);
      ws?.close();
    };
  }, [enabled, qc]);

  return state;
}
