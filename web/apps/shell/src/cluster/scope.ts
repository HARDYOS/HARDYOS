import { type ApiClient, createApiClient } from "@hardy/api-client";
import type { components } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { create } from "zustand";
import { api, unwrap } from "../api";

export type ClusterNodes = components["schemas"]["ClusterNodes"];
export type ClusterNode = components["schemas"]["ClusterNode"];
export type ClusterStatus = components["schemas"]["ClusterStatus"];
export type ClusterNodeStatus = components["schemas"]["ClusterNodeStatus"];

/**
 * The cluster desktop's node scope. The person signs in on one server (the
 * entry node); /api/v1/nodes/{node}/... reaches any other member through
 * it. The server switcher picks the node new windows open for; "" is this
 * server.
 */
interface ScopeState {
  node: string;
  setNode(node: string): void;
}

export const useClusterScope = create<ScopeState>((set) => ({
  node: "",
  setNode: (node) => set({ node }),
}));

const clients = new Map<string, ApiClient>();

/** An API client for a member ("" or undefined: this server, the shared client). */
export function nodeApi(node?: string): ApiClient {
  if (!node) return api;
  let c = clients.get(node);
  if (!c) {
    c = createApiClient(new URL(`/api/v1/nodes/${encodeURIComponent(node)}`, window.location.origin).toString());
    clients.set(node, c);
  }
  return c;
}

/** The node-scoped client for an app window: its args.node, else this server. */
export function useNodeApi(args?: Record<string, string>): ApiClient {
  return nodeApi(args?.node);
}

/** The cluster's servers for the switcher (refreshed every 10 s). */
export function useClusterNodes(enabled = true) {
  return useQuery({
    queryKey: ["cluster", "nodes"],
    queryFn: () => unwrap(api.GET("/cluster/nodes")),
    refetchInterval: 10_000,
    enabled,
  });
}

/** This server's full view of the cluster (administrators). */
export function useClusterStatus(enabled = true) {
  return useQuery({
    queryKey: ["cluster", "status"],
    queryFn: () => unwrap(api.GET("/cluster")),
    refetchInterval: 5_000,
    enabled,
  });
}

/** Window title for a window opened on another member. */
export function scopedTitle(title: string, node: string | undefined, self: string | undefined): string {
  if (!node || node === self) return title;
  return `${title} — ${node}`;
}

/** Nanoseconds (Go durations) as a short round-trip time. */
export function rtt(ns: number | undefined): string {
  if (!ns) return "–";
  const ms = ns / 1e6;
  return ms < 10 ? `${ms.toFixed(1)} ms` : `${Math.round(ms)} ms`;
}
