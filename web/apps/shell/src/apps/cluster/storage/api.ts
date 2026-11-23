import type { components } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { api, unwrap } from "../../../api";

type S = components["schemas"];
export type ClusterStorageOverview = S["ClusterStorageOverview"];
export type ClusterStorageWorkload = S["ClusterStorageWorkload"];
export type ClusterStorageNodeStatus = S["ClusterStorageNodeStatus"];
export type ClusterStorageSANStatus = S["ClusterStorageSANStatus"];
export type ClusterStorageNetwork = S["ClusterStorageNetwork"];
export type ClusterStorageCandidate = S["ClusterStorageCandidate"];
export type ClusterStoragePlan = S["ClusterStoragePlan"];
export type ClusterStorageSnapshot = S["ClusterStorageSnapshot"];
export type ClusterAppModeRequest = S["ClusterAppModeRequest"];

export const storageKeys = {
  overview: ["cluster", "storage"] as const,
  nodes: ["cluster", "storage", "nodes"] as const,
  exports: ["cluster", "storage", "exports"] as const,
  network: ["cluster", "storage", "network"] as const,
};

export function useClusterStorage() {
  return useQuery({ queryKey: storageKeys.overview, queryFn: () => unwrap(api.GET("/cluster/storage")), refetchInterval: 10_000 });
}

export function useClusterStorageNodes(enabled = true) {
  return useQuery({
    queryKey: storageKeys.nodes,
    queryFn: () => unwrap(api.GET("/cluster/storage/nodes")),
    refetchInterval: 15_000,
    enabled,
  });
}

export function useClusterStorageExports(enabled = true) {
  return useQuery({
    queryKey: storageKeys.exports,
    queryFn: () => unwrap(api.GET("/cluster/storage/exports")),
    refetchInterval: 15_000,
    enabled,
  });
}

export function useStorageNetwork() {
  return useQuery({ queryKey: storageKeys.network, queryFn: () => unwrap(api.GET("/cluster/storage/network")) });
}

/** Mbit/s as people say it: "10 Gb/s", "1 Gb/s", "100 Mb/s". */
export function speed(mbps: number): string {
  if (!mbps) return "no link";
  return mbps >= 1000 ? `${mbps / 1000} Gb/s` : `${mbps} Mb/s`;
}

export const kindLabel: Record<ClusterStorageCandidate["kind"], string> = {
  dedicated: "Its own port",
  vlan: "A VLAN on the LAN port",
  lan: "The LAN itself",
};
