import type { ClusterNetcheck, ClusterNetcheckPath } from "@hardy/api-client";
import { describe, expect, it } from "vitest";
import { whereLabel } from "../store/OtherServers";
import { netcheckRows, pathSummary } from "./NetCheck";

const path = (peer: string, p: "lan" | "storage", ok: boolean, extra: Partial<ClusterNetcheckPath> = {}): ClusterNetcheckPath => ({
  peer,
  path: p,
  ok,
  answered: true,
  rtt: 400_000,
  sameSubnet: true,
  mtu: p === "storage" ? 9000 : 1500,
  peerMtu: p === "storage" ? 9000 : 1500,
  bulk: true,
  ...extra,
});

describe("the local-network check", () => {
  const r: ClusterNetcheck = {
    ok: false,
    reason: "c2 → nas on the storage network: not reachable",
    perMember: [
      { node: "c1", name: "c1", role: "compute", ok: true, paths: [path("nas", "lan", true), path("nas", "storage", true)] },
      {
        node: "c2",
        name: "c2",
        role: "compute",
        ok: false,
        reason: "c2 → nas on the storage network: not reachable",
        paths: [path("nas", "lan", true), path("nas", "storage", false, { answered: false, reason: "c2 → nas on the storage network: not reachable" })],
      },
      { node: "nas", name: "NAS", role: "storage", ok: true, paths: [] },
      { node: "c3", name: "c3", role: "compute", ok: true, skipped: true, paths: [] },
    ],
  };

  it("puts each server's LAN and storage probes of a peer on one row, with names", () => {
    const rows = netcheckRows(r);
    expect(rows).toHaveLength(2);
    expect(rows[1]).toMatchObject({ from: "c2", to: "NAS" });
    expect(rows[1]?.lan?.ok).toBe(true);
    expect(rows[1]?.storage?.ok).toBe(false);
  });

  it("says what each path measured", () => {
    expect(pathSummary(path("nas", "storage", true))).toEqual({ tone: "good", text: "0.4 ms · same subnet · MTU 9000" });
    expect(pathSummary(path("nas", "storage", false, { peerMtu: 1500 })).text).toContain("MTU 9000/1500");
    expect(pathSummary(path("nas", "lan", true, { sameSubnet: false })).text).toBe("0.4 ms · routed");
    expect(pathSummary(path("nas", "lan", false, { answered: false }))).toEqual({ tone: "bad", text: "no answer" });
    expect(pathSummary(undefined).text).toBe("–");
  });

  it("labels apps on other servers", () => {
    expect(whereLabel({ node: "c1", nodeName: "c1", cluster: false })).toBe("on c1");
    expect(whereLabel({ node: "c1", nodeName: "", cluster: true })).toBe("cluster app, now on c1");
  });
});
