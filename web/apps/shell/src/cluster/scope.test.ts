import { describe, expect, it } from "vitest";
import { api } from "../api";
import { appById } from "../shell";
import { nodeApi, rtt, scopedTitle, useClusterScope } from "./scope";

describe("cluster scope", () => {
  it("uses the shared client for this server and a node-scoped one for others", () => {
    expect(nodeApi()).toBe(api);
    expect(nodeApi("")).toBe(api);
    const c1 = nodeApi("c1");
    expect(c1).not.toBe(api);
    expect(nodeApi("c1")).toBe(c1);
  });

  it("titles windows opened for another member", () => {
    expect(scopedTitle("Virtual Machines", "c1", "nas")).toBe("Virtual Machines — c1");
    expect(scopedTitle("Virtual Machines", "nas", "nas")).toBe("Virtual Machines");
    expect(scopedTitle("Virtual Machines", undefined, "nas")).toBe("Virtual Machines");
  });

  it("finds an app from a node-scoped window id", () => {
    expect(appById("os.hardy.vms@c1")?.id).toBe("os.hardy.vms");
    expect(appById("os.hardy.cluster")?.name).toBe("Cluster");
  });

  it("formats round-trip times and keeps the picked node", () => {
    expect(rtt(undefined)).toBe("–");
    expect(rtt(1_500_000)).toBe("1.5 ms");
    expect(rtt(42_000_000)).toBe("42 ms");
    useClusterScope.getState().setNode("c2");
    expect(useClusterScope.getState().node).toBe("c2");
    useClusterScope.getState().setNode("");
  });
});
