import { describe, expect, it } from "vitest";
import { timingProblems, timingsFromStatus } from "./haApi";

const defaults = timingsFromStatus({
  heartbeat: 1e9,
  suspect: 10e9,
  quorumLease: 15e9,
  selfStop: 5e9,
  watchdog: 10e9,
  dead: 40e9,
  storageIsolated: 15e9,
  lanIsolated: 60e9,
  fenceAck: 30e9,
});

describe("failover timings", () => {
  it("accepts the defaults", () => {
    expect(defaults.deadMs).toBe(40000);
    expect(timingProblems(defaults)).toEqual([]);
  });
  it("refuses F < Q + W + 10 s", () => {
    expect(timingProblems({ ...defaults, deadMs: 30000 }).join(" ")).toMatch(/no sooner than 35 s/);
  });
  it("refuses S >= W", () => {
    expect(timingProblems({ ...defaults, selfStopMs: 10000 }).length).toBeGreaterThan(0);
  });
});
