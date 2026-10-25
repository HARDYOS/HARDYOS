import { describe, expect, it } from "vitest";
import { buildSpec, defaultLayout } from "./CreatePool";

const d = (n: string) => `/dev/disk/by-id/${n}`;

describe("buildSpec", () => {
  it("builds a RAIDZ2 pool with special, log, cache and spare", () => {
    const roles = {
      [d("a")]: "data", [d("b")]: "data", [d("c")]: "data", [d("e")]: "data", [d("f")]: "data", [d("g")]: "data",
      [d("n1")]: "special", [d("n2")]: "special",
      [d("s1")]: "log",
      [d("l2")]: "cache",
      [d("sp")]: "spare",
      [d("x")]: "none",
    } as const;
    const { spec, problems } = buildSpec("tank", { ...roles }, "raidz2", true);
    expect(problems).toEqual([]);
    expect(spec.data).toEqual([{ type: "raidz2", disks: [d("a"), d("b"), d("c"), d("e"), d("f"), d("g")] }]);
    expect(spec.special).toEqual({ type: "mirror", disks: [d("n1"), d("n2")] });
    expect(spec.log).toEqual({ type: "stripe", disks: [d("s1")] });
    expect(spec.cache).toEqual([d("l2")]);
    expect(spec.spares).toEqual([d("sp")]);
    expect(spec.encrypt).toBe(true);
  });

  it("reports problems the server would reject", () => {
    expect(buildSpec("tank", {}, "mirror", false).problems[0]).toMatch(/at least one data disk/);
    expect(buildSpec("tank", { [d("a")]: "data", [d("b")]: "data" }, "raidz2", false).problems[0]).toMatch(/at least 4/);
    expect(buildSpec("tank", { [d("a")]: "data", [d("b")]: "data", [d("n")]: "special" }, "mirror", false).problems[0]).toMatch(/mirrored/);
  });

  it("makes one vdev per disk for a stripe", () => {
    const { spec } = buildSpec("scratch", { [d("a")]: "data", [d("b")]: "data" }, "stripe", false);
    expect(spec.data).toHaveLength(2);
  });

  it("picks the default layout from the disk count", () => {
    expect([1, 2, 3, 4, 5, 6, 11, 14].map(defaultLayout)).toEqual(["stripe", "mirror", "mirror", "raidz1", "raidz1", "raidz2", "raidz2", "raidz2"]);
  });
});
