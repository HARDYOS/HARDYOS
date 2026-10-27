import { describe, expect, it } from "vitest";
import { linkTarget } from "./links";

describe("notification links", () => {
  it("opens the Backup app on its tabs", () => {
    expect(linkTarget("backup/tasks/t1")).toEqual({ app: "os.hardy.backup", args: { tab: "tasks", id: "t1" } });
    expect(linkTarget("backup/replication")).toEqual({ app: "os.hardy.backup", args: { tab: "replication" } });
    expect(linkTarget("control/replication")).toEqual({ app: "os.hardy.control", args: { section: "replication" } });
  });
});
