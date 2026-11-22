import { describe, expect, it } from "vitest";
import { BUILTIN_TABS } from "./apps/backup/Backup";
import { EXTRA_TABS } from "./apps/backup/tabs";
import { SECTIONS } from "./apps/control-panel/ControlPanel";
import { isLinkShaped, linkTarget } from "./links";
import emitted from "./notification-links.json";
import { appById } from "./shell";

// Each pattern in notification-links.json with its {name} parts filled in.
// The daemon side (daemon/internal/notify/links_test.go) checks that this
// list holds every Link hardyd can emit.
const examples = emitted.links.map((p) => p.replace(/\{[a-z]+\}/g, "x-1"));

describe("notification links", () => {
  it("opens the Backup app on its tabs", () => {
    expect(linkTarget("backup/tasks/t1")).toEqual({ app: "os.hardy.backup", args: { tab: "tasks", id: "t1" } });
    expect(linkTarget("backup/replication")).toEqual({ app: "os.hardy.backup", args: { tab: "replication" } });
    expect(linkTarget("control/replication")).toEqual({ app: "os.hardy.control", args: { section: "replication" } });
    expect(linkTarget("backup/targets/off")).toEqual({ app: "os.hardy.backup", args: { tab: "destinations", id: "off" } });
  });

  it("still opens links stored by older versions", () => {
    expect(linkTarget("control-panel/mail")).toEqual({ app: "os.hardy.control", args: { section: "mail" } });
    expect(isLinkShaped("control-panel/hostnames")).toBe(true);
  });

  it.each(examples)("opens %s somewhere real", (link) => {
    expect(isLinkShaped(link)).toBe(true);
    const t = linkTarget(link);
    expect(t).not.toBeNull();
    expect(appById(t!.app), t!.app).toBeDefined();
    if (t!.app === "os.hardy.control" && t!.args?.section) {
      expect(SECTIONS.map((s) => s.id)).toContain(t!.args.section);
    }
    if (t!.app === "os.hardy.backup" && t!.args?.tab) {
      expect([...BUILTIN_TABS, ...EXTRA_TABS].map((s) => s.id)).toContain(t!.args.tab);
    }
    if (t!.app === "os.hardy.storage" && t!.args?.section) {
      expect(["disks"]).toContain(t!.args.section);
    }
  });

  it("rejects links that aren't shaped like hardyd's", () => {
    expect(isLinkShaped("javascript:alert(1)")).toBe(false);
    expect(isLinkShaped("control/../x/y/z")).toBe(false);
    expect(isLinkShaped("Control/mail")).toBe(false);
    expect(linkTarget("nowhere/at/all")).toBeNull();
  });
});
