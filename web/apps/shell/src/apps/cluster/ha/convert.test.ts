import { describe, expect, it } from "vitest";
import { api } from "../../../api";
import { nodeApi } from "../../../cluster/scope";
import { type Conversion, canAbandon, canUndo, isLastCopy, keptDeleteApi, keptID, keptKind } from "./haApi";

const conv = (over: Partial<Conversion>): Conversion => ({
  id: "abc",
  direction: "ha",
  kind: "vm",
  workload: "web",
  name: "Web",
  storagePool: "nas",
  localPool: "tank",
  phase: "copy",
  state: "failed",
  jobId: "j",
  wasRunning: true,
  options: {},
  bytesDone: 0,
  bytesTotal: 0,
  actor: "alice",
  started: "2026-11-27T10:00:00Z",
  updated: "2026-11-27T10:05:00Z",
  ...over,
});

describe("conversions", () => {
  it("abandons only what only copied so far", () => {
    expect(canAbandon(conv({ phase: "final" }))).toBe(true);
    expect(canAbandon(conv({ phase: "park" }))).toBe(false);
    expect(canAbandon(conv({ phase: "copy", state: "running" }))).toBe(false);
    expect(canAbandon(conv({ direction: "local", phase: "copy" }))).toBe(true);
    expect(canAbandon(conv({ direction: "local", phase: "remove" }))).toBe(false);
  });
  it("undoes a failed conversion to cluster storage once the local copy was put aside", () => {
    expect(canUndo(conv({ phase: "start" }))).toBe(true);
    expect(canUndo(conv({ phase: "copy" }))).toBe(false);
    expect(canUndo(conv({ phase: "start", state: "done" }))).toBe(false);
    expect(canUndo(conv({ direction: "local", phase: "adopt" }))).toBe(false);
  });
  it("asks a second confirmation only for a kept copy without an expiry", () => {
    expect(isLastCopy({ keepUntil: undefined })).toBe(true);
    expect(isLastCopy({ keepUntil: "2026-11-28T10:00:00Z" })).toBe(false);
  });
  it("reads a kept copy's workload from its name", () => {
    expect(keptID("vm-web-1764240000")).toBe("web");
    expect(keptID("app-home-assistant-1764240000")).toBe("home-assistant");
    expect(keptID("share-media-1764240000")).toBe("media");
    expect(keptKind({ kind: "share" })).toBe("shared folder");
  });
  it("deletes another member's kept copy through that member's own API", () => {
    expect(keptDeleteApi({ deleteOn: undefined })).toBe(api);
    expect(keptDeleteApi({ deleteOn: "c2" })).toBe(nodeApi("c2"));
    expect(keptDeleteApi({ deleteOn: "c2" })).not.toBe(api);
  });
});
