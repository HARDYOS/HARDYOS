import type { VMTemplate, VMUserTemplate } from "@hardy/api-client";
import { describe, expect, it } from "vitest";
import { scheduleProblems, scheduleSummary, templateIdFrom } from "./polish";
import { AUDIO_RATE, MAX_AUDIO_CHUNK, audioOffMessage, audioOnMessages, parseAudio, s16leToChannels } from "./qemuAudio";
import { caps, linux, win11 } from "./testFixtures";
import { fromUserTemplate, initialState, stepProblems, toRequest } from "./wizard";

const debian: VMTemplate = { ...linux, id: "debian13", name: "Debian 13", catalog: "debian-13", images: [] };
const win: VMTemplate = { ...win11, unattend: true, editions: ["Windows 11 Pro", "Windows 11 Home"], sound: true, clipboard: true };

describe("one-click templates", () => {
  it("fetches a verified image instead of a link", () => {
    let s = initialState(debian, caps);
    expect(s.source).toBe("catalog");
    s = { ...s, name: "Deb", id: "deb", sshKeys: "ssh-ed25519 AAAA me", hostname: "deb1" };
    expect(stepProblems(s, "media", { template: debian, caps, taken: [], library: [] })).toEqual([]);
    const r = toRequest(s, debian);
    expect(r.catalog).toBe("debian-13");
    expect(r.downloads).toBeUndefined();
    expect(r.spec.disks[0]!.import).toBeUndefined();
    expect(r.spec.media).toEqual([{ kind: "cloudinit" }]);
    expect(r.spec.cloudInit?.hostname).toBe("deb1");
  });

  it("installs Windows by itself with an account, the drivers and the answer disc", () => {
    let s = initialState(win, caps);
    expect(s.unattend).toBe(true);
    expect(s.edition).toBe("Windows 11 Pro");
    s = { ...s, name: "Kids PC", id: "kids-pc", file: "Win11.iso", user: "", password: "" };
    const ctx = { template: win, caps, taken: [], library: [] };
    expect(stepProblems(s, "media", ctx).join(" ")).toMatch(/Windows user name/);
    s = { ...s, user: "Administrator", password: "long enough" };
    expect(stepProblems(s, "media", ctx).join(" ")).toMatch(/not Administrator/);
    s = { ...s, user: "kids", locale: "de-DE", timeZone: "W. Europe Standard Time" };
    expect(stepProblems(s, "media", ctx)).toEqual([]);
    const r = toRequest(s, win);
    expect(r.spec.media).toEqual([{ kind: "iso", iso: "Win11.iso" }, { kind: "virtio" }, { kind: "unattend" }]);
    expect(r.spec.unattend).toEqual({ user: "kids", locale: "de-DE", pending: true, timeZone: "W. Europe Standard Time", edition: "Windows 11 Pro" });
    expect(r.password).toBe("long enough");
    expect(r.spec.sound).toBe(true);
    expect(r.spec.clipboard).toBe(true);
    // Turned off: the old way, no answer disc and no password.
    const manual = toRequest({ ...s, unattend: false, virtio: true }, win);
    expect(manual.spec.media.map((m) => m.kind)).toEqual(["iso", "virtio"]);
    expect(manual.password).toBeUndefined();
    expect(manual.spec.unattend).toBeUndefined();
  });

  it("makes a VM from a saved template by copying its disks", () => {
    const ut: VMUserTemplate = {
      id: "base",
      name: "Base",
      description: "",
      pool: "tank",
      created: "2026-11-21T00:00:00Z",
      from: "web",
      bytes: 1,
      spec: {
        id: "",
        name: "",
        template: "linux",
        os: "linux",
        pool: "tank",
        cpu: { cores: 3, threads: 1 },
        memory: { mb: 3072, balloon: true },
        firmware: { type: "uefi", secureBoot: false, tpm: false },
        disks: [{ name: "disk0", sizeGB: 20, bus: "virtio-scsi" }],
        media: [{ kind: "cloudinit" }],
        nics: [{ mode: "nat", model: "virtio" }],
        video: "virtio",
        guestAgent: true,
        boot: ["disk"],
        autostart: { enabled: false, order: 0, delaySec: 0 },
        devices: [],
        cloudInit: { user: "cade", sshKeys: ["ssh-ed25519 AAAA me"], installAgent: true },
      },
    };
    let s = fromUserTemplate(ut, linux, caps);
    s = { ...s, name: "Copy", id: "copy", disks: [...s.disks, { name: "disk1", sizeGB: 10, bus: "virtio-scsi" }] };
    expect(stepProblems(s, "media", { template: linux, caps, taken: [], library: [] })).toEqual([]);
    const r = toRequest(s, linux);
    expect(r.spec.disks[0]).toEqual({ name: "disk0", sizeGB: 20, bus: "virtio-scsi", clone: { template: "base" } });
    expect(r.spec.disks[1]!.clone).toBeUndefined();
    expect(r.spec.fromTemplate).toBe("base");
    expect(r.spec.cpu).toEqual({ cores: 3, threads: 1 });
    expect(r.spec.media).toEqual([{ kind: "cloudinit" }]);
    expect(r.downloads).toBeUndefined();
    expect(r.catalog).toBeUndefined();
    expect(stepProblems({ ...s, disks: [] }, "disks", { template: linux, caps, taken: [], library: [] }).join(" ")).toMatch(/template's disks/);
  });
});

describe("snapshot schedules", () => {
  it("checks counts and says what it keeps", () => {
    expect(scheduleProblems({ hourly: 24, daily: 7, weekly: 4, monthly: 12 })).toEqual([]);
    expect(scheduleProblems({ hourly: 49, daily: 0, weekly: 0, monthly: 0 })[0]).toMatch(/Hourly/);
    expect(scheduleProblems({ hourly: 0, daily: -1, weekly: 0, monthly: 0 })[0]).toMatch(/Daily/);
    expect(scheduleSummary(null)).toBe("Off");
    expect(scheduleSummary({ hourly: 0, daily: 7, weekly: 4, monthly: 0 })).toBe("Keeps 7 daily, 4 weekly");
  });

  it("makes template short names", () => {
    expect(templateIdFrom("Web server template")).toBe("web-server-template");
    expect(templateIdFrom("2025 base")).toBe("t-2025-base");
  });
});

describe("QEMU audio in the console", () => {
  it("asks for 16-bit stereo, then turns sound on and off", () => {
    const on = audioOnMessages();
    expect(Array.from(on.slice(0, 6))).toEqual([255, 1, 0, 2, 3, 2]);
    expect(new DataView(on.buffer).getUint32(6)).toBe(AUDIO_RATE);
    expect(Array.from(on.slice(10))).toEqual([255, 1, 0, 0]);
    expect(Array.from(audioOffMessage())).toEqual([255, 1, 0, 1]);
  });

  it("reads begin, end and data messages, waiting for whole ones", () => {
    expect(parseAudio(new Uint8Array([255, 1]))).toEqual({ need: true });
    expect(parseAudio(new Uint8Array([255, 1, 0, 1]))).toEqual({ need: false, consumed: 4, event: { kind: "begin" } });
    expect(parseAudio(new Uint8Array([255, 1, 0, 0, 9]))).toEqual({ need: false, consumed: 4, event: { kind: "end" } });
    const msg = new Uint8Array([255, 1, 0, 2, 0, 0, 0, 4, 0x00, 0x40, 0x00, 0xc0, 7]);
    const r = parseAudio(msg);
    expect(r).toMatchObject({ need: false, consumed: 12 });
    expect(parseAudio(msg.slice(0, 10))).toEqual({ need: true });
    if ("event" in r && r.event.kind === "data") {
      const [l, rr] = s16leToChannels(r.event.data);
      expect(l![0]).toBeCloseTo(0.5);
      expect(rr![0]).toBeCloseTo(-0.5);
    } else {
      throw new Error("no data");
    }
  });

  it("refuses what it doesn't know or that is too big", () => {
    expect(parseAudio(new Uint8Array([255, 2, 0, 0]))).toHaveProperty("error");
    expect(parseAudio(new Uint8Array([255, 1, 0, 9]))).toHaveProperty("error");
    const big = new Uint8Array(8);
    big.set([255, 1, 0, 2]);
    new DataView(big.buffer).setUint32(4, MAX_AUDIO_CHUNK + 1);
    expect(parseAudio(big)).toHaveProperty("error");
  });
});
