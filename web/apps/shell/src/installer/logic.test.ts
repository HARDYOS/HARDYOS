import type { Disk } from "@hardy/api-client";
import { describe, expect, it } from "vitest";
import { RESTORE_STEP, formatCode, hostnameError, ineligibleReason, networkErrors, stepIndex, suggestBootDisks, usernameError } from "./logic";

const GB = 1e9;
function disk(name: string, p: Partial<Disk> = {}): Disk {
  return {
    name, path: `/dev/${name}`, byId: `/dev/disk/by-id/x-${name}`, model: "M", serial: "S", wwn: "", transport: "sata",
    kind: "ssd", sizeBytes: 500 * GB, physSector: 4096, removable: false, usage: "free", pool: "", usageDetail: "blank",
    partitions: [], powerLossProt: null, ...p,
  };
}

describe("ineligibleReason", () => {
  it("rejects the live USB, the running system and tiny disks", () => {
    expect(ineligibleReason(disk("sdz", { usage: "mounted", usageDetail: "sdz1 is mounted at /run/live/medium" }))).toMatch(/In use/);
    expect(ineligibleReason(disk("sda", { usage: "boot" }))).toMatch(/running system/);
    expect(ineligibleReason(disk("sda", { sizeBytes: 8 * GB }))).toMatch(/Too small/);
  });
  it("allows a previous install's boot pool and disks with data", () => {
    expect(ineligibleReason(disk("sda", { usage: "boot", pool: "rpool" }))).toBeNull();
    expect(ineligibleReason(disk("sda", { usage: "has-data" }))).toBeNull();
  });
});

describe("suggestBootDisks", () => {
  it("picks a matched pair of small NVMe drives and leaves the HDDs for data", () => {
    const disks = [
      disk("sda", { kind: "hdd", sizeBytes: 12e12 }),
      disk("sdb", { kind: "hdd", sizeBytes: 12e12 }),
      disk("nvme0n1", { kind: "nvme", sizeBytes: 256 * GB }),
      disk("nvme1n1", { kind: "nvme", sizeBytes: 256 * GB }),
      disk("nvme2n1", { kind: "nvme", sizeBytes: 2e12 }),
    ];
    expect(suggestBootDisks(disks)).toEqual(["/dev/disk/by-id/x-nvme0n1", "/dev/disk/by-id/x-nvme1n1"]);
  });
  it("skips disks that belong to a data pool", () => {
    const disks = [disk("sda", { usage: "pool", pool: "tank", sizeBytes: 120 * GB }), disk("sdb", { sizeBytes: 240 * GB })];
    expect(suggestBootDisks(disks)).toEqual(["/dev/disk/by-id/x-sdb"]);
  });
  it("falls back to the smallest eligible disk of any kind", () => {
    const disks = [disk("sda", { kind: "hdd", sizeBytes: 4e12 }), disk("sdb", { kind: "hdd", sizeBytes: 1e12 }), disk("sdc", { usage: "mounted" })];
    expect(suggestBootDisks(disks)).toEqual(["/dev/disk/by-id/x-sdb"]);
  });
  it("suggests nothing when no disk fits", () => {
    expect(suggestBootDisks([disk("sdc", { usage: "mounted" })])).toEqual([]);
  });
});

describe("validation", () => {
  it("checks hostnames and usernames like the server", () => {
    expect(hostnameError("nas-01")).toBeNull();
    expect(hostnameError("-nas")).not.toBeNull();
    expect(hostnameError("NAS")).not.toBeNull();
    expect(usernameError("cade")).toBeNull();
    expect(usernameError("root")).toMatch(/reserved/);
    expect(usernameError("1abc")).not.toBeNull();
  });
  it("checks static network settings", () => {
    expect(networkErrors({ mode: "dhcp" })).toEqual({});
    expect(networkErrors({ mode: "static", interface: "eno1", address: "192.168.1.20/24", gateway: "192.168.1.1", dns: ["1.1.1.1"] })).toEqual({});
    const bad = networkErrors({ mode: "static", interface: "", address: "192.168.1.20", gateway: "", dns: ["dns.google"] });
    expect(Object.keys(bad).sort()).toEqual(["address", "dns", "interface"]);
    expect(networkErrors({ mode: "static", interface: "eno1", address: "192.168.1.20/24", gateway: "10.0.0.1" }).gateway).toMatch(/inside/);
    expect(networkErrors({ mode: "static", interface: "eno1", address: "fd00::20/64", gateway: "fd00::1" })).toEqual({});
  });
});

describe("helpers", () => {
  it("formats typed codes", () => {
    expect(formatCode("k7qm4txp")).toBe("K7QM-4TXP");
    expect(formatCode("k7q")).toBe("K7Q");
    expect(formatCode("K7QM-4TXP-EXTRA")).toBe("K7QM-4TXP");
  });
  it("maps job messages to steps", () => {
    expect(stepIndex("Creating the boot pool")).toBe(2);
    expect(stepIndex("something else")).toBe(-1);
    // Restoring from a cloud backup adds a step before the boot loader.
    expect(stepIndex(RESTORE_STEP)).toBe(-1);
    expect(stepIndex(RESTORE_STEP, true)).toBe(5);
    expect(stepIndex("Installing the boot loader", true)).toBe(6);
  });
});
