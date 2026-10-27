import { describe, expect, it } from "vitest";
import { keysymsFor, consoleURL } from "./Console";
import { caps, linux, opnsense, win11 } from "./testFixtures";
import { applyPreset, fileFromURL, idFromName, idProblem, initialState, stepProblems, toRequest } from "./wizard";

describe("the New VM wizard's model", () => {
  it("makes short names from names", () => {
    expect(idFromName("Dad's Windows 11")).toBe("dads-windows-11");
    expect(idFromName("  Café — Server!! ")).toBe("cafe-server");
    expect(idFromName("2025 lab")).toBe("vm-2025-lab");
    expect(idFromName("x")).toBe("");
    expect(idFromName("a".repeat(40)).length).toBe(32);
    expect(idProblem("isos", [])).toMatch(/keeps/);
    expect(idProblem("web", ["web"])).toMatch(/already/);
    expect(idProblem("Web", [])).toMatch(/lowercase/);
    expect(idProblem("web-server", [])).toBeNull();
  });

  it("names downloads like the server does", () => {
    expect(fileFromURL("https://example.com/a/OPNsense-25.7-dvd-amd64.iso.bz2?x=1")).toBe("OPNsense-25.7-dvd-amd64.iso");
    expect(fileFromURL("https://example.com/img%20one.qcow2.gz")).toBe("img one.qcow2");
    expect(fileFromURL("not a url")).toBe("");
  });

  it("builds a Windows 11 VM: installer first, drivers disc, Secure Boot and TPM", () => {
    let s = initialState(win11, caps);
    s = { ...s, name: "Kids PC", id: "kids-pc", file: "Win11_24H2_English_x64.iso" };
    const r = toRequest(s, win11);
    expect(r.spec.firmware).toEqual({ type: "uefi", secureBoot: true, tpm: true });
    expect(r.spec.media).toEqual([{ kind: "iso", iso: "Win11_24H2_English_x64.iso" }, { kind: "virtio" }]);
    expect(r.spec.boot).toEqual(["cdrom", "disk"]);
    expect(r.spec.disks).toEqual([{ name: "disk0", sizeGB: 96, bus: "virtio-scsi" }]);
    expect(r.spec.nics).toEqual([{ mode: "bridge", model: "virtio" }]);
    expect(r.spec.pool).toBe("tank");
    expect(r.downloads).toBeUndefined();
    expect(r.password).toBeUndefined();
  });

  it("builds a Linux cloud VM: image downloaded and imported, sign-in by key and password", () => {
    let s = initialState(linux, caps);
    expect(s.source).toBe("url");
    s = { ...s, name: "Web", id: "web", sshKeys: "ssh-ed25519 AAAA key1\n\n ssh-rsa BBBB key2 ", password: "correct horse", sha256: "AB".repeat(32) };
    const r = toRequest(s, linux);
    expect(r.downloads).toEqual([{ url: linux.images![0]!.urls!.x86_64, sha256: "ab".repeat(32) }]);
    expect(r.spec.disks[0]!.import).toEqual({ file: "noble-server-cloudimg-amd64.img" });
    expect(r.spec.media).toEqual([{ kind: "cloudinit" }]);
    expect(r.spec.cloudInit).toEqual({ user: "admin", sshKeys: ["ssh-ed25519 AAAA key1", "ssh-rsa BBBB key2"], installAgent: true });
    expect(r.password).toBe("correct horse");
    expect(r.spec.boot).toEqual(["disk"]);
  });

  it("gives routers two network cards, and VLANs their tag", () => {
    let s = initialState(opnsense, caps);
    expect(s.nics).toHaveLength(2);
    s = { ...s, nics: [{ mode: "vlan", vlan: 99 }, { mode: "bridge", vlan: 0 }] };
    expect(toRequest(s, opnsense).spec.nics).toEqual([
      { mode: "vlan", model: "virtio", vlan: 99 },
      { mode: "bridge", model: "virtio" },
    ]);
  });

  it("keeps a disk size the person chose when the preset changes", () => {
    let s = initialState(win11, caps);
    s = applyPreset(s, win11, "power");
    expect(s.disks[0]!.sizeGB).toBe(160);
    s = { ...s, disks: [{ ...s.disks[0]!, sizeGB: 500 }] };
    s = applyPreset(s, win11, "light");
    expect(s.cores).toBe(2);
    expect(s.disks[0]!.sizeGB).toBe(500);
  });

  it("explains what's missing on each step", () => {
    const ctx = { template: win11, caps, taken: ["kids-pc"], library: [] };
    let s = initialState(win11, caps);
    expect(stepProblems(s, "resources", ctx)).toContain("Give the VM a name");
    s = { ...s, name: "Kids PC", id: "kids-pc" };
    expect(stepProblems(s, "resources", ctx).join()).toMatch(/already/);
    s = { ...s, id: "kids", memoryMB: 2048 };
    expect(stepProblems(s, "resources", ctx).join()).toMatch(/at least 4 GB/);
    expect(stepProblems({ ...s, memoryMB: 8192 }, "resources", ctx)).toEqual([]);
    expect(stepProblems(s, "media", ctx)).toEqual(["Choose an installer disc"]);
    expect(stepProblems({ ...s, source: "url", url: "http://x/a.iso" }, "media", ctx).join()).toMatch(/https/);
    expect(stepProblems({ ...s, source: "url", url: "https://x/a.zip" }, "media", ctx).join()).toMatch(/\.iso/);
    const lctx = { ...ctx, template: linux };
    const l = { ...initialState(linux, caps), name: "Web", id: "web" };
    expect(stepProblems(l, "media", lctx).join()).toMatch(/SSH key or a password/);
    expect(stepProblems({ ...l, password: "short" }, "media", lctx).join()).toMatch(/8 characters/);
    expect(stepProblems({ ...l, sshKeys: "ssh-ed25519 AAAA me" }, "media", lctx)).toEqual([]);
    expect(stepProblems({ ...l, nics: [{ mode: "vlan", vlan: 0 }] }, "network", lctx).join()).toMatch(/VLAN/);
  });
});

describe("console helpers", () => {
  it("builds the WebSocket address from the page's", () => {
    expect(consoleURL("/api/v1/vms/web/console/ws?token=x", { protocol: "https:", host: "nas.local" })).toBe("wss://nas.local/api/v1/vms/web/console/ws?token=x");
    expect(consoleURL("/p", { protocol: "http:", host: "127.0.0.1:8080" })).toBe("ws://127.0.0.1:8080/p");
  });
  it("types text as keysyms", () => {
    expect(keysymsFor("aZ\n")).toEqual([
      { keysym: 0x61, code: null },
      { keysym: 0x5a, code: null },
      { keysym: 0xff0d, code: "Enter" },
    ]);
    expect(keysymsFor("€")[0]!.keysym).toBe(0x01000000 + 0x20ac);
  });
});
