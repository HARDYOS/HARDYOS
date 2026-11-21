import type { HostnamesStatus } from "@hardy/api-client";
import { describe, expect, it } from "vitest";
import { daysLeft, dnsmasqLines, hostnamesState, routerRecords, tokenProblems } from "./hostnamesRules";

const token = "abcdefghijklmnopqrstuvwxyz0123456789ABCD";

function status(over: Partial<HostnamesStatus> = {}): HostnamesStatus {
  return {
    active: false,
    settings: { enabled: false, email: "", staging: false },
    token: { set: false, base: "", zone: "", verifiedAt: null, apex: false },
    remoteBase: "",
    desktopUrl: "",
    certificate: null,
    lastError: null,
    names: [
      { label: "nas", host: "nas.home.example.net", what: "Desktop" },
      { label: "photos", host: "photos.home.example.net", what: "Photos" },
    ],
    lan: { addresses: ["192.168.1.5"], netbirdIp: "", domainDns: false, domain: "" },
    ...over,
  };
}

describe("hostnames rules", () => {
  it("checks the token and base before sending", () => {
    expect(tokenProblems(token, "home.example.net", "")).toEqual([]);
    expect(tokenProblems("short", "home.example.net", "")).toHaveLength(1);
    expect(tokenProblems(token + " x", "home.example.net", "")).toHaveLength(1);
    expect(tokenProblems(token, "localhost", "")).toHaveLength(1);
    expect(tokenProblems(token, "*.example.net", "")).toHaveLength(1);
    // Must match Remote Access's base when it has one.
    expect(tokenProblems(token, "home.example.net", "home.example.net")).toEqual([]);
    expect(tokenProblems(token, "other.example.net", "home.example.net")).toHaveLength(1);
  });
  it("describes the state", () => {
    expect(hostnamesState(status()).label).toBe("Off");
    expect(hostnamesState(status({ token: { set: true, base: "b.net", zone: "b.net", verifiedAt: null, apex: true } })).label).toBe("Ready");
    expect(
      hostnamesState(status({ token: { set: true, base: "b.net", zone: "b.net", verifiedAt: null, apex: true }, settings: { enabled: true, email: "", staging: false } }))
        .label,
    ).toBe("No certificate");
    expect(hostnamesState(status({ active: true })).tone).toBe("good");
  });
  it("counts days left", () => {
    const now = Date.parse("2026-11-21T00:00:00Z");
    expect(daysLeft("2026-12-21T00:00:00Z", now)).toBe(30);
    expect(daysLeft("2026-11-20T00:00:00Z", now)).toBe(-1);
  });
  it("lists router records", () => {
    const st = status();
    expect(routerRecords(st, "")).toEqual([]);
    expect(routerRecords(st, "192.168.1.5")).toEqual([
      { name: "nas.home.example.net", type: "A", value: "192.168.1.5" },
      { name: "photos.home.example.net", type: "A", value: "192.168.1.5" },
    ]);
    expect(dnsmasqLines(st, "192.168.1.5")).toBe("address=/nas.home.example.net/192.168.1.5\naddress=/photos.home.example.net/192.168.1.5");
  });
});
