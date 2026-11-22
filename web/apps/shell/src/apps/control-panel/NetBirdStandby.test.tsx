import type { NBStandbyStatus } from "@hardy/api-client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { NetBirdStandby } from "./NetBirdStandby";
import { copyAge, formProblems, isPublicIPv4, isPublicIPv6, looksLikeHostKey, standbyState, takeoverBlockers } from "./netbirdStandbyRules";

const HOSTKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl root@vps";

function status(over: Partial<NBStandbyStatus> = {}): NBStandbyStatus {
  return {
    connection: {
      configured: true,
      vpsHost: "vps.example.net",
      vpsPort: 22,
      vpsUser: "hardyos-standby",
      hostKey: HOSTKEY,
      hostKeyFingerprint: "SHA256:abc",
      hostname: "vpn.example.net",
      publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
      snapshots: [
        {
          id: "s1",
          at: "2026-11-21T11:50:00Z",
          sealedBytes: 2048,
          info: {
            created: "2026-11-21T11:50:00Z",
            hostname: "vpn.example.net",
            image: "netbirdio/netbird-server:0.83.1",
            digest: "",
            version: "0.83.1",
            peers: 7,
            setupKeys: 2,
            files: [],
            bytes: 1024,
            sha256: "x",
            warnings: [],
            generation: "00112233445566778899aabbccddeeff",
          },
        },
      ],
      mode: "standby",
      networkOpen: false,
      publicIPv4: "93.184.215.14",
      publicIPv6: "",
      from: ["100.64.0.5"],
      handbackCopy: false,
    },
    settings: { intervalMinutes: 15, autoSync: true, publicIPv4: "93.184.215.14", publicIPv6: "", connectFrom: ["100.64.0.5"] },
    health: { state: "ok", stale: false, staleAfterMinutes: 75 },
    history: [],
    app: { installed: true, state: "stopped", version: "0.83.1" },
    dns: {
      tokenSet: true,
      base: "home.example.net",
      zone: "example.net",
      name: "vpn.example.net",
      adopted: [{ id: "r1", type: "A", content: "198.51.100.10", ttl: 300, proxied: false }],
      inBase: false,
      inZone: true,
    },
    takeover: null,
    standbyVersion: "0.83.1",
    versionNewer: false,
    portForwards: [
      { protocol: "TCP", public: 80, internal: 44620, purpose: "HTTP" },
      { protocol: "TCP", public: 443, internal: 44621, purpose: "HTTPS" },
      { protocol: "UDP", public: 3478, internal: 44622, purpose: "STUN" },
    ],
    clientConnected: true,
    clientIp: "100.64.0.5",
    managementUrl: "https://vpn.example.net",
    ...over,
  };
}

describe("NetBird standby rules", () => {
  it("checks addresses and keys", () => {
    expect(isPublicIPv4("93.184.215.14")).toBe(true);
    for (const a of ["203.0.113.5", "198.51.100.7", "192.0.2.1", "192.168.1.2", "10.1.1.1", "172.20.0.1", "100.100.0.1", "127.0.0.1", "300.1.1.1", "1.2.3"]) expect(isPublicIPv4(a)).toBe(false);
    expect(isPublicIPv6("2606:4700:4700::1111")).toBe(true);
    expect(isPublicIPv6("2001:db8::1")).toBe(false);
    expect(isPublicIPv6("fd00::1")).toBe(false);
    expect(looksLikeHostKey(HOSTKEY)).toBe(true);
    expect(looksLikeHostKey("vps.example.net " + HOSTKEY)).toBe(true);
    expect(looksLikeHostKey("ssh-ed25519")).toBe(false);
    expect(looksLikeHostKey(HOSTKEY + "\n" + HOSTKEY)).toBe(false);
  });

  it("checks the form", () => {
    const f = { hostname: "vpn.example.net", vpsHost: "vps.example.net", vpsPort: "22", vpsUser: "hardyos-standby", hostKey: HOSTKEY, publicIPv4: "93.184.215.14", publicIPv6: "", intervalMinutes: "15", connectFrom: "100.64.0.5" };
    expect(formProblems(f)).toEqual([]);
    expect(formProblems({ ...f, hostname: "vpn" })).toHaveLength(1);
    expect(formProblems({ ...f, publicIPv4: "192.168.1.5" })).toHaveLength(1);
    expect(formProblems({ ...f, intervalMinutes: "2" })).toHaveLength(1);
    expect(formProblems({ ...f, vpsUser: "-oProxyCommand=x" })).toHaveLength(1);
    expect(formProblems({ ...f, hostKey: "nope" })).toHaveLength(1);
  });

  it("says what blocks a take-over", () => {
    expect(takeoverBlockers(status())).toEqual([]);
    expect(takeoverBlockers(status({ app: { installed: false, state: "", version: "" } }))[0]).toMatch(/Install/);
    expect(takeoverBlockers(status({ dns: { ...status().dns, name: "" } }))[0]).toMatch(/manage vpn.example.net/);
    const aaaa = status({ dns: { ...status().dns, adopted: [...status().dns.adopted, { id: "r2", type: "AAAA", content: "2001:db8::1", ttl: 300, proxied: false }] } });
    expect(takeoverBlockers(aaaa)[0]).toMatch(/IPv6/);
    expect(standbyState(status({ health: { state: "stale", stale: true, staleAfterMinutes: 75 } })).tone).toBe("bad");
    expect(copyAge(status(), Date.parse("2026-11-21T12:00:00Z"))).toBe("10 min old");
  });
});

function serve(st: NBStandbyStatus, calls: { method: string; path: string; body: unknown }[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request) => {
      const url = new URL(input.url);
      const path = url.pathname.replace("/api/v1", "");
      const body = input.method !== "GET" ? await input.clone().json().catch(() => null) : null;
      calls.push({ method: input.method, path, body });
      const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
      if (path === "/netbird-standby") return json(st);
      if (path === "/netbird-standby/takeover" || path === "/netbird-standby/handback") return json({ job: { id: "j1" }, warnings: [] }, 202);
      if (path === "/jobs/j1") return json({ id: "j1", state: "succeeded", progress: 100, title: "x" });
      return json({ code: "not_found", message: path }, 404);
    }),
  );
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <NetBirdStandby />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("NetBirdStandby", () => {
  it("shows the port forwards and takes over only with the name typed", async () => {
    const calls: { method: string; path: string; body: unknown }[] = [];
    serve(status(), calls);
    renderPage();
    expect(await screen.findByText("In sync")).toBeTruthy();
    expect(screen.getByText("44621")).toBeTruthy();
    expect(screen.getByText("3478")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Take over" }));
    const confirm = await screen.findByLabelText("Type vpn.example.net to confirm");
    const buttons = screen.getAllByRole("button", { name: "Take over" });
    const submit = buttons[buttons.length - 1]!;
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(confirm, { target: { value: "vpn.example.net" } });
    expect((submit as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(submit);
    await waitFor(() => expect(calls.some((c) => c.path === "/netbird-standby/takeover")).toBe(true));
    const sent = calls.find((c) => c.path === "/netbird-standby/takeover")!;
    expect(sent.body).toEqual({ confirm: "vpn.example.net", acceptVersion: false, acceptVpsAlive: false });
  });

  it("hands back only with the split-brain warning ticked", async () => {
    const calls: { method: string; path: string; body: unknown }[] = [];
    const st = status({
      health: { state: "takenover", stale: false, staleAfterMinutes: 75 },
      connection: { ...status().connection!, mode: "takenover", networkOpen: true },
      app: { installed: true, state: "running", version: "0.83.1" },
      takeover: { at: "2026-11-21T12:00:00Z", by: "cade", snapshotAt: "2026-11-21T11:50:00Z", finalSync: false, dnsChanged: true, fenced: true, ipv4: "93.184.215.14", peersTotal: 7, peersConnected: 6, notes: [] },
    });
    serve(st, calls);
    renderPage();
    expect(await screen.findByText("Taken over")).toBeTruthy();
    expect(screen.getByText("6 / 7")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Take over" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Hand back to the VPS" }));
    fireEvent.change(await screen.findByLabelText("Type vpn.example.net to confirm"), { target: { value: "vpn.example.net" } });
    const submit = screen.getByRole("button", { name: "Hand back" }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/replaced by the standby/));
    expect(submit.disabled).toBe(false);
    fireEvent.click(submit);
    await waitFor(() => expect(calls.some((c) => c.path === "/netbird-standby/handback")).toBe(true));
    expect(calls.find((c) => c.path === "/netbird-standby/handback")!.body).toEqual({ confirm: "vpn.example.net", acceptSplitBrain: true, discard: false });
  });
});
