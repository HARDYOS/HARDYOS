import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { zonedToUTC } from "./DateTime";
import { Network } from "./Network";

const baseStatus = {
  config: {
    hostname: "hardyos",
    dns: [],
    search: [],
    interfaces: [
      { name: "ens33", mode: "dhcp" },
      { name: "ens34", mode: "off" },
    ],
    bonds: [],
    vlans: [],
  },
  ports: ["ens33", "ens34"],
  live: [
    { name: "ens33", kind: "port", mac: "00:0c:29:aa:bb:cc", up: true, carrier: true, speedMbps: 1000, addresses: ["192.168.252.128/24"] },
    { name: "ens34", kind: "port", mac: "00:0c:29:aa:bb:cd", up: false, carrier: false, speedMbps: 0, addresses: [] },
  ],
  pending: null as null | { appliedAt: string; deadline: string; addresses: string[] },
  gateway: "192.168.252.2",
  dns: ["192.168.252.2"],
  lastRevert: null,
};

type Call = { method: string; path: string; body: unknown };

function serve(status: typeof baseStatus, calls: Call[], applyResponse?: { status: number; body: unknown }) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request) => {
      const url = new URL(input.url);
      const path = url.pathname.replace("/api/v1", "");
      const body = input.method !== "GET" ? await input.clone().json().catch(() => null) : null;
      calls.push({ method: input.method, path, body });
      const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });
      if (path === "/network" && input.method === "GET") return json(status);
      if (path === "/network" && input.method === "PUT") {
        if (applyResponse) return json(applyResponse.body, applyResponse.status);
        return json({ job: { id: "j1", state: "queued", progress: 0, title: "Apply network settings" }, warnings: [] }, 202);
      }
      if (path === "/jobs/j1") return json({ id: "j1", state: "running", progress: 20, title: "Apply network settings", message: "Restarting the network" });
      if (path === "/network/confirm") return json(status.config);
      if (path === "/health") return json({ status: "ok", uptimeSeconds: 1 });
      return json({ code: "not_found", message: path }, 404);
    }),
  );
}

function renderNetwork() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Network />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("Network", () => {
  it("shows the current setup and applies a fixed address, warning that this page moves", async () => {
    const calls: Call[] = [];
    serve(structuredClone(baseStatus), calls);
    renderNetwork();
    expect(await screen.findByDisplayValue("hardyos")).toBeTruthy();
    expect(screen.getByText("1 Gb/s")).toBeTruthy();
    expect(screen.getByText("no cable")).toBeTruthy();
    const apply = screen.getByRole("button", { name: "Apply…" }) as HTMLButtonElement;
    expect(apply.disabled).toBe(true);

    fireEvent.change(screen.getByLabelText("How ens33 gets its address"), { target: { value: "static" } });
    fireEvent.change(screen.getByLabelText("ens33 address"), { target: { value: "192.168.252.50/24" } });
    fireEvent.change(screen.getByLabelText("ens33 gateway"), { target: { value: "192.168.252.2" } });
    fireEvent.change(screen.getByLabelText("DNS servers"), { target: { value: "192.168.252.2, 1.1.1.1" } });
    expect(apply.disabled).toBe(false);
    fireEvent.click(apply);

    // jsdom's page isn't at the server's address, so pretend it is.
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/3 minutes/)).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    const put = calls.find((c) => c.method === "PUT")!.body as typeof baseStatus.config;
    expect(put.interfaces[0]).toEqual({ name: "ens33", mode: "static", address: "192.168.252.50/24", gateway: "192.168.252.2" });
    expect(put.dns).toEqual(["192.168.252.2", "1.1.1.1"]);
    expect(await screen.findByText("Restarting the network")).toBeTruthy();
  });

  it("lists every problem the server finds", async () => {
    const calls: Call[] = [];
    serve(structuredClone(baseStatus), calls, {
      status: 400,
      body: { code: "invalid", message: "Some settings need fixing.", details: ["the server name must be…", "ens33: gateway 10.0.0.1 is outside 192.168.252.0/24"] },
    });
    renderNetwork();
    fireEvent.change(await screen.findByDisplayValue("hardyos"), { target: { value: "Bad Name" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply…" }));
    fireEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Apply" }));
    expect(await screen.findByText("Some settings need fixing.")).toBeTruthy();
    expect(screen.getByText(/gateway 10.0.0.1 is outside/)).toBeTruthy();
  });

  it("bonds ports and adds a VLAN on the bond", async () => {
    const calls: Call[] = [];
    serve(structuredClone(baseStatus), calls);
    renderNetwork();
    await screen.findByDisplayValue("hardyos");
    fireEvent.click(screen.getByRole("button", { name: /Add bond/ }));
    const boxes = screen.getAllByRole("checkbox");
    boxes.forEach((b) => fireEvent.click(b));
    expect(screen.getAllByText("Part of bond0").length).toBe(2);
    fireEvent.click(screen.getByRole("button", { name: /Add VLAN/ }));
    expect((screen.getByLabelText("Port or bond") as HTMLSelectElement).value).toBe("bond0");
    fireEvent.click(screen.getByRole("button", { name: "Apply…" }));
    fireEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    const put = calls.find((c) => c.method === "PUT")!.body as {
      interfaces: { mode: string }[];
      bonds: { name: string; members: string[]; policy: string }[];
      vlans: { parent: string; id: number }[];
    };
    expect(put.bonds[0]).toMatchObject({ name: "bond0", members: ["ens33", "ens34"], policy: "active-backup" });
    expect(put.interfaces.every((i) => i.mode === "member")).toBe(true);
    expect(put.vlans[0]).toMatchObject({ parent: "bond0", id: 10 });
  });

  it("asks to keep a waiting change and confirms it", async () => {
    const calls: Call[] = [];
    const st = structuredClone(baseStatus);
    st.pending = { appliedAt: new Date().toISOString(), deadline: new Date(Date.now() + 150_000).toISOString(), addresses: [] };
    serve(st, calls);
    renderNetwork();
    expect(await screen.findByText("Keep the new network settings?")).toBeTruthy();
    expect(screen.getByText(/2:[23]\d/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Apply…" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Keep settings" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/network/confirm")).toBe(true));
  });
});

describe("zonedToUTC", () => {
  it("reads a wall-clock time in the server's zone", () => {
    expect(zonedToUTC("2026-10-25T20:00", "America/Denver")).toBe("2026-10-26T02:00:00.000Z");
    expect(zonedToUTC("2026-07-01T12:30:15", "Europe/London")).toBe("2026-07-01T11:30:15.000Z");
    expect(zonedToUTC("2026-01-01T00:00", "Etc/UTC")).toBe("2026-01-01T00:00:00.000Z");
  });
});
