import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { StorageNetworkStep } from "./StorageNetworkStep";

const info = {
  candidates: [
    { kind: "dedicated", interface: "enp2s0", speedMbps: 10000, carrier: true, defaultRoute: false },
    { kind: "vlan", interface: "enp1s0", speedMbps: 1000, carrier: true, defaultRoute: true, warning: "shares the LAN port's bandwidth" },
    { kind: "lan", interface: "enp1s0", speedMbps: 1000, carrier: true, defaultRoute: true, warning: "storage traffic shares the wire" },
  ],
  plan: null,
  subnet: "10.77.0.0/24",
  suggested: "10.77.0.21/24",
  current: "",
  interface: "",
  jumbo: { enp2s0: true, enp1s0: true },
  live: [],
  pending: false,
};

type Call = { method: string; path: string; query: string; body: unknown };

function serve(calls: Call[], reply?: { status: number; body: unknown } | ((query: string) => { status: number; body: unknown } | null)) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request) => {
      const url = new URL(input.url);
      const path = url.pathname.replace("/api/v1", "");
      const body = input.method !== "GET" ? await input.clone().json().catch(() => null) : null;
      calls.push({ method: input.method, path, query: url.search, body });
      const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });
      if (path === "/cluster/storage/network" && input.method === "GET") return json(info);
      if (path === "/cluster/storage/network" && input.method === "POST") {
        const r = typeof reply === "function" ? reply(url.search) : reply;
        if (r) return json(r.body, r.status);
        return json({ job: { id: "j1", state: "queued", progress: 0, title: "Set up the storage network" }, warnings: [] }, 202);
      }
      if (path === "/network") return json({ config: {}, ports: [], live: [], pending: null, gateway: "", dns: [], lastRevert: null });
      if (path === "/jobs/j1") return json({ id: "j1", state: "running", progress: 30, title: "Set up the storage network", message: "Setting up" });
      return json({ code: "not_found", message: path }, 404);
    }),
  );
}

function renderStep() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <StorageNetworkStep />
    </QueryClientProvider>,
  );
}

describe("StorageNetworkStep", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("offers the fastest dedicated port first and applies the plan with the suggested address", async () => {
    const calls: Call[] = [];
    serve(calls);
    renderStep();
    const radios = await screen.findAllByRole("radio");
    expect((radios[0] as HTMLInputElement).checked).toBe(true);
    expect(screen.getByText("10 Gb/s")).toBeTruthy();
    expect((screen.getByLabelText("This server's storage address") as HTMLInputElement).value).toBe("10.77.0.21/24");
    fireEvent.click(screen.getByRole("switch"));
    fireEvent.click(screen.getByRole("button", { name: "Set up the storage network" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    const post = calls.find((c) => c.method === "POST")!;
    expect(post.body).toEqual({ kind: "dedicated", interface: "enp2s0", address: "10.77.0.21/24", mtu: 9000 });
    expect(await screen.findByText("Setting up")).toBeTruthy();
  });

  it("asks for the server's name when the storage address changes and sends it again with it", async () => {
    const calls: Call[] = [];
    const msg = "This changes c1's storage address from 10.77.0.21 to 10.77.0.31. Type the server's name to confirm.";
    serve(calls, (q) => (q.includes("confirm=c1") ? null : { status: 409, body: { code: "confirm", message: msg } }));
    renderStep();
    await screen.findAllByRole("radio");
    fireEvent.change(screen.getByLabelText("This server's storage address"), { target: { value: "10.77.0.31/24" } });
    fireEvent.click(screen.getByRole("button", { name: "Set up the storage network" }));
    expect(await screen.findByText(msg)).toBeTruthy();
    const button = screen.getByRole("button", { name: "Change the storage address" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Type this server's name to confirm"), { target: { value: "c1" } });
    expect(button.disabled).toBe(false);
    fireEvent.click(button);
    expect(await screen.findByText("Setting up")).toBeTruthy();
    const posts = calls.filter((c) => c.method === "POST");
    expect(posts).toHaveLength(2);
    expect(posts[0]!.query).toBe("");
    expect(posts[1]!.query).toBe("?confirm=c1");
    expect(posts[1]!.body).toMatchObject({ address: "10.77.0.31/24" });
  });

  it("asks for a VLAN id and shows every problem the server reports", async () => {
    const calls: Call[] = [];
    serve(calls, { status: 400, body: { code: "invalid", message: "Some settings need fixing.", details: ["the VLAN id must be 1-4094"] } });
    renderStep();
    const radios = await screen.findAllByRole("radio");
    fireEvent.click(radios[1]!);
    const vlan = screen.getByLabelText("VLAN") as HTMLInputElement;
    fireEvent.change(vlan, { target: { value: "0" } });
    fireEvent.click(screen.getByRole("button", { name: "Set up the storage network" }));
    expect(await screen.findByText("the VLAN id must be 1-4094")).toBeTruthy();
    const post = calls.find((c) => c.method === "POST")!;
    expect(post.body).toMatchObject({ kind: "vlan", interface: "enp1s0", vlan: 0 });
  });
});
