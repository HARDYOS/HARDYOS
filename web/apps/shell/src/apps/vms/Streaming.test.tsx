import type { VM, VMTemplate } from "@hardy/api-client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { StreamingPanel, deviceNameOK, pinOK, portSummary } from "./Streaming";
import { caps, win11 } from "./testFixtures";
import { initialState, setsUpStreaming, stepProblems, toRequest } from "./wizard";

type Call = { method: string; path: string; body: unknown };

function serve(routes: Record<string, () => unknown>, calls: Call[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const path = new URL(req.url).pathname.replace("/api/v1", "");
      const body = req.method !== "GET" ? await req.clone().json().catch(() => null) : null;
      calls.push({ method: req.method, path, body });
      const h = routes[`${req.method} ${path}`] ?? routes[path];
      const out = h ? h() : { __status: 404, code: "not_found", message: path };
      const { __status = 200, ...rest } = (out ?? {}) as { __status?: number };
      return new Response(JSON.stringify(rest), { status: __status, headers: { "Content-Type": "application/json" } });
    }),
  );
}

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const job = (id: string) => ({ id, kind: "k", title: "k", state: "queued", progress: 0, message: "", error: "", params: {}, result: {}, createdBy: 1, createdAt: "", startedAt: null, finishedAt: null });
const accepted = (id: string) => ({ __status: 202, job: job(id), warnings: [] });

const gaming: VMTemplate = { ...win11, id: "gaming", name: "Gaming PC", group: "gaming", gpu: true, unattend: true, streaming: true, editions: ["Windows 11 Pro"] };

const game = {
  id: "game", name: "Game", template: "gaming", os: "windows", state: "running", description: "", uuid: "u", pool: "tank", video: "vga", guestAgent: true,
  boot: ["disk"], autostart: { enabled: false, order: 0, delaySec: 0 }, devices: [{ kind: "gpu", id: "0000:01:00.0" }], media: [],
  firmware: { type: "uefi", secureBoot: true, tpm: true }, nics: [{ mode: "bridge", model: "virtio", mac: "52:54:00:00:00:01" }], dataset: "tank/vms/game",
  cpuPercent: 0, memoryUsedMB: 0, addresses: ["192.168.1.77"], passwordSet: false, restartNeeded: false, diskUsage: {}, liveUSB: [], snapshotsBehind: false,
  cpu: { cores: 8, threads: 2 }, memory: { mb: 16384, balloon: false }, disks: [], streaming: { remote: false, sunshine: true, user: "hardyos", certSHA256: "a".repeat(64) },
} as unknown as VM;

const status = (o: Record<string, unknown> = {}) => ({
  setUp: true, installPending: false, running: true, hasGPU: true, address: "192.168.1.77", reachable: true, user: "hardyos", accountKept: true,
  devices: [{ name: "Living room TV", uuid: "0123ABCD-0000-1111-2222-333344445555", enabled: true }],
  waiting: [{ id: "cd".repeat(16), name: "Steam Deck", address: "192.168.1.30", viaNetBird: false }],
  remote: false, forwarding: false, netbirdAddress: "100.92.1.2", ports: { tcp: [47984, 47989, 48010], udp: [47998, 47999, 48000, 48002, 48010] },
  peers: [], netbirdKernel: true, bridgeAddress: "192.168.1.10",
  netbirdPeers: [{ ip: "100.92.0.5", name: "deck.netbird.cloud", connected: true, proxy: false }, { ip: "100.92.0.9", name: "proxy-eu", connected: true, proxy: true }],
  ...o,
});

describe("game streaming in the wizard", () => {
  it("sets streaming up with the unattended install of the gaming template", () => {
    let s = initialState(gaming, caps);
    expect(s.streaming).toBe(true);
    s = { ...s, name: "Game", id: "game", file: "Win11.iso", user: "cade", password: "Windows pass 1" };
    expect(setsUpStreaming(s, gaming)).toBe(true);
    const r = toRequest(s, gaming);
    expect(r.spec.media).toEqual([{ kind: "iso", iso: "Win11.iso" }, { kind: "virtio" }, { kind: "unattend" }, { kind: "streaming" }]);
    expect(r.spec.streaming).toEqual({ remote: false, sunshine: true });
    // Without the unattended install there's nothing to run it at first sign-in.
    const manual = toRequest({ ...s, unattend: false }, gaming);
    expect(manual.spec.streaming).toBeUndefined();
    expect(manual.spec.media.some((m) => m.kind === "streaming")).toBe(false);
    // Off: nothing.
    expect(toRequest({ ...s, streaming: false }, gaming).spec.streaming).toBeUndefined();
    // Templates without it never ask.
    expect(initialState(win11, caps).streaming).toBe(false);
  });

  it("needs the first card on the home network with spoofing off", () => {
    const s = { ...initialState(gaming, caps), file: "Win11.iso" };
    const ctx = { template: gaming, caps, taken: [], library: [] };
    expect(stepProblems(s, "network", ctx)).toEqual([]);
    expect(stepProblems({ ...s, nics: [{ mode: "nat", vlan: 0, allowSpoofing: false }] }, "network", ctx).join()).toMatch(/home network/);
    expect(stepProblems({ ...s, nics: [{ mode: "bridge", vlan: 0, allowSpoofing: true }] }, "network", ctx).join()).toMatch(/spoofing off/);
  });
});

describe("the Streaming panel", () => {
  it("checks PINs and names, and sums up ports", () => {
    expect(pinOK("4821")).toBe(true);
    expect(pinOK("482")).toBe(false);
    expect(pinOK("48211")).toBe(false);
    expect(deviceNameOK("Steam Deck")).toBe(true);
    expect(deviceNameOK("a\nb")).toBe(false);
    expect(portSummary([48010, 47998, 47999, 48000, 48002])).toBe("47998–48000, 48002, 48010");
  });

  it("shows Sunshine's state, pairs with a PIN and unpairs", async () => {
    const calls: Call[] = [];
    serve(
      {
        "/vms/game/streaming": () => status(),
        "POST /vms/game/streaming/pair": () => accepted("j1"),
        "POST /vms/game/streaming/unpair": () => accepted("j2"),
      },
      calls,
    );
    const onJob = vi.fn();
    wrap(<StreamingPanel vm={game} onJob={onJob} />);
    expect(await screen.findByText("Sunshine is running")).toBeTruthy();
    expect(screen.getByText("Living room TV")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Enter its PIN" }));
    const dialog = await screen.findByRole("dialog");
    const pair = within(dialog).getByRole("button", { name: "Pair" }) as HTMLButtonElement;
    expect(pair.disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText("PIN"), { target: { value: "48a21" } });
    expect((within(dialog).getByLabelText("PIN") as HTMLInputElement).value).toBe("4821");
    fireEvent.click(pair);
    await waitFor(() => expect(onJob).toHaveBeenCalled());
    expect(calls.find((c) => c.path === "/vms/game/streaming/pair")?.body).toEqual({ pairingId: "cd".repeat(16), pin: "4821", name: "Steam Deck" });
    fireEvent.click(screen.getByRole("button", { name: "Unpair Living room TV" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/vms/game/streaming/unpair")).toBe(true));
    expect(calls.find((c) => c.path === "/vms/game/streaming/unpair")?.body).toEqual({ uuid: "0123ABCD-0000-1111-2222-333344445555" });
    // The driver is the person's to install: no unlocks.
    expect(screen.getByText(/no vGPU unlocks and no licence workarounds/)).toBeTruthy();
  });

  it("reveals Sunshine's password only after the admin's own password", async () => {
    const calls: Call[] = [];
    let good = false;
    serve(
      {
        "/vms/game/streaming": () => status(),
        "POST /vms/game/streaming/reveal": () => (good ? { user: "hardyos", password: "Abcdefghijkmnopqrstuvw23" } : { __status: 401, code: "bad_credentials", message: "no" }),
      },
      calls,
    );
    wrap(<StreamingPanel vm={game} onJob={vi.fn()} />);
    fireEvent.click(await screen.findByRole("button", { name: /Show the password/ }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Your password"), { target: { value: "wrong" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Show" }));
    expect(await within(dialog).findByText("That password isn't right.")).toBeTruthy();
    good = true;
    fireEvent.click(within(dialog).getByRole("button", { name: "Show" }));
    expect(await screen.findByText("Abcdefghijkmnopqrstuvw23")).toBeTruthy();
    expect(calls.filter((c) => c.path === "/vms/game/streaming/reveal").map((c) => c.body)).toEqual([{ password: "wrong" }, { password: "wrong" }]);
  });

  it("publishes to chosen NetBird devices only, never the proxy", async () => {
    const calls: Call[] = [];
    serve({ "/vms/game/streaming": () => status(), "PUT /vms/game/streaming/remote": () => accepted("j3") }, calls);
    const onJob = vi.fn();
    wrap(<StreamingPanel vm={game} onJob={onJob} />);
    fireEvent.click(await screen.findByRole("switch", { name: /Play away from home/ }));
    expect(screen.getByText(/access policies don't apply/)).toBeTruthy();
    const publish = screen.getByRole("button", { name: "Publish to these devices" }) as HTMLButtonElement;
    expect(publish.disabled).toBe(true);
    expect((screen.getByRole("checkbox", { name: "proxy-eu" }) as HTMLInputElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: "deck.netbird.cloud" }));
    fireEvent.click(publish);
    await waitFor(() => expect(onJob).toHaveBeenCalled());
    expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ enabled: true, peers: ["100.92.0.5"] });
  });

  it("turns NetBird off and says where to connect", async () => {
    const calls: Call[] = [];
    serve({ "/vms/game/streaming": () => status({ remote: true, forwarding: true, peers: ["100.92.0.5"] }), "PUT /vms/game/streaming/remote": () => accepted("j4") }, calls);
    const onJob = vi.fn();
    wrap(<StreamingPanel vm={game} onJob={onJob} />);
    expect(await screen.findByText("Forwarding now, to your NetBird devices only.")).toBeTruthy();
    fireEvent.click(screen.getByRole("switch", { name: /Play away from home/ }));
    await waitFor(() => expect(onJob).toHaveBeenCalled());
    expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ enabled: false });
  });

  it("shows the address with its port for a VM on its own port set", async () => {
    serve({
      "/vms/game/streaming": () =>
        status({ remote: true, forwarding: true, peers: ["100.92.0.5"], base: 48089, moonlight: "100.92.1.2:48089", ports: { tcp: [48084, 48089, 48110], udp: [48098, 48099, 48100, 48102, 48110] } }),
    }, []);
    wrap(<StreamingPanel vm={game} onJob={vi.fn()} />);
    expect((await screen.findAllByText("100.92.1.2:48089")).length).toBeGreaterThan(0);
    expect(document.body.textContent).toContain("48084");
  });

  it("asks before pairing a device that came through NetBird", async () => {
    const calls: Call[] = [];
    serve(
      {
        "/vms/game/streaming": () => status({ waiting: [{ id: "cd".repeat(16), name: "Deck", address: "192.168.1.10", viaNetBird: true }] }),
        "POST /vms/game/streaming/pair": () => accepted("j5"),
      },
      calls,
    );
    const onJob = vi.fn();
    wrap(<StreamingPanel vm={game} onJob={onJob} />);
    expect(await screen.findByText("Through NetBird")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Enter its PIN" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("PIN"), { target: { value: "1234" } });
    const pair = within(dialog).getByRole("button", { name: "Pair" }) as HTMLButtonElement;
    expect(pair.disabled).toBe(true);
    fireEvent.click(within(dialog).getByRole("switch", { name: /pair it anyway/ }));
    fireEvent.click(pair);
    await waitFor(() => expect(onJob).toHaveBeenCalled());
    expect(calls.find((c) => c.path === "/vms/game/streaming/pair")?.body).toEqual({ pairingId: "cd".repeat(16), pin: "1234", name: "Deck", confirmRemote: true });
  });

  it("gives the steps by hand for a GPU VM HardyOS didn't set up", async () => {
    serve({ "/vms/game/streaming": () => status({ setUp: false, reachable: false, devices: [], waiting: [] }) }, []);
    wrap(<StreamingPanel vm={{ ...game, streaming: undefined } as VM} onJob={vi.fn()} />);
    expect(await screen.findByText(/for this one, by hand/)).toBeTruthy();
  });
});
