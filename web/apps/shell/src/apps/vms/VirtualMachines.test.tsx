import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ConsoleView } from "./Console";
import { DevicesStep } from "./DevicesStep";
import { VirtualMachinesView } from "./VirtualMachines";
import { caps, linux, opnsense, win11 } from "./testFixtures";

type Call = { method: string; path: string; body: unknown };
type Handler = (req: { method: string; path: string; body: unknown; query: URLSearchParams }) => unknown;

function serve(routes: Record<string, Handler>, calls: Call[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const u = new URL(req.url);
      const path = u.pathname.replace("/api/v1", "");
      const body = req.method !== "GET" ? await req.clone().json().catch(() => null) : null;
      calls.push({ method: req.method, path, body });
      const h = routes[`${req.method} ${path}`] ?? routes[path];
      const out = h ? h({ method: req.method, path, body, query: u.searchParams }) : { __status: 404, code: "not_found", message: path };
      const { __status = 200, ...rest } = (out ?? {}) as { __status?: number };
      const payload = Array.isArray(out) ? out : rest;
      return new Response(__status === 204 ? null : JSON.stringify(payload), { status: __status, headers: { "Content-Type": "application/json" } });
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
  vi.restoreAllMocks();
});

const job = (id: string, kind: string, state = "running") => ({ id, kind, title: kind, state, progress: 40, message: "working", error: "", params: {}, result: {}, createdBy: 1, createdAt: "", startedAt: null, finishedAt: null });
const accepted = (id: string, kind: string) => ({ __status: 202, job: job(id, kind, "queued"), warnings: [] });

function vm(o: Record<string, unknown>) {
  return {
    description: "", uuid: "u", pool: "tank", video: "virtio", guestAgent: true, boot: ["disk"], autostart: { enabled: false, order: 0, delaySec: 0 },
    devices: [], media: [], firmware: { type: "uefi", secureBoot: false, tpm: false }, nics: [{ mode: "bridge", model: "virtio", mac: "52:54:00:00:00:01" }],
    dataset: "tank/vms/x", cpuPercent: 0, memoryUsedMB: 0, addresses: [], passwordSet: false, restartNeeded: false, diskUsage: { disk0: 1e9 },
    cpu: { cores: 2, threads: 1 }, memory: { mb: 4096, balloon: true }, disks: [{ name: "disk0", sizeGB: 32, bus: "virtio-scsi" }], os: "linux",
    ...o,
  };
}

const web = vm({ id: "web", name: "Web server", template: "linux", state: "running", cpuPercent: 42, memoryUsedMB: 2048, addresses: ["192.168.1.51"] });
const win = vm({ id: "win", name: "Windows 11", template: "windows11", os: "windows", state: "stopped" });

const library = { pool: "tank", path: "/mnt/tank/shares/isos", tasks: [], files: [{ name: "Win11_24H2_English_x64.iso", kind: "iso", size: 6e9, modified: "2026-10-20T10:00:00Z", usedBy: [] }] };

function routes(extra: Record<string, Handler> = {}): Record<string, Handler> {
  return {
    "/vms": () => ({ vms: [web, win], kept: [] }),
    "/vms/templates": () => [win11, linux, opnsense],
    "/vms/capabilities": () => caps,
    "/vms/isos": () => library,
    "/vms/web": () => web,
    "/vms/win": () => win,
    "/vms/win/snapshots": () => [{ name: "vm-20261020-101500", label: "Fresh install", created: "2026-10-20T10:15:00Z", bytes: 1e9, consistent: true }],
    "/devices": () => ({ __status: 404, code: "not_found", message: "no devices API" }),
    ...extra,
  };
}

describe("Virtual Machines", () => {
  it("lists VMs, running ones first, and starts one", async () => {
    const calls: Call[] = [];
    serve(routes({ "POST /vms/win/start": () => accepted("j1", "vms.start") }), calls);
    const opened: string[] = [];
    wrap(<VirtualMachinesView onOpenConsole={(v) => opened.push(v.id)} />);
    const cards = await screen.findAllByRole("article");
    expect(cards.map((c) => c.getAttribute("aria-label"))).toEqual(["Web server", "Windows 11"]);
    const webCard = within(cards[0]!);
    expect(webCard.getByText("Running")).toBeTruthy();
    expect(webCard.getByText("192.168.1.51")).toBeTruthy();
    fireEvent.click(webCard.getByRole("button", { name: /Screen/ }));
    expect(opened).toEqual(["web"]);
    fireEvent.click(within(cards[1]!).getByRole("button", { name: /Start/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/vms/win/start")).toBe(true));
  });

  it("creates a Windows 11 VM with the wizard", async () => {
    const calls: Call[] = [];
    serve(routes({ "POST /vms": () => accepted("j2", "vms.create"), "/jobs/j2": () => job("j2", "vms.create") }), calls);
    wrap(<VirtualMachinesView onOpenConsole={() => {}} />);
    fireEvent.click((await screen.findAllByRole("button", { name: /New VM/ }))[0]!);
    fireEvent.click(await screen.findByRole("button", { name: "Windows 11" }));

    // Name and size: the short name follows the name.
    const next = () => fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect((screen.getByRole("button", { name: "Next" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Kids PC" } });
    expect((screen.getByLabelText("Short name") as HTMLInputElement).value).toBe("kids-pc");
    fireEvent.click(screen.getByRole("radio", { name: /Power/ }));
    next();
    // Disks on the library's pool.
    expect((await screen.findByLabelText("Pool") as HTMLSelectElement).value).toBe("tank");
    next();
    // Installer from the library; the drivers disc is on by default.
    fireEvent.click(await screen.findByRole("option", { name: /Win11_24H2/ }));
    expect((screen.getByRole("switch", { name: /VirtIO drivers disc/ }) as HTMLInputElement).checked).toBe(true);
    next();
    // Network: home network by default, with a word about the bridge.
    expect(screen.getByRole("radio", { name: /Home network/ }).getAttribute("aria-checked")).toBe("true");
    expect(screen.getByText(/sets up a bridge/)).toBeTruthy();
    next();
    // Devices: part D isn't here yet.
    expect(await screen.findByText(/Device passthrough comes with the Devices update/)).toBeTruthy();
    next();
    expect(screen.getByText("Ready to create")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Create VM" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/vms")).toBe(true));
    const body = calls.find((c) => c.method === "POST" && c.path === "/vms")!.body as { spec: Record<string, unknown>; start: boolean };
    expect(body.start).toBe(true);
    expect(body.spec).toMatchObject({
      id: "kids-pc",
      name: "Kids PC",
      template: "windows11",
      os: "windows",
      pool: "tank",
      cpu: { cores: 8, threads: 1 },
      memory: { mb: 16384, balloon: true },
      firmware: { type: "uefi", secureBoot: true, tpm: true },
      disks: [{ name: "disk0", sizeGB: 160, bus: "virtio-scsi" }],
      media: [{ kind: "iso", iso: "Win11_24H2_English_x64.iso" }, { kind: "virtio" }],
      boot: ["cdrom", "disk"],
    });
    expect(await screen.findByText("Creating Kids PC")).toBeTruthy();
  });

  it("goes back to a snapshot only with the VM's name typed", async () => {
    const calls: Call[] = [];
    serve(routes({ "POST /vms/win/rollback": () => accepted("j3", "vms.rollback"), "/jobs/j3": () => job("j3", "vms.rollback") }), calls);
    wrap(<VirtualMachinesView onOpenConsole={() => {}} />);
    fireEvent.click(await screen.findByRole("article", { name: "Windows 11" }));
    fireEvent.click(await screen.findByRole("tab", { name: "Snapshots" }));
    fireEvent.click(await screen.findByRole("button", { name: /Go back/ }));
    const dialog = await screen.findByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: "Go back" }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText(/Type Windows 11 to confirm/), { target: { value: "Windows 11" } });
    fireEvent.click(confirm);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/vms/win/rollback")).toBe(true));
    expect(calls.find((c) => c.path === "/vms/win/rollback")!.body).toEqual({ snapshot: "vm-20261020-101500", confirm: "Windows 11" });
  });

  it("saves hardware changes, and removing a disk names it", async () => {
    const calls: Call[] = [];
    const twoDisks = { ...win, disks: [{ name: "disk0", sizeGB: 32, bus: "virtio-scsi" }, { name: "disk1", sizeGB: 100, bus: "virtio-scsi" }] };
    serve(routes({ "/vms/win": () => twoDisks, "PUT /vms/win": () => accepted("j4", "vms.update"), "/jobs/j4": () => job("j4", "vms.update") }), calls);
    wrap(<VirtualMachinesView onOpenConsole={() => {}} />);
    fireEvent.click(await screen.findByRole("article", { name: "Windows 11" }));
    fireEvent.click(await screen.findByRole("tab", { name: "Hardware" }));
    fireEvent.change(await screen.findByLabelText("disk0 size"), { target: { value: "64" } });
    fireEvent.click(screen.getByRole("button", { name: "Remove disk1" }));
    expect(screen.getByText(/Saving deletes disk1/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    const body = calls.find((c) => c.method === "PUT")!.body as { spec: { disks: unknown[] }; removeDisks: string[] };
    expect(body.removeDisks).toEqual(["disk1"]);
    expect(body.spec.disks).toEqual([{ name: "disk0", sizeGB: 64, bus: "virtio-scsi" }]);
  });

  it("shows part D's devices when its API is there", async () => {
    serve(routes({ "/devices": () => ({ gpus: [{ id: "0000:01:00.0", name: "Quadro RTX 4000" }], pci: [], usb: [] }) }), []);
    const picked: unknown[] = [];
    wrap(<DevicesStep template={win11} devices={[]} onChange={(d) => picked.push(d)} />);
    fireEvent.click(await screen.findByRole("button", { name: /Quadro RTX 4000/ }));
    expect(picked).toEqual([[{ kind: "gpu", id: "0000:01:00.0" }]]);
  });
});

// noVNC, as far as the console window uses it.
const rfbs: { url: string; options: unknown; calls: string[] }[] = [];
vi.mock("@novnc/novnc", () => ({
  default: class extends EventTarget {
    calls: string[] = [];
    scaleViewport = false;
    resizeSession = false;
    focusOnClick = false;
    background = "";
    constructor(_el: HTMLElement, url: string, options: unknown) {
      super();
      rfbs.push({ url, options, calls: this.calls });
      setTimeout(() => this.dispatchEvent(new Event("connect")), 0);
    }
    sendCtrlAltDel() {
      this.calls.push("ctrl-alt-del");
    }
    sendKey(k: number, _c: string | null, down: boolean) {
      this.calls.push(`${down ? "down" : "up"}:${k}`);
    }
    focus() {}
    disconnect() {
      this.calls.push("disconnect");
    }
  },
}));

describe("VM screen window", () => {
  it("asks for a one-time pass, connects noVNC and sends keys", async () => {
    const calls: Call[] = [];
    serve({ "POST /vms/web/console": () => ({ token: "t", expires: "", path: "/api/v1/vms/web/console/ws?token=t" }) }, calls);
    const { unmount } = wrap(<ConsoleView id="web" name="Web server" />);
    await waitFor(() => expect(rfbs).toHaveLength(1));
    expect(rfbs[0]!.url).toMatch(/^ws:\/\/.+\/api\/v1\/vms\/web\/console\/ws\?token=t$/);
    expect(rfbs[0]!.options).toEqual({ wsProtocols: ["binary"] });
    await waitFor(() => expect((screen.getByRole("button", { name: /Ctrl\+Alt\+Del/ }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: /Ctrl\+Alt\+Del/ }));
    fireEvent.click(screen.getByRole("button", { name: /Type text/ }));
    fireEvent.change(await screen.findByLabelText("Text to type"), { target: { value: "hi" } });
    fireEvent.click(screen.getByRole("button", { name: "Type it" }));
    expect(rfbs[0]!.calls).toEqual(["ctrl-alt-del", "down:104", "up:104", "down:105", "up:105"]);
    unmount();
    expect(rfbs[0]!.calls.at(-1)).toBe("disconnect");
  });
});
