import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ConsoleView } from "./Console";
import { inventory } from "./devices/devices.fixtures";
import { VirtualMachinesView } from "./VirtualMachines";
import { caps, linux, win11 } from "./testFixtures";

type Call = { method: string; path: string; body: unknown };
type Handler = () => unknown;

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
      const out = h ? h() : { __status: 404, code: "not_found", message: path };
      const { __status = 200, ...rest } = (out ?? {}) as { __status?: number };
      const payload = Array.isArray(out) ? out : rest;
      return new Response(JSON.stringify(payload), { status: __status, headers: { "Content-Type": "application/json" } });
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

function vm(o: Record<string, unknown>) {
  return {
    description: "", uuid: "u", pool: "tank", video: "virtio", guestAgent: true, boot: ["disk"], autostart: { enabled: false, order: 0, delaySec: 0 },
    devices: [], media: [], firmware: { type: "uefi", secureBoot: false, tpm: false }, nics: [{ mode: "bridge", model: "virtio", mac: "52:54:00:00:00:01" }],
    dataset: "tank/vms/x", cpuPercent: 0, memoryUsedMB: 0, addresses: [], passwordSet: false, restartNeeded: false, diskUsage: { disk0: 1e9 }, liveUSB: [], snapshotsBehind: false,
    cpu: { cores: 2, threads: 1 }, memory: { mb: 4096, balloon: true }, disks: [{ name: "disk0", sizeGB: 32, bus: "virtio-scsi" }], os: "linux",
    ...o,
  };
}

const web = vm({ id: "web", name: "Web server", template: "linux", state: "running", liveUSB: [] });
const win = vm({
  id: "win", name: "Windows 11", template: "windows11", os: "windows", state: "stopped", guestAgent: false,
  media: [{ kind: "iso", iso: "Win11.iso" }, { kind: "virtio" }, { kind: "unattend" }],
  unattend: { user: "kids", locale: "en-US", pending: true, started: true },
});

function routes(extra: Record<string, Handler> = {}): Record<string, Handler> {
  return {
    "/vms": () => ({ vms: [web, win], kept: [] }),
    "/vms/templates": () => [win11, linux],
    "/vms/capabilities": () => caps,
    "/vms/isos": () => ({ pool: "tank", path: "/x", tasks: [], files: [] }),
    "/vms/web": () => web,
    "/vms/win": () => win,
    "/vms/win/snapshots": () => [
      { name: "vm-auto-daily-20261121-0000", label: "Automatic (daily)", created: "2026-11-21T00:00:00Z", bytes: 1e6, consistent: false, kind: "daily" },
    ],
    "/devices": () => inventory(),
    ...extra,
  };
}

describe("VM polish on the VM's page", () => {
  it("saves a snapshot schedule and marks automatic, crash-consistent snapshots", async () => {
    const calls: Call[] = [];
    serve(routes({ "PUT /vms/win/schedule": () => accepted("j1"), "/jobs/j1": () => job("j1") }), calls);
    wrap(<VirtualMachinesView onOpenConsole={() => {}} />);
    fireEvent.click(await screen.findByRole("article", { name: "Windows 11" }));
    fireEvent.click(await screen.findByRole("tab", { name: "Snapshots" }));
    expect(await screen.findByText("Crash-consistent")).toBeTruthy();
    expect(await screen.findByText("Daily")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Daily"), { target: { value: "7" } });
    fireEvent.change(screen.getByLabelText("Weekly"), { target: { value: "4" } });
    fireEvent.click(screen.getByRole("button", { name: "Save schedule" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && c.path === "/vms/win/schedule")).toBe(true));
    expect(calls.find((c) => c.path === "/vms/win/schedule")!.body).toEqual({ schedule: { hourly: 0, daily: 7, weekly: 4, monthly: 0 } });
  });

  it("asks for the VM's name when fewer automatic snapshots would delete some", async () => {
    const calls: Call[] = [];
    let tries = 0;
    serve(
      routes({
        "PUT /vms/win/schedule": () =>
          ++tries === 1
            ? { __status: 400, code: "confirm_required", message: "these counts delete 1 automatic snapshots Windows 11 has now; type the VM's name (Windows 11) to confirm" }
            : accepted("j9"),
        "/jobs/j9": () => job("j9"),
      }),
      calls,
    );
    wrap(<VirtualMachinesView onOpenConsole={() => {}} />);
    fireEvent.click(await screen.findByRole("article", { name: "Windows 11" }));
    fireEvent.click(await screen.findByRole("tab", { name: "Snapshots" }));
    fireEvent.change(await screen.findByLabelText("Hourly"), { target: { value: "1" } });
    fireEvent.click(screen.getByRole("button", { name: "Save schedule" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/delete 1 automatic/)).toBeTruthy();
    fireEvent.change(within(dialog).getByLabelText(/Type Windows 11 to confirm/), { target: { value: "Windows 11" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save and delete" }));
    await waitFor(() => expect(tries).toBe(2));
    expect(calls.filter((c) => c.path === "/vms/win/schedule")[1]!.body).toEqual({ schedule: { hourly: 1, daily: 0, weekly: 0, monthly: 0 }, confirm: "Windows 11" });
  });

  it("takes the Windows setup disc out, and makes a template of a stopped VM", async () => {
    const calls: Call[] = [];
    serve(routes({ "PUT /vms/win": () => accepted("j2"), "/jobs/j2": () => job("j2"), "POST /vms/win/template": () => accepted("j3"), "/jobs/j3": () => job("j3") }), calls);
    wrap(<VirtualMachinesView onOpenConsole={() => {}} />);
    fireEvent.click(await screen.findByRole("article", { name: "Windows 11" }));
    fireEvent.click(await screen.findByRole("button", { name: /take out the setup disc/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && c.path === "/vms/win")).toBe(true));
    const spec = (calls.find((c) => c.method === "PUT")!.body as { spec: { media: { kind: string }[]; unattend?: unknown } }).spec;
    expect(spec.media.map((m) => m.kind)).toEqual(["iso", "virtio"]);
    expect(spec.unattend).toBeUndefined();

    fireEvent.click(await screen.findByRole("tab", { name: "Settings" }));
    fireEvent.click(await screen.findByRole("button", { name: /Make template/ }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Name"), { target: { value: "Clean Windows" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Make template" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/vms/win/template")).toBe(true));
    expect(calls.find((c) => c.path === "/vms/win/template")!.body).toEqual({ templateId: "win-template", name: "Clean Windows", description: "" });
  });

  it("plugs a USB device into a running VM", async () => {
    const calls: Call[] = [];
    serve(routes({ "POST /vms/web/usb": () => accepted("j4"), "/jobs/j4": () => job("j4") }), calls);
    wrap(<VirtualMachinesView onOpenConsole={() => {}} />);
    fireEvent.click(await screen.findByRole("article", { name: "Web server" }));
    fireEvent.click(await screen.findByRole("tab", { name: "Hardware" }));
    const select = (await screen.findByLabelText("Device")) as HTMLSelectElement;
    await waitFor(() => expect(select.options.length).toBeGreaterThan(1));
    // The hub isn't offered.
    expect(Array.from(select.options).some((o) => o.text.includes("Hub"))).toBe(false);
    fireEvent.change(select, { target: { value: "046d:c52b" } });
    fireEvent.click(screen.getByRole("button", { name: /Plug in/ }));
    await waitFor(() => expect(calls.some((c) => c.path === "/vms/web/usb")).toBe(true));
    expect(calls.find((c) => c.path === "/vms/web/usb")!.body).toEqual({ device: "046d:c52b", persist: false });
  });
});

const pasted: string[] = [];
vi.mock("@novnc/novnc", () => ({
  default: class extends EventTarget {
    scaleViewport = false;
    resizeSession = false;
    focusOnClick = false;
    background = "";
    constructor() {
      super();
      setTimeout(() => {
        this.dispatchEvent(new Event("connect"));
        this.dispatchEvent(new CustomEvent("clipboard", { detail: { text: "copied in the guest" } }));
      }, 0);
    }
    clipboardPasteFrom(t: string) {
      pasted.push(t);
    }
    focus() {}
    disconnect() {}
  },
}));

describe("VM screen clipboard", () => {
  it("shows what the guest copied and pastes into it", async () => {
    serve({ "POST /vms/web/console": () => ({ token: "t", expires: "", path: "/api/v1/vms/web/console/ws?token=t" }) }, []);
    wrap(<ConsoleView id="web" name="Web server" />);
    const btn = await screen.findByRole("button", { name: /Clipboard/ });
    await waitFor(() => expect((btn as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(btn);
    const dialog = await screen.findByRole("dialog");
    expect((within(dialog).getByLabelText("Copied in the VM") as HTMLTextAreaElement).value).toBe("copied in the guest");
    fireEvent.change(within(dialog).getByLabelText("To paste into the VM"), { target: { value: "hello vm" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Paste into the VM" }));
    expect(pasted).toEqual(["hello vm"]);
    // No sound card acknowledged: the button stays off.
    expect((screen.getByRole("button", { name: /Sound off/ }) as HTMLButtonElement).disabled).toBe(true);
  });
});
