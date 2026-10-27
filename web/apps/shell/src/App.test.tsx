import { QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { queryClient } from "./api";
import { App } from "./App";
import { useWM } from "./wm/store";

type Handler = (req: Request) => { status?: number; body?: unknown } | undefined;

function mockServer(routes: Record<string, Handler>) {
  const calls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request) => {
      const url = new URL(input.url);
      const key = `${input.method} ${url.pathname.replace("/api/v1", "")}`;
      calls.push(key);
      const h = routes[key];
      const res = h?.(input) ?? { status: 404, body: { code: "not_found", message: key } };
      return new Response(res.body === undefined ? null : JSON.stringify(res.body), {
        status: res.status ?? 200,
        headers: { "Content-Type": "application/json" },
      });
    }),
  );
  return calls;
}

const admin = {
  id: 1, username: "cade", displayName: "Cade", email: "", role: "admin", disabled: false, breakGlass: true,
  createdAt: "2026-10-24T00:00:00Z", lastLoginAt: null,
};

const desktopRoutes: Record<string, Handler> = {
  "GET /system/info": () => ({ body: { hostname: "nas-01", os: "Debian GNU/Linux 13 (trixie)", kernel: "6.12", version: "0.1.0", uptimeSecs: 7200 } }),
  "GET /system/metrics": () => ({ body: { current: { time: "2026-10-24T00:00:00Z", cpuPercent: 12, memUsed: 4e9, memTotal: 16e9, arcBytes: 2e9, netRxBps: 1e6, netTxBps: 1e5, load1: 0.3, uptimeSecs: 7200 }, history: [], cpus: 8 } }),
  "GET /storage/pools": () => ({
    body: [
      { name: "rpool", sizeBytes: 250e9, allocBytes: 3e9, freeBytes: 247e9, fragmentation: 0, capacityPct: 1, health: "ONLINE", guid: "0" },
      { name: "tank", sizeBytes: 48e12, allocBytes: 21.4e12, freeBytes: 26.6e12, fragmentation: 2, capacityPct: 45, health: "ONLINE", guid: "1" },
    ],
  }),
  "GET /notifications": () => ({ body: [] }),
};

function renderApp() {
  return render(
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  queryClient.clear();
  useWM.setState({ windows: [], focusedId: null, nextZ: 1 });
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("App", () => {
  it("shows first-run setup and signs the new admin in", async () => {
    let created = false;
    mockServer({
      "GET /setup": () => ({ body: { needsAdmin: !created } }),
      "GET /auth/me": () => (created ? { body: admin } : { status: 401, body: { code: "unauthenticated", message: "sign in required" } }),
      "POST /setup/admin": () => {
        created = true;
        return { status: 201, body: admin };
      },
      ...desktopRoutes,
    });
    renderApp();
    expect(await screen.findByText("Welcome to HardyOS")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "cade" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "supersecret1" } });
    fireEvent.change(screen.getByLabelText("Repeat password"), { target: { value: "supersecret1" } });
    fireEvent.click(screen.getByRole("button", { name: "Create account and continue" }));
    expect(await screen.findByRole("navigation", { name: "Dock" })).toBeTruthy();
    expect(await screen.findByText("nas-01")).toBeTruthy();
  });

  it("signs in, shows the desktop with admin apps, and opens a window from the dock", async () => {
    let signedIn = false;
    mockServer({
      "GET /setup": () => ({ body: { needsAdmin: false } }),
      "GET /auth/me": () => (signedIn ? { body: admin } : { status: 401, body: { code: "unauthenticated", message: "x" } }),
      "POST /auth/login": (req) => {
        void req;
        signedIn = true;
        return { body: admin };
      },
      ...desktopRoutes,
    });
    renderApp();
    fireEvent.change(await screen.findByLabelText("Username"), { target: { value: "cade" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "supersecret1" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    const dock = await screen.findByRole("navigation", { name: "Dock" });
    expect(dock.textContent).toContain("Storage Manager");
    expect(await screen.findByText("tank")).toBeTruthy();
    // The boot pool is the system, not storage: no desktop widget for it.
    expect(screen.queryByText("rpool")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Resource Monitor" }));
    await waitFor(() => expect(useWM.getState().windows).toHaveLength(1));
    expect(screen.getByRole("region", { name: "Resource Monitor window" })).toBeTruthy();
  });

  it("shows the sign-in error and hides admin apps from regular users", async () => {
    let signedIn = false;
    mockServer({
      "GET /setup": () => ({ body: { needsAdmin: false } }),
      "GET /auth/me": () => (signedIn ? { body: { ...admin, id: 2, username: "kid", role: "user" } } : { status: 401, body: { code: "unauthenticated", message: "x" } }),
      "POST /auth/login": (req) => {
        void req;
        if (!signedIn) {
          signedIn = true;
          return { status: 401, body: { code: "bad_credentials", message: "incorrect username or password" } };
        }
        return { body: { ...admin, id: 2, username: "kid", role: "user" } };
      },
      ...desktopRoutes,
    });
    renderApp();
    fireEvent.change(await screen.findByLabelText("Username"), { target: { value: "kid" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "wrong-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("incorrect username or password")).toBeTruthy();

    signedIn = false;
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "kidpassword1" } });
    signedIn = true;
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    const dock = await screen.findByRole("navigation", { name: "Dock" });
    expect(dock.textContent).not.toContain("Storage Manager");
    expect(dock.textContent).not.toContain("Control Panel");
    expect(dock.textContent).toContain("Resource Monitor");
  });

  it("offers domain sign-in and keeps domain users away from the HardyOS password", async () => {
    let signedIn = false;
    let loginBody: Record<string, unknown> | null = null;
    const alice = {
      ...admin, id: 3, username: "HOME\\alice", displayName: "Alice Hardy", role: "user", breakGlass: false,
      source: "domain", principal: "HOME\\alice", groups: ["HOME\\Domain Users", "HOME\\Family"],
    };
    mockServer({
      "GET /setup": () => ({ body: { needsAdmin: false, domainSignIn: true } }),
      "GET /auth/me": () => (signedIn ? { body: alice } : { status: 401, body: { code: "unauthenticated", message: "x" } }),
      "POST /auth/login": (req) => {
        void req.clone().json().then((b) => (loginBody = b as Record<string, unknown>));
        signedIn = true;
        return { body: alice };
      },
      ...desktopRoutes,
    });
    renderApp();
    expect(await screen.findByText(/You can use your domain account/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "HOME\\alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "Al1ce-Passw0rd!" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await screen.findByRole("navigation", { name: "Dock" });
    expect(loginBody).toMatchObject({ username: "HOME\\alice" });
    fireEvent.click(screen.getByRole("button", { name: "Account: Alice Hardy" }));
    expect(screen.getByText(/Your password belongs to the domain/)).toBeTruthy();
    expect(screen.queryByRole("menuitem", { name: /Change password/ })).toBeNull();
  });

  it("runs the live installer: unlock, choose disks, settings, admin, install", async () => {
    let unlocked = false;
    let job: Record<string, unknown> | null = null;
    let installBody: Record<string, unknown> | null = null;
    const disk = (name: string, kind: string, size: number, extra = {}) => ({
      name, path: `/dev/${name}`, byId: `/dev/disk/by-id/ata-${name}`, model: `Model ${name}`, serial: `SN-${name}`, wwn: "",
      transport: "sata", kind, sizeBytes: size, physSector: 4096, removable: false, usage: "free", pool: "",
      usageDetail: "blank", partitions: [], powerLossProt: null, ...extra,
    });
    mockServer({
      "GET /installer": () => ({ body: { active: true, unlocked, version: "0.1.0", ...(job ? { job } : {}) } }),
      "POST /installer/unlock": () => {
        unlocked = true;
        return { body: { active: true, unlocked: true, version: "0.1.0" } };
      },
      "GET /installer/hardware": () => ({
        body: {
          disks: [
            disk("sda", "hdd", 12e12),
            disk("sdb", "ssd", 250e9),
            disk("sdc", "ssd", 250e9),
            disk("sdd", "ssd", 32e9, { removable: true, usage: "mounted", usageDetail: "sdd1 is mounted at /run/live/medium" }),
          ],
          nics: [{ name: "eno1", mac: "aa", speedMbps: 1000, up: true, driver: "e1000e", addresses: ["192.168.1.50/24"] }],
          memBytes: 16e9, cpu: "Test CPU", virtual: false, hostname: "hardyos",
        },
      }),
      "POST /installer/check": () => ({
        body: { version: "0.1.0", bootEnvironment: "hardyos-0.1.0", disks: [{ disk: disk("sdb", "ssd", 250e9), warnings: ["is a test warning"] }] },
      }),
      "POST /installer/install": (req) => {
        void req.clone().json().then((b) => (installBody = b as Record<string, unknown>));
        job = { id: "j1", kind: "system.install", title: "Install HardyOS", state: "running", progress: 20, message: "Copying HardyOS onto the boot disks",
          error: "", params: {}, result: {}, createdBy: null, createdAt: new Date().toISOString(), startedAt: new Date().toISOString(), finishedAt: null };
        return { status: 202, body: job };
      },
    });
    renderApp();

    fireEvent.change(await screen.findByLabelText("Installer code"), { target: { value: "k7qm4txp" } });
    expect((screen.getByLabelText("Installer code") as HTMLInputElement).value).toBe("K7QM-4TXP");
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));

    expect(await screen.findByText("Install HardyOS 0.1.0")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));

    // A fresh server by default (no restore from a cloud backup).
    expect(await screen.findByRole("heading", { name: "Restore from backup" })).toBeTruthy();
    expect((screen.getByRole("radio", { name: "A fresh server" }) as HTMLInputElement).checked).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));

    // The two small SSDs are suggested; the live USB can't be picked.
    expect(await screen.findByText("Choose the boot disks")).toBeTruthy();
    const boxes = screen.getAllByRole("checkbox") as HTMLInputElement[];
    expect(boxes.map((b) => b.checked)).toEqual([false, true, true, false]);
    expect(boxes[3]!.disabled).toBe(true);
    expect(screen.getByText(/Mirrored across 2 disks/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));

    fireEvent.change(await screen.findByLabelText("Server name"), { target: { value: "nas" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));

    fireEvent.change(await screen.findByLabelText("Username"), { target: { value: "cade" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "supersecret1" } });
    fireEvent.change(screen.getByLabelText("Repeat password"), { target: { value: "supersecret1" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));

    expect(await screen.findByText("is a test warning")).toBeTruthy();
    const install = screen.getByRole("button", { name: "Erase disks and install" }) as HTMLButtonElement;
    expect(install.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Type ERASE to confirm"), { target: { value: "erase" } });
    await waitFor(() => expect(install.disabled).toBe(false));
    fireEvent.click(install);

    expect(await screen.findByText("Installing HardyOS")).toBeTruthy();
    await waitFor(() => expect(installBody).not.toBeNull());
    expect(installBody).toMatchObject({
      plan: { disks: ["/dev/disk/by-id/ata-sdb", "/dev/disk/by-id/ata-sdc"], hostname: "nas", network: { mode: "dhcp" } },
      admin: { username: "cade", password: "supersecret1" },
      confirmWipe: true,
    });
  });
});
