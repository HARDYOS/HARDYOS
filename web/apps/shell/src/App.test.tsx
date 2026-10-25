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
  "GET /storage/pools": () => ({ body: [{ name: "tank", sizeBytes: 48e12, allocBytes: 21.4e12, freeBytes: 26.6e12, fragmentation: 2, capacityPct: 45, health: "ONLINE", guid: "1" }] }),
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
});
