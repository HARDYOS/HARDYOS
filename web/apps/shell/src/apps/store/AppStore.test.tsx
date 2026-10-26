import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppStoreView, appUrl } from "./AppStore";

type Call = { method: string; path: string; body: unknown };

const icon = "data:image/svg+xml;base64,PHN2Zy8+";

const kincast = {
  source: "catalog",
  ref: "kincast",
  id: "kincast",
  name: "KinCast",
  version: "1.1.0",
  summary: "Your family's private YouTube.",
  description: "Share home videos and go live.",
  publisher: "Hardy Networks",
  website: "https://github.com/hardynetworks/kintube",
  icon,
  minMemoryMB: 2048,
  ports: [
    { name: "WEB", label: "Website", default: 8095, protocol: "tcp", web: true },
    { name: "RTMP", label: "Live streaming", default: 1935, protocol: "tcp", web: false },
  ],
  settings: [
    { env: "MAX_UPLOAD_GB", label: "Largest video upload (GB)", help: "", type: "number", default: "20", options: [], required: true },
    { env: "X264_PRESET", label: "Processing speed", help: "", type: "select", default: "veryfast", options: ["veryfast", "fast"], required: false },
    { env: "ADMIN_PASSWORD", label: "Admin password", help: "", type: "password", default: "", options: [], required: true },
    { env: "KEEP_ORIGINALS", label: "Keep originals", help: "", type: "boolean", default: "true", options: [], required: false },
  ],
  permissions: [],
  images: ["postgres:16-alpine", "ghcr.io/hardynetworks/kintube:${KINCAST_TAG}"],
};

const installed = {
  id: "kincast",
  name: "KinCast",
  version: "1.0.0",
  summary: "Your family's private YouTube.",
  publisher: "Hardy Networks",
  website: "",
  icon,
  dataset: "tank/apps/kincast",
  state: "running",
  containers: [{ service: "app", state: "running", health: "healthy", status: "Up 3 minutes (healthy)", image: "x" }],
  ports: [{ name: "WEB", label: "Website", port: 8095, protocol: "tcp" }],
  web: { port: 8095, path: "/", scheme: "http" },
  installedAt: "2026-10-26T01:00:00Z",
  updatedAt: "2026-10-26T01:00:00Z",
};

function serve(state: { installed: boolean; configured: boolean }, calls: Call[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const path = new URL(req.url).pathname.replace("/api/v1", "");
      const body = req.method !== "GET" ? await req.clone().json().catch(() => null) : null;
      calls.push({ method: req.method, path, body });
      const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });
      if (path === "/apps")
        return json({
          available: true,
          configured: state.configured,
          pool: state.configured ? "tank" : "",
          engineRunning: state.configured,
          engineVersion: state.configured ? "26.1.5" : "",
          problem: "",
          apps: state.installed ? [installed] : [],
          keptData: [],
          updates: state.installed ? { kincast: "1.1.0" } : {},
        });
      if (path === "/apps/catalog") return json([kincast]);
      if (path === "/apps/plan")
        return json({
          package: kincast,
          ports: { WEB: 8096, RTMP: 1935 },
          pools: state.configured ? [] : ["tank", "media"],
          enginePool: state.configured ? "tank" : "",
          installed: state.installed,
          installedVersion: state.installed ? "1.0.0" : "",
          keptData: false,
          available: true,
          problem: "",
        });
      if (path === "/apps/install" && req.method === "POST")
        return json({ job: { id: "job-1", kind: "apps.install", title: "Install KinCast 1.1.0", state: "queued", progress: 0, message: "" }, warnings: [] }, 202);
      if (path === "/jobs/job-1") return json({ id: "job-1", kind: "apps.install", title: "Install KinCast 1.1.0", state: "running", progress: 40, message: "Downloading app (2 of 3)" });
      if (path === "/apps/kincast/stop") return json({ ...installed, state: "stopped" });
      if (path === "/apps/kincast" && req.method === "DELETE")
        return json({ job: { id: "job-2", kind: "apps.remove", title: "Remove KinCast", state: "queued", progress: 0, message: "" }, warnings: [] }, 202);
      if (path === "/jobs/job-2") return json({ id: "job-2", kind: "apps.remove", title: "Remove KinCast", state: "running", progress: 20, message: "Stopping" });
      return json({ code: "not_found", message: path }, 404);
    }),
  );
}

function renderStore(isAdmin = true) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <AppStoreView isAdmin={isAdmin} />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("App Store", () => {
  it("installs an app from the catalog with its settings", async () => {
    const calls: Call[] = [];
    serve({ installed: false, configured: false }, calls);
    renderStore();
    expect(await screen.findByText("No apps yet")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Browse apps" }));
    const card = await screen.findByRole("article", { name: "KinCast" });
    fireEvent.click(within(card).getByRole("button", { name: "Install" }));

    const dialog = await screen.findByRole("dialog", { name: "Install KinCast" });
    // First app: choose the pool. Ports come from the plan (the default was taken).
    expect((within(dialog).getByLabelText("Pool for apps") as HTMLSelectElement).value).toBe("tank");
    expect((within(dialog).getByLabelText("Website") as HTMLInputElement).value).toBe("8096");
    expect(within(dialog).getByText(/can only see its own folder/)).toBeTruthy();
    const install = within(dialog).getByRole("button", { name: "Install" }) as HTMLButtonElement;
    // The required password is still empty.
    expect(install.disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText("Admin password"), { target: { value: "s3cret-pass" } });
    fireEvent.change(within(dialog).getByLabelText("Pool for apps"), { target: { value: "media" } });
    fireEvent.change(within(dialog).getByLabelText("Live streaming"), { target: { value: "80" } });
    expect(within(dialog).getByText("Use a port from 1024 to 65535")).toBeTruthy();
    fireEvent.change(within(dialog).getByLabelText("Live streaming"), { target: { value: "1936" } });
    expect(install.disabled).toBe(false);
    fireEvent.click(install);

    expect(await screen.findByText("Downloading app (2 of 3)")).toBeTruthy();
    const req = calls.find((c) => c.path === "/apps/install")!;
    expect(req.body).toEqual({
      source: "catalog",
      ref: "kincast",
      pool: "media",
      ports: { WEB: 8096, RTMP: 1936 },
      settings: { MAX_UPLOAD_GB: "20", X264_PRESET: "veryfast", ADMIN_PASSWORD: "s3cret-pass", KEEP_ORIGINALS: "true" },
    });
  });

  it("shows installed apps with an update, and stops and removes them", async () => {
    const calls: Call[] = [];
    serve({ installed: true, configured: true }, calls);
    renderStore();
    const card = await screen.findByRole("article", { name: "KinCast" });
    expect(within(card).getByText("Running")).toBeTruthy();
    expect(within(card).getByText("Version 1.1.0 is available")).toBeTruthy();
    expect(within(card).getByRole("link", { name: "Open" }).getAttribute("href")).toBe(`http://${window.location.hostname}:8095/`);

    fireEvent.click(within(card).getByRole("button", { name: /Stop/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/apps/kincast/stop")).toBe(true));

    fireEvent.click(within(card).getByRole("button", { name: "Remove KinCast" }));
    const dialog = await screen.findByRole("dialog", { name: "Remove KinCast?" });
    const remove = within(dialog).getByRole("button", { name: "Remove" }) as HTMLButtonElement;
    expect(remove.disabled).toBe(true);
    fireEvent.click(within(dialog).getByRole("switch", { name: /Also delete its data/ }));
    fireEvent.change(within(dialog).getByLabelText("Type KinCast to confirm"), { target: { value: "kincast" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove and delete data" }));
    await waitFor(() => expect(calls.find((c) => c.method === "DELETE")?.body).toEqual({ confirm: "kincast", deleteData: true }));
    expect(await screen.findByText("Stopping")).toBeTruthy();
  });

  it("reinstalling keeps current settings unless changed", async () => {
    const calls: Call[] = [];
    serve({ installed: true, configured: true }, calls);
    renderStore();
    fireEvent.click(await screen.findByRole("button", { name: "Discover" }));
    const card = await screen.findByRole("article", { name: "KinCast" });
    fireEvent.click(within(card).getByRole("button", { name: "Reinstall…" }));
    const dialog = await screen.findByRole("dialog", { name: "Reinstall KinCast" });
    expect(within(dialog).queryByLabelText("Pool for apps")).toBeNull();
    fireEvent.change(within(dialog).getByLabelText("Processing speed"), { target: { value: "fast" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Reinstall" }));
    await waitFor(() => expect(calls.find((c) => c.path === "/apps/install")?.body).toEqual({
      source: "catalog",
      ref: "kincast",
      ports: { WEB: 8096, RTMP: 1935 },
      settings: { X264_PRESET: "fast" },
    }));
  });

  it("family members can open apps but not manage them", async () => {
    serve({ installed: true, configured: true }, []);
    renderStore(false);
    const card = await screen.findByRole("article", { name: "KinCast" });
    expect(within(card).getByRole("link", { name: "Open" })).toBeTruthy();
    expect(within(card).queryByRole("button", { name: /Stop/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Discover" })).toBeNull();
    expect(screen.queryByText(/Upload a package/)).toBeNull();
  });

  it("builds app addresses on the desktop's host", () => {
    expect(appUrl({ web: { port: 8095, path: "/", scheme: "http" } }, "nas.local")).toBe("http://nas.local:8095/");
    expect(appUrl({ web: null }, "nas.local")).toBeNull();
  });
});
