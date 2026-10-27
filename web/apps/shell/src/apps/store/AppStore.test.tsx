import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppFrameView, frameable } from "./AppFrame";
import { AppStoreView, appUrl } from "./AppStore";
import { idFromName } from "./CreateApp";

type Call = { method: string; path: string; body: unknown };
type Handler = (req: { method: string; path: string; body: unknown; query: URLSearchParams }) => unknown;

const icon = "data:image/svg+xml;base64,PHN2Zy8+";

const kincast = {
  source: "catalog",
  ref: "kincast",
  sourceName: "",
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
  grants: [],
  shares: [],
  fixedPorts: false,
  images: ["postgres:16-alpine", "ghcr.io/hardynetworks/kintube:${KINCAST_TAG}"],
};

const labnotes = {
  ...kincast,
  source: "imported",
  ref: "a".repeat(64),
  sourceName: "Hardy Labs",
  catalogId: 1,
  id: "labnotes",
  name: "Lab Notes",
  version: "2.0.0",
  publisher: "Labs",
  ports: [{ name: "WEB", label: "Website", default: 8300, protocol: "tcp", web: true }],
  settings: [],
  permissions: ["Uses the host network"],
  grants: [{ grant: "hostNetwork", label: "Use the server's network directly" }],
  shares: [{ name: "MEDIA", label: "Media library", help: "Where your videos are", access: "write", suggest: "media", required: true }],
  fixedPorts: true,
  images: ["ghcr.io/lab/notes:2"],
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
  source: "catalog",
  sourceName: "",
  uid: 30001,
  shares: [{ name: "MEDIA", label: "Videos", share: "media", path: "Home videos", access: "read" }],
  grants: [],
  limits: { memoryMB: 0, cpus: 0 },
  permissions: [],
};

const job = (id: string, kind: string, state = "running", extra: Record<string, unknown> = {}) => ({
  id,
  kind,
  title: kind,
  state,
  progress: 40,
  message: `${kind} working`,
  error: "",
  result: {},
  ...extra,
});
const accepted = (id: string, kind: string) => ({ __status: 202, job: job(id, kind, "queued"), warnings: [] });

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

function overview(apps: unknown[], updates: Record<string, string> = {}) {
  return { available: true, configured: true, pool: "tank", engineRunning: true, engineVersion: "26.1.5", problem: "", apps, keptData: [], updates };
}

const plan = (pkg: unknown, extra: Record<string, unknown> = {}) => ({
  package: pkg,
  ports: { WEB: 8096, RTMP: 1935 },
  pools: [],
  enginePool: "tank",
  installed: false,
  installedVersion: "",
  keptData: false,
  available: true,
  problem: "",
  ...extra,
});

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const next = (dialog: HTMLElement) => fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));

describe("App Store install", () => {
  it("installs a catalog app step by step with its settings", async () => {
    const calls: Call[] = [];
    serve(
      {
        "/apps": () => ({ ...overview([]), configured: false, pool: "" }),
        "/apps/catalog": () => [kincast],
        "/apps/catalogs": () => [],
        "/apps/plan": () => plan(kincast, { pools: ["tank", "media"], enginePool: "" }),
        "/users": () => [],
        "/domain": () => ({ __status: 404, code: "not_found", message: "" }),
        "POST /apps/install": () => accepted("job-1", "apps.install"),
        "/jobs/job-1": () => job("job-1", "apps.install"),
      },
      calls,
    );
    wrap(<AppStoreView isAdmin />);
    expect(await screen.findByText("No apps yet")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Browse apps" }));
    const card = await screen.findByRole("article", { name: "KinCast" });
    fireEvent.click(within(card).getByRole("button", { name: "Install" }));

    const dialog = await screen.findByRole("dialog", { name: "Install KinCast" });
    expect((within(dialog).getByLabelText("Pool for apps") as HTMLSelectElement).value).toBe("tank");
    expect((within(dialog).getByLabelText("Website") as HTMLInputElement).value).toBe("8096");
    const nextBtn = within(dialog).getByRole("button", { name: "Next" }) as HTMLButtonElement;
    // The required password is still empty.
    expect(nextBtn.disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText("Admin password"), { target: { value: "s3cret-pass" } });
    fireEvent.change(within(dialog).getByLabelText("Pool for apps"), { target: { value: "media" } });
    fireEvent.change(within(dialog).getByLabelText("Live streaming"), { target: { value: "80" } });
    expect(within(dialog).getByText("Use a port from 1024 to 65535")).toBeTruthy();
    fireEvent.change(within(dialog).getByLabelText("Live streaming"), { target: { value: "1936" } });
    expect(nextBtn.disabled).toBe(false);
    next(dialog);
    // No shares: straight to permissions, plainly labelled.
    expect(within(dialog).getByText(/can only see its own folder/)).toBeTruthy();
    next(dialog);
    expect(within(dialog).getByRole("switch", { name: /Everyone signed in/ })).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Install" }));

    expect(await screen.findByText("apps.install working")).toBeTruthy();
    expect(calls.find((c) => c.path === "/apps/install")!.body).toEqual({
      source: "catalog",
      ref: "kincast",
      pool: "media",
      ports: { WEB: 8096, RTMP: 1936 },
      settings: { MAX_UPLOAD_GB: "20", X264_PRESET: "veryfast", ADMIN_PASSWORD: "s3cret-pass", KEEP_ORIGINALS: "true" },
    });
  });

  it("installs a third-party app with shared folders, ticked permissions, limits and who can use it", async () => {
    const calls: Call[] = [];
    serve(
      {
        "/apps": () => overview([]),
        "/apps/catalog": () => [],
        "/apps/catalogs": () => [
          {
            id: 1,
            url: "https://labs.example/index.json",
            name: "Hardy Labs",
            addedAt: "2026-10-26T01:00:00Z",
            addedBy: "cade",
            fetchedAt: "2026-10-26T01:00:00Z",
            lastError: "",
            apps: [{ id: "labnotes", name: "Lab Notes", version: "2.0.0", summary: "Notes.", url: "https://labs.example/l.hardyapp", sha256: "a".repeat(64), icon: "" }],
          },
        ],
        "/apps/plan": () => plan(labnotes, { ports: { WEB: 8300 } }),
        "/shares": () => ({
          shares: [
            { id: "media", name: "Media", description: "", pool: "tank", path: "/mnt/tank/shares/media", mounted: true, apps: [] },
            { id: "backups", name: "Backups", description: "", pool: "tank", path: "/mnt/tank/shares/backups", mounted: true, apps: [] },
          ],
        }),
        "/users": () => [{ id: 2, username: "kid", displayName: "Kid", email: "", role: "user", disabled: false, breakGlass: false, createdAt: "", lastLoginAt: null }],
        "/domain": () => ({ provisioned: true, config: { netbios: "HOME" }, running: true, responding: true, problem: "", available: true }),
        "/domain/users": () => ({ users: [] }),
        "/domain/groups": () => ({ groups: [{ name: "Family", description: "", members: [], builtin: false }] }),
        "POST /apps/install": () => accepted("job-1", "apps.install"),
        "/jobs/job-1": () => job("job-1", "apps.install"),
      },
      calls,
    );
    wrap(<AppStoreView isAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: "Discover" }));
    const section = await screen.findByRole("region", { name: "Hardy Labs" });
    expect(within(section).getAllByText("Third-party").length).toBeGreaterThan(0);
    fireEvent.click(within(within(section).getByRole("article", { name: "Lab Notes" })).getByRole("button", { name: "Install" }));

    const dialog = await screen.findByRole("dialog", { name: "Install Lab Notes" });
    expect(within(dialog).getByText("Third-party")).toBeTruthy();
    // Host-network apps keep their ports.
    expect((within(dialog).getByLabelText("Website") as HTMLInputElement).readOnly).toBe(true);
    next(dialog);

    // The suggested shared folder is preselected (whole folders only); make it read-only.
    await waitFor(() => expect((within(dialog).getByLabelText("Shared folder for Media library") as HTMLSelectElement).value).toBe("media"));
    expect(within(dialog).queryByLabelText(/Subfolder/)).toBeNull();
    fireEvent.click(within(dialog).getByRole("switch", { name: /Only let it read/ }));
    next(dialog);

    // Not from the catalog: unticked boxes and a red warning; can't go on without them.
    expect(within(dialog).getByRole("alert").textContent).toMatch(/isn't from HardyOS's catalog/);
    const box = within(dialog).getByRole("checkbox", { name: /network directly/ }) as HTMLInputElement;
    expect(box.checked).toBe(false);
    expect((within(dialog).getByRole("button", { name: "Next" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(box);
    next(dialog);

    // Only the kid and the Family group, with a memory limit.
    fireEvent.click(within(dialog).getByRole("switch", { name: /Everyone signed in/ }));
    expect((within(dialog).getByRole("button", { name: "Install" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(await within(dialog).findByRole("checkbox", { name: "kid" }));
    fireEvent.click(await within(dialog).findByRole("checkbox", { name: "HOME\\Family" }));
    fireEvent.click(within(dialog).getByText("Advanced: resource limits"));
    fireEvent.change(within(dialog).getByLabelText("Memory limit (MB)"), { target: { value: "512" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Install" }));

    await waitFor(() =>
      expect(calls.find((c) => c.path === "/apps/install")?.body).toEqual({
        source: "imported",
        ref: "a".repeat(64),
        catalogId: 1,
        ports: { WEB: 8300 },
        settings: {},
        shares: { MEDIA: { share: "media", path: "", access: "read" } },
        grants: ["hostNetwork"],
        limits: { memoryMB: 512, cpus: 0 },
        access: [
          { kind: "user", name: "kid" },
          { kind: "group", name: "HOME\\Family" },
        ],
      }),
    );
    // The plan names the catalog the admin installs from.
    expect(calls.find((c) => c.path === "/apps/plan")?.body).toEqual({ source: "imported", ref: "a".repeat(64), catalogId: 1 });
  });

  it("reinstalling keeps current settings unless changed", async () => {
    const calls: Call[] = [];
    serve(
      {
        "/apps": () => overview([installed], { kincast: "1.1.0" }),
        "/apps/catalog": () => [kincast],
        "/apps/catalogs": () => [],
        "/apps/plan": () => plan(kincast, { installed: true, installedVersion: "1.0.0" }),
        "/users": () => [],
        "/domain": () => ({ __status: 404, code: "x", message: "" }),
        "POST /apps/install": () => accepted("job-1", "apps.install"),
        "/jobs/job-1": () => job("job-1", "apps.install"),
      },
      calls,
    );
    wrap(<AppStoreView isAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: "Discover" }));
    fireEvent.click(within(await screen.findByRole("article", { name: "KinCast" })).getByRole("button", { name: "Reinstall…" }));
    const dialog = await screen.findByRole("dialog", { name: "Reinstall KinCast" });
    expect(within(dialog).queryByLabelText("Pool for apps")).toBeNull();
    fireEvent.change(within(dialog).getByLabelText("Processing speed"), { target: { value: "fast" } });
    next(dialog);
    next(dialog);
    fireEvent.click(within(dialog).getByRole("button", { name: "Reinstall" }));
    await waitFor(() =>
      expect(calls.find((c) => c.path === "/apps/install")?.body).toEqual({ source: "catalog", ref: "kincast", ports: { WEB: 8096, RTMP: 1935 }, settings: { X264_PRESET: "fast" } }),
    );
  });
});

describe("Installed apps", () => {
  const base = (calls: Call[], extra: Record<string, Handler> = {}) =>
    serve(
      {
        "/apps": () => overview([installed], { kincast: "1.1.0" }),
        "/users": () => [{ id: 2, username: "kid", displayName: "", email: "", role: "user", disabled: false, breakGlass: false, createdAt: "", lastLoginAt: null }],
        "/domain": () => ({ __status: 404, code: "x", message: "" }),
        "POST /apps/kincast/stop": () => ({ ...installed, state: "stopped" }),
        "DELETE /apps/kincast": () => accepted("job-2", "apps.remove"),
        "/jobs/job-2": () => job("job-2", "apps.remove"),
        "/apps/kincast/config": () => ({
          id: "kincast",
          source: "catalog",
          sourceName: "",
          uid: 30001,
          manifest: {},
          ports: { WEB: 8095 },
          settings: [
            { env: "X264_PRESET", value: "veryfast", set: true },
            { env: "ADMIN_PASSWORD", value: "", set: true },
          ],
          shares: [],
          grants: [],
          limits: { memoryMB: 0, cpus: 0 },
          package: { ...kincast, ports: [kincast.ports[0]], settings: [kincast.settings[1], kincast.settings[2]] },
        }),
        "PATCH /apps/kincast/config": () => accepted("job-4", "apps.reconfigure"),
        "/jobs/job-4": () => job("job-4", "apps.reconfigure"),
        "/apps/kincast/access": () => ({ principals: [] }),
        "PUT /apps/kincast/access": (r) => r.body,
        "/apps/kincast/snapshots": () => ({ snapshots: [{ name: "hardyos-update-20261026-120000", created: "2026-10-26T12:00:00Z", version: "1.0.0" }] }),
        "POST /apps/kincast/rollback": () => accepted("job-5", "apps.rollback"),
        "/jobs/job-5": () => job("job-5", "apps.rollback"),
        ...extra,
      },
      calls,
    );

  it("shows apps with an update, opens them in windows, stops and removes them", async () => {
    const calls: Call[] = [];
    base(calls);
    const onOpen = vi.fn();
    wrap(<AppStoreView isAdmin onOpen={onOpen} />);
    const card = await screen.findByRole("article", { name: "KinCast" });
    expect(within(card).getByText("Running")).toBeTruthy();
    expect(within(card).getByText("Version 1.1.0 is available")).toBeTruthy();
    expect(within(card).getByText(/A snapshot is taken first/)).toBeTruthy();
    fireEvent.click(within(card).getByRole("button", { name: "Open" }));
    expect(onOpen).toHaveBeenCalledWith(expect.objectContaining({ id: "kincast", name: "KinCast" }));

    fireEvent.click(within(card).getByRole("button", { name: /Stop/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/apps/kincast/stop")).toBe(true));

    fireEvent.click(within(card).getByRole("button", { name: "Remove KinCast" }));
    const dialog = await screen.findByRole("dialog", { name: "Remove KinCast?" });
    expect((within(dialog).getByRole("button", { name: "Remove" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(within(dialog).getByRole("switch", { name: /Also delete its data/ }));
    fireEvent.change(within(dialog).getByLabelText("Type KinCast to confirm"), { target: { value: "kincast" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove and delete data" }));
    await waitFor(() => expect(calls.find((c) => c.method === "DELETE")?.body).toEqual({ confirm: "kincast", deleteData: true }));
    expect(await screen.findByText("apps.remove working")).toBeTruthy();
  });

  it("changes settings, who can use it, and rolls back from the details view", async () => {
    const calls: Call[] = [];
    base(calls);
    wrap(<AppStoreView isAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: "KinCast settings" }));
    expect(await screen.findByRole("tablist", { name: "KinCast sections" })).toBeTruthy();
    expect(screen.getByText(/uid 30001/)).toBeTruthy();
    expect(screen.getByText(/Home videos/)).toBeTruthy();

    fireEvent.click(screen.getByRole("tab", { name: "Settings" }));
    const speed = (await screen.findByLabelText("Processing speed")) as HTMLSelectElement;
    expect(speed.value).toBe("veryfast");
    expect((screen.getByLabelText("Admin password") as HTMLInputElement).placeholder).toBe("Keep current password");
    fireEvent.change(speed, { target: { value: "fast" } });
    fireEvent.change(screen.getByLabelText("Memory limit (MB)"), { target: { value: "1024" } });
    fireEvent.click(screen.getByRole("button", { name: "Save and restart" }));
    await waitFor(() =>
      expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ settings: { X264_PRESET: "fast" }, limits: { memoryMB: 1024, cpus: 0 } }),
    );
    expect(await screen.findByText("apps.reconfigure working")).toBeTruthy();

    fireEvent.click(screen.getByRole("tab", { name: "Who can use it" }));
    fireEvent.click(await screen.findByRole("switch", { name: /Everyone signed in/ }));
    fireEvent.click(await screen.findByRole("checkbox", { name: "kid" }));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ principals: [{ kind: "user", name: "kid" }] }));

    fireEvent.click(screen.getByRole("tab", { name: "Snapshots" }));
    fireEvent.click(await screen.findByRole("button", { name: "Roll back" }));
    const confirm = await screen.findByRole("dialog", { name: "Roll KinCast back?" });
    fireEvent.change(within(confirm).getByLabelText("Type KinCast to confirm"), { target: { value: "KinCast" } });
    fireEvent.click(within(confirm).getByRole("button", { name: "Roll back" }));
    await waitFor(() =>
      expect(calls.find((c) => c.path === "/apps/kincast/rollback")?.body).toEqual({ snapshot: "hardyos-update-20261026-120000", confirm: "KinCast" }),
    );
  });

  it("shows a blocked app and takes the admin to its settings", async () => {
    const calls: Call[] = [];
    const blocked = { ...installed, state: "stopped", blocked: "after going back to hardyos-update-1 it needs something it isn't allowed now: the GPU." };
    base(calls, { "/apps": () => overview([blocked]) });
    wrap(<AppStoreView isAdmin />);
    const card = await screen.findByRole("article", { name: "KinCast" });
    expect(within(card).getByText("KinCast can't start yet")).toBeTruthy();
    expect(within(card).getByText(/needs something it isn't allowed now/)).toBeTruthy();
    expect((within(card).getByRole("button", { name: /Start/ }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(within(card).getByRole("button", { name: "Open settings" }));
    expect(await screen.findByLabelText("Processing speed")).toBeTruthy();
    expect(screen.getByRole("tab", { name: "Settings" }).getAttribute("aria-selected")).toBe("true");
  });

  it("shows a rollback that restored the data but needs a permission as restored", async () => {
    const calls: Call[] = [];
    base(calls, {
      "/jobs/job-5": () =>
        job("job-5", "apps.rollback", "failed", {
          error: "KinCast's data is back at hardyos-update-20261026-120000, but the app stays stopped",
          result: { id: "kincast", snapshot: "hardyos-update-20261026-120000", restored: true, blocked: "it needs the GPU again." },
        }),
    });
    wrap(<AppStoreView isAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: "KinCast settings" }));
    fireEvent.click(await screen.findByRole("tab", { name: "Snapshots" }));
    fireEvent.click(await screen.findByRole("button", { name: "Roll back" }));
    const confirm = await screen.findByRole("dialog", { name: "Roll KinCast back?" });
    fireEvent.change(within(confirm).getByLabelText("Type KinCast to confirm"), { target: { value: "KinCast" } });
    fireEvent.click(within(confirm).getByRole("button", { name: "Roll back" }));
    expect(await screen.findByText("Restored — needs a permission before it can start")).toBeTruthy();
    expect(screen.getByText(/it needs the GPU again/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Open settings" }));
    expect(await screen.findByLabelText("Processing speed")).toBeTruthy();
  });

  it("offers a rollback when an update fails after its snapshot", async () => {
    const calls: Call[] = [];
    base(calls, {
      "POST /apps/kincast/update": () => accepted("job-3", "apps.update"),
      "/jobs/job-3": () => job("job-3", "apps.update", "failed", { error: "the app didn't start", result: { id: "kincast", snapshot: "hardyos-update-20261026-120000" } }),
    });
    wrap(<AppStoreView isAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: "KinCast settings" }));
    expect(await screen.findByText(/A snapshot of KinCast is taken first/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Update" }));
    expect(await screen.findByText("The update didn't finish")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Roll back…" }));
    expect(await screen.findByRole("button", { name: "Roll back" })).toBeTruthy();
  });

  it("asks for new permissions an update needs", async () => {
    const calls: Call[] = [];
    let n = 0;
    base(calls, {
      "/apps": () => overview([{ ...installed, source: "imported", sourceName: "Hardy Labs", grants: ["hostNetwork"] }], { kincast: "1.1.0" }),
      "POST /apps/kincast/update": () =>
        n++ === 0
          ? { __status: 400, code: "grants_required", message: "asks for more", details: ["GPU"], grants: [{ grant: "gpu", label: "Use the graphics card" }] }
          : accepted("job-3", "apps.update"),
      "/jobs/job-3": () => job("job-3", "apps.update"),
    });
    wrap(<AppStoreView isAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: "KinCast settings" }));
    fireEvent.click(await screen.findByRole("button", { name: "Update" }));
    const dialog = await screen.findByRole("dialog", { name: "The new KinCast asks for more" });
    const allow = within(dialog).getByRole("button", { name: "Allow and update" }) as HTMLButtonElement;
    expect(allow.disabled).toBe(true);
    fireEvent.click(within(dialog).getByRole("checkbox", { name: /graphics card/ }));
    fireEvent.click(allow);
    await waitFor(() => expect(calls.filter((c) => c.path === "/apps/kincast/update")[1]?.body).toEqual({ grants: ["hostNetwork", "gpu"] }));
  });

  it("family members can open the apps they may use but not manage them", async () => {
    base([]);
    const onOpen = vi.fn();
    wrap(<AppStoreView isAdmin={false} onOpen={onOpen} />);
    const card = await screen.findByRole("article", { name: "KinCast" });
    fireEvent.click(within(card).getByRole("button", { name: "Open" }));
    expect(onOpen).toHaveBeenCalled();
    expect(within(card).queryByRole("button", { name: /Stop/ })).toBeNull();
    expect(within(card).queryByText(/Version 1.1.0/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Discover" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Catalogs" })).toBeNull();
    expect(screen.queryByText(/Upload a package/)).toBeNull();
  });

  it("warns in red and needs a tick before another source takes over an installed app", async () => {
    const calls: Call[] = [];
    const evil = { ...kincast, source: "imported", ref: "e".repeat(64), sourceName: "Evil Apps", catalogId: 7, settings: [] };
    serve(
      {
        "/apps": () => overview([installed]),
        "/apps/catalog": () => [],
        "/apps/catalogs": () => [
          {
            id: 7,
            url: "https://evil.example/index.json",
            name: "Evil Apps",
            addedAt: "",
            addedBy: "cade",
            fetchedAt: null,
            lastError: "",
            localNetwork: false,
            apps: [{ id: "kincast", name: "KinCast", version: "9.9.9", summary: "", url: "https://evil.example/k.hardyapp", sha256: "e".repeat(64), icon: "" }],
          },
        ],
        "/apps/plan": () =>
          plan(evil, { installed: true, installedVersion: "1.0.0", installedSource: "catalog", installedSourceName: "", replaceSourceRequired: true }),
        "/users": () => [],
        "/domain": () => ({ __status: 404, code: "x", message: "" }),
        "POST /apps/install": () => accepted("job-1", "apps.install"),
        "/jobs/job-1": () => job("job-1", "apps.install"),
      },
      calls,
    );
    wrap(<AppStoreView isAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: "Discover" }));
    const section = await screen.findByRole("region", { name: "Evil Apps" });
    fireEvent.click(within(within(section).getByRole("article", { name: "KinCast" })).getByRole("button", { name: "Reinstall…" }));
    const dialog = await screen.findByRole("dialog", { name: "Reinstall KinCast" });
    const warning = within(dialog).getAllByRole("alert").find((a) => /take over/.test(a.textContent ?? ""));
    expect(warning?.textContent).toMatch(/installed from HardyOS's catalog.*from the Evil Apps catalog/);
    next(dialog);
    next(dialog);
    const install = within(dialog).getByRole("button", { name: "Reinstall" }) as HTMLButtonElement;
    expect(install.disabled).toBe(true);
    fireEvent.click(within(dialog).getByRole("checkbox", { name: /Replace the installed KinCast/ }));
    expect(install.disabled).toBe(false);
    fireEvent.click(install);
    await waitFor(() => expect(calls.find((c) => c.path === "/apps/install")?.body).toMatchObject({ source: "imported", catalogId: 7, replaceSource: true }));
  });
});

describe("Catalogs and custom apps", () => {
  it("imports a catalog", async () => {
    const calls: Call[] = [];
    let list: unknown[] = [];
    serve(
      {
        "/apps": () => overview([]),
        "/apps/catalogs": () => list,
        "POST /apps/catalogs": (r) => {
          list = [{ id: 1, url: (r.body as { url: string }).url, name: "Hardy Labs", addedAt: "", addedBy: "cade", fetchedAt: "2026-10-26T01:00:00Z", lastError: "1 apps were left out: plain", apps: [] }];
          return list[0];
        },
      },
      calls,
    );
    wrap(<AppStoreView isAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: "Catalogs" }));
    expect(await screen.findByText("No catalogs imported")).toBeTruthy();
    const input = screen.getByLabelText("Catalog address");
    fireEvent.change(input, { target: { value: "http://labs.example/index.json" } });
    expect((screen.getByRole("button", { name: /Import catalog/ }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(input, { target: { value: "https://labs.example/index.json" } });
    fireEvent.click(screen.getByRole("button", { name: /Import catalog/ }));
    expect(await screen.findByText(/were left out/)).toBeTruthy();
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ url: "https://labs.example/index.json", localNetwork: false });

    // A catalog at home needs "On my network" ticked.
    fireEvent.change(input, { target: { value: "https://192.168.1.20/index.json" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /On my network/ }));
    fireEvent.click(screen.getByRole("button", { name: /Import catalog/ }));
    await waitFor(() =>
      expect(calls.filter((c) => c.method === "POST").at(-1)?.body).toEqual({ url: "https://192.168.1.20/index.json", localNetwork: true }),
    );
  });

  it("creates an app from a Compose file and goes on to install it", async () => {
    const calls: Call[] = [];
    const custom = { ...kincast, source: "custom", ref: "c".repeat(64), id: "my-wiki", name: "My Wiki", settings: [], ports: [kincast.ports[0]] };
    serve({ "/apps": () => overview([]), "POST /apps/custom": () => plan(custom, { ports: { WEB: 8080 } }), "/users": () => [], "/domain": () => ({ __status: 404 }) }, calls);
    wrap(<AppStoreView isAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: "Create an app" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "My Wiki" } });
    expect((screen.getByLabelText(/App id/) as HTMLInputElement).value).toBe("my-wiki");
    fireEvent.click(screen.getByRole("button", { name: "Use an example" }));
    fireEvent.click(screen.getByRole("button", { name: "Continue to install" }));
    expect(await screen.findByRole("dialog", { name: "Install My Wiki" })).toBeTruthy();
    const body = calls.find((c) => c.path === "/apps/custom")!.body as Record<string, unknown>;
    expect(body).toMatchObject({ id: "my-wiki", name: "My Wiki", webPort: "WEB", ports: [{ name: "WEB", label: "Website", default: 8080 }] });
    expect(String(body.compose)).toContain("${HARDY_PORT_WEB}");
  });

  it("derives app ids from names", () => {
    expect(idFromName("My Wiki!")).toBe("my-wiki");
    expect(idFromName("3D Printer")).toBe("d-printer");
  });
});

describe("App windows", () => {
  it("frames the app through its proxy", async () => {
    serve({ "POST /apps/kincast/open": () => ({ url: "https://nas.local:44300/__hardyos/auth?token=t", proxied: true }) }, []);
    wrap(<AppFrameView id="kincast" name="KinCast" />);
    const frame = (await screen.findByTitle("KinCast")) as HTMLIFrameElement;
    expect(frame.tagName).toBe("IFRAME");
    expect(frame.src).toBe("https://nas.local:44300/__hardyos/auth?token=t");
    // Sandboxed: no top navigation.
    const sandbox = frame.getAttribute("sandbox") ?? "";
    expect(sandbox.split(" ").sort()).toEqual(
      ["allow-downloads", "allow-forms", "allow-modals", "allow-popups", "allow-popups-to-escape-sandbox", "allow-same-origin", "allow-scripts"].sort(),
    );
    expect(sandbox).not.toContain("top-navigation");
    expect(screen.getByRole("button", { name: /Open in new tab/ })).toBeTruthy();
  });

  it("frames a published app at its own address", async () => {
    serve({ "POST /apps/jellyfin/open": () => ({ url: "https://jellyfin.home.example.net/", proxied: true, published: true }) }, []);
    wrap(<AppFrameView id="jellyfin" name="Jellyfin" />);
    const frame = (await screen.findByTitle("Jellyfin")) as HTMLIFrameElement;
    expect(frame.src).toBe("https://jellyfin.home.example.net/");
    expect(screen.getByText("jellyfin.home.example.net")).toBeTruthy();
  });

  it("knows what a secure desktop can frame", () => {
    expect(frameable({ url: "http://nas:8095/", proxied: false }, "https:")).toBe(false);
    expect(frameable({ url: "http://nas:8095/", proxied: false }, "http:")).toBe(true);
    expect(frameable({ url: "https://nas:44300/", proxied: true }, "https:")).toBe(true);
  });

  it("builds app addresses on the desktop's host", () => {
    expect(appUrl({ web: { port: 8095, path: "/", scheme: "http" } }, "nas.local")).toBe("http://nas.local:8095/");
    expect(appUrl({ web: null }, "nas.local")).toBeNull();
  });
});
