import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BackupView, BUILTIN_TABS } from "./Backup";
import { EXTRA_TABS } from "./tabs";

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
      return new Response(__status === 204 ? null : JSON.stringify(rest), { status: __status, headers: { "Content-Type": "application/json" } });
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

const target = {
  id: "off",
  name: "Offsite",
  kind: "s3",
  endpoint: "https://s3.example.com",
  bucket: "nas-backups",
  prefix: "hardyos",
  createdAt: "2026-10-20T10:00:00Z",
  accessKeyHint: "…1234",
  maintenance: { weekday: 0, time: "04:30", checkPercent: 5 },
  kitDownloadedAt: null,
  lastCheck: null,
};

const run = { id: "r1", taskId: "t1", kind: "backup", target: "off", jobId: "j", trigger: "schedule", state: "succeeded", startedAt: "2026-10-26T01:30:00Z", finishedAt: "2026-10-26T01:40:00Z", files: 1200, bytes: 5e9, added: 2e8, detail: {}, error: "" };

const task = {
  id: "t1",
  name: "Nightly",
  target: "off",
  items: [{ kind: "share", id: "media" }, { kind: "system" }],
  schedule: { frequency: "daily", time: "01:30" },
  retention: { daily: 7, weekly: 4, monthly: 12 },
  enabled: true,
  createdAt: "",
  updatedAt: "",
  lastRun: run,
  nextRun: "2026-10-28T01:30:00Z",
  running: false,
};

function routes(extra: Record<string, Handler> = {}, tasks: unknown[] = [task]): Record<string, Handler> {
  return {
    "GET /backup": () => ({ targets: [target], tasks, offer: null }),
    "GET /shares": () => ({ shares: [{ id: "media", name: "Media" }, { id: "docs", name: "Documents" }] }),
    "GET /apps": () => ({ apps: [{ id: "kincast", name: "KinCast" }] }),
    "GET /vms": () => ({ vms: [{ id: "web", name: "Web server" }], kept: [] }),
    "GET /backup/runs": () => ({ runs: [run] }),
    "GET /backup/targets/off/versions": () => ({
      versions: [{ run: "r1", task: "t1", time: "2026-10-26T01:30:00Z", manifest: "m", items: [{ item: "share:media", snapshot: "aaaaaaaa", time: "", files: 3, bytes: 300 }] }],
    }),
    "GET /backup/targets/off/browse": () => ({ entries: [{ name: "Photos", path: "Photos", dir: true, type: "dir", size: 0, modified: "2026-10-01T00:00:00Z" }, { name: "a.txt", path: "a.txt", dir: false, type: "file", size: 12, modified: "2026-10-01T00:00:00Z" }] }),
    ...extra,
  };
}

describe("Backup app", () => {
  it("has tabs other parts can add to", () => {
    expect(BUILTIN_TABS.map((t) => t.id)).toEqual(["tasks", "restore", "destinations", "history"]);
    expect(Array.isArray(EXTRA_TABS)).toBe(true);
  });

  it("lists tasks with their last run and switches tabs", async () => {
    const calls: Call[] = [];
    serve(routes(), calls);
    wrap(<BackupView />);
    expect(await screen.findByRole("article", { name: "Nightly" })).toBeTruthy();
    expect(await screen.findByText("Media")).toBeTruthy();
    expect(screen.getByText("Settings and domain")).toBeTruthy();
    fireEvent.click(screen.getByRole("tab", { name: "History" }));
    expect(await screen.findByRole("table")).toBeTruthy();
    fireEvent.click(screen.getByRole("tab", { name: "Destinations" }));
    expect(await screen.findByText("Kit not saved")).toBeTruthy();
  });

  it("makes a task in four steps", async () => {
    const calls: Call[] = [];
    serve(routes({ "POST /backup/tasks": ({ body }) => ({ __status: 201, ...task, ...(body as object), id: "t2" }) }, []), calls);
    wrap(<BackupView />);
    fireEvent.click(await screen.findByRole("button", { name: /Make a backup task/ }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(await within(dialog).findByRole("checkbox", { name: "Documents" }));
    fireEvent.click(within(dialog).getByRole("checkbox", { name: /Settings and domain/ }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    fireEvent.change(within(dialog).getByLabelText("How often"), { target: { value: "weekly" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    const make = within(dialog).getByRole("button", { name: "Make task" });
    expect((make as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText("Task name"), { target: { value: "Weekly docs" } });
    fireEvent.click(make);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/backup/tasks")).toBe(true));
    const body = calls.find((c) => c.method === "POST" && c.path === "/backup/tasks")!.body as Record<string, unknown>;
    expect(body).toMatchObject({
      name: "Weekly docs",
      target: "off",
      items: [{ kind: "share", id: "docs" }, { kind: "system" }],
      schedule: { frequency: "weekly", weekdays: [0] },
      retention: { daily: 7, weekly: 4, monthly: 12 },
    });
  });

  it("asks for the password before handing out the recovery kit", async () => {
    const calls: Call[] = [];
    serve(routes({ "POST /backup/targets/off/recovery-kit": () => ({ fileName: "hardyos-recovery-kit-off.txt", text: "KIT" }) }), calls);
    const created = vi.fn(() => "blob:x");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: created, revokeObjectURL: vi.fn() }));
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    wrap(<BackupView initial="destinations" />);
    fireEvent.click(await screen.findByRole("button", { name: /Recovery kit/ }));
    const dialog = await screen.findByRole("dialog");
    const download = within(dialog).getByRole("button", { name: "Download kit" }) as HTMLButtonElement;
    expect(download.disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText("Your password"), { target: { value: "supersecret1" } });
    fireEvent.click(download);
    await waitFor(() => expect(calls.find((c) => c.path === "/backup/targets/off/recovery-kit")?.body).toEqual({ password: "supersecret1" }));
    expect(await screen.findByText("Saved")).toBeTruthy();
    expect(created).toHaveBeenCalled();
  });

  it("restores chosen files and needs the name typed for a rollback", async () => {
    const calls: Call[] = [];
    serve(
      routes({
        "POST /backup/restore": () => ({ __status: 202, job: { id: "j1", kind: "backup.cloud.restore", title: "", state: "queued", progress: 0, message: "", error: "", params: {}, result: {}, createdBy: 1, createdAt: "", startedAt: null, finishedAt: null }, warnings: [] }),
        "GET /jobs/j1": () => ({ id: "j1", state: "running", progress: 50, message: "Restoring", error: "" }),
      }),
      calls,
    );
    wrap(<BackupView initial="restore" />);
    const versions = await screen.findByRole("region", { name: "Versions" });
    fireEvent.click((await within(versions).findAllByRole("button"))[0]!);

    // A rollback needs the folder's name typed.
    fireEvent.click(await screen.findByRole("button", { name: "Roll back to this version" }));
    const confirm = await screen.findByRole("dialog");
    const go = within(confirm).getByRole("button", { name: "Roll back" }) as HTMLButtonElement;
    expect(go.disabled).toBe(true);
    fireEvent.change(within(confirm).getByRole("textbox"), { target: { value: "Media" } });
    expect(go.disabled).toBe(false);
    fireEvent.click(within(confirm).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    // Chosen files into a new folder.
    fireEvent.click(await screen.findByRole("checkbox", { name: "Choose a.txt" }));
    fireEvent.click(screen.getByRole("button", { name: "Restore…" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Restore" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/backup/restore")).toBe(true));
    expect(calls.find((c) => c.method === "POST" && c.path === "/backup/restore")!.body).toMatchObject({ target: "off", snapshot: "aaaaaaaa", paths: ["a.txt"], mode: "copy" });
    expect(calls.filter((c) => c.method === "POST" && c.path === "/backup/restore")).toHaveLength(1);
  });
});
