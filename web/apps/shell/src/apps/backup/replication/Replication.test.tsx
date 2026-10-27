import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AcceptPanel } from "./AcceptPanel";
import { ReplicationTab, taskRequest } from "./ReplicationTab";
import { intervalLabel, restoredID, snapshotTime, splitInterval, taskStatus } from "./replicationApi";

const target = { id: "t1", name: "bravo", address: "bravo:44400", sourceId: "abcdef123456", pin: "0123456789abcdef", createdAt: "2026-10-27T10:00:00Z" };
const task = {
  id: "task01",
  name: "Hourly to bravo",
  targetId: "t1",
  items: [{ kind: "share", id: "media" }],
  intervalMinutes: 60,
  bandwidthKBps: 0,
  keepLocal: 3,
  keepRemote: 14,
  enabled: true,
  lastRunAt: "2026-10-27T10:00:00Z",
  lastSuccessAt: "2026-10-27T10:00:00Z",
  lastError: "",
  lastBytes: 4096,
  alert: "",
  createdAt: "2026-10-27T09:00:00Z",
  updatedAt: "2026-10-27T09:00:00Z",
  targetName: "bravo",
  runningJob: "",
  nextRunAt: "2026-10-27T11:00:00Z",
  stale: false,
};
const overview = { hostname: "alpha", pin: "f".repeat(64), port: 44400, targets: [target], tasks: [task] };
const items = {
  items: [
    { kind: "share", id: "media", name: "Media", pool: "tank", dataset: "tank/shares/media", usedBytes: 1 << 30 },
    { kind: "vm", id: "web", name: "Web server", pool: "tank", dataset: "tank/vms/web", usedBytes: 8 << 30 },
  ],
};
const receive = {
  receiving: true,
  hostname: "bravo",
  port: 44400,
  pin: "e".repeat(64),
  pairing: null,
  addresses: [
    { address: "192.168.1.20", interface: "enp1s0", netbird: false },
    { address: "100.64.0.7", interface: "wt0", netbird: true },
  ],
  sources: [
    {
      id: "src0001",
      name: "alpha",
      pool: "tank",
      quotaBytes: 100 * 2 ** 30,
      minKeep: 3,
      minAgeDays: 7,
      minIntervalMinutes: 0,
      maxDatasets: 1000,
      maxSnapshots: 20000,
      allowBrowse: false,
      createdAt: "2026-10-27T09:00:00Z",
      lastSeenAt: "2026-10-27T10:00:00Z",
      items: [],
      usedBytes: 5 << 30,
      replicas: [{ kind: "share", id: "media", name: "Media", pool: "tank", usedBytes: 5 << 30, snapshots: 3, lastSnapshot: "hardyos-repl-task01-20261027T100000Z", partial: false }],
    },
  ],
};

type Call = { method: string; path: string; body: unknown };

function serve(calls: Call[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const url = new URL(req.url);
      const path = url.pathname.replace("/api/v1", "");
      const body = req.method !== "GET" ? await req.clone().json().catch(() => null) : null;
      calls.push({ method: req.method, path, body });
      const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });
      const job = { id: "job_1", kind: "x", title: "x", state: "queued", progress: 0, message: "", error: "", params: {}, result: {}, createdBy: 1, createdAt: "", startedAt: null, finishedAt: null };
      if (path === "/replication") return json(overview);
      if (path === "/replication/items") return json(items);
      if (path === "/replication/receive") return json(receive);
      if (path === "/storage/pools") return json([{ name: "tank" }, { name: "backup" }]);
      if (path === "/replication/targets/t1/replicas") return json({ items: [] });
      if (path === "/replication/receive/pairing" && req.method === "POST")
        return json({ job, code: "ABCDE-FGHIJ-KLMNO-PQRST-UVWXYZ", expiresAt: "2026-10-27T10:30:00Z", port: 44400, hostname: "bravo" }, 202);
      if (path.startsWith("/jobs/")) return json(job);
      if (req.method !== "GET") return json({ job, warnings: [] }, 202);
      return json({ code: "not_found", message: path }, 404);
    }),
  );
}

function wrap(node: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>);
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("replication helpers", () => {
  it("formats intervals, times and names", () => {
    expect(intervalLabel(15)).toBe("every 15 minutes");
    expect(intervalLabel(60)).toBe("every hour");
    expect(intervalLabel(360)).toBe("every 6 hours");
    expect(intervalLabel(2880)).toBe("every 2 days");
    expect(splitInterval(120)).toEqual({ value: 2, unit: "hours" });
    expect(snapshotTime("hardyos-repl-task01-20261027T101500Z")).toBe("2026-10-27T10:15:00Z");
    expect(snapshotTime("manual")).toBeNull();
    expect(restoredID("media", ["media-restored"])).toBe("media-restored-2");
    expect(taskStatus({ ...task, stale: true } as never).text).toBe("behind");
    expect(taskStatus({ ...task, runningJob: "job_1" } as never).text).toBe("running");
    expect(
      taskRequest({ name: " T ", targetId: "t1", items: [], every: 2, unit: "hours", bandwidthKBps: 512.4, keepLocal: 2, keepRemote: 5, enabled: true }),
    ).toEqual({ name: "T", targetId: "t1", items: [], intervalMinutes: 120, bandwidthKBps: 512, keepLocal: 2, keepRemote: 5, enabled: true });
  });
});

describe("ReplicationTab", () => {
  it("lists tasks and runs one now", async () => {
    const calls: Call[] = [];
    serve(calls);
    wrap(<ReplicationTab />);
    expect(await screen.findByText("Hourly to bravo")).toBeTruthy();
    expect(screen.getByText("up to date")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Run now/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/replication/tasks/task01/run")).toBe(true));
  });

  it("pairs with a server using its code", async () => {
    const calls: Call[] = [];
    serve(calls);
    wrap(<ReplicationTab />);
    fireEvent.click(await screen.findByRole("button", { name: /Pair with a server/ }));
    const dialog = await screen.findByRole("dialog");
    const pair = within(dialog).getByRole("button", { name: "Pair" }) as HTMLButtonElement;
    expect(pair.disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText("The other server's address"), { target: { value: "nas2.home.example" } });
    fireEvent.change(within(dialog).getByLabelText("Pairing code"), { target: { value: "ABCDE-FGHIJ-KLMNO-PQRST-UVWXYZ" } });
    fireEvent.click(pair);
    await waitFor(() =>
      expect(calls.find((c) => c.path === "/replication/targets")?.body).toEqual({ address: "nas2.home.example", code: "ABCDE-FGHIJ-KLMNO-PQRST-UVWXYZ" }),
    );
  });

  it("creates a task with the chosen items and schedule", async () => {
    const calls: Call[] = [];
    serve(calls);
    wrap(<ReplicationTab />);
    fireEvent.click(await screen.findByRole("button", { name: /New task/ }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Name"), { target: { value: "VMs nightly" } });
    fireEvent.click(await within(dialog).findByRole("checkbox", { name: /Web server/ }));
    fireEvent.change(within(dialog).getByLabelText("Run every"), { target: { value: "1" } });
    fireEvent.change(within(dialog).getByLabelText("Unit"), { target: { value: "days" } });
    expect(within(dialog).getByText(/guest agent/)).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(calls.find((c) => c.method === "POST" && c.path === "/replication/tasks")?.body).toEqual({
        name: "VMs nightly",
        targetId: "t1",
        items: [{ kind: "vm", id: "web" }],
        intervalMinutes: 1440,
        bandwidthKBps: 0,
        keepLocal: 3,
        keepRemote: 14,
        enabled: true,
      }),
    );
  });

  it("deletes a task only with its name typed", async () => {
    const calls: Call[] = [];
    serve(calls);
    wrap(<ReplicationTab />);
    fireEvent.click(await screen.findByRole("button", { name: "Delete Hourly to bravo" }));
    const dialog = await screen.findByRole("dialog");
    const btn = within(dialog).getByRole("button", { name: "Delete task" }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    fireEvent.change(within(dialog).getByRole("textbox"), { target: { value: "Hourly to bravo" } });
    fireEvent.click(btn);
    await waitFor(() => expect(calls.find((c) => c.method === "DELETE")?.body).toEqual({ confirm: "Hourly to bravo" }));
  });
});

describe("AcceptPanel", () => {
  it("makes a pairing code and shows it once", async () => {
    const calls: Call[] = [];
    serve(calls);
    wrap(<AcceptPanel />);
    expect(await screen.findByText("alpha")).toBeTruthy();
    expect(screen.getByText("NetBird")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Make a pairing code/ }));
    const dialog = await screen.findByRole("dialog");
    await within(dialog).findByRole("option", { name: "backup" });
    fireEvent.change(within(dialog).getByLabelText("Space limit (GiB)"), { target: { value: "500" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Make code" }));
    expect(await screen.findByText("ABCDE-FGHIJ-KLMNO-PQRST-UVWXYZ")).toBeTruthy();
    expect(calls.find((c) => c.path === "/replication/receive/pairing")?.body).toEqual({ pool: "tank", quotaBytes: 500 * 2 ** 30, minKeep: 3, minAgeDays: 7 });
  });

  it("deletes a source's replicas with its name typed", async () => {
    const calls: Call[] = [];
    serve(calls);
    wrap(<AcceptPanel />);
    fireEvent.click(await screen.findByRole("button", { name: "Delete alpha's replicas" }));
    const dialog = await screen.findByRole("dialog");
    const btn = within(dialog).getByRole("button", { name: "Delete replicas" }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText("Type alpha to confirm"), { target: { value: "alpha" } });
    fireEvent.click(btn);
    await waitFor(() =>
      expect(calls.find((c) => c.method === "DELETE" && c.path === "/replication/receive/sources/src0001")?.body).toEqual({ confirm: "alpha", deleteReplicas: true }),
    );
  });

  it("changes a source's rules, browsing included", async () => {
    const calls: Call[] = [];
    serve(calls);
    wrap(<AcceptPanel />);
    fireEvent.click(await screen.findByRole("button", { name: "Rules for alpha" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("switch", { name: /browse its replicas/ }));
    fireEvent.change(within(dialog).getByLabelText("Keep every snapshot for (days)"), { target: { value: "30" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({
        quotaBytes: 100 * 2 ** 30,
        minKeep: 3,
        minAgeDays: 30,
        minIntervalMinutes: 0,
        maxDatasets: 1000,
        maxSnapshots: 20000,
        allowBrowse: true,
      }),
    );
  });
});
