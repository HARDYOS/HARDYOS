import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Updates } from "./Updates";

const versions = [
  { dataset: "rpool/ROOT/hardyos-0.2.0", name: "hardyos-0.2.0", version: "0.2.0", created: 2_000_000_000, default: true, running: true, trying: false },
  { dataset: "rpool/ROOT/hardyos-0.1.0", name: "hardyos-0.1.0", version: "0.1.0", created: 1_900_000_000, default: false, running: false, trying: false },
];

const upToDate = { autoCheck: true, current: "0.2.0", lastCheck: "2026-10-25T12:00:00Z", lastError: "", available: null };

function serve(status: unknown, calls: { method: string; path: string; body: unknown }[], check: unknown = upToDate) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request) => {
      const url = new URL(input.url);
      const path = url.pathname.replace("/api/v1", "");
      const body = input.method !== "GET" ? await input.clone().json().catch(() => null) : null;
      calls.push({ method: input.method, path, body });
      if (path === "/system/updates") return new Response(JSON.stringify(status), { headers: { "Content-Type": "application/json" } });
      if (path === "/system/updates/check") {
        const b = input.method === "PUT" ? { ...(check as object), ...(body as object) } : check;
        return new Response(JSON.stringify(b), { headers: { "Content-Type": "application/json" } });
      }
      if (path === "/system/updates/install-available") {
        return new Response(JSON.stringify({ job: { id: "j2", state: "queued", progress: 0, title: "Download and install HardyOS 0.3.0" }, warnings: [] }), {
          status: 202,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (path === "/jobs/j2") {
        return new Response(JSON.stringify({ id: "j2", state: "running", progress: 12, title: "Download and install HardyOS 0.3.0", message: "Downloading the update (70 of 589 MB)" }), {
          headers: { "Content-Type": "application/json" },
        });
      }
      if (path.startsWith("/system/versions/")) {
        return new Response(JSON.stringify({ job: { id: "j1" }, warnings: [] }), { status: 202, headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ code: "not_found", message: path }), { status: 404 });
    }),
  );
}

function renderUpdates() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Updates />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("Updates", () => {
  it("lists versions and goes back to an older one with settings restored", async () => {
    const calls: { method: string; path: string; body: unknown }[] = [];
    serve({ running: "hardyos-0.2.0", versions, pending: null, last: { ok: true, version: "0.2.0", message: "Updated to HardyOS 0.2.0.", at: "2026-10-25T12:00:00Z" }, restoreOnBoot: false, managed: true }, calls);
    renderUpdates();
    expect(await screen.findByText("Running HardyOS 0.2.0")).toBeTruthy();
    expect(screen.getByText(/Updated to HardyOS 0.2.0/)).toBeTruthy();
    expect(screen.getByText("Install an update file")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Use this version" }));
    fireEvent.click(await screen.findByRole("switch", { name: /Also restore settings/ }));
    fireEvent.click(screen.getAllByRole("button", { name: "Use this version" }).at(-1)!);
    await waitFor(() => expect(calls.some((c) => c.path === "/system/versions/hardyos-0.1.0/activate")).toBe(true));
    expect(calls.find((c) => c.path.endsWith("/activate"))!.body).toEqual({ restoreSettings: true });
    expect(await screen.findByText("HardyOS 0.1.0 starts after a restart")).toBeTruthy();
  });

  it("shows a pending update with restart, and a rolled-back result", async () => {
    const calls: { method: string; path: string; body: unknown }[] = [];
    serve(
      {
        running: "hardyos-0.2.0",
        versions: [...versions, { dataset: "rpool/ROOT/hardyos-0.3.0", name: "hardyos-0.3.0", version: "0.3.0", created: 2_100_000_000, default: false, running: false, trying: true }],
        pending: { bootEnvironment: "hardyos-0.3.0", dataset: "rpool/ROOT/hardyos-0.3.0", version: "0.3.0", fromBootEnvironment: "hardyos-0.2.0", fromVersion: "0.2.0", stagedAt: "2026-10-25T12:00:00Z", notes: "New photos app" },
        last: { ok: false, version: "0.2.5", message: "HardyOS 0.2.5 didn't start correctly, so the server went back to 0.2.0.", at: "2026-10-24T12:00:00Z" },
        restoreOnBoot: false,
        managed: true,
      },
      calls,
    );
    renderUpdates();
    expect(await screen.findByText("HardyOS 0.3.0 is ready")).toBeTruthy();
    expect(screen.getByText("New photos app")).toBeTruthy();
    expect(screen.getByText("The last update was rolled back")).toBeTruthy();
    expect(screen.queryByText("Install an update file")).toBeNull();
    expect(screen.getByRole("button", { name: /Restart now/ })).toBeTruthy();
    // No switching while an update waits.
    expect(screen.queryByRole("button", { name: "Use this version" })).toBeNull();
  });

  it("offers a version found by the automatic check and installs it", async () => {
    const calls: { method: string; path: string; body: unknown }[] = [];
    serve(
      { running: "hardyos-0.2.0", versions, pending: null, last: null, restoreOnBoot: false, managed: true },
      calls,
      {
        autoCheck: true,
        current: "0.2.0",
        lastCheck: new Date().toISOString(),
        lastError: "",
        available: {
          version: "0.3.0",
          name: "HardyOS 0.3.0",
          notes: "File sharing over SMB.",
          url: "https://github.com/HARDYOS/HARDYOS/releases/download/v0.3.0/hardyos-0.3.0-amd64.hupd",
          pageUrl: "https://github.com/HARDYOS/HARDYOS/releases/tag/v0.3.0",
          size: 617_000_000,
          publishedAt: new Date().toISOString(),
        },
      },
    );
    renderUpdates();
    expect(await screen.findByText("HardyOS 0.3.0 is available")).toBeTruthy();
    expect(screen.getByText("File sharing over SMB.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Install" }));
    expect(await screen.findByText(/Downloading the update/)).toBeTruthy();
    expect(calls.some((c) => c.path === "/system/updates/install-available")).toBe(true);
  });

  it("says when it's up to date or couldn't check, and turns daily checks off", async () => {
    const calls: { method: string; path: string; body: unknown }[] = [];
    serve({ running: "hardyos-0.2.0", versions, pending: null, last: null, restoreOnBoot: false, managed: true }, calls, {
      ...upToDate,
      lastError: "couldn't reach GitHub to check for updates: no route to host",
    });
    renderUpdates();
    expect(await screen.findByText("Couldn't check for updates")).toBeTruthy();
    expect(screen.getByText(/no route to host/)).toBeTruthy();
    fireEvent.click(screen.getByRole("switch", { name: /Check for updates every day/ }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT" && c.path === "/system/updates/check")?.body).toEqual({ autoCheck: false }));
    fireEvent.click(screen.getByRole("button", { name: /Check now/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/system/updates/check")).toBe(true));
  });
});
