import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Updates } from "./Updates";

const versions = [
  { dataset: "rpool/ROOT/hardyos-0.2.0", name: "hardyos-0.2.0", version: "0.2.0", created: 2_000_000_000, default: true, running: true, trying: false },
  { dataset: "rpool/ROOT/hardyos-0.1.0", name: "hardyos-0.1.0", version: "0.1.0", created: 1_900_000_000, default: false, running: false, trying: false },
];

function serve(status: unknown, calls: { method: string; path: string; body: unknown }[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request) => {
      const url = new URL(input.url);
      const path = url.pathname.replace("/api/v1", "");
      const body = input.method === "POST" ? await input.clone().json().catch(() => null) : null;
      calls.push({ method: input.method, path, body });
      if (path === "/system/updates") return new Response(JSON.stringify(status), { headers: { "Content-Type": "application/json" } });
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
    expect(screen.getByText("Install an update")).toBeTruthy();

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
    expect(screen.queryByText("Install an update")).toBeNull();
    expect(screen.getByRole("button", { name: /Restart now/ })).toBeTruthy();
    // No switching while an update waits.
    expect(screen.queryByRole("button", { name: "Use this version" })).toBeNull();
  });
});
