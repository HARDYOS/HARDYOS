import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ReplicationTab } from "./ReplicationTab";

const A = "a11ce0000000000000000001";
const target = { id: "t1", name: "bravo", address: "bravo:44400", sourceId: "abcdef123456", pin: "0123456789abcdef", createdAt: "2026-10-27T10:00:00Z" };
const overview = { hostname: "alpha", pin: "f".repeat(64), port: 44400, targets: [target], tasks: [] };
const items = {
  items: [
    { kind: "share", id: "media", name: "Media", pool: "tank", dataset: "tank/shares/media", usedBytes: 1 << 30 },
    { kind: "app", id: "roundcube", name: "Mail (Roundcube)", pool: "tank", dataset: "tank/apps/roundcube", usedBytes: 1 << 20 },
    { kind: "mail", id: "mail", name: "Mail", pool: "tank", dataset: "tank/mail", usedBytes: 4 << 30 },
  ],
};
const snap = "hardyos-repl-task01-20261027T100000Z";

type Call = { method: string; path: string; body: unknown };

function serve(calls: Call[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const path = new URL(req.url).pathname.replace("/api/v1", "");
      const body = req.method !== "GET" ? await req.clone().json().catch(() => null) : null;
      calls.push({ method: req.method, path, body });
      const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });
      const job = { id: "job_1", kind: "x", title: "x", state: "queued", progress: 0, message: "", error: "", params: {}, result: {}, createdBy: 1, createdAt: "", startedAt: null, finishedAt: null };
      if (path === "/replication") return json(overview);
      if (path === "/replication/items") return json(items);
      if (path === "/storage/pools") return json([{ name: "tank" }]);
      if (path === "/mail/restore-targets") return json({ hostname: "mail.example.net", domains: ["example.net"], mailboxes: [{ key: A, address: "alice@example.net" }], webmail: false });
      if (path === "/replication/targets/t1/replicas")
        return json({ items: [{ kind: "mail", id: "mail", name: "Mail", pool: "tank", usedBytes: 4 << 30, snapshots: 1, lastSnapshot: snap, partial: false }] });
      if (path === "/replication/targets/t1/replicas/mail/mail/snapshots") return json({ snapshots: [{ name: snap, guid: "1", created: "2026-10-27T10:00:00Z" }] });
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

describe("Mail in replication", () => {
  it("has mail and webmail ticked for a new task", async () => {
    const calls: Call[] = [];
    serve(calls);
    wrap(<ReplicationTab />);
    fireEvent.click(await screen.findByRole("button", { name: /New task/ }));
    const dialog = await screen.findByRole("dialog");
    await waitFor(() => expect((within(dialog).getByRole("checkbox", { name: /^Mail\b(?! \()/ }) as HTMLInputElement).checked).toBe(true));
    expect((within(dialog).getByRole("checkbox", { name: /Roundcube/ }) as HTMLInputElement).checked).toBe(true);
    expect((within(dialog).getByRole("checkbox", { name: /Media/ }) as HTMLInputElement).checked).toBe(false);
    expect(within(dialog).getByText(/never mounts or shows it/)).toBeTruthy();
    fireEvent.change(within(dialog).getByLabelText("Name"), { target: { value: "Mail" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect((calls.find((c) => c.method === "POST" && c.path === "/replication/tasks")?.body as { items: unknown[] }).items).toEqual([
        { kind: "app", id: "roundcube" },
        { kind: "mail", id: "mail" },
      ]),
    );
  });

  it("restores the mail from a replica without browsing it", async () => {
    const calls: Call[] = [];
    serve(calls);
    wrap(<ReplicationTab />);
    fireEvent.click(await screen.findByRole("button", { name: /Browse & restore/ }));
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByText(/can't be browsed/)).toBeTruthy();
    fireEvent.click(await within(dialog).findByRole("radio", { name: /Calendars and contacts/ }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Restore" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/replication/targets/t1/restore")).toBe(true));
    expect(calls.find((c) => c.method === "POST" && c.path === "/replication/targets/t1/restore")!.body).toEqual({
      kind: "mail",
      id: "mail",
      snapshot: snap,
      confirm: true,
      mail: { scope: "calendars", key: A, into: A, mode: "copy" },
    });
    expect(calls.some((c) => c.path.includes("/browse"))).toBe(false);
  });
});
