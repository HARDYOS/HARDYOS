import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CloudVersions } from "./CloudVersions";

type Call = { method: string; path: string; body: unknown; query: string };

function serve(calls: Call[], versions: unknown[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const u = new URL(req.url);
      const path = u.pathname.replace("/api/v1", "");
      const body = req.method !== "GET" ? await req.clone().json().catch(() => null) : null;
      calls.push({ method: req.method, path, body, query: u.search });
      let out: unknown = { code: "not_found", message: path };
      let status = 404;
      if (path === "/files/backups") [out, status] = [{ versions }, 200];
      if (path === "/files/backups/browse") [out, status] = [{ entries: [{ name: "a.txt", path: "a.txt", dir: false, type: "file", size: 5, modified: "2026-10-01T00:00:00Z" }] }, 200];
      if (path === "/files/backups/restore") [out, status] = [{ job: { id: "j9", state: "queued", progress: 0, message: "", error: "" }, warnings: [] }, 202];
      if (path === "/jobs/j9") [out, status] = [{ id: "j9", state: "running", progress: 10, message: "Restoring", error: "" }, 200];
      return new Response(JSON.stringify(out), { status, headers: { "Content-Type": "application/json" } });
    }),
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const entry = { name: "notes.txt", path: "docs/notes.txt", dir: false, size: 10, modified: "", writable: true };
const wrap = (canWrite: boolean) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <CloudVersions share="family" entry={entry as never} canWrite={canWrite} />
    </QueryClientProvider>,
  );

describe("File Manager: versions in cloud backups", () => {
  it("shows nothing when there are no versions", async () => {
    const calls: Call[] = [];
    serve(calls, []);
    const { container } = wrap(true);
    await waitFor(() => expect(calls.length).toBe(1));
    await waitFor(() => expect(container.textContent).toBe(""));
  });

  it("restores the file, and files picked while browsing, as the person", async () => {
    const calls: Call[] = [];
    serve(calls, [{ target: "off", targetName: "Offsite", run: "r1", time: "2026-10-20T01:30:00Z", snapshot: "aaaaaaaa" }]);
    wrap(true);
    fireEvent.click(await screen.findByRole("button", { name: /Restore notes.txt/ }));
    let dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("radio", { name: /Where they were/ }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Restore" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/files/backups/restore")).toBe(true));
    expect(calls.find((c) => c.path === "/files/backups/restore")!.body).toEqual({ share: "family", target: "off", snapshot: "aaaaaaaa", paths: ["docs/notes.txt"], mode: "in_place" });

    fireEvent.click(screen.getByRole("button", { name: /Browse the backup/ }));
    dialog = await screen.findByRole("dialog");
    fireEvent.click(await within(dialog).findByRole("checkbox", { name: "Choose a.txt" }));
    expect(calls.find((c) => c.path === "/files/backups/browse")!.query).toContain("share=family");
    fireEvent.click(within(dialog).getByRole("button", { name: "Restore…" }));
    const second = (await screen.findAllByRole("dialog")).at(-1)!;
    fireEvent.click(within(second).getByRole("button", { name: "Restore" }));
    await waitFor(() => expect(calls.filter((c) => c.path === "/files/backups/restore")).toHaveLength(2));
    expect(calls.filter((c) => c.path === "/files/backups/restore")[1]!.body).toMatchObject({ paths: ["a.txt"], mode: "copy" });
  });

  it("lets people without write access only browse", async () => {
    const calls: Call[] = [];
    serve(calls, [{ target: "off", targetName: "Offsite", run: "r1", time: "2026-10-20T01:30:00Z", snapshot: "aaaaaaaa" }]);
    wrap(false);
    expect(await screen.findByRole("button", { name: /Browse the backup/ })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Restore notes.txt/ })).toBeNull();
  });
});
