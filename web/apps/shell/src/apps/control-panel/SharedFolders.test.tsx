import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SharedFolders } from "./SharedFolders";
import { deriveId, idProblem, nameProblem, quotaBytes, quotaFields } from "./sharesRules";

type Call = { method: string; path: string; body: unknown };

const media = {
  id: "media",
  name: "Media",
  description: "Movies, TV shows, music and photos",
  pool: "tank",
  dataset: "tank/shares/media",
  path: "/mnt/tank/shares/media",
  mounted: true,
  quotaBytes: 2e12,
  usedBytes: 1.6e12,
  recycle: true,
  guest: false,
  access: [{ kind: "everyone", level: "read" }],
  apps: [{ app: "jellyfin", uid: 30001, level: "read" }],
  createdAt: "2026-10-26T12:00:00Z",
};
const backups = { ...media, id: "backups", name: "Backups", description: "", dataset: "tank/shares/backups", path: "/mnt/tank/shares/backups", quotaBytes: 0, usedBytes: 5e9, recycle: false, access: [], apps: [] };

function serve(state: { shares: unknown[] }, calls: Call[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const path = new URL(req.url).pathname.replace("/api/v1", "");
      const body = req.method !== "GET" ? await req.clone().json().catch(() => null) : null;
      calls.push({ method: req.method, path, body });
      const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });
      const job = (kind: string) => json({ job: { id: "job-1", kind, title: kind, state: "queued", progress: 0, message: "" }, warnings: [] }, 202);
      if (path === "/shares" && req.method === "GET") return json({ shares: state.shares });
      if (path === "/shares" && req.method === "POST") return job("shares.create");
      if (path === "/shares/starter") return job("shares.starter");
      if (path.startsWith("/shares/") && req.method === "PATCH") return job("shares.update");
      if (path.startsWith("/shares/") && req.method === "DELETE") return job("shares.delete");
      if (path === "/jobs/job-1") return json({ id: "job-1", kind: "shares", title: "Shared folder", state: "succeeded", progress: 100, message: "", error: "" });
      if (path === "/storage/pools")
        return json([
          { name: "rpool", sizeBytes: 1e11, allocBytes: 1e10, freeBytes: 9e10, fragmentation: 1, capacityPct: 10, health: "ONLINE", guid: "1" },
          { name: "tank", sizeBytes: 8e12, allocBytes: 2e12, freeBytes: 6e12, fragmentation: 1, capacityPct: 25, health: "ONLINE", guid: "2" },
        ]);
      if (path === "/domain")
        return json({ available: true, provisioned: true, config: { domain: "home.hardynetworks.net", netbios: "HOME" }, running: true, responding: true, problem: "" });
      if (path === "/domain/users")
        return json({
          users: [
            { username: "Administrator", displayName: "", builtin: true, enabled: true, groups: [] },
            { username: "alice", displayName: "Alice Hardy", builtin: false, enabled: true, groups: ["Family"] },
          ],
        });
      if (path === "/domain/groups")
        return json({
          groups: [
            { name: "Domain Users", description: "", members: [], builtin: true },
            { name: "Schema Admins", description: "", members: [], builtin: true },
            { name: "Family", description: "", members: ["alice"], builtin: false },
          ],
        });
      return json({ code: "not_found", message: path }, 404);
    }),
  );
}

function renderShares(admin = true) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <SharedFolders admin={admin} />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("shared folder rules", () => {
  it("match the server", () => {
    expect(deriveId("TV & Movies")).toBe("tv-movies");
    expect(deriveId("  Kids' (old) photos ")).toBe("kids-old-photos");
    expect(deriveId("日本")).toBe("");
    expect(nameProblem("a/b")).toMatch(/letters, digits/);
    expect(nameProblem("Homes")).toMatch(/reserved/);
    expect(nameProblem("...")).toMatch(/at least one/);
    expect(nameProblem("Family Photos")).toBeNull();
    expect(idProblem("Photos")).not.toBeNull();
    expect(idProblem("photos")).toBeNull();
    expect(quotaBytes("", "GB")).toBe(0);
    expect(quotaBytes("1.5", "TB")).toBe(1.5e12);
    expect(quotaBytes("lots", "GB")).toBeNull();
    expect(quotaFields(2e12)).toEqual({ value: "2", unit: "TB" });
    expect(quotaFields(500e9)).toEqual({ value: "500", unit: "GB" });
  });
});

describe("SharedFolders", () => {
  it("offers the starter set when there are none", async () => {
    const calls: Call[] = [];
    serve({ shares: [] }, calls);
    renderShares();
    expect(await screen.findByText("Start with the usual folders")).toBeTruthy();
    expect(screen.getByText(/Control Panel › File Services/)).toBeTruthy();
    fireEvent.click(await screen.findByRole("button", { name: "Create both" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/shares/starter")).toBe(true));
    expect(calls.find((c) => c.path === "/shares/starter")!.body).toEqual({ pool: "tank", media: true, backups: true });
    await waitFor(() => expect(calls.filter((c) => c.path === "/shares" && c.method === "GET").length).toBeGreaterThan(1));
  });

  it("lists shared folders with their quota, access and apps", async () => {
    serve({ shares: [backups, media] }, []);
    renderShares();
    expect(await screen.findByText("Media")).toBeTruthy();
    expect(screen.getByText("Backups")).toBeTruthy();
    expect(screen.getByText("1.6 TB")).toBeTruthy();
    expect(screen.getByText("2 TB")).toBeTruthy();
    expect(screen.getByText("Everyone (read)")).toBeTruthy();
    expect(screen.getByText("Apps: jellyfin")).toBeTruthy();
    expect(screen.getByText("Administrators only")).toBeTruthy();
    expect(screen.getByRole("progressbar", { name: "Media quota used" }).getAttribute("aria-valuenow")).toBe("80");
  });

  it("creates a shared folder with domain access rules", async () => {
    const calls: Call[] = [];
    serve({ shares: [media] }, calls);
    renderShares();
    fireEvent.click(await screen.findByRole("button", { name: /New shared folder/ }));
    const dialog = await screen.findByRole("dialog");
    const d = within(dialog);
    // Only data pools are offered.
    expect(d.queryByRole("option", { name: "rpool" })).toBeNull();
    fireEvent.change(d.getByLabelText("Name"), { target: { value: "a/b" } });
    expect(d.getByText(/letters, digits/)).toBeTruthy();
    expect((d.getByRole("button", { name: "Create" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(d.getByLabelText("Name"), { target: { value: " Family  Photos " } });
    expect(d.getByText("family-photos")).toBeTruthy();
    fireEvent.change(d.getByLabelText("Quota"), { target: { value: "500" } });

    await waitFor(() => expect(d.getByRole("button", { name: /Add someone/ })).toBeTruthy());
    fireEvent.click(d.getByRole("button", { name: /Add someone/ }));
    await waitFor(() => expect(d.getByRole("option", { name: "Family (group)" })).toBeTruthy());
    // Built-in groups other than Domain Users and Domain Admins aren't offered.
    expect(d.queryByRole("option", { name: /Schema Admins/ })).toBeNull();
    fireEvent.change(d.getByLabelText("Who, rule 1"), { target: { value: "group:home\\family" } });
    fireEvent.change(d.getByLabelText(/Access for/), { target: { value: "write" } });
    fireEvent.click(d.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/shares")).toBe(true));
    expect(calls.find((c) => c.method === "POST" && c.path === "/shares")!.body).toEqual({
      pool: "tank",
      name: "Family Photos",
      quotaBytes: 500e9,
      recycle: true,
      guest: false,
      access: [{ kind: "group", name: "HOME\\Family", level: "write" }],
    });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("edits a shared folder, keeping what wasn't changed", async () => {
    const calls: Call[] = [];
    serve({ shares: [media] }, calls);
    renderShares();
    fireEvent.click(await screen.findByRole("button", { name: "Edit Media" }));
    const d = within(await screen.findByRole("dialog"));
    expect((d.getByLabelText("Quota") as HTMLInputElement).value).toBe("2");
    fireEvent.click(d.getByRole("switch", { name: /Guest access/ }));
    fireEvent.click(d.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    const patch = calls.find((c) => c.method === "PATCH")!;
    expect(patch.path).toBe("/shares/media");
    expect(patch.body).toEqual({
      name: "Media",
      description: "Movies, TV shows, music and photos",
      quotaBytes: 2e12,
      recycle: true,
      guest: true,
      access: [{ kind: "everyone", level: "read" }],
    });
  });

  it("deletes only after the name is typed, and not while apps use it", async () => {
    const calls: Call[] = [];
    serve({ shares: [backups, media] }, calls);
    renderShares();
    fireEvent.click(await screen.findByRole("button", { name: "Delete Media" }));
    expect(await screen.findByText(/jellyfin uses Media/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "OK" }));

    fireEvent.click(screen.getByRole("button", { name: "Delete Backups" }));
    const d = within(await screen.findByRole("dialog"));
    const del = d.getByRole("button", { name: "Delete it and its files" }) as HTMLButtonElement;
    expect(del.disabled).toBe(true);
    fireEvent.change(d.getByLabelText("Type Backups to confirm"), { target: { value: "Backups" } });
    expect(del.disabled).toBe(false);
    fireEvent.click(del);
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE")).toBe(true));
    const call = calls.find((c) => c.method === "DELETE")!;
    expect(call.path).toBe("/shares/backups");
    expect(call.body).toEqual({ confirm: "Backups" });
  });

  it("shows family members the list without changes or access details", async () => {
    serve({ shares: [{ ...media, access: [], apps: [], pool: "", dataset: "" }] }, []);
    renderShares(false);
    expect(await screen.findByText("Media")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /New shared folder/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit Media" })).toBeNull();
    expect(screen.queryByText("Who can use it")).toBeNull();
  });
});
