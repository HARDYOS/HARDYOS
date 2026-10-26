import type { Share } from "@hardy/api-client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mountCommands, nfsClientProblem } from "./nfsRules";
import { ShareNFSSection } from "./ShareNFSSection";
import { ShareSnapshotsSection, snapshotNameProblem } from "./ShareSnapshotsSection";

type Call = { method: string; path: string; body: unknown };

const media: Share = {
  id: "media",
  name: "Media",
  description: "",
  pool: "tank",
  dataset: "tank/shares/media",
  path: "/mnt/tank/shares/media",
  mounted: true,
  quotaBytes: 0,
  usedBytes: 1e9,
  recycle: true,
  guest: false,
  access: [],
  apps: [],
  createdAt: "2026-10-26T12:00:00Z",
  services: {
    smb: { enabled: true, timeMachine: false, timeMachineMaxBytes: 0, previousVersions: true },
    nfs: { enabled: false, clients: [] },
    snapshots: { hourly: 24, daily: 14, weekly: 8, monthly: 6 },
    sftp: false,
    webdav: false,
  },
};

function serve(calls: Call[], fresh: Share = media) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const path = decodeURIComponent(new URL(req.url).pathname.replace("/api/v1", ""));
      const body = req.method !== "GET" ? await req.clone().json().catch(() => null) : null;
      calls.push({ method: req.method, path, body });
      const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });
      const job = (kind: string) => json({ job: { id: "job-1", kind, title: kind, state: "queued", progress: 0, message: "" }, warnings: [] }, 202);
      if (path === "/shares/media/snapshots" && req.method === "GET")
        return json({
          snapshots: [
            { name: "before-cleanup", kind: "manual", createdAt: "2026-10-26T13:20:00Z", usedBytes: 4096, referBytes: 1e9 },
            { name: "hardyos-auto-hourly_2026-10-26-1300", kind: "hourly", createdAt: "2026-10-26T13:00:02Z", usedBytes: 0, referBytes: 1e9 },
          ],
        });
      if (path === "/shares/media/snapshots" && req.method === "POST") return job("snapshots.create");
      if (path.startsWith("/shares/media/snapshots/") && req.method === "DELETE") return job("snapshots.delete");
      if (path === "/shares/media/nfs") return json({ enabled: true, path: "/mnt/tank/shares/media", uid: 31000, running: true });
      if (path === "/shares/media" && req.method === "GET") return json(fresh);
      if (path === "/shares/media" && req.method === "PATCH") return job("shares.update");
      if (path === "/jobs/job-1") return json({ id: "job-1", kind: "x", title: "x", state: "succeeded", progress: 100, message: "", error: "" });
      return json({ code: "not_found", message: path }, 404);
    }),
  );
}

function renderIn(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("rules", () => {
  it("checks NFS clients like the server", () => {
    for (const ok of ["192.168.1.50", "192.168.1.0/24", "10.0.0.0/8", "fd00::50", "2001:db8::/64", "::ffff:192.168.1.9"]) expect(nfsClientProblem(ok)).toBeNull();
    for (const bad of ["", "*", "nas.local", "0.0.0.0/0", "::/0", "0.0.0.0", "::", "192.168.1.256", "192.168.1.0/33", "fd00::/129", "fe80::1%eth0", "1.2.3.4/24/1", "10.0.0.1(rw)"])
      expect(nfsClientProblem(bad)).not.toBeNull();
  });
  it("writes mount commands", () => {
    const c = mountCommands("nas.home", "/mnt/tank/shares/media", "media");
    expect(c.linux).toBe("sudo mkdir -p /mnt/media\nsudo mount -t nfs nas.home:/mnt/tank/shares/media /mnt/media");
    expect(c.mac).toContain("sudo mount -t nfs -o resvport,rw nas.home:/mnt/tank/shares/media ~/media");
    expect(c.finder).toBe("nfs://nas.home/mnt/tank/shares/media");
    expect(mountCommands("fd00::2", "/mnt/x", "x").linux).toContain("[fd00::2]:/mnt/x");
  });
  it("checks snapshot names like the server", () => {
    expect(snapshotNameProblem("")).toBeNull();
    expect(snapshotNameProblem("before-cleanup")).toBeNull();
    for (const bad of ["hardyos-auto-hourly_2026-10-26-1300", "a b", "-x", "a@b", "x".repeat(65)]) expect(snapshotNameProblem(bad)).not.toBeNull();
  });
});

describe("ShareSnapshotsSection", () => {
  it("explains the defaults for a new folder", () => {
    renderIn(<ShareSnapshotsSection />);
    expect(screen.getByText(/24 hourly, 14 daily, 8 weekly and 6 monthly/)).toBeTruthy();
  });

  it("lists, takes, deletes and changes retention", async () => {
    const calls: Call[] = [];
    serve(calls);
    renderIn(<ShareSnapshotsSection share={media} />);
    const table = await screen.findByRole("table", { name: "Snapshots of Media" });
    expect(within(table).getByText("before-cleanup")).toBeTruthy();
    expect(within(table).getByText("Taken by hand")).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Take a snapshot now"), { target: { value: "before upgrade" } });
    expect(screen.getByText(/no spaces/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Take a snapshot now"), { target: { value: "before-upgrade" } });
    fireEvent.click(screen.getByRole("button", { name: /Take snapshot/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/shares/media/snapshots")).toBe(true));
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ name: "before-upgrade" });

    fireEvent.click(screen.getByRole("button", { name: "Delete snapshot before-cleanup" }));
    fireEvent.click(await screen.findByRole("button", { name: "Delete snapshot" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE")).toBe(true));
    expect(calls.find((c) => c.method === "DELETE")).toMatchObject({ path: "/shares/media/snapshots/before-cleanup", body: { confirm: "before-cleanup" } });

    fireEvent.change(screen.getByLabelText("Hourly to keep"), { target: { value: "500" } });
    expect(screen.getByText("0 to 168")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Hourly to keep"), { target: { value: "12" } });
    expect(screen.getByText(/deletes the oldest ones/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Save snapshot settings" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ services: { ...media.services, snapshots: { hourly: 12, daily: 14, weekly: 8, monthly: 6 } } });
  });
});

describe("ShareNFSSection", () => {
  it("turns NFS on without losing changes another section saved", async () => {
    const calls: Call[] = [];
    // SMB was turned off meanwhile; saving NFS must keep that.
    serve(calls, { ...media, services: { ...media.services, smb: { ...media.services.smb, enabled: false } } });
    renderIn(<ShareNFSSection share={media} />);
    fireEvent.click(screen.getByRole("switch", { name: /Share over NFS/ }));
    const client = screen.getByLabelText("Computer or network 1");
    fireEvent.change(client, { target: { value: "0.0.0.0/0" } });
    expect(screen.getByRole("alert").textContent).toMatch(/every address/);
    expect((screen.getByRole("button", { name: "Save NFS settings" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(client, { target: { value: "192.168.1.0/24" } });
    fireEvent.change(screen.getByLabelText("Access for computer or network 1"), { target: { value: "write" } });
    fireEvent.click(screen.getByRole("button", { name: "Save NFS settings" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({
      services: { ...media.services, smb: { ...media.services.smb, enabled: false }, nfs: { enabled: true, clients: [{ client: "192.168.1.0/24", access: "write" }] } },
    });
    // Saved: the mount commands show.
    expect(await screen.findByLabelText("Linux")).toBeTruthy();
    expect(screen.getByLabelText("Linux").textContent).toContain(":/mnt/tank/shares/media /mnt/media");
    expect(await screen.findByText("31000")).toBeTruthy();
  });
});
