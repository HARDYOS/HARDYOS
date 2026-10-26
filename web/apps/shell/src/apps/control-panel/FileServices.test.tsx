import type { FileServicesStatus, Share } from "@hardy/api-client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FileServices } from "./FileServices";
import { linuxMount, smbPath, tmSizeBytes, tmSizeFields } from "./fileServicesRules";
import { ShareSMBSection } from "./ShareSMBSection";

type Call = { method: string; path: string; body: unknown };

const backups: Share = {
  id: "backups",
  name: "Backups",
  description: "",
  pool: "tank",
  dataset: "tank/shares/backups",
  path: "/mnt/tank/shares/backups",
  mounted: true,
  quotaBytes: 0,
  usedBytes: 0,
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

const joined: FileServicesStatus = {
  available: true,
  joined: true,
  domain: { domain: "home.example.net", realm: "HOME.EXAMPLE.NET", netbios: "HOME" },
  localDomain: "home.example.net",
  serverName: "HARDYOS",
  hostName: "hardyos.home.example.net",
  running: true,
  winbind: true,
  problem: "",
  settings: { smbEnabled: true, homes: { enabled: false, pool: "", quotaBytes: 0 }, sftpEnabled: false, webdavEnabled: false },
  shares: [
    { id: "backups", name: "Backups", smb: true, timeMachine: true, previousVersions: true, recycle: false, guest: false, sftp: false, webdav: false, available: true, skipped: [] },
    { id: "media", name: "Family Media", smb: true, timeMachine: false, previousVersions: true, recycle: true, guest: true, sftp: false, webdav: false, available: true, skipped: ["admin"] },
  ],
  addresses: ["192.168.1.105"],
  joinedAt: "2026-10-26T12:00:00Z",
};

function serve(calls: Call[], status: FileServicesStatus) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const path = decodeURIComponent(new URL(req.url).pathname.replace("/api/v1", ""));
      const body = req.method !== "GET" ? await req.clone().json().catch(() => null) : null;
      calls.push({ method: req.method, path, body });
      const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });
      const job = (kind: string) => json({ job: { id: "job-1", kind, title: kind, state: "queued", progress: 0, message: "" }, warnings: [] }, 202);
      if (path === "/files") return json(status);
      if (path === "/files/join") return job("files.join");
      if (path === "/files/leave") return job("files.leave");
      if (path === "/files/settings") return job("files.settings");
      if (path === "/storage/pools") return json([{ name: "tank" }]);
      if (path === "/shares/backups" && req.method === "GET") return json(backups);
      if (path === "/shares/backups" && req.method === "PATCH") return job("shares.update");
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

describe("file services rules", () => {
  it("writes connection paths", () => {
    expect(smbPath("windows", "HARDYOS", "Family Media")).toBe("\\\\HARDYOS\\Family Media");
    expect(smbPath("mac", "hardyos.home.example.net", "Family Media")).toBe("smb://hardyos.home.example.net/Family%20Media");
    expect(linuxMount("nas", "Kids' TV & Films", "HOME")).toContain("/mnt/kids-tv-films");
  });
  it("reads Time Machine sizes", () => {
    expect(tmSizeBytes("", "GB")).toBe(0);
    expect(tmSizeBytes("500", "GB")).toBe(500e9);
    expect(tmSizeBytes("1,5", "TB")).toBe(1.5e12);
    expect(tmSizeBytes("abc", "GB")).toBeNull();
    expect(tmSizeBytes("0", "GB")).toBeNull();
    expect(tmSizeFields(2e12)).toEqual({ value: "2", unit: "TB" });
    expect(tmSizeFields(0)).toEqual({ value: "", unit: "GB" });
  });
});

describe("FileServices", () => {
  it("joins this server's own domain with only the password", async () => {
    const calls: Call[] = [];
    serve(calls, { ...joined, joined: false, domain: null, shares: [] });
    renderIn(<FileServices admin />);
    fireEvent.change(await screen.findByLabelText("Password"), { target: { value: "S3cret!" } });
    fireEvent.click(screen.getByRole("button", { name: "Join the domain" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/files/join")).toBe(true));
    const join = calls.find((c) => c.path === "/files/join");
    expect(join?.body).toEqual({ adminUser: "Administrator", adminPassword: "S3cret!" });
  });

  it("shows how to connect, and leaves with confirmation", async () => {
    const calls: Call[] = [];
    serve(calls, joined);
    renderIn(<FileServices admin />);
    expect(await screen.findByText("SMB file server")).toBeTruthy();
    expect(screen.getAllByText("\\\\HARDYOS\\Family Media").length).toBeGreaterThan(0);
    expect(screen.getAllByText("smb://hardyos.home.example.net/Backups").length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "Leave the domain" }));
    const confirm = await screen.findAllByRole("button", { name: "Leave the domain" });
    fireEvent.click(confirm[confirm.length - 1] as HTMLElement);
    await waitFor(() => expect(calls.some((c) => c.path === "/files/leave")).toBe(true));
    expect(calls.find((c) => c.path === "/files/leave")?.body).toEqual({ confirm: true });
  });

  it("hides the settings from family members", async () => {
    serve([], joined);
    renderIn(<FileServices admin={false} />);
    expect(await screen.findByText("How to connect")).toBeTruthy();
    expect(screen.queryByText("SMB file server")).toBeNull();
    expect(screen.queryByText("Home folders")).toBeNull();
  });
});

describe("ShareSMBSection", () => {
  it("turns Time Machine on with a size, keeping the other services", async () => {
    const calls: Call[] = [];
    serve(calls, joined);
    renderIn(<ShareSMBSection share={backups} />);
    fireEvent.click(await screen.findByRole("switch", { name: /Time Machine/ }));
    fireEvent.change(screen.getByLabelText("Most each Mac may use"), { target: { value: "1" } });
    fireEvent.change(screen.getByLabelText("Time Machine size unit"), { target: { value: "TB" } });
    fireEvent.click(screen.getByRole("button", { name: "Save SMB settings" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    const patch = calls.find((c) => c.method === "PATCH")?.body as { services: Share["services"] };
    expect(patch.services.smb).toEqual({ enabled: true, previousVersions: true, timeMachine: true, timeMachineMaxBytes: 1e12 });
    expect(patch.services.snapshots).toEqual(backups.services.snapshots);
  });

  it("explains it for new folders", () => {
    serve([], joined);
    renderIn(<ShareSMBSection />);
    expect(screen.getByText(/On for new folders/)).toBeTruthy();
  });
});
