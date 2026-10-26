import type { Share } from "@hardy/api-client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { davURL, davWindowsPath, rcloneConfig, sftpCommand, sftpURL } from "./remoteRules";
import { ShareRemoteSection } from "./ShareRemoteSection";

type Call = { method: string; path: string; body: unknown };

const media: Share = {
  id: "media",
  name: "Family Media",
  description: "",
  pool: "tank",
  dataset: "tank/shares/media",
  path: "/mnt/tank/shares/media",
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
    nfs: { enabled: true, clients: [{ client: "192.168.1.0/24", access: "read" }] },
    snapshots: { hourly: 24, daily: 14, weekly: 8, monthly: 6 },
    sftp: false,
    webdav: false,
  },
};

function serve(calls: Call[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const path = decodeURIComponent(new URL(req.url).pathname.replace("/api/v1", ""));
      const body = req.method !== "GET" ? await req.clone().json().catch(() => null) : null;
      calls.push({ method: req.method, path, body });
      const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });
      if (path === "/shares/media" && req.method === "GET") return json(media);
      if (path === "/shares/media" && req.method === "PATCH")
        return json({ job: { id: "job-1", kind: "shares.update", title: "x", state: "queued", progress: 0, message: "" }, warnings: [] }, 202);
      if (path === "/jobs/job-1") return json({ id: "job-1", kind: "x", title: "x", state: "succeeded", progress: 100, message: "", error: "" });
      if (path === "/files") return json({ joined: false, settings: { sftpEnabled: false, webdavEnabled: false }, shares: [] });
      return json({ code: "not_found", message: path }, 404);
    }),
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("remote access addresses", () => {
  it("builds WebDAV, SFTP and rclone addresses", () => {
    expect(davURL("nas.home.net")).toBe("https://nas.home.net/dav/");
    expect(davURL("nas.home.net", "Family Media")).toBe("https://nas.home.net/dav/Family%20Media/");
    expect(davWindowsPath("nas.home.net", "Media")).toBe("\\\\nas.home.net@SSL\\dav\\Media");
    expect(davWindowsPath("nas:8443")).toBe("\\\\nas@SSL@8443\\dav");
    expect(sftpURL("nas", "HOME", "Media")).toBe("sftp://HOME%5Cyourname@nas/Media/");
    expect(sftpCommand("nas", "HOME")).toBe("sftp 'HOME\\yourname@nas'");
    expect(rcloneConfig("nas", "HOME")).toContain("url=https://nas/dav/ vendor=other");
  });
});

describe("ShareRemoteSection", () => {
  it("turns SFTP on without touching the other services", async () => {
    const calls: Call[] = [];
    serve(calls);
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <ShareRemoteSection share={media} />
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByRole("switch", { name: /SFTP/ }));
    fireEvent.click(screen.getByRole("button", { name: /Save SFTP and WebDAV/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ services: { ...media.services, sftp: true } });
  });

  it("says they're off for new folders", () => {
    const qc = new QueryClient();
    render(
      <QueryClientProvider client={qc}>
        <ShareRemoteSection />
      </QueryClientProvider>,
    );
    expect(screen.getByText(/Off for new folders/)).toBeTruthy();
  });
});
