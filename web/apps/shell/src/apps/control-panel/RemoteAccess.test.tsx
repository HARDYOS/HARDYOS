import type { PublishItem, RemoteCheck, RemoteStatus } from "@hardy/api-client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CheckView, RemoteAccess } from "./RemoteAccess";
import { PublishEditor } from "./RemoteAccessPublish";
import { clientState, managementHost, publishSummary, secretProblem, validDomain, validSetupKey } from "./remoteAccessRules";

type Call = { method: string; path: string; body: unknown };

const notJoined: RemoteStatus = {
  available: true,
  client: { installed: true, joined: false, running: false, state: "off", connected: false, peersTotal: 0, peersConnected: 0, managementConnected: false, interface: "wt0" },
  defaultManagementUrl: "https://vpn.hardynetworks.net",
  settings: {
    enabled: false,
    baseDomain: "",
    apiUrl: "",
    cluster: "",
    desktopName: "nas",
    defaultMode: "netbird",
    instance: "",
    hasToken: false,
    tokenUnreadable: false,
  },
  items: [],
  gateway: { listening: false },
};

const jellyfin: PublishItem = {
  key: "app:jellyfin",
  label: "jellyfin",
  name: "Jellyfin",
  domain: "jellyfin.home.example.net",
  url: "https://jellyfin.home.example.net",
  config: { mode: "public", auth: "sso", groups: [], hardyosSignIn: true, hasSecret: false, default: true },
  published: true,
  status: "active",
};

const joined: RemoteStatus = {
  ...notJoined,
  client: {
    installed: true,
    joined: true,
    running: true,
    state: "connected",
    connected: true,
    ip: "100.83.40.2",
    network: "100.83.0.0/16",
    fqdn: "nas.netbird.selfhosted",
    peersTotal: 4,
    peersConnected: 3,
    managementUrl: "https://vpn.hardynetworks.net",
    managementConnected: true,
    hostname: "nas",
    interface: "wt0",
  },
  settings: { ...notJoined.settings!, enabled: true, baseDomain: "home.example.net", instance: "a1b2c3", hasToken: true },
  items: [
    {
      key: "desktop",
      label: "nas",
      name: "Desktop",
      domain: "nas.home.example.net",
      url: "https://nas.home.example.net",
      config: { mode: "public", auth: "none", groups: [], hardyosSignIn: false, hasSecret: false, default: true },
      published: true,
      status: "active",
    },
    jellyfin,
  ],
  lastSync: { at: "2026-10-26T18:00:00Z", created: 0, updated: 0, deleted: 0 },
  gateway: { listening: true, address: "100.83.40.2:44200" },
};

const check: RemoteCheck = {
  steps: [
    { id: "token", title: "Access token", state: "ok", detail: "NetBird accepted the token." },
    { id: "domain", title: "Base domain in NetBird", state: "bad", detail: "home.example.net isn't a custom domain in NetBird yet." },
    { id: "dns", title: "Wildcard DNS record", state: "bad", detail: "No CNAME yet." },
  ],
  record: { type: "CNAME", name: "*.home.example.net", target: "proxy.hardynetworks.net", proxy: "DNS only", ttl: "Auto" },
  ready: false,
  supportsPrivate: false,
  domains: [],
  clusters: [{ id: "c1", address: "proxy.hardynetworks.net", type: "account", online: true, connected_proxies: 1 }],
  groups: [{ id: "g-all", name: "All" }, { id: "g-family", name: "Family" }],
};

function serve(calls: Call[], status: RemoteStatus) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const path = decodeURIComponent(new URL(req.url).pathname.replace("/api/v1", ""));
      const body = req.method !== "GET" ? await req.clone().json().catch(() => null) : null;
      calls.push({ method: req.method, path, body });
      const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });
      const job = (kind: string) => json({ job: { id: "job-1", kind, title: kind, state: "queued", progress: 0, message: "" }, warnings: [] }, 202);
      if (path === "/remote" && req.method === "GET") return json(status);
      if (path === "/remote/check") return json(check);
      if (path.startsWith("/remote/") || path.endsWith("/publish")) return job("remote");
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

describe("remote access rules", () => {
  it("checks what people type", () => {
    expect(validDomain("home.hardynetworks.net")).toBe(true);
    expect(validDomain("Home.Example.net")).toBe(true);
    expect(validDomain("localhost")).toBe(false);
    expect(validDomain("*.example.net")).toBe(false);
    expect(validSetupKey("A1B2C3D4-0000-1111-2222-333344445555")).toBe(true);
    expect(validSetupKey("--setup-key")).toBe(false);
    expect(managementHost("https://vpn.hardynetworks.net")).toBe("vpn.hardynetworks.net");
    expect(secretProblem("password", "short", false)).toBe("Use at least 8 characters");
    expect(secretProblem("pin", "12a4", false)).toBe("A PIN is 4 to 12 digits");
    expect(secretProblem("pin", "", true)).toBe("");
    expect(secretProblem("sso", "", false)).toBe("");
  });
  it("says how things are published", () => {
    expect(publishSummary(jellyfin.config)).toBe("Public, HardyOS sign-in (SSO)");
    expect(publishSummary({ ...jellyfin.config, mode: "netbird" })).toBe("NetBird devices only");
    expect(clientState(joined.client).label).toBe("Connected");
    expect(clientState({ ...joined.client, connected: false, state: "needs_login" }).tone).toBe("bad");
  });
});

describe("RemoteAccess", () => {
  it("joins NetBird with a setup key", async () => {
    const calls: Call[] = [];
    serve(calls, notJoined);
    renderIn(<RemoteAccess />);
    fireEvent.change(await screen.findByLabelText("Setup key"), { target: { value: "A1B2C3D4-0000-1111-2222-333344445555" } });
    fireEvent.click(screen.getByRole("button", { name: "Join" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/remote/join")).toBe(true));
    expect(calls.find((c) => c.path === "/remote/join")?.body).toEqual({
      managementUrl: "https://vpn.hardynetworks.net",
      setupKey: "A1B2C3D4-0000-1111-2222-333344445555",
      hostname: "nas",
    });
  });

  it("shows the connection and leaves only with the server's name typed", async () => {
    const calls: Call[] = [];
    serve(calls, joined);
    renderIn(<RemoteAccess />);
    expect(await screen.findByText("100.83.40.2")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Leave" }));
    const leave = await screen.findAllByRole("button", { name: "Leave" });
    const confirm = leave[leave.length - 1] as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Type vpn.hardynetworks.net to confirm"), { target: { value: "vpn.hardynetworks.net" } });
    fireEvent.click(confirm);
    await waitFor(() => expect(calls.some((c) => c.path === "/remote/leave")).toBe(true));
    expect(calls.find((c) => c.path === "/remote/leave")?.body).toEqual({ confirm: "vpn.hardynetworks.net" });
  });

  it("sends the access token only when one is typed", async () => {
    const calls: Call[] = [];
    serve(calls, joined);
    renderIn(<RemoteAccess />);
    fireEvent.click(await screen.findByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/remote/publishing")).toBe(true));
    const first = calls.find((c) => c.path === "/remote/publishing")?.body as Record<string, unknown>;
    expect(first.token).toBeUndefined();
    expect(first.baseDomain).toBe("home.example.net");
    fireEvent.change(screen.getByLabelText("NetBird access token"), { target: { value: "nbp_new" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.filter((c) => c.path === "/remote/publishing").length).toBe(2));
    expect((calls.filter((c) => c.path === "/remote/publishing")[1]?.body as Record<string, unknown>).token).toBe("nbp_new");
  });

  it("lists what's published", async () => {
    serve([], joined);
    renderIn(<RemoteAccess />);
    expect(await screen.findByText("https://jellyfin.home.example.net")).toBeTruthy();
    expect(screen.getAllByText("Public, HardyOS sign-in (SSO)").length).toBeGreaterThan(0);
  });
});

describe("CheckView", () => {
  it("shows the exact Cloudflare record and adds the domain", () => {
    const onDomain = vi.fn();
    renderIn(<CheckView c={check} cluster="" setCluster={() => {}} busy={false} onDomain={onDomain} error={null} />);
    const table = screen.getByRole("table", { name: "DNS record to add" });
    expect(table.textContent).toContain("*.home.example.net");
    expect(table.textContent).toContain("proxy.hardynetworks.net");
    expect(table.textContent).toContain("DNS only");
    fireEvent.click(screen.getByRole("button", { name: "Add to NetBird" }));
    expect(onDomain).toHaveBeenCalledWith("add");
  });
});

describe("PublishEditor", () => {
  it("needs a long enough password and sends it once", async () => {
    const calls: Call[] = [];
    serve(calls, joined);
    renderIn(<PublishEditor item={jellyfin} groups={check.groups} supportsPrivate={false} />);
    fireEvent.change(screen.getByLabelText("How Jellyfin is published"), { target: { value: "public" } });
    fireEvent.change(screen.getByLabelText("Sign-in in front"), { target: { value: "password" } });
    const save = screen.getByRole("button", { name: "Save" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "short" } });
    expect(save.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "family-secret-1" } });
    expect(save.disabled).toBe(false);
    fireEvent.click(save);
    await waitFor(() => expect(calls.some((c) => c.path === "/apps/jellyfin/publish")).toBe(true));
    expect(calls.find((c) => c.path === "/apps/jellyfin/publish")?.body).toEqual({
      mode: "public",
      auth: "password",
      groups: [],
      hardyosSignIn: true,
      secret: "family-secret-1",
    });
  });

  it("can't choose NetBird-only without a private cluster", () => {
    serve([], joined);
    renderIn(<PublishEditor item={jellyfin} supportsPrivate={false} />);
    const opt = screen.getByRole("option", { name: /NetBird devices only/ }) as HTMLOptionElement;
    expect(opt.disabled).toBe(true);
  });

  it("publishes the desktop through its own endpoint", async () => {
    const calls: Call[] = [];
    serve(calls, joined);
    renderIn(<PublishEditor item={joined.items[0]!} />);
    fireEvent.change(screen.getByLabelText("How Desktop is published"), { target: { value: "netbird" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/remote/desktop")).toBe(true));
    expect((calls.find((c) => c.path === "/remote/desktop")?.body as Record<string, unknown>).mode).toBe("netbird");
  });
});
