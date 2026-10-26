import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Domain } from "./Domain";
import { defaultShortName, domainProblem, passwordProblem } from "./domainRules";

type Call = { method: string; path: string; body: unknown };

const config = {
  domain: "home.hardynetworks.net",
  realm: "HOME.HARDYNETWORKS.NET",
  netbios: "HOME",
  dcName: "dc1.home.hardynetworks.net",
  address: "192.168.1.20/24",
  gateway: "192.168.1.1",
  parent: "enp1s0",
  mac: "02:11:22:33:44:55",
  forwarders: ["192.168.1.1"],
  enabled: true,
  createdAt: "2026-10-25T23:33:00Z",
  host: "dc1",
  others: [{ name: "dc2.home.hardynetworks.net", address: "192.168.1.21" }],
};

function serve(state: { provisioned: boolean }, calls: Call[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const path = new URL(req.url).pathname.replace("/api/v1", "");
      const body = req.method !== "GET" ? await req.clone().json().catch(() => null) : null;
      calls.push({ method: req.method, path, body });
      const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });
      if (path === "/domain" && req.method === "GET")
        return json({ available: true, provisioned: state.provisioned, config: state.provisioned ? config : null, running: state.provisioned, responding: state.provisioned, problem: "" });
      if (path === "/domain/suggest") return json({ parent: "enp1s0", hostAddress: "192.168.1.105/24", gateway: "192.168.1.1", dns: ["192.168.1.1"], address: "192.168.1.20/24" });
      if (path === "/domain/join" && req.method === "POST")
        return json({ job: { id: "job-2", kind: "domain.join", title: "Join the domain", state: "queued", progress: 0, message: "" }, warnings: [] }, 202);
      if (path === "/jobs/job-2") return json({ id: "job-2", kind: "domain.join", title: "Join the domain", state: "running", progress: 10, message: "Copying the domain from 192.168.1.20" });
      if (path === "/domain" && req.method === "POST")
        return json({ job: { id: "job-1", kind: "domain.provision", title: "Create the domain", state: "queued", progress: 0, message: "" }, warnings: [] }, 202);
      if (path === "/jobs/job-1") return json({ id: "job-1", kind: "domain.provision", title: "Create the domain", state: "running", progress: 10, message: "Creating the domain database" });
      if (path === "/domain/users")
        return json({
          users: [
            { username: "Administrator", givenName: "", surname: "", displayName: "", email: "", enabled: true, lockedOut: false, mustChangePassword: false, groups: ["Domain Admins"], created: "", lastLogon: 0, builtin: true },
            { username: "alice", givenName: "Alice", surname: "Hardy", displayName: "Alice Hardy", email: "", enabled: false, lockedOut: false, mustChangePassword: false, groups: ["Domain Users", "Family"], created: "", lastLogon: 0, builtin: false },
          ],
        });
      return json({ code: "not_found", message: path }, 404);
    }),
  );
}

function renderDomain() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Domain />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("domain rules", () => {
  it("matches the server", () => {
    expect(domainProblem("hardy.local")).toMatch(/\.local/);
    expect(domainProblem("home")).toMatch(/two parts/);
    expect(domainProblem("home.hardynetworks.net")).toBeNull();
    expect(defaultShortName("home.hardynetworks.net")).toBe("HOME");
    expect(passwordProblem("short1A")).toMatch(/8 characters/);
    expect(passwordProblem("alllowercase")).toMatch(/three of/);
    expect(passwordProblem("Alice-2026!x", "alice")).toMatch(/user name/);
    expect(passwordProblem("Sunfl0wer-Kite", "alice")).toBeNull();
  });
});

describe("Domain", () => {
  it("sets up a domain with the suggested address and never sends a mismatched password", async () => {
    const calls: Call[] = [];
    serve({ provisioned: false }, calls);
    renderDomain();
    fireEvent.click(await screen.findByRole("button", { name: "Create a domain" }));
    const name = await screen.findByLabelText("Domain name");
    expect((screen.getByLabelText("Domain controller address") as HTMLInputElement).value).toBe("192.168.1.20");

    fireEvent.change(name, { target: { value: "hardy.local" } });
    expect(await screen.findByText(/cause trouble with Macs/)).toBeTruthy();
    fireEvent.change(name, { target: { value: "home.hardynetworks.net" } });
    expect((screen.getByLabelText("Short name") as HTMLInputElement).value).toBe("HOME");

    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "Fam1ly-Domain!" } });
    fireEvent.change(screen.getByLabelText("Password again"), { target: { value: "Fam1ly-Domain?" } });
    const create = screen.getByRole("button", { name: "Create the domain" }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Password again"), { target: { value: "Fam1ly-Domain!" } });
    expect(create.disabled).toBe(false);
    fireEvent.click(create);

    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/domain")).toBe(true));
    const post = calls.find((c) => c.method === "POST" && c.path === "/domain")!.body as Record<string, unknown>;
    expect(post).toMatchObject({ domain: "home.hardynetworks.net", netbios: "HOME", adminPassword: "Fam1ly-Domain!", address: "192.168.1.20", gateway: "192.168.1.1" });
    expect(await screen.findByText("Creating the domain database")).toBeTruthy();
  });

  it("joins an existing domain without asking for a new password twice", async () => {
    const calls: Call[] = [];
    serve({ provisioned: false }, calls);
    renderDomain();
    fireEvent.click(await screen.findByRole("button", { name: "Join a domain" }));
    fireEvent.change(await screen.findByLabelText("Domain name"), { target: { value: "home.hardynetworks.net" } });
    fireEvent.change(screen.getByLabelText("An existing domain controller's address"), { target: { value: "192.168.1.20" } });
    fireEvent.change(screen.getByLabelText("This server's domain controller address"), { target: { value: "192.168.1.21" } });
    fireEvent.change(screen.getByLabelText("Administrator password"), { target: { value: "Fam1ly-Domain!" } });
    fireEvent.click(screen.getByRole("button", { name: "Join the domain" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/domain/join")).toBe(true));
    const post = calls.find((c) => c.path === "/domain/join")!.body as Record<string, unknown>;
    expect(post).toMatchObject({ domain: "home.hardynetworks.net", existing: "192.168.1.20", adminPassword: "Fam1ly-Domain!", address: "192.168.1.21" });
    expect(screen.queryByLabelText("Password again")).toBeNull();
    expect(await screen.findByText("Copying the domain from 192.168.1.20")).toBeTruthy();
  });

  it("shows a running domain and its accounts", async () => {
    serve({ provisioned: true }, []);
    renderDomain();
    expect(await screen.findByText("Running")).toBeTruthy();
    expect(screen.getAllByText("dc1.home.hardynetworks.net").length).toBeGreaterThan(0);
    // Both DCs listed, and the router gets both as DNS servers.
    expect(screen.getByText("dc2.home.hardynetworks.net")).toBeTruthy();
    expect(screen.getByText("DNS 2: 192.168.1.21")).toBeTruthy();
    // Shared domain: remove this server, not delete the domain.
    expect(screen.getByRole("button", { name: /Remove this server/ })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Delete domain/ })).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: "Users" }));
    expect(await screen.findByText("Alice Hardy")).toBeTruthy();
    expect(screen.getByText("Turned off")).toBeTruthy();
    // Built-in accounts are hidden until asked for.
    expect(screen.queryByText("Administrator")).toBeNull();
  });
});
