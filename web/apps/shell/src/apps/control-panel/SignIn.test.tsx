import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SignIn } from "./SignIn";
import { fillStep, linesToList, validClientForm } from "./SignInRules";

const status = {
  issuer: "https://sso.home.hardynetworks.net",
  issuerChosen: false,
  derivedIssuer: "https://sso.home.hardynetworks.net",
  discovery: "https://sso.home.hardynetworks.net/.well-known/openid-configuration",
  localAccounts: false,
  keys: [{ id: "k1", algorithm: "RS256", state: "active", createdAt: "2026-10-26T10:00:00Z", activatedAt: "2026-10-26T10:00:00Z" }],
};
const nb = "https://vpn.hardynetworks.net";
const presets = [
  {
    id: "netbird",
    name: "NetBird",
    description: "Sign in to NetBird with HardyOS.",
    client: { name: "NetBird", kind: "confidential", firstParty: true, preset: "netbird", redirectUris: [nb + "/oauth2/callback"], postLogoutRedirectUris: [] },
    redirectFromApp: nb + "/oauth2/callback/",
    steps: [
      { where: "Add Identity Provider", field: "Client ID", value: "{clientId}" },
      { where: "Add Identity Provider", field: "Client Secret", value: "{clientSecret}" },
      { where: "Add Identity Provider", field: "Issuer", value: "{issuer}" },
    ],
    notes: [],
  },
];

type Call = { method: string; path: string; body: unknown };

function serve(calls: Call[]) {
  const clients: Record<string, unknown>[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const path = new URL(req.url).pathname.replace("/api/v1", "");
      const body = req.method !== "GET" ? await req.clone().json().catch(() => null) : null;
      calls.push({ method: req.method, path, body });
      const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });
      if (path === "/oidc") return json(status);
      if (path === "/oidc/presets") return json({ presets });
      if (path === "/oidc/clients" && req.method === "GET") return json({ clients });
      if (path === "/oidc/clients" && req.method === "POST") {
        const c = { ...(body as object), id: "hos-abc", managedBy: "", disabled: false, hasSecret: true, allowedGroups: [], createdAt: "", updatedAt: "" };
        clients.push(c);
        return json({ client: c, secret: "s3cret" }, 201);
      }
      if (path === "/oidc/clients/hos-abc" && req.method === "PATCH") return json({ client: { ...clients[0], ...(body as object) } });
      return json({ code: "not_found", message: path }, 404);
    }),
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("SignIn", () => {
  it("adds NetBird from the preset, shows the secret once and saves NetBird's redirect URL", async () => {
    const calls: Call[] = [];
    serve(calls);
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <SignIn />
      </QueryClientProvider>,
    );
    expect(await screen.findByText(status.issuer)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /add app/i }));
    expect(await screen.findByText("Sign in to NetBird with HardyOS.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /^add$/i }));
    await waitFor(() => expect(calls.map((c) => c.method + " " + c.path)).toContain("POST /oidc/clients"));
    expect((await screen.findAllByText("s3cret")).length).toBe(2); // the details and the NetBird step
    const created = calls.find((c) => c.method === "POST" && c.path === "/oidc/clients");
    expect((created?.body as { preset: string }).preset).toBe("netbird");
    // The steps carry the real values.
    expect(screen.getAllByText("hos-abc").length).toBeGreaterThan(1);
    const save = screen.getByRole("button", { name: /save the redirect url/i }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Redirect URL NetBird shows"), { target: { value: nb + "/oauth2/callback/hardyos-x1" } });
    fireEvent.click(save);
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    const patch = calls.find((c) => c.method === "PATCH");
    expect((patch?.body as { redirectUris: string[] }).redirectUris).toEqual([nb + "/oauth2/callback/hardyos-x1"]);
  });
});

describe("SignInRules", () => {
  it("checks client forms like the server", () => {
    const ok = { name: "x", kind: "confidential" as const, redirectUris: ["https://a.example/cb"], allowedGroups: [] };
    expect(validClientForm(ok)).toBeNull();
    expect(validClientForm({ ...ok, redirectUris: ["http://a.example/cb"] })).toMatch(/https/);
    expect(validClientForm({ ...ok, redirectUris: ["http://localhost:53000"] })).toMatch(/https/);
    expect(validClientForm({ ...ok, kind: "public", redirectUris: ["http://localhost:53000"] })).toBeNull();
    expect(validClientForm({ ...ok, allowedGroups: ["Family"] })).toMatch(/DOMAIN/);
    expect(validClientForm({ ...ok, allowedGroups: ["HOME\\Family"] })).toBeNull();
    expect(linesToList(" a \n\n b ")).toEqual(["a", "b"]);
    expect(fillStep("{issuer}/.well-known/openid-configuration", { clientId: "c", clientSecret: "s", issuer: "https://i" })).toBe(
      "https://i/.well-known/openid-configuration",
    );
  });
});
