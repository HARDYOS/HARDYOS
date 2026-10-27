import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Mail } from "./Mail";

const overview = {
  settings: { enabled: false, pool: "", hostname: "", defaultDomain: "", addressStyle: "firstname", defaultQuotaMb: 10240, vpsPeer: "", tlsMode: "self", junkScore: 6, maxMessageMb: 50, sendPerHour: 200 },
  sesSecretSet: false,
  cloudflareTokenSet: false,
  domains: [
    {
      name: "example.net",
      selector: "hardyos202610",
      dkimPublicKey: "",
      dmarcPolicy: "quarantine",
      mtaSts: "off",
      cloudflare: false,
      sesDkimTokens: [],
      sesStatus: "",
      createdAt: "2026-10-27T10:00:00Z",
    },
  ],
  mailboxCount: 0,
  netbirdAddress: "100.90.1.7",
  webmailInstalled: false,
  pools: ["tank"],
  publishedUrl: "",
};

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
      if (path === "/mail" && req.method === "GET") return json(overview);
      if (path === "/mail/settings") return json({ job: { id: "job_1", kind: "mail.apply", title: "Set up the mail server", state: "queued" }, warnings: [] }, 202);
      if (path === "/jobs/job_1") return json({ id: "job_1", kind: "mail.apply", title: "Set up the mail server", state: "running", progress: 30 });
      if (path === "/mail/domains/example.net/dns")
        return json({ domain: "example.net", records: [{ type: "MX", name: "example.net", value: "mail.example.net", priority: 10, purpose: "mx", required: true }], missing: {} });
      return json({ code: "not_found", message: path }, 404);
    }),
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderMail() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Mail />
    </QueryClientProvider>,
  );
}

describe("Control Panel › Mail", () => {
  it("explains what's missing and saves the settings as a job", async () => {
    const calls: Call[] = [];
    serve(calls);
    renderMail();
    fireEvent.click(await screen.findByRole("switch", { name: /Mail server/ }));
    expect(await screen.findByText(/Before turning it on/)).toBeTruthy();
    expect(screen.getByText(/Choose the pool mail is kept on/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Keep mail on"), { target: { value: "tank" } });
    fireEvent.change(screen.getByLabelText("Mail server's name"), { target: { value: "mail.example.net" } });
    fireEvent.change(screen.getByLabelText("VPS's NetBird address"), { target: { value: "100.90.1.2" } });
    fireEvent.click(screen.getByRole("button", { name: /Save and apply/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && c.path === "/mail/settings")).toBe(true));
    const put = calls.find((c) => c.path === "/mail/settings")!.body as { settings: { enabled: boolean; pool: string; vpsPeer: string } };
    expect(put.settings).toMatchObject({ enabled: true, pool: "tank", vpsPeer: "100.90.1.2" });
    expect(put).not.toHaveProperty("sesSecretKey");
  });

  it("shows a domain's DNS records", async () => {
    serve([]);
    renderMail();
    fireEvent.click(await screen.findByRole("tab", { name: "Domains & DNS" }));
    expect(await screen.findByText("mail.example.net", { exact: false })).toBeTruthy();
  });
});
