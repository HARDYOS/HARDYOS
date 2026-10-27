import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Notifications } from "./Notifications";

type Call = { method: string; path: string; body: unknown };

const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "Content-Type": "application/json" } });

const desktop = { id: 1, type: "desktop", name: "Desktop", enabled: true, config: {}, secretsSet: {}, lastAt: null, lastOk: null, lastError: "" };
const discord = {
  id: 2,
  type: "discord",
  name: "Family Discord",
  enabled: true,
  config: { urlHost: "discord.com" },
  secretsSet: { url: true },
  lastAt: "2026-10-27T09:00:00Z",
  lastOk: false,
  lastError: "the service answered 404 Not Found",
};
const categories = [
  { id: "disk", label: "Disks", description: "SMART" },
  { id: "*", label: "Everything else", description: "Any other" },
];
const settings = { quietHours: { enabled: false, start: "22:00", end: "07:00", allow: "critical" }, dedupMinutes: 30, maxPerHour: 6, serverUrl: "" };

function serve(calls: Call[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request) => {
      const path = new URL(input.url).pathname.replace("/api/v1", "");
      const body = input.method !== "GET" ? await input.clone().json().catch(() => null) : null;
      calls.push({ method: input.method, path, body });
      switch (`${input.method} ${path}`) {
        case "GET /alerts/channels":
          return json([desktop, discord]);
        case "POST /alerts/channels":
          return json({ ...discord, id: 3, type: "smtp", name: "Gmail", config: (body as { config: object }).config }, 201);
        case "POST /alerts/channels/2/test":
          return json({ ok: false, error: "the service answered 404 Not Found" });
        case "GET /alerts/routes":
          return json([
            { category: "*", channelId: 1, minSeverity: "info" },
            { category: "*", channelId: 2, minSeverity: "warning" },
          ]);
        case "PUT /alerts/routes":
          return json((body as { routes: unknown[] }).routes);
        case "GET /alerts/categories":
          return json(categories);
        case "GET /alerts/settings":
          return json(settings);
        case "GET /alerts/deliveries":
          return json([{ id: 9, at: "2026-10-27T09:00:00Z", channelId: 2, kind: "pool.health", severity: "critical", title: "Pool tank is faulted", status: "failed", detail: "404" }]);
      }
      return json({ code: "not_found", message: path }, 404);
    }),
  );
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Notifications />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("Notifications", () => {
  it("lists channels without secrets, tests one and routes disks to critical only", async () => {
    const calls: Call[] = [];
    serve(calls);
    renderPage();
    expect((await screen.findAllByText("Family Discord")).length).toBeGreaterThan(0);
    expect(screen.getByText("discord.com")).toBeTruthy();
    expect(screen.getAllByText("the service answered 404 Not Found").length).toBeGreaterThan(0);
    expect(await screen.findByText("Pool tank is faulted")).toBeTruthy();

    const card = screen.getAllByText("Family Discord").map((e) => e.closest(".channel")).find(Boolean) as HTMLElement;
    fireEvent.click(within(card).getByRole("button", { name: "Test" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/alerts/channels/2/test")).toBe(true));

    fireEvent.change(await screen.findByLabelText("Disks to Family Discord"), { target: { value: "critical" } });
    fireEvent.click(screen.getByRole("button", { name: "Save routing" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && c.path === "/alerts/routes")).toBe(true));
    const routes = (calls.find((c) => c.method === "PUT")!.body as { routes: { category: string; channelId: number; minSeverity: string }[] }).routes;
    expect(routes).toContainEqual({ category: "disk", channelId: 2, minSeverity: "critical" });
    expect(routes).toContainEqual({ category: "*", channelId: 1, minSeverity: "info" });
  });

  it("adds a Gmail channel with an app password sent only as a secret", async () => {
    const calls: Call[] = [];
    serve(calls);
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /Add channel/ }));
    fireEvent.click(screen.getByRole("button", { name: /Email \(SMTP\)/ }));
    expect((screen.getByLabelText("Mail server") as HTMLInputElement).value).toBe("smtp.gmail.com");
    fireEvent.change(screen.getByLabelText("User name"), { target: { value: "cade@gmail.com" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "abcd efgh ijkl mnop" } });
    fireEvent.change(screen.getByLabelText("From"), { target: { value: "cade@gmail.com" } });
    fireEvent.change(screen.getByLabelText("To"), { target: { value: "cade@example.com, wife@example.com" } });
    fireEvent.click(screen.getAllByRole("button", { name: "Add channel" }).at(-1)!);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/alerts/channels")).toBe(true));
    const body = calls.find((c) => c.method === "POST" && c.path === "/alerts/channels")!.body as {
      type: string;
      config: Record<string, unknown>;
      secrets: Record<string, string>;
    };
    expect(body.type).toBe("smtp");
    expect(body.config).toMatchObject({ host: "smtp.gmail.com", port: 587, security: "starttls", username: "cade@gmail.com", to: ["cade@example.com", "wife@example.com"] });
    expect(body.config).not.toHaveProperty("password");
    expect(body.secrets).toEqual({ password: "abcd efgh ijkl mnop" });
  });
});
