import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BackupView } from "./Backup";
import { itemKey, itemLabel, parseItemKey } from "./backupApi";
import { mailConfirmation } from "./MailRestore";

type Call = { method: string; path: string; body: unknown };
type Handler = (req: { body: unknown; query: URLSearchParams }) => unknown;

function serve(routes: Record<string, Handler>, calls: Call[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const u = new URL(req.url);
      const path = u.pathname.replace("/api/v1", "");
      const body = req.method !== "GET" ? await req.clone().json().catch(() => null) : null;
      calls.push({ method: req.method, path, body });
      const h = routes[`${req.method} ${path}`] ?? routes[path];
      const out = h ? h({ body, query: u.searchParams }) : { __status: 404, code: "not_found", message: path };
      const { __status = 200, ...rest } = (out ?? {}) as { __status?: number };
      return new Response(JSON.stringify(rest), { status: __status, headers: { "Content-Type": "application/json" } });
    }),
  );
}

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const A = "a11ce0000000000000000001";
const B = "b0b000000000000000000002";
const target = { id: "off", name: "Offsite", kind: "s3", endpoint: "https://s3.example.com", bucket: "b", createdAt: "", maintenance: { weekday: 0, time: "04:30", checkPercent: 5 } };
const here = { hostname: "mail.example.net", domains: ["example.net"], mailboxes: [{ key: A, address: "alice@example.net" }, { key: B, address: "bob@example.net" }], webmail: false };
const job = { __status: 202, job: { id: "j1", kind: "backup.cloud.restore", title: "", state: "queued", progress: 0, message: "", error: "", params: {}, result: {} }, warnings: [] };

function routes(extra: Record<string, Handler> = {}): Record<string, Handler> {
  return {
    "GET /backup": () => ({ targets: [target], tasks: [], offer: null }),
    "GET /shares": () => ({ shares: [{ id: "media", name: "Media" }] }),
    "GET /apps": () => ({ apps: [] }),
    "GET /vms": () => ({ vms: [], kept: [] }),
    "GET /mail/restore-targets": () => here,
    "GET /backup/targets/off/versions": () => ({
      versions: [{ run: "r1", task: "t1", time: "2026-11-20T01:30:00Z", manifest: "m", thisServer: true, items: [{ item: "mail", snapshot: "dddddddd", webmail: "eeeeeeee", time: "", files: 30, bytes: 3000 }] }],
    }),
    "GET /backup/targets/off/mail": ({ query }) =>
      query.get("snapshot") === "dddddddd" ? { hostname: "mail.example.net", domains: ["example.net"], mailboxes: [{ key: A, address: "alice@example.net" }], webmail: true } : { __status: 400 },
    "GET /jobs/j1": () => ({ id: "j1", state: "running", progress: 50, message: "Restoring", error: "" }),
    "POST /backup/restore": () => job,
    ...extra,
  };
}

describe("Mail in backups", () => {
  it("keys the mail item without an id", () => {
    expect(itemKey({ kind: "mail" })).toBe("mail");
    expect(parseItemKey("mail")).toEqual({ kind: "mail" });
    expect(itemLabel("mail", {})).toBe("Mail");
  });

  it("asks for the right confirmation", () => {
    const boxes = here.mailboxes;
    expect(mailConfirmation({ scope: "mailbox", key: A, into: A, domain: "", mode: "copy" }, boxes)).toBe("");
    expect(mailConfirmation({ scope: "mailbox", key: A, into: A, domain: "", mode: "overwrite" }, boxes)).toBe("alice@example.net");
    // Another mailbox, even into a new folder: its address.
    expect(mailConfirmation({ scope: "calendars", key: A, into: B, domain: "", mode: "copy" }, boxes)).toBe("bob@example.net");
    expect(mailConfirmation({ scope: "domain", key: "", into: "", domain: "example.net", mode: "overwrite" }, boxes)).toBe("example.net");
    expect(mailConfirmation({ scope: "domain", key: "", into: "", domain: "example.net", mode: "copy" }, boxes)).toBe("");
    expect(mailConfirmation({ scope: "all", key: "", into: "", domain: "", mode: "copy" }, boxes)).toBe("mail");
  });

  it("ticks Mail for a new task when the server has a mail server", async () => {
    const calls: Call[] = [];
    serve(routes({ "POST /backup/tasks": ({ body }) => ({ __status: 201, id: "t2", ...(body as object) }) }), calls);
    wrap(<BackupView />);
    fireEvent.click(await screen.findByRole("button", { name: /Make a backup task/ }));
    const dialog = await screen.findByRole("dialog");
    const mail = (await within(dialog).findByRole("checkbox", { name: /^Mail/ })) as HTMLInputElement;
    await waitFor(() => expect(mail.checked).toBe(true));
    fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    fireEvent.change(within(dialog).getByLabelText("Task name"), { target: { value: "Mail" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Make task" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/backup/tasks")).toBe(true));
    expect((calls.find((c) => c.path === "/backup/tasks" && c.method === "POST")!.body as { items: unknown[] }).items).toEqual([{ kind: "mail" }]);
  });

  it("restores a mailbox over itself only with its address typed, and everything only with mail typed", async () => {
    const calls: Call[] = [];
    serve(routes(), calls);
    wrap(<BackupView initial="restore" />);
    const versions = await screen.findByRole("region", { name: "Versions" });
    fireEvent.click((await within(versions).findAllByRole("button"))[0]!);
    const pane = await screen.findByRole("region", { name: "Restore" });
    expect(await within(pane).findByText(/with webmail settings/)).toBeTruthy();
    const go = (await within(pane).findByRole("button", { name: "Restore" })) as HTMLButtonElement;
    expect(go.disabled).toBe(false); // into a new folder: nothing to type
    fireEvent.click(within(pane).getByRole("radio", { name: /Replace what's there/ }));
    expect(go.disabled).toBe(true);
    fireEvent.change(within(pane).getByLabelText("Type alice@example.net to confirm"), { target: { value: "alice@example.net" } });
    expect(go.disabled).toBe(false);
    fireEvent.click(go);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/backup/restore")).toBe(true));
    expect(calls.find((c) => c.method === "POST" && c.path === "/backup/restore")!.body).toEqual({
      target: "off",
      snapshot: "dddddddd",
      mode: "mail",
      mail: { scope: "mailbox", key: A, into: A, mode: "overwrite", confirm: "alice@example.net" },
    });

    fireEvent.click(within(pane).getByRole("radio", { name: /Everything/ }));
    const go2 = within(pane).getByRole("button", { name: "Restore" }) as HTMLButtonElement;
    expect(go2.disabled).toBe(true);
    expect(within(pane).getByText(/so do webmail settings/)).toBeTruthy();
    fireEvent.change(within(pane).getByLabelText("Type mail to confirm"), { target: { value: "mail" } });
    fireEvent.click(go2);
    await waitFor(() => expect(calls.filter((c) => c.method === "POST" && c.path === "/backup/restore")).toHaveLength(2));
    expect(calls.filter((c) => c.method === "POST" && c.path === "/backup/restore")[1]!.body).toEqual({
      target: "off",
      snapshot: "dddddddd",
      mode: "mail",
      mail: { scope: "all", confirm: "mail" },
    });
  });
});
