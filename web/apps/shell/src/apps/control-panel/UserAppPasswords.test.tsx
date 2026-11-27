import type { User } from "@hardy/api-client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { UserAppPasswordsDialog, lastUsedText } from "./UserAppPasswords";

const alice = { id: 7, username: "HOME\\alice", displayName: "Alice", source: "domain" } as unknown as User;

type Call = { method: string; path: string };

function serve(calls: Call[], initial: unknown[]) {
  let list = [...initial] as { id: number }[];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const path = new URL(req.url).pathname.replace("/api/v1", "");
      calls.push({ method: req.method, path });
      const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });
      if (path === "/users/7/app-passwords" && req.method === "GET") return json(list);
      const m = /^\/users\/7\/app-passwords\/(\d+)$/.exec(path);
      if (m && req.method === "DELETE") {
        list = list.filter((p) => p.id !== Number(m[1]));
        return new Response(null, { status: 204 });
      }
      return json({ code: "not_found", message: path }, 404);
    }),
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function show(onClose = () => undefined) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <UserAppPasswordsDialog user={alice} onClose={onClose} />
    </QueryClientProvider>,
  );
}

describe("an administrator's view of someone's app passwords", () => {
  it("lists them with scope, made and last used, and revokes one after confirming", async () => {
    const calls: Call[] = [];
    serve(calls, [
      { id: 3, name: "Laptop SFTP", scopes: ["sftp", "files"], createdAt: "2026-11-01T10:00:00Z", lastUsedAt: "2026-11-26T10:00:00Z", lastUsedIp: "203.0.113.9" },
      { id: 2, name: "Phone mail", scopes: ["mail"], createdAt: "2026-10-01T10:00:00Z", lastUsedAt: null, lastUsedIp: "" },
    ]);
    show();
    expect(await screen.findByText("Laptop SFTP")).toBeTruthy();
    expect(screen.getByText("Shared folders (SFTP) · Files (WebDAV)")).toBeTruthy();
    expect(screen.getByText(/from 203\.0\.113\.9/)).toBeTruthy();
    expect(screen.getByText("never used")).toBeTruthy();
    // Nothing is revoked without the confirmation.
    fireEvent.click(screen.getByRole("button", { name: "Revoke Phone mail" }));
    expect(await screen.findByText(/Revoke Phone mail\?/)).toBeTruthy();
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(await screen.findByText("Phone mail")).toBeTruthy();
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    // Confirmed: revoked, and the list follows.
    fireEvent.click(screen.getByRole("button", { name: "Revoke Phone mail" }));
    fireEvent.click(await screen.findByRole("button", { name: /^Revoke$/ }));
    await waitFor(() => expect(calls).toContainEqual({ method: "DELETE", path: "/users/7/app-passwords/2" }));
    await waitFor(() => expect(screen.queryByText("Phone mail")).toBeNull());
    expect(screen.getByText("Laptop SFTP")).toBeTruthy();
  });

  it("says when there are none", async () => {
    serve([], []);
    show();
    expect(await screen.findByText("Alice has no app passwords.")).toBeTruthy();
  });

  it("describes the last use", () => {
    expect(lastUsedText({ lastUsedAt: null, lastUsedIp: "" })).toBe("never used");
    expect(lastUsedText({ lastUsedAt: "x", lastUsedIp: "192.168.1.20" }, () => "today")).toBe("used today from 192.168.1.20");
    expect(lastUsedText({ lastUsedAt: "x", lastUsedIp: "" }, () => "today")).toBe("used today");
  });
});
