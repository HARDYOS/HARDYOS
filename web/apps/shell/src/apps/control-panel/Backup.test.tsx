import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Backup } from "./Backup";

const manifest = { format: 1, createdAt: "2026-10-25T09:15:00Z", version: "0.2.0", hostname: "nas", schema: 7, secrets: false, entries: [], users: 2, note: "nightly" };
const base = {
  settings: { nightly: true, pool: "", keep: 14, time: "03:15" },
  pools: ["tank"],
  backups: [{ pool: "tank", name: "hardyos-settings-nas-20261025-091500.hbak", size: 48_000, manifest }],
  lastRun: "2026-10-25T09:15:00Z",
  lastError: "",
  pending: null as null | { manifest: typeof manifest; stagedAt: string },
  lastResult: null,
};

type Call = { method: string; path: string; body: unknown };

function serve(status: typeof base, calls: Call[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const url = new URL(req.url);
      const path = url.pathname.replace("/api/v1", "");
      const body = req.method !== "GET" && path !== "/system/backups/upload" ? await req.clone().json().catch(() => null) : null;
      calls.push({ method: req.method, path, body });
      const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });
      if (path === "/system/backups") return json(status);
      if (path === "/system/backups/restore") {
        const b = body as { password?: string; upload?: string };
        if (b.upload && b.password !== "right password") return json({ code: "invalid", message: "the password is wrong, or the backup is damaged" }, 400);
        return json({ manifest, stagedAt: new Date().toISOString() });
      }
      if (path === "/system/backups/upload") return json({ upload: "upload-abc.hbak" });
      if (path === "/system/backups/download") return json({ name: "download-1.hbak", file: "hardyos-settings-nas-20261025-091500.hbak", size: 4000 });
      if (path === "/system/backups/restore/cancel") return new Response(null, { status: 204 });
      return json({ code: "not_found", message: path }, 404);
    }),
  );
}

function renderBackup() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Backup />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("Backup", () => {
  it("lists pool backups and restores one at the next restart", async () => {
    const calls: Call[] = [];
    serve(structuredClone(base), calls);
    renderBackup();
    expect(await screen.findByText("Backups on your pools")).toBeTruthy();
    expect(screen.getByText("nightly")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Restore…" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/aren't touched/)).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Restore at next restart" }));
    await waitFor(() => expect(calls.find((c) => c.path === "/system/backups/restore")?.body).toEqual({ pool: "tank", name: base.backups[0]!.name }));
  });

  it("downloads a password-protected backup", async () => {
    const calls: Call[] = [];
    serve(structuredClone(base), calls);
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    renderBackup();
    const download = await screen.findByRole("button", { name: "Download" });
    expect((download as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "long enough pw" } });
    fireEvent.change(screen.getByLabelText("Repeat the password"), { target: { value: "long enough px" } });
    expect(screen.getByText("The passwords don't match")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Repeat the password"), { target: { value: "long enough pw" } });
    fireEvent.click(download);
    await waitFor(() => expect(click).toHaveBeenCalled());
    expect(calls.find((c) => c.path === "/system/backups/download")?.body).toEqual({ password: "long enough pw", secrets: true });
    click.mockRestore();
  });

  it("asks for the password of a protected file and keeps the upload after a wrong one", async () => {
    const calls: Call[] = [];
    serve(structuredClone(base), calls);
    renderBackup();
    await screen.findByText("Restore from a file");
    const file = new File([new Uint8Array([72, 79, 83, 66, 65, 75, 48, 49, 1, 0, 0])], "settings.hbak");
    fireEvent.change(screen.getByLabelText("Backup file"), { target: { files: [file] } });
    const pw = await screen.findByLabelText("Backup password");
    fireEvent.change(pw, { target: { value: "wrong" } });
    fireEvent.click(screen.getByRole("button", { name: "Restore at next restart" }));
    expect(await screen.findByText(/password is wrong/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Backup password"), { target: { value: "right password" } });
    fireEvent.click(screen.getByRole("button", { name: "Restore at next restart" }));
    await waitFor(() => expect(calls.filter((c) => c.path === "/system/backups/restore").length).toBe(2));
    expect(calls.filter((c) => c.path === "/system/backups/upload").length).toBe(1);
  });

  it("shows a waiting restore with the accounts warning", async () => {
    const calls: Call[] = [];
    const st = structuredClone(base);
    st.pending = { manifest, stagedAt: new Date().toISOString() };
    serve(st, calls);
    renderBackup();
    expect(await screen.findByText(/are ready to restore/)).toBeTruthy();
    expect(screen.getByText(/sign in with an account from the backup \(2 accounts\)/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Don't restore" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/system/backups/restore/cancel")).toBe(true));
  });
});
