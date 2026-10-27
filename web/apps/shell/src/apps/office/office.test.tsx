import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Office } from "../control-panel/Office";
import { FileManagerView } from "../files/FileManager";
import { ShareLinkDialog } from "../files/dialogs";
import { HOME } from "../files/paths";
import { editableFormat, opensInEditor } from "./officeApi";

type Call = { method: string; path: string; body: unknown };
type Handler = (c: Call) => unknown;

function serve(routes: Record<string, Handler>, calls: Call[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
      const u = new URL(req.url);
      const path = u.pathname.replace("/api/v1", "");
      const body = req.method === "GET" ? null : await req.clone().json().catch(() => null);
      const call = { method: req.method, path, body };
      calls.push(call);
      const h = routes[`${req.method} ${path}`] ?? routes[path];
      const out = h ? h(call) : { __status: 404, code: "not_found", message: path };
      const { __status = 200, ...rest } = (out ?? {}) as { __status?: number };
      return new Response(JSON.stringify(Array.isArray(out) ? out : rest), { status: __status, headers: { "Content-Type": "application/json" } });
    }),
  );
}

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

const T = "2026-10-20T10:00:00Z";
const entry = (path: string, extra: Record<string, unknown> = {}) => ({
  name: path.slice(path.lastIndexOf("/") + 1),
  path,
  dir: false,
  size: 1200,
  modified: T,
  writable: true,
  ...extra,
});

const FORMATS = [
  { ext: "docx", documentType: "word", editable: true, lossy: false },
  { ext: "xlsx", documentType: "cell", editable: true, lossy: false },
  { ext: "pptx", documentType: "slide", editable: true, lossy: false },
  { ext: "csv", documentType: "cell", editable: true, lossy: true },
  { ext: "doc", documentType: "word", editable: false, lossy: false },
];
const ON = { enabled: true, ready: true, editorLimit: 20, activeEditors: 3, openDocuments: 1, maxFileMB: 100, formats: FORMATS, installed: true };

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("office helpers", () => {
  it("knows which files open and which save", () => {
    const st = ON as never;
    expect(opensInEditor(st, { name: "Plan.DOCX", dir: false })).toBe(true);
    expect(opensInEditor(st, { name: "photo.jpg", dir: false })).toBe(false);
    expect(opensInEditor(st, { name: "x.docx", dir: true })).toBe(false);
    expect(opensInEditor({ ...ON, ready: false } as never, { name: "a.docx", dir: false })).toBe(false);
    expect(opensInEditor(undefined, { name: "a.docx", dir: false })).toBe(false);
    expect(editableFormat(st, "old.doc")).toBe(false);
    expect(editableFormat(st, "list.csv")).toBe(true);
  });
});

describe("File Manager with the office suite", () => {
  it("opens documents in the editor and makes new ones", async () => {
    const calls: Call[] = [];
    serve(
      {
        "/files/shares": () => ({ shares: [{ id: "docs", name: "Docs", writable: true, recycle: true }] }),
        "/files/list": () => ({ entries: [entry("Plan.docx"), entry("Budget.xlsx"), entry("photo.jpg")] }),
        "/office": () => ON,
        "POST /office/new": (c) => {
          const b = c.body as { name: string };
          return { __status: 201, ...entry(b.name) };
        },
      },
      calls,
    );
    const openDoc = vi.fn();
    wrap(<FileManagerView isAdmin openDoc={openDoc} />);
    const plan = await screen.findByRole("option", { name: /Plan\.docx/ });
    await waitFor(() => expect(calls.some((c) => c.path === "/office")).toBe(true));
    fireEvent.doubleClick(plan);
    await waitFor(() => expect(openDoc).toHaveBeenCalledWith("docs", "Plan.docx", "Plan.docx", "edit"));

    // Right-click offers the editor and read-only.
    fireEvent.contextMenu(screen.getByRole("option", { name: /Budget\.xlsx/ }));
    const menu = await screen.findByRole("menu");
    fireEvent.click(within(menu).getByRole("menuitem", { name: "Open read only" }));
    expect(openDoc).toHaveBeenLastCalledWith("docs", "Budget.xlsx", "Budget.xlsx", "view");

    // New document: a spreadsheet named "Taxes".
    fireEvent.click(screen.getByRole("button", { name: "New document" }));
    fireEvent.click(await screen.findByRole("radio", { name: /Spreadsheet/ }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Taxes" } });
    fireEvent.click(screen.getByRole("button", { name: "Create and open" }));
    await waitFor(() => expect(openDoc).toHaveBeenLastCalledWith("docs", "Taxes.xlsx", "Taxes.xlsx", "edit"));
    const made = calls.find((c) => c.method === "POST" && c.path === "/office/new");
    expect(made?.body).toEqual({ share: "docs", dir: "", kind: "spreadsheet", name: "Taxes.xlsx" });
  });

  it("previews as before when the office suite is off", async () => {
    const calls: Call[] = [];
    serve(
      {
        "/files/shares": () => ({ shares: [{ id: HOME, name: "Home", writable: true, recycle: false }] }),
        "/files/list": () => ({ entries: [entry("Plan.docx")] }),
        "/office": () => ({ ...ON, enabled: false, ready: false }),
      },
      calls,
    );
    const openDoc = vi.fn();
    wrap(<FileManagerView isAdmin openDoc={openDoc} />);
    const plan = await screen.findByRole("option", { name: /Plan\.docx/ });
    await waitFor(() => expect(calls.some((c) => c.path === "/office")).toBe(true));
    expect(screen.queryByRole("button", { name: "New document" })).toBeNull();
    vi.spyOn(document.body, "appendChild");
    fireEvent.doubleClick(plan);
    expect(openDoc).not.toHaveBeenCalled();
  });
});

describe("share links for editing", () => {
  it("offers edit only when chosen, and sends it", async () => {
    const calls: Call[] = [];
    serve(
      {
        "POST /sharelinks": () => ({
          __status: 201,
          url: "/s/abc",
          token: "abc",
          link: { id: 1, access: "edit", expiresAt: T, hasPassword: false },
        }),
      },
      calls,
    );
    wrap(<ShareLinkDialog share="docs" entry={entry("Plan.docx") as never} office={ON as never} onClose={() => undefined} />);
    const select = screen.getByLabelText("People can") as HTMLSelectElement;
    expect(select.value).toBe("view");
    fireEvent.change(select, { target: { value: "edit" } });
    expect(screen.getByText(/Anyone with the link can change the document/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Create link" }));
    await screen.findByText("Link ready");
    expect((calls[0]!.body as { access: string }).access).toBe("edit");
    expect(screen.getByText(/edit it in their browser/)).toBeTruthy();
  });

  it("has no edit choice for files the editor can't save, or with the suite off", () => {
    serve({}, []);
    const { unmount } = wrap(<ShareLinkDialog share="docs" entry={entry("old.doc") as never} office={ON as never} onClose={() => undefined} />);
    expect(screen.queryByLabelText("People can")).toBeNull();
    unmount();
    wrap(<ShareLinkDialog share="docs" entry={entry("Plan.docx") as never} office={{ ...ON, enabled: false } as never} onClose={() => undefined} />);
    expect(screen.queryByLabelText("People can")).toBeNull();
  });
});

describe("Control Panel › Office", () => {
  it("turns the suite on, on the chosen pool", async () => {
    const calls: Call[] = [];
    serve(
      {
        "/office": () => ({ ...ON, enabled: false, ready: false, installed: false, pools: ["tank", "fast"], settings: { enabled: false, maxFileMB: 100, fontsShare: "" } }),
        "POST /office/enable": () => ({ __status: 202, job: { id: "j1", kind: "office.enable", title: "Turn on the office suite", state: "queued", progress: 0 }, warnings: [] }),
        "/jobs/j1": () => ({ id: "j1", kind: "office.enable", title: "Turn on the office suite", state: "running", progress: 40, message: "Downloading" }),
      },
      calls,
    );
    wrap(<Office />);
    fireEvent.change(await screen.findByLabelText("Pool for apps"), { target: { value: "fast" } });
    fireEvent.click(screen.getByRole("button", { name: "Turn on the office suite" }));
    await waitFor(() => expect(calls.find((c) => c.path === "/office/enable")?.body).toEqual({ pool: "fast" }));
  });

  it("shows who's editing against the 20-editor limit and asks before turning off", async () => {
    const calls: Call[] = [];
    serve(
      {
        "/office": () => ({
          ...ON,
          activeEditors: 18,
          appState: "running",
          version: "9.4.0.1",
          settings: { enabled: true, maxFileMB: 100, fontsShare: "" },
          sessions: [{ share: "docs", place: "docs", path: "Plan.docx", editors: ["Cade", "Sam (guest)"], opened: T, saves: 2, state: "open" }],
          listeners: { officePort: 44250, office: true, internal: "172.17.0.1:44251" },
        }),
        "POST /office/disable": (c) =>
          (c.body as { confirm: boolean }).confirm
            ? { __status: 202, job: { id: "j2", state: "queued", progress: 0, title: "Turn off" }, warnings: [] }
            : { __status: 409, code: "confirm_required", message: "18 people are editing" },
        "/jobs/j2": () => ({ id: "j2", state: "succeeded", progress: 100, title: "Turn off" }),
      },
      calls,
    );
    wrap(<Office />);
    expect(await screen.findByText("18 of 20 editing now")).toBeTruthy();
    expect(screen.getByText("Cade, Sam (guest)")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Turn off" }));
    fireEvent.click(await screen.findByRole("button", { name: "Turn off anyway" }));
    await waitFor(() => expect(calls.filter((c) => c.path === "/office/disable").map((c) => c.body)).toEqual([{ confirm: false }, { confirm: true }]));
  });
});
