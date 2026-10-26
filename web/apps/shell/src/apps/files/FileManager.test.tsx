import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { uploadFile } from "./fileApi";
import { FileManagerView } from "./FileManager";
import { HOME, crumbs, downloadUrl, kindOf, nameProblem, numbered, parent, sortEntries } from "./paths";
import { clickSelect, emptySelection, moveSelect } from "./selection";

type Call = { method: string; path: string; body: unknown; query: URLSearchParams; headers: Headers };
type Handler = (req: Call) => unknown;

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
const dir = (path: string, extra: Record<string, unknown> = {}) => entry(path, { dir: true, size: 0, ...extra });

const SHARES = [
  { id: "media", name: "Media", writable: true, recycle: true },
  { id: HOME, name: "Home", writable: true, recycle: false },
  { id: "backups", name: "Backups", writable: false, recycle: false },
];

function readBlob(b: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result));
    r.onerror = () => reject(r.error);
    r.readAsText(b);
  });
}

function serve(routes: Record<string, Handler>, calls: Call[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      // jsdom's Blob (an upload chunk) isn't one Node's Request understands: read it here.
      const blob = init?.body instanceof Blob ? await readBlob(init.body) : null;
      const req = typeof input === "string" ? new Request(new URL(input, "http://x"), blob === null ? init : { ...init, body: blob }) : input;
      const u = new URL(req.url);
      const path = u.pathname.replace("/api/v1", "");
      let body: unknown = null;
      if (req.method === "PUT") body = await req.clone().text();
      else if (req.method !== "GET")
        body = await req
          .clone()
          .json()
          .catch(() => null);
      const call = { method: req.method, path, body, query: u.searchParams, headers: req.headers };
      calls.push(call);
      const h = routes[`${req.method} ${path}`] ?? routes[path];
      const out = h ? h(call) : { __status: 404, code: "not_found", message: path };
      if (out instanceof Response) return out;
      const { __status = 200, ...rest } = (out ?? {}) as { __status?: number };
      const payload = Array.isArray(out) ? out : rest;
      return new Response(__status === 204 ? null : JSON.stringify(payload), { status: __status, headers: { "Content-Type": "application/json" } });
    }),
  );
}

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

/** A tree of folders: share -> path -> entries. */
function tree(t: Record<string, Record<string, ReturnType<typeof entry>[]>>): Handler {
  return ({ query }) => {
    const list = t[query.get("share") ?? ""]?.[query.get("path") ?? ""];
    return list ? { entries: list } : { __status: 404, code: "not_found", message: "there's no such file or folder" };
  };
}

const mediaTree = {
  media: {
    "": [entry("notes.txt", { size: 300 }), dir("Photos"), entry("Report.pdf", { size: 90_000 }), dir("Movies"), entry(".recycle", { dir: true })],
    Photos: [entry("Photos/beach.jpg", { size: 2_400_000 }), entry("Photos/snow.jpg"), dir("Photos/2024")],
    "Photos/2024": [],
    Movies: [entry("Movies/trip.mp4", { size: 50_000_000 })],
  },
  [HOME]: { "": [entry("todo.md")] },
  backups: { "": [entry("old.tar", { writable: false })] },
};

const listbox = () => screen.getByRole("listbox", { name: /^Files in/ });
const option = (name: string) => screen.getByRole("option", { name: new RegExp(`^${name.replace(/[.()]/g, "\\$&")}`) });

beforeEach(() => {
  try {
    localStorage.clear();
  } catch {
    /* none */
  }
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("paths and selection", () => {
  it("sorts folders first and names naturally", () => {
    const list = [entry("b10.txt"), dir("Zed"), entry("b2.txt", { size: 5 }), dir("alpha")];
    expect(sortEntries(list, { key: "name", asc: true }).map((e) => e.name)).toEqual(["alpha", "Zed", "b2.txt", "b10.txt"]);
    expect(sortEntries(list, { key: "size", asc: true }).map((e) => e.name)).toEqual(["alpha", "Zed", "b2.txt", "b10.txt"]);
    expect(sortEntries(list, { key: "name", asc: false }).map((e) => e.name)).toEqual(["Zed", "alpha", "b10.txt", "b2.txt"]);
  });
  it("checks names and builds paths", () => {
    expect(nameProblem("")).toBe("Type a name.");
    expect(nameProblem("a/b")).toMatch(/can't contain/);
    expect(nameProblem(".recycle")).toMatch(/kept for HardyOS/);
    expect(nameProblem("Photos", ["photos"])).toMatch(/already here/);
    expect(nameProblem("New folder")).toBeNull();
    expect(numbered("photo.jpg", 2)).toBe("photo (2).jpg");
    expect(numbered("README", 3)).toBe("README (3)");
    expect(parent("a/b/c")).toBe("a/b");
    expect(crumbs("a/b").map((c) => c.path)).toEqual(["a", "a/b"]);
    expect(kindOf({ name: "x.MP4", dir: false })).toBe("video");
    expect(downloadUrl("media", ["a b.txt", "c"], { snapshot: "s1" })).toBe("/api/v1/files/download?share=media&path=a+b.txt&path=c&snapshot=s1");
  });
  it("selects like a desktop file manager", () => {
    const order = ["a", "b", "c", "d", "e"];
    let s = clickSelect(emptySelection(), order, "b", {});
    s = clickSelect(s, order, "d", { shift: true });
    expect([...s.selected]).toEqual(["b", "c", "d"]);
    s = clickSelect(s, order, "c", { toggle: true });
    expect([...s.selected].sort()).toEqual(["b", "d"]);
    s = moveSelect(clickSelect(emptySelection(), order, "a", {}), order, 1, true);
    s = moveSelect(s, order, 1, true);
    expect([...s.selected]).toEqual(["a", "b", "c"]);
    expect([...moveSelect(s, order, 10, false).selected]).toEqual(["e"]);
  });
});

describe("File Manager", () => {
  it("shows places, opens Home first, browses folders with breadcrumbs, sorting and the keyboard", async () => {
    const calls: Call[] = [];
    serve({ "/files/shares": () => ({ shares: SHARES }), "/files/list": tree(mediaTree) }, calls);
    wrap(<FileManagerView isAdmin={false} />);

    const places = await screen.findByRole("navigation", { name: "Places" });
    await within(places).findByRole("button", { name: "Home" });
    const names = within(places)
      .getAllByRole("button")
      .map((b) => b.textContent);
    expect(names).toEqual(["Home", "Backupsread only", "Media", "Links I've shared"]);
    expect(await screen.findByRole("option", { name: /todo\.md/ })).toBeTruthy();

    fireEvent.click(within(places).getByRole("button", { name: "Media" }));
    await screen.findByRole("option", { name: /^Movies/ });
    // Folders first, then files; the recycle bin is never listed.
    expect(screen.getAllByRole("option").map((o) => o.textContent?.split(/\d/)[0]?.replace(/–.*/, ""))).toEqual(
      expect.arrayContaining([expect.stringContaining("Movies"), expect.stringContaining("Photos")]),
    );
    const order = screen.getAllByRole("option").map((o) => within(o).getByText(/./, { selector: ".fm-ellipsis" }).textContent);
    expect(order).toEqual(["Movies", "Photos", "notes.txt", "Report.pdf"]);
    expect(screen.queryByText(".recycle")).toBeNull();
    expect(screen.getByText("Deleted items go to this folder's recycle bin.")).toBeTruthy();

    // Sort by size, biggest first.
    fireEvent.click(screen.getByRole("button", { name: "Size" }));
    fireEvent.click(screen.getByRole("button", { name: /Size/ }));
    expect(screen.getAllByRole("option").map((o) => within(o).getByText(/./, { selector: ".fm-ellipsis" }).textContent)).toEqual([
      "Photos",
      "Movies",
      "Report.pdf",
      "notes.txt",
    ]);

    // Double-click opens a folder; the breadcrumb leads back; Backspace goes up.
    fireEvent.doubleClick(option("Photos"));
    await screen.findByRole("option", { name: /beach\.jpg/ });
    const path = screen.getByRole("navigation", { name: "Path" });
    expect(within(path).getByRole("button", { name: "Photos" }).getAttribute("aria-current")).toBe("location");
    // Keyboard: Down selects the first item, Enter opens the folder.
    fireEvent.keyDown(listbox(), { key: "ArrowDown" });
    expect(option("2024").getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(listbox(), { key: "Enter" });
    expect(await screen.findByText("This folder is empty")).toBeTruthy();
    expect(screen.getByRole("button", { name: /Upload files/ })).toBeTruthy();
    fireEvent.keyDown(listbox(), { key: "Backspace" });
    await screen.findByRole("option", { name: /beach\.jpg/ });
    fireEvent.click(within(screen.getByRole("navigation", { name: "Path" })).getByRole("button", { name: "Media" }));
    await screen.findByRole("option", { name: /^Movies/ });

    // Grid view and the filter box.
    fireEvent.click(screen.getByRole("button", { name: "Grid view" }));
    expect(listbox().className).toContain("fm-list--grid");
    fireEvent.change(screen.getByPlaceholderText("Filter"), { target: { value: "rep" } });
    expect(screen.getAllByRole("option")).toHaveLength(1);
    fireEvent.change(screen.getByPlaceholderText("Filter"), { target: { value: "zzz" } });
    expect(screen.getByText("Nothing matches")).toBeTruthy();

    // A read-only folder has no upload or new folder.
    fireEvent.click(within(places).getByRole("button", { name: /Backups/ }));
    await screen.findByRole("option", { name: /old\.tar/ });
    expect(screen.queryByRole("button", { name: /Upload/ })).toBeNull();
    expect(screen.getByText("Read only")).toBeTruthy();
  });

  it("selects with shift and ctrl, then deletes to the recycle bin with the Delete key", async () => {
    const calls: Call[] = [];
    serve({ "/files/shares": () => ({ shares: SHARES }), "/files/list": tree(mediaTree), "POST /files/delete": () => ({ recycled: true }) }, calls);
    wrap(<FileManagerView isAdmin={false} initial={{ kind: "folder", share: "media", path: "" }} />);
    await screen.findByRole("option", { name: /^Movies/ });

    fireEvent.click(option("Movies"));
    fireEvent.click(option("notes.txt"), { shiftKey: true });
    expect(screen.getAllByRole("option", { selected: true })).toHaveLength(3);
    fireEvent.click(option("Photos"), { ctrlKey: true });
    expect(screen.getAllByRole("option", { selected: true }).map((o) => o.textContent)).toEqual([
      expect.stringContaining("Movies"),
      expect.stringContaining("notes.txt"),
    ]);
    expect(screen.getByText(/2 selected/, { selector: ".fm-actions__count" })).toBeTruthy();

    fireEvent.keyDown(listbox(), { key: "Delete" });
    const dialog = await screen.findByRole("dialog", { name: "Delete 2 items?" });
    expect(within(dialog).getByText(/recycle bin, where they're kept for 30 days/)).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Move to recycle bin" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/files/delete")).toBe(true));
    expect(calls.find((c) => c.path === "/files/delete")!.body).toEqual({ share: "media", paths: ["Movies", "notes.txt"] });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    // Ctrl+A then Escape.
    fireEvent.keyDown(listbox(), { key: "a", ctrlKey: true });
    expect(screen.getAllByRole("option", { selected: true })).toHaveLength(4);
    fireEvent.keyDown(listbox(), { key: "Escape" });
    expect(screen.queryAllByRole("option", { selected: true })).toHaveLength(0);
  });

  it("says deleting is for good where there's no recycle bin, and follows a delete job", async () => {
    const calls: Call[] = [];
    let polls = 0;
    serve(
      {
        "/files/shares": () => ({ shares: SHARES }),
        "/files/list": tree(mediaTree),
        "POST /files/delete": () => ({
          __status: 202,
          job: { id: "j1", kind: "files.delete", title: "Delete", state: "queued", progress: 0, message: "", error: "", result: {} },
          warnings: [],
        }),
        "/jobs/j1": () => ({
          id: "j1",
          kind: "files.delete",
          title: "Delete",
          state: ++polls > 1 ? "succeeded" : "running",
          progress: 50,
          message: "",
          error: "",
          result: { recycled: false },
        }),
      },
      calls,
    );
    wrap(<FileManagerView isAdmin={false} initial={{ kind: "folder", share: HOME, path: "" }} />);
    fireEvent.click(await screen.findByRole("option", { name: /todo\.md/ }));
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    const dialog = await screen.findByRole("dialog", { name: "Delete “todo.md”?" });
    expect(within(dialog).getByText(/no recycle bin, so it's gone for good/)).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete for good" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull(), { timeout: 4000 });
    expect(polls).toBeGreaterThanOrEqual(2);
  });

  it("makes folders and renames with F2, checking names", async () => {
    const calls: Call[] = [];
    serve(
      {
        "/files/shares": () => ({ shares: SHARES }),
        "/files/list": tree(mediaTree),
        "POST /files/mkdir": ({ body }) => ({ __status: 201, ...dir((body as { path: string }).path) }),
        "POST /files/rename": ({ body }) => entry((body as { name: string }).name),
      },
      calls,
    );
    wrap(<FileManagerView isAdmin={false} initial={{ kind: "folder", share: "media", path: "" }} />);
    await screen.findByRole("option", { name: /^Movies/ });

    fireEvent.click(screen.getByRole("button", { name: /New folder/ }));
    let dialog = await screen.findByRole("dialog", { name: "New folder" });
    const input = within(dialog).getByLabelText("Folder name");
    fireEvent.change(input, { target: { value: "photos" } });
    expect(within(dialog).getByText("Something with that name is already here.")).toBeTruthy();
    fireEvent.change(input, { target: { value: "Taxes" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() => expect(calls.find((c) => c.path === "/files/mkdir")?.body).toEqual({ share: "media", path: "Taxes" }));

    fireEvent.click(option("notes.txt"));
    fireEvent.keyDown(listbox(), { key: "F2" });
    dialog = await screen.findByRole("dialog", { name: "Rename “notes.txt”" });
    const name = within(dialog).getByLabelText("New name") as HTMLInputElement;
    expect(name.value).toBe("notes.txt");
    expect((within(dialog).getByRole("button", { name: "Rename" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(name, { target: { value: "a/b" } });
    expect(within(dialog).getByText("Names can't contain /.")).toBeTruthy();
    fireEvent.change(name, { target: { value: "shopping.txt" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Rename" }));
    await waitFor(() => expect(calls.find((c) => c.path === "/files/rename")?.body).toEqual({ share: "media", path: "notes.txt", name: "shopping.txt" }));
  });

  it("moves and copies with the folder picker, only into folders you can change", async () => {
    const calls: Call[] = [];
    serve(
      { "/files/shares": () => ({ shares: SHARES }), "/files/list": tree(mediaTree), "POST /files/move": () => ({}), "POST /files/copy": () => ({}) },
      calls,
    );
    wrap(<FileManagerView isAdmin={false} initial={{ kind: "folder", share: "media", path: "" }} />);
    await screen.findByRole("option", { name: /^Movies/ });

    fireEvent.click(option("Photos"));
    fireEvent.click(screen.getByRole("button", { name: "Move to…" }));
    let dialog = await screen.findByRole("dialog", { name: "Move “Photos”" });
    // The read-only Backups folder isn't offered.
    const select = within(dialog).getByLabelText("Folder") as HTMLSelectElement;
    expect(Array.from(select.options).map((o) => o.textContent)).toEqual(["Home", "Media"]);
    // It's already here, and can't go into itself.
    expect((within(dialog).getByRole("button", { name: "Move here" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(await within(dialog).findByRole("option", { name: /Photos/ }));
    expect(within(dialog).getByText("A folder can't go inside itself.")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Up one folder" }));
    fireEvent.click(await within(dialog).findByRole("option", { name: /Movies/ }));
    await waitFor(() => expect((within(dialog).getByRole("button", { name: "Move here" }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(within(dialog).getByRole("button", { name: "Move here" }));
    await waitFor(() =>
      expect(calls.find((c) => c.path === "/files/move")?.body).toEqual({ share: "media", paths: ["Photos"], toShare: "media", toDir: "Movies" }),
    );

    fireEvent.click(option("notes.txt"));
    fireEvent.click(screen.getByRole("button", { name: "Copy to…" }));
    dialog = await screen.findByRole("dialog", { name: "Copy “notes.txt”" });
    fireEvent.change(within(dialog).getByLabelText("Folder"), { target: { value: HOME } });
    await within(dialog).findByText("No folders in here.");
    fireEvent.click(within(dialog).getByRole("button", { name: "Copy here" }));
    await waitFor(() => expect(calls.find((c) => c.path === "/files/copy")?.body).toEqual({ share: "media", paths: ["notes.txt"], toShare: HOME, toDir: "" }));
  });

  it("uploads dropped files in chunks with progress, never replacing a file", async () => {
    const calls: Call[] = [];
    const uploads: Record<string, { size: number; received: number; path: string }> = {};
    let n = 0;
    serve(
      {
        "/files/shares": () => ({ shares: SHARES }),
        "/files/list": tree(mediaTree),
        "POST /files/upload": ({ body }) => {
          const b = body as { path: string; size: number };
          const id = `u${++n}`;
          uploads[id] = { size: b.size, received: 0, path: b.path };
          return { __status: 201, id, size: b.size, received: 0 };
        },
        "PUT /files/upload/u1": ({ body, query }) => {
          const u = uploads.u1!;
          expect(Number(query.get("offset"))).toBe(u.received);
          u.received += (body as string).length;
          return { id: "u1", size: u.size, received: u.received, ...(u.received >= u.size ? { entry: entry(u.path) } : {}) };
        },
        "PUT /files/upload/u2": ({ body }) => {
          const u = uploads.u2!;
          u.received += (body as string).length;
          return { id: "u2", size: u.size, received: u.received, entry: entry(u.path) };
        },
      },
      calls,
    );
    wrap(<FileManagerView isAdmin={false} initial={{ kind: "folder", share: "media", path: "" }} />);
    await screen.findByRole("option", { name: /^Movies/ });

    const files = [new File(["hello world"], "notes.txt", { type: "text/plain" }), new File(["x"], "new.bin")];
    const target = listbox().closest(".fm-folder")!;
    fireEvent.dragEnter(target, { dataTransfer: { types: ["Files"], files, items: [] } });
    expect(screen.getByText("Drop to upload to Media")).toBeTruthy();
    fireEvent.drop(target, { dataTransfer: { types: ["Files"], files, items: [] } });

    const tray = await screen.findByRole("region", { name: "Uploads" });
    await waitFor(() => expect(within(tray).getByText("Uploads finished")).toBeTruthy());
    // notes.txt is taken: saved as a copy next to it.
    expect(within(tray).getByText("notes (2).txt")).toBeTruthy();
    expect(within(tray).getByText(/was taken, so this is a new copy/)).toBeTruthy();
    const starts = calls.filter((c) => c.method === "POST" && c.path === "/files/upload").map((c) => c.body);
    expect(starts).toEqual([
      { share: "media", path: "notes (2).txt", size: 11, overwrite: false },
      { share: "media", path: "new.bin", size: 1, overwrite: false },
    ]);
    expect(calls.filter((c) => c.method === "PUT").every((c) => c.headers.get("X-HardyOS-Request") === "1")).toBe(true);
    // The folder is listed again once they're in.
    await waitFor(() => expect(calls.filter((c) => c.path === "/files/list" && c.query.get("share") === "media").length).toBeGreaterThan(1));
  });

  it("previews images and text, and shows previous versions to download or restore", async () => {
    const calls: Call[] = [];
    serve(
      {
        "/files/shares": () => ({ shares: SHARES }),
        "/files/list": tree(mediaTree),
        "/files/download": ({ query, headers }) =>
          new Response(query.get("path") === "notes.txt" ? `range=${headers.get("Range")}` : "x", { status: 206, headers: { "Content-Type": "text/plain" } }),
        "/files/snapshots": () => ({
          versions: [
            { snapshot: "hardyos-auto-daily_2026-10-19-0000", taken: "2026-10-19T00:00:00Z", size: 280, modified: "2026-10-18T12:00:00Z" },
            { snapshot: "hardyos-auto-weekly_2026-10-12-0000", taken: "2026-10-12T00:00:00Z", size: 200, modified: "2026-10-11T12:00:00Z" },
          ],
        }),
        "POST /files/restore": () => ({ path: "notes (restored 2026-10-19).txt" }),
      },
      calls,
    );
    wrap(<FileManagerView isAdmin={false} initial={{ kind: "folder", share: "media", path: "" }} />);
    await screen.findByRole("option", { name: /^Movies/ });

    // Enter on a text file opens the preview, reading the start with a Range request.
    fireEvent.click(option("notes.txt"));
    fireEvent.keyDown(listbox(), { key: "Enter" });
    const pv = await screen.findByRole("dialog", { name: "Preview of notes.txt" });
    expect(await within(pv).findByText("range=bytes=0-262143")).toBeTruthy();
    // Right goes to the next previewable file: the PDF.
    fireEvent.keyDown(document, { key: "ArrowRight" });
    const pdf = await screen.findByRole("dialog", { name: "Preview of Report.pdf" });
    expect(within(pdf).getByTitle("Report.pdf").getAttribute("src")).toBe("/api/v1/files/download?share=media&path=Report.pdf&inline=1");
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog", { name: /Preview/ })).toBeNull());

    // Previous versions.
    fireEvent.click(option("notes.txt"));
    fireEvent.click(screen.getByRole("button", { name: "Previous versions" }));
    const panel = await screen.findByRole("complementary", { name: "Previous versions" });
    expect(await within(panel).findByText(/Daily snapshot/)).toBeTruthy();
    const dl = within(panel).getAllByRole("link", { name: /Download the version/ })[0]!;
    expect(dl.getAttribute("href")).toBe("/api/v1/files/download?share=media&path=notes.txt&snapshot=hardyos-auto-daily_2026-10-19-0000");
    fireEvent.click(within(panel).getAllByRole("button", { name: /Restore the version/ })[1]!);
    expect(await within(panel).findByText(/Saved as “notes \(restored 2026-10-19\)\.txt”/)).toBeTruthy();
    expect(calls.find((c) => c.path === "/files/restore")!.body).toEqual({
      share: "media",
      path: "notes.txt",
      snapshot: "hardyos-auto-weekly_2026-10-12-0000",
    });
  });

  it("opens images in the preview from a double-click", async () => {
    serve({ "/files/shares": () => ({ shares: SHARES }), "/files/list": tree(mediaTree) }, []);
    wrap(<FileManagerView isAdmin={false} initial={{ kind: "folder", share: "media", path: "Photos" }} />);
    fireEvent.doubleClick(await screen.findByRole("option", { name: /beach\.jpg/ }));
    const pv = await screen.findByRole("dialog", { name: "Preview of beach.jpg" });
    expect(within(pv).getByRole("img", { name: "beach.jpg" }).getAttribute("src")).toBe("/api/v1/files/download?share=media&path=Photos%2Fbeach.jpg&inline=1");
    expect(within(pv).getByText("1 / 2")).toBeTruthy();
  });

  it("shows empty and error states", async () => {
    serve(
      {
        "/files/shares": () => ({ shares: SHARES }),
        "/files/list": ({ query }) =>
          query.get("share") === "backups"
            ? { __status: 403, code: "forbidden", message: "you don't have access to that" }
            : { __status: 404, code: "not_found", message: "gone" },
      },
      [],
    );
    wrap(<FileManagerView isAdmin={false} initial={{ kind: "folder", share: "media", path: "Old" }} />);
    expect(await screen.findByText("This folder isn't there any more")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Backups/ }));
    expect(await screen.findByText("You can't open this folder")).toBeTruthy();
  });

  it("says so when the person has no folders, or the list can't load", async () => {
    serve({ "/files/shares": () => ({ shares: [] }) }, []);
    wrap(<FileManagerView isAdmin />);
    expect(await screen.findByText("No folders for you yet")).toBeTruthy();
    cleanup();
    serve({ "/files/shares": () => ({ __status: 500, code: "internal", message: "boom" }) }, []);
    wrap(<FileManagerView isAdmin={false} />);
    expect(await screen.findByText("Couldn't load your folders")).toBeTruthy();
  });

  it("makes a share link, lists it under Links I've shared and turns it off", async () => {
    const calls: Call[] = [];
    const link = {
      id: 7,
      share: "media",
      path: "Photos",
      name: "Photos",
      dir: true,
      createdById: 2,
      createdBy: "HOME\\mom",
      createdAt: T,
      expiresAt: "2026-11-19T10:00:00Z",
      hasPassword: true,
      allowUpload: true,
      maxDownloads: 0,
      maxUploadBytes: 50_000_000_000,
      uploadedBytes: 0,
      maxZipBytes: 20_000_000_000,
      downloadCount: 3,
      lastUsedAt: null,
      revoked: false,
      status: "active",
    };
    let revoked = false;
    serve(
      {
        "/files/shares": () => ({ shares: SHARES }),
        "/files/list": tree(mediaTree),
        "POST /sharelinks": () => ({ __status: 201, link, url: `/s/${"t".repeat(43)}`, token: "t".repeat(43) }),
        "/sharelinks": ({ query }) => ({
          links:
            query.get("scope") === "all"
              ? [link, { ...link, id: 8, createdBy: "kid", name: "x.txt", dir: false, status: "expired" }]
              : [{ ...link, revoked, status: revoked ? "revoked" : "active" }],
        }),
        "POST /sharelinks/7/revoke": () => {
          revoked = true;
          return { ...link, revoked: true, status: "revoked" };
        },
      },
      calls,
    );
    wrap(<FileManagerView isAdmin initial={{ kind: "folder", share: "media", path: "" }} />);
    await screen.findByRole("option", { name: /^Movies/ });

    fireEvent.contextMenu(option("Photos"));
    fireEvent.click(await screen.findByRole("menuitem", { name: "Share link" }));
    const dialog = await screen.findByRole("dialog", { name: "Share “Photos”" });
    fireEvent.change(within(dialog).getByLabelText("Works for"), { target: { value: "30" } });
    fireEvent.click(within(dialog).getByRole("switch", { name: "Ask for a password" }));
    fireEvent.change(within(dialog).getByLabelText("Password"), { target: { value: "abc" } });
    expect((within(dialog).getByRole("button", { name: "Create link" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText("Password"), { target: { value: "sunny-day" } });
    expect(within(dialog).queryByLabelText("Upload limit")).toBeNull();
    fireEvent.click(within(dialog).getByRole("switch", { name: /Let people add files/ }));
    // Uploads on: how much the link may take in, 10 GB unless changed.
    expect((within(dialog).getByLabelText("Upload limit") as HTMLSelectElement).value).toBe("10000000000");
    fireEvent.change(within(dialog).getByLabelText("Upload limit"), { target: { value: "50000000000" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create link" }));
    const ready = await screen.findByRole("dialog", { name: "Link ready" });
    expect((within(ready).getByLabelText("Share link") as HTMLInputElement).value).toBe(`${window.location.origin}/s/${"t".repeat(43)}`);
    expect(calls.find((c) => c.path === "/sharelinks" && c.method === "POST")!.body).toEqual({
      share: "media",
      path: "Photos",
      expiresInDays: 30,
      password: "sunny-day",
      allowUpload: true,
      maxUploadBytes: 50_000_000_000,
    });
    fireEvent.click(within(ready).getByRole("button", { name: "Done" }));

    fireEvent.click(screen.getByRole("button", { name: "Links I've shared" }));
    const row = (await screen.findByText("Photos", { selector: ".fm-links__target .fm-ellipsis" })).closest("tr")!;
    expect(within(row).getByText("Active")).toBeTruthy();
    expect(within(row).getByText(/password · uploads on/)).toBeTruthy();
    fireEvent.click(within(row).getByRole("button", { name: /Turn off the link/ }));
    const confirm = await screen.findByRole("dialog", { name: "Turn off this link?" });
    fireEvent.click(within(confirm).getByRole("button", { name: "Turn off" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/sharelinks/7/revoke")).toBe(true));
    expect(await screen.findByText("Turned off")).toBeTruthy();

    // Admins see everyone's links.
    fireEvent.click(screen.getByRole("button", { name: "All links" }));
    expect(await screen.findByText("kid")).toBeTruthy();
    expect(screen.getByText("Expired")).toBeTruthy();
  });

  it("doesn't offer All links or sharing read-only files to non-admins", async () => {
    serve({ "/files/shares": () => ({ shares: SHARES }), "/files/list": tree(mediaTree) }, []);
    wrap(<FileManagerView isAdmin={false} initial={{ kind: "folder", share: "backups", path: "" }} />);
    fireEvent.click(await screen.findByRole("option", { name: /old\.tar/ }));
    expect(screen.queryByRole("button", { name: "All links" })).toBeNull();
    const bar = screen.getByRole("toolbar", { name: "Selection" });
    expect(within(bar).queryByRole("button", { name: "Share link" })).toBeNull();
    expect(within(bar).queryByRole("button", { name: "Delete" })).toBeNull();
    expect(within(bar).getByRole("button", { name: "Download" })).toBeTruthy();
  });
});

describe("chunked upload", () => {
  it("sends chunks at offsets, retries a failed one, and cancels on the server", async () => {
    const calls: Call[] = [];
    let fails = 1;
    let received = 0;
    serve(
      {
        "POST /files/upload": () => ({ __status: 201, id: "up", size: 10, received: 0 }),
        "PUT /files/upload/up": ({ body, query }) => {
          if (Number(query.get("offset")) === 4 && fails-- > 0) return { __status: 503, code: "busy", message: "busy" };
          received = Number(query.get("offset")) + (body as string).length;
          return { id: "up", size: 10, received, ...(received === 10 ? { entry: entry("big.bin") } : {}) };
        },
        "DELETE /files/upload/up": () => ({ __status: 204 }),
      },
      calls,
    );
    const progress: number[] = [];
    const out = await uploadFile(new File(["0123456789"], "big.bin"), "media", "big.bin", { chunkSize: 4, onProgress: (s) => progress.push(s) });
    expect(out?.path).toBe("big.bin");
    expect(calls.filter((c) => c.method === "PUT").map((c) => `${c.query.get("offset")}:${c.body}`)).toEqual(["0:0123", "4:4567", "4:4567", "8:89"]);
    expect(progress).toEqual([0, 4, 8, 10]);

    // Cancelling aborts and tells the server.
    calls.length = 0;
    const ctl = new AbortController();
    const p = uploadFile(new File(["0123456789"], "big.bin"), "media", "big.bin", {
      chunkSize: 4,
      signal: ctl.signal,
      onProgress: (s) => {
        if (s === 4) ctl.abort();
      },
    });
    await expect(p).rejects.toThrow();
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(calls.some((c) => c.method === "DELETE" && c.path === "/files/upload/up")).toBe(true);
  });
});
