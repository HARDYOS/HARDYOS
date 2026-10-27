import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Markdown, parse, safeHref } from "./markdown";
import { NotesView, isNote, noteFile, noteTitle } from "./Notes";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("markdown", () => {
  it("parses blocks", () => {
    const b = parse("# Title\n\nSome *text*\nmore\n\n- [ ] milk\n- [x] eggs\n\n1. one\n2. two\n\n> quoted\n\n```js\nlet x = 1;\n```\n\n---");
    expect(b.map((x) => x.t)).toEqual(["h", "p", "list", "list", "quote", "code", "hr"]);
    expect(b[1]).toEqual({ t: "p", text: "Some *text* more" });
    expect(b[2]).toEqual({ t: "list", ordered: false, items: [{ text: "milk", task: true, done: false }, { text: "eggs", task: true, done: true }] });
    expect(b[5]).toEqual({ t: "code", lang: "js", text: "let x = 1;" });
  });

  it("never turns a note into HTML or unsafe links", () => {
    const onNote = vi.fn();
    const { container } = render(
      <Markdown
        source={'<script>alert(1)</script> <img src=x onerror=alert(1)> [click](javascript:alert(1)) [ok](https://example.com) [[Shopping list|the list]] **bold** `code`'}
        onNote={onNote}
      />,
    );
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain("<script>alert(1)</script>");
    const links = Array.from(container.querySelectorAll("a"));
    expect(links.map((a) => a.getAttribute("href"))).toEqual(["https://example.com/"]);
    expect(links[0]!.getAttribute("rel")).toBe("noopener noreferrer");
    expect(container.querySelector("strong")?.textContent).toBe("bold");
    expect(container.querySelector("code")?.textContent).toBe("code");
    fireEvent.click(screen.getByRole("button", { name: "the list" }));
    expect(onNote).toHaveBeenCalledWith("Shopping list");
    expect(safeHref("data:text/html,x")).toBeNull();
    expect(safeHref("mailto:a@b.c")).toBe("mailto:a@b.c");
  });
});

describe("Notes", () => {
  it("names notes", () => {
    expect(isNote({ name: "a.md", dir: false })).toBe(true);
    expect(isNote({ name: "a.txt", dir: false })).toBe(false);
    expect(noteTitle("Shopping.md")).toBe("Shopping");
    expect(noteFile("Shopping")).toBe("Shopping.md");
    expect(noteFile("x.markdown")).toBe("x.markdown");
  });

  it("lists notes, opens one and won't save over someone else's change", async () => {
    const calls: { method: string; path: string; body: unknown }[] = [];
    let modified = "2026-10-20T10:00:00Z";
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: Request | string, init?: RequestInit) => {
        const req = typeof input === "string" ? new Request(new URL(input, "http://x"), init) : input;
        const u = new URL(req.url);
        const path = u.pathname.replace("/api/v1", "");
        calls.push({ method: req.method, path, body: null });
        const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
        if (path === "/files/shares") return json({ shares: [{ id: "family", name: "Family", writable: true, recycle: true }] });
        if (path === "/files/list")
          return json({
            entries: [
              { name: "Groceries.md", path: "Wiki/Groceries.md", dir: false, size: 20, modified, writable: true },
              { name: "photo.jpg", path: "Wiki/photo.jpg", dir: false, size: 20, modified, writable: true },
            ],
          });
        if (path === "/files/download") return new Response("# Groceries\n\n- [ ] milk");
        if (path === "/files/stat") return json({ name: "Groceries.md", path: "Wiki/Groceries.md", dir: false, size: 20, modified, writable: true });
        return json({ code: "not_found", message: path }, 404);
      }),
    );
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrap = (ui: ReactNode) => render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
    wrap(<NotesView initial={{ share: "family", dir: "Wiki" }} />);
    const item = await screen.findByRole("button", { name: /Groceries/ });
    expect(screen.queryByText("photo")).toBeNull();
    fireEvent.click(item);
    const text = (await screen.findByLabelText("Note text (Markdown)")) as HTMLTextAreaElement;
    expect(text.value).toContain("milk");
    expect(screen.getByRole("checkbox", { name: "Not done" })).toBeTruthy();
    // Someone else saves it meanwhile.
    modified = "2026-10-21T09:00:00Z";
    fireEvent.change(text, { target: { value: "# Groceries\n\n- [ ] milk\n- [ ] bread" } });
    fireEvent.keyDown(text, { key: "s", ctrlKey: true });
    expect(await screen.findByText("Someone else changed this note")).toBeTruthy();
    await waitFor(() => expect(calls.some((c) => c.path.startsWith("/files/upload"))).toBe(false));
  });
});
