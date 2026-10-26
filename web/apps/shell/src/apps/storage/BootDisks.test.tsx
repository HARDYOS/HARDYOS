import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SystemPoolCard } from "./BootDisks";

const leaf = (name: string, state: string, note = "") => ({ name, type: "disk", class: "data", state, read: 0, write: 0, checksum: 0, disk: name.startsWith("/dev") ? name.replace(/-part3$/, "") : name, note, children: [] });
const boot = {
  pool: "rpool",
  status: {
    name: "rpool",
    state: "DEGRADED",
    status: "",
    action: "",
    errors: "",
    expand: null,
    scan: { kind: "none", state: "none", percent: null, errors: null, finishedAt: null, remaining: "" },
    groups: [],
    root: {
      name: "rpool", type: "root", class: "data", state: "DEGRADED", read: 0, write: 0, checksum: 0, disk: "", note: "",
      children: [{ name: "mirror-0", type: "mirror", class: "data", state: "DEGRADED", read: 0, write: 0, checksum: 0, disk: "", note: "",
        children: [leaf("/dev/disk/by-id/nvme-BOOT1-part3", "ONLINE"), leaf("1234567890123456789", "UNAVAIL", "was /dev/disk/by-id/nvme-BOOT2-part3")] }],
    },
  },
  disks: [{ byId: "/dev/disk/by-id/nvme-BOOT1", espPartUUID: "1" }, { byId: "/dev/disk/by-id/nvme-BOOT2", espPartUUID: "2" }],
  candidates: [{ name: "sda", path: "/dev/sda", byId: "/dev/disk/by-id/ata-NEW", model: "Samsung 870", serial: "", wwn: "", transport: "sata", kind: "ssd", sizeBytes: 512e9, physSector: 4096, removable: false, usage: "free", pool: "", usageDetail: "", partitions: [], powerLossProt: null }],
  minBytes: 256e9,
};
const pool = { name: "rpool", health: "DEGRADED", sizeBytes: 250e9, allocBytes: 5e9, freeBytes: 245e9, capacityPct: 2, fragmentation: 1, dedupRatio: 1, readOnly: false, guid: "1", altroot: "" };

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("SystemPoolCard", () => {
  it("shows a failed boot disk and replaces it", async () => {
    const calls: { path: string; body: unknown }[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: Request) => {
        const path = new URL(input.url).pathname.replace("/api/v1", "");
        const body = input.method === "POST" ? await input.clone().json() : null;
        calls.push({ path, body });
        const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });
        if (path === "/storage/boot") return json(boot);
        if (path === "/storage/boot/replace") return json({ job: { id: "j9" }, warnings: [] }, 202);
        if (path === "/jobs/j9") return json({ id: "j9", state: "running", progress: 10, title: "Replace a boot disk", message: "Partitioning the new disk" });
        return json({ code: "not_found", message: path }, 404);
      }),
    );
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <SystemPoolCard pool={pool as never} />
      </QueryClientProvider>,
    );
    expect(await screen.findByText("A boot disk has failed")).toBeTruthy();
    expect(screen.getByText("nvme-BOOT2-part3")).toBeTruthy();
    expect(screen.getByText("missing")).toBeTruthy();
    const rows = screen.getAllByRole("row");
    fireEvent.click(within(rows[2]!).getByRole("button", { name: "Replace…" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/Samsung 870/)).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Erase and replace" }));
    await waitFor(() =>
      expect(calls.find((c) => c.path === "/storage/boot/replace")?.body).toEqual({ old: "1234567890123456789", disk: "/dev/disk/by-id/ata-NEW", confirmWipe: true }),
    );
    expect(await screen.findByText("Partitioning the new disk")).toBeTruthy();
  });
});
