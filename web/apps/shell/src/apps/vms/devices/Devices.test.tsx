import type { VMDevice } from "@hardy/api-client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { type ReactNode, useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { type Call, inventory, nvidiaStatus, serve } from "./devices.fixtures";
import { DevicePicker, DevicesView, gpuName } from "./index";

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

const done = (id: string, title: string) => ({ id, state: "succeeded", progress: 100, title, message: "" });

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("Devices view", () => {
  it("shows each GPU with its owner, users and vGPU capacity, and turns IOMMU on", async () => {
    const calls: Call[] = [];
    serve(
      {
        "/devices": inventory(),
        "/devices/nvidia": nvidiaStatus(),
        "POST /devices/iommu/enable": { job: { id: "j1" }, warnings: [] },
        "/jobs/j1": done("j1", "Turn on IOMMU"),
      },
      calls,
    );
    wrap(<DevicesView />);
    const quadro = await screen.findByLabelText("NVIDIA Quadro RTX 4000");
    expect(within(quadro).getByText("Docker apps")).toBeTruthy();
    expect(within(quadro).getByText(/In use now by the app jellyfin/)).toBeTruthy();
    expect(within(quadro).getByText(/Set up for the VM gaming/)).toBeTruthy();
    const rtx6000 = screen.getByLabelText("NVIDIA Quadro RTX 6000/8000");
    expect(within(rtx6000).getByText("5 of 6 free")).toBeTruthy();
    expect(within(rtx6000).getByText(/VM office/)).toBeTruthy();
    // Only the unused slice can be removed.
    expect(within(rtx6000).getAllByRole("button", { name: /Remove/ })).toHaveLength(1);

    fireEvent.click(screen.getByRole("button", { name: "Turn on IOMMU" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/devices/iommu/enable")).toBe(true));
    expect(await screen.findByText("Turn on IOMMU: done")).toBeTruthy();
  });

  it("installs the NVIDIA driver only after the licence is agreed to", async () => {
    const calls: Call[] = [];
    let status = nvidiaStatus();
    serve(
      {
        "/devices": inventory(),
        "/devices/nvidia": () => status,
        "POST /devices/nvidia/prepare": () => {
          status = nvidiaStatus({ licence: { sha256: "a".repeat(64), version: "550.163.01-2", packages: [], prepared: "2026-10-27T00:00:00Z", source: "x" } });
          return { job: { id: "p1" }, warnings: [] };
        },
        "/jobs/p1": done("p1", "Get the NVIDIA driver and its licence"),
        "/devices/nvidia/licence": { text: "NVIDIA Software License\nterms…", licence: { sha256: "a".repeat(64), version: "550.163.01-2", packages: [], prepared: "", source: "" } },
        "POST /devices/nvidia/install": { job: { id: "i1" }, warnings: [] },
        "/jobs/i1": { id: "i1", state: "running", progress: 40, title: "Install the NVIDIA driver", message: "Installing the NVIDIA driver and building it" },
      },
      calls,
    );
    wrap(<DevicesView />);
    fireEvent.click(await screen.findByRole("button", { name: "Get the NVIDIA driver" }));
    fireEvent.click(await screen.findByRole("button", { name: "Read NVIDIA's licence and install" }));
    expect(await screen.findByText(/terms…/)).toBeTruthy();
    const install = screen.getByRole("button", { name: "Agree and install" }) as HTMLButtonElement;
    expect(install.disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: /I have read NVIDIA's licence and agree to it/ }));
    expect(install.disabled).toBe(false);
    fireEvent.click(install);
    await waitFor(() => expect(calls.some((c) => c.path === "/devices/nvidia/install")).toBe(true));
    expect(calls.find((c) => c.path === "/devices/nvidia/install")!.body).toEqual({ licenceSha256: "a".repeat(64), accept: true });
    expect(await screen.findByText("Installing the NVIDIA driver and building it")).toBeTruthy();
  });

  it("updates without the NVIDIA driver once, after asking, and says when it must go back in", async () => {
    const calls: Call[] = [];
    const consent = { by: "cade", at: "2026-10-27T00:00:00Z", licenceSha256: "a".repeat(64), version: "550.163.01-2", packages: [], installed: true };
    serve(
      {
        "/devices": inventory(),
        "/devices/nvidia": nvidiaStatus({ installed: true, loaded: true, version: "550.163.01", consent }),
        "POST /devices/nvidia/skip-next-update": { job: { id: "s1" }, warnings: [] },
        "/jobs/s1": done("s1", "Install the next update without the NVIDIA drivers"),
      },
      calls,
    );
    wrap(<DevicesView />);
    fireEvent.click(await screen.findByRole("button", { name: "Update without the NVIDIA driver this time" }));
    expect(calls.some((c) => c.path === "/devices/nvidia/skip-next-update")).toBe(false);
    fireEvent.click(await screen.findByRole("button", { name: "Update without it" }));
    await waitFor(() => expect(calls.find((c) => c.path === "/devices/nvidia/skip-next-update")?.body).toEqual({ skip: true, confirm: true }));
    cleanup();

    serve(
      {
        "/devices": inventory(),
        "/devices/nvidia": nvidiaStatus({
          reinstallNeeded: { driver: true, vgpu: false, by: "cade", at: "2026-10-27T00:00:00Z", reason: "This version was installed without the NVIDIA drivers, as chosen by cade." },
        }),
      },
      [],
    );
    wrap(<DevicesView />);
    expect(await screen.findByText("Install the NVIDIA driver again")).toBeTruthy();
  });

  it("explains a device that didn't come back", async () => {
    const calls: Call[] = [];
    serve(
      {
        "/devices": inventory({ stuck: [{ address: "0000:02:00.0", vm: "win11", driver: "amdgpu", message: "The graphics card 0000:02:00.0 didn't come back from the VM win11." }] }),
        "/devices/nvidia": nvidiaStatus(),
        "POST /devices/reconcile": { job: { id: "r1" }, warnings: [] },
        "/jobs/r1": done("r1", "Give back devices of stopped VMs"),
      },
      calls,
    );
    wrap(<DevicesView />);
    expect(await screen.findByText(/didn't come back from the VM win11/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/devices/reconcile")).toBe(true));
  });
});

function Picker({ onValue }: { onValue: (v: VMDevice[]) => void }) {
  const [v, setV] = useState<VMDevice[]>([]);
  return (
    <DevicePicker
      vm="gaming"
      value={v}
      onChange={(n) => {
        setV(n);
        onValue(n);
      }}
    />
  );
}

describe("Device picker", () => {
  it("adds a whole GPU, a slice and a USB device by port, and shows hardyd's problems", async () => {
    const calls: Call[] = [];
    serve(
      {
        "/devices": inventory(),
        "POST /devices/check": (b: unknown) => {
          const ds = (b as { devices: VMDevice[] }).devices;
          return ds.some((d) => d.kind === "gpu" && d.id === "0000:01:00.0")
            ? { ok: false, problems: [{ device: "0000:01:00.0", message: "The graphics card 0000:01:00.0 is in use by the app jellyfin right now." }] }
            : { ok: true, problems: [] };
        },
      },
      calls,
    );
    let value: VMDevice[] = [];
    wrap(<Picker onValue={(v) => (value = v)} />);
    const quadro = await screen.findByRole("radiogroup", { name: "NVIDIA Quadro RTX 4000" });
    fireEvent.click(within(quadro).getByLabelText("The whole card"));
    expect(value).toEqual([{ kind: "gpu", id: "0000:01:00.0" }]);
    expect(screen.getByText(/Docker apps can't use this card/)).toBeTruthy();
    expect(await screen.findByText(/in use by the app jellyfin right now/)).toBeTruthy();

    const rtx = screen.getByRole("radiogroup", { name: "NVIDIA Quadro RTX 6000/8000" });
    // Slices exist, so the whole card isn't offered.
    expect((within(rtx).getByLabelText("The whole card") as HTMLInputElement).disabled).toBe(true);
    fireEvent.click(within(rtx).getByLabelText("A slice (vGPU)"));
    expect(value).toContainEqual({ kind: "vgpu", id: "0000:05:00.0", vgpuType: "nvidia-256" });
    expect(screen.getByRole("combobox", { name: /Slice size/ }).textContent).toContain("GRID RTX6000-4Q · 4 GB · 5 left");

    // USB: hubs aren't offered; by device, then by port.
    expect(screen.queryByText("USB2.0 Hub")).toBeNull();
    fireEvent.click(screen.getByRole("checkbox", { name: /USB Receiver/ }));
    expect(value).toContainEqual({ kind: "usb", id: "046d:c52b" });
    fireEvent.change(screen.getByRole("combobox", { name: /How to find USB Receiver/ }), { target: { value: "port" } });
    expect(value).toContainEqual({ kind: "usb", id: "1-2" });
    expect(value).not.toContainEqual({ kind: "usb", id: "046d:c52b" });

    // The boot disk controller can't be picked.
    const sata = screen.getByRole("checkbox", { name: /Cannon Lake PCH SATA/ }) as HTMLInputElement;
    expect(sata.disabled).toBe(true);
    expect(screen.getByText(/Holds the boot disk/)).toBeTruthy();
    await waitFor(() => expect(calls.filter((c) => c.path === "/devices/check").length).toBeGreaterThan(0));
  });

  it("names GPUs in plain words", () => {
    const inv = inventory();
    expect(inv.gpus.map(gpuName)).toEqual(["Intel UHD Graphics 630", "NVIDIA Quadro RTX 4000", "NVIDIA Quadro RTX 6000/8000"]);
  });
});
