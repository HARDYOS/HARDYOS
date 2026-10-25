import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { formatUptime } from "./hooks/useSystemInfo";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("App", () => {
  it("renders the menu bar, dock and status from hardyd", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: Request | string | URL) => {
        const url = input instanceof Request ? input.url : String(input);
        const body = url.includes("/health")
          ? { status: "ok", uptimeSeconds: 7200 }
          : { version: "0.1.0-test", commit: "abc", goVersion: "go1.24", os: "linux", arch: "amd64" };
        return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
      }),
    );

    render(<App />);
    expect(screen.getByRole("navigation", { name: "Dock" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Storage Manager" })).toBeTruthy();
    expect(await screen.findByText("0.1.0-test")).toBeTruthy();
    expect(screen.getByText("2 hours")).toBeTruthy();
  });

  it("shows an error when hardyd is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new Error("offline"))));
    render(<App />);
    expect(await screen.findByRole("alert")).toBeTruthy();
  });
});

describe("formatUptime", () => {
  it("picks the largest whole unit", () => {
    expect(formatUptime(30)).toBe("1 minute");
    expect(formatUptime(3600 * 5)).toBe("5 hours");
    expect(formatUptime(86400 * 12)).toBe("12 days");
  });
});
