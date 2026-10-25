import { describe, expect, it } from "vitest";
import { bitsPerSecond, bytes, duration, initials, relativeTime } from "./format";

describe("format", () => {
  it("formats bytes with decimal units", () => {
    expect(bytes(0)).toBe("0 B");
    expect(bytes(12_000_138_625_024)).toBe("12 TB");
    expect(bytes(21_400_000_000_000)).toBe("21.4 TB");
    expect(bytes(256_060_514_304)).toBe("256 GB");
    expect(bytes(null)).toBe("–");
  });
  it("formats rates in bits", () => {
    expect(bitsPerSecond(10_500_000)).toBe("84 Mb/s");
    expect(bitsPerSecond(500)).toBe("4.0 Kb/s");
  });
  it("formats durations", () => {
    expect(duration(30)).toBe("1 minute");
    expect(duration(12 * 86_400)).toBe("12 days");
  });
  it("formats relative times", () => {
    const now = Date.parse("2026-10-24T12:00:00Z");
    expect(relativeTime("2026-10-24T11:59:50Z", now)).toBe("just now");
    expect(relativeTime("2026-10-24T10:00:00Z", now)).toBe("2 hours ago");
    expect(relativeTime(null, now)).toBe("never");
  });
  it("makes initials", () => {
    expect(initials("Cade Hardy")).toBe("CH");
    expect(initials("cade")).toBe("CA");
  });
});
