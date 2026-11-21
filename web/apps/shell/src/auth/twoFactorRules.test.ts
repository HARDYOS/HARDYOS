import type { TwoFactorStatus } from "@hardy/api-client";
import { describe, expect, it } from "vitest";
import { cleanCode, codeReady, graceText, isChallenge, recoveryCodesText, setupCodeReady, totpReady, twoFactorLabel } from "./twoFactorRules";

const off: TwoFactorStatus = {
  enabled: false, enabledAt: null, recoveryCodesLeft: 0, required: false, graceUntil: null, locked: false, setupCodeExpires: null, mustEnroll: false,
};

describe("two-factor rules", () => {
  it("tells a challenge from a user", () => {
    expect(isChallenge({ challenge: "abc", step: "totp", expiresAt: "2026-11-21T00:00:00Z" })).toBe(true);
    expect(isChallenge({ id: 1, username: "cade" } as never)).toBe(false);
    expect(isChallenge(null)).toBe(false);
  });

  it("accepts codes as people type them", () => {
    expect(cleanCode(" 123 456 ")).toBe("123456");
    expect(totpReady("123 456")).toBe(true);
    expect(totpReady("12345")).toBe(false);
    expect(codeReady("ABCD-efgh-2345-6789")).toBe(true);
    expect(codeReady("abcd-efgh")).toBe(false);
    expect(totpReady("abcd-efgh-2345-6789")).toBe(false);
    expect(setupCodeReady("abcd efgh 2345 6789")).toBe(true);
  });

  it("words the administrators' grace period", () => {
    const now = new Date("2026-11-21T12:00:00Z");
    expect(graceText(off, now)).toBeNull();
    expect(graceText({ ...off, required: true, graceUntil: "2026-11-24T13:00:00Z" }, now)).toBe("Set up two-factor sign-in within 3 days");
    expect(graceText({ ...off, required: true, graceUntil: "2026-11-21T18:00:00Z" }, now)).toBe("Set up two-factor sign-in today");
    expect(graceText({ ...off, required: true, graceUntil: "2026-11-20T00:00:00Z" }, now)).toBe("Two-factor sign-in is required now");
    expect(graceText({ ...off, enabled: true, required: true, graceUntil: "2026-11-24T00:00:00Z" }, now)).toBeNull();
  });

  it("labels the users list", () => {
    expect(twoFactorLabel({ ...off, enabled: true, recoveryCodesLeft: 10 })).toEqual({ text: "2FA on", tone: "good" });
    expect(twoFactorLabel({ ...off, enabled: true, recoveryCodesLeft: 1 }).tone).toBe("warn");
    expect(twoFactorLabel({ ...off, enabled: true, locked: true }).tone).toBe("bad");
    expect(twoFactorLabel({ ...off, required: true, mustEnroll: true, graceUntil: "2026-11-20T00:00:00Z" }).text).toBe("2FA required now");
    expect(twoFactorLabel(off).text).toBe("2FA off");
    expect(twoFactorLabel(undefined).tone).toBe("neutral");
  });

  it("writes recovery codes to a file", () => {
    const t = recoveryCodesText(["aaaa-bbbb-cccc-dddd", "eeee-ffff-gggg-hhhh"], "Cade", "nas.local");
    expect(t).toContain("Cade on nas.local");
    expect(t).toContain(" 1. aaaa-bbbb-cccc-dddd");
    expect(t).toContain(" 2. eeee-ffff-gggg-hhhh");
  });
});
