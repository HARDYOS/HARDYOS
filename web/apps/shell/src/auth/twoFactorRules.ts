import type { AppPasswordScope, LoginChallenge, RouterTrust, TwoFactorStatus, User } from "@hardy/api-client";

/** The "trust the router's address" switch's line: on, lapsed or off. */
export function routerTrustText(t: RouterTrust, when: (iso: string) => string): string {
  if (t.on) {
    return `On since ${t.since ? when(t.since) : "?"} for ${t.ip ?? "the router"}. Whatever the router forwards (port forwards, NAT reflection, tunnels) isn't asked for a code.`;
  }
  if (t.lapsed) {
    return `Lapsed: it was turned on for ${t.ip ?? "another router"}, and the router changed. Requests from the router count as outside.`;
  }
  return "Off: requests from the router's own address count as outside. Turn on only if devices at home reach HardyOS through the router (for example a separate network behind it) and nothing from the internet does.";
}


/** What POST /auth/login answered: signed in, or a second step. */
export function isChallenge(x: User | LoginChallenge | undefined | null): x is LoginChallenge {
  return !!x && typeof (x as LoginChallenge).challenge === "string" && typeof (x as LoginChallenge).step === "string";
}

/** A code as typed: spaces and dashes dropped, lower case. */
export function cleanCode(code: string): string {
  return code.replace(/[\s-]/g, "").toLowerCase();
}

/** Whether a typed code can be sent: 6 digits, or a 16-character recovery code. */
export function codeReady(code: string): boolean {
  const c = cleanCode(code);
  return /^\d{6}$/.test(c) || /^[a-z0-9]{16}$/.test(c);
}

/** Whether a typed code is a 6-digit authenticator code (only those). */
export function totpReady(code: string): boolean {
  return /^\d{6}$/.test(cleanCode(code));
}

/** Whether a typed setup code has the shape of one. */
export function setupCodeReady(code: string): boolean {
  return /^[a-z0-9]{16}$/.test(cleanCode(code));
}

/** The administrator's grace period, in words ("3 days left", "ends today"). */
export function graceText(st: TwoFactorStatus | undefined, now: Date = new Date()): string | null {
  if (!st || st.enabled || !st.required || !st.graceUntil) return null;
  const ms = new Date(st.graceUntil).getTime() - now.getTime();
  if (ms <= 0) return "Two-factor sign-in is required now";
  const days = Math.floor(ms / 86_400_000);
  if (days === 0) return "Set up two-factor sign-in today";
  return `Set up two-factor sign-in within ${days} day${days === 1 ? "" : "s"}`;
}

export const SCOPE_LABELS: Record<AppPasswordScope, string> = {
  files: "Files (WebDAV)",
  mail: "Mail (IMAP and SMTP)",
  calendars: "Calendars and contacts",
};

/** One line describing a person's two-factor state for the users list. */
export function twoFactorLabel(st: TwoFactorStatus | undefined): { text: string; tone: "good" | "warn" | "bad" | "neutral" } {
  if (!st) return { text: "Unknown", tone: "neutral" };
  if (st.enabled) {
    if (st.locked) return { text: "2FA codes from outside off (wrong codes)", tone: "bad" };
    if (st.recoveryCodesLeft <= 2) return { text: `2FA on · ${st.recoveryCodesLeft} recovery codes left`, tone: "warn" };
    return { text: "2FA on", tone: "good" };
  }
  if (st.mustEnroll) return { text: "2FA required now", tone: "bad" };
  if (st.required && st.graceUntil) return { text: `2FA due ${new Date(st.graceUntil).toLocaleDateString()}`, tone: "warn" };
  if (st.required) return { text: "2FA required at next sign-in", tone: "warn" };
  return { text: "2FA off", tone: "neutral" };
}

/** Recovery codes as a text file to save. */
export function recoveryCodesText(codes: string[], who: string, host: string): string {
  return [
    `HardyOS recovery codes for ${who}${host ? ` on ${host}` : ""}`,
    "Each code signs you in once if you lose your authenticator app.",
    "",
    ...codes.map((c, i) => `${String(i + 1).padStart(2, " ")}. ${c}`),
    "",
  ].join("\n");
}
