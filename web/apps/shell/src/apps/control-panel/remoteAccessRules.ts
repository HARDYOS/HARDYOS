import type { NetBirdClientStatus, PublishConfig, RemoteCheckStep } from "@hardy/api-client";
import type { Tone } from "../../ui";

/** NetBird's client state in words, with a tone for its badge. */
export function clientState(st: NetBirdClientStatus): { tone: Tone; label: string } {
  if (!st.installed) return { tone: "neutral", label: "Not installed" };
  if (st.connected) return { tone: "good", label: "Connected" };
  switch (st.state) {
    case "off":
      return st.joined ? { tone: "bad", label: "Off" } : { tone: "neutral", label: "Not joined" };
    case "connecting":
      return { tone: "warn", label: "Connecting" };
    case "needs_login":
    case "session_expired":
    case "login_failed":
      return { tone: "bad", label: "Needs a new setup key" };
    case "idle":
      return { tone: "warn", label: "Idle" };
    default:
      return { tone: "warn", label: "Unknown" };
  }
}

export const STEP_TONE: Record<RemoteCheckStep["state"], Tone> = { ok: "good", warn: "warn", bad: "bad", skipped: "neutral" };
export const STEP_LABEL: Record<RemoteCheckStep["state"], string> = { ok: "OK", warn: "Check", bad: "Missing", skipped: "Skipped" };

/** Whether s is a domain like home.example.net. */
export function validDomain(s: string): boolean {
  const d = s.trim().toLowerCase();
  if (!d.includes(".") || d.length > 253 || d.endsWith(".")) return false;
  return d.split(".").every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l));
}

/** Whether s is one DNS label (nas, jellyfin). */
export function validLabel(s: string): boolean {
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(s.trim());
}

/** Whether s looks like a NetBird setup key. */
export function validSetupKey(s: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(s.trim());
}

/** The host name of a management URL ("" when it isn't one). */
export function managementHost(u: string): string {
  try {
    return new URL(u).hostname;
  } catch {
    return "";
  }
}

/** How something is published, in a few words. */
export function publishSummary(c: PublishConfig): string {
  if (c.mode === "off") return "Not published";
  if (c.mode === "netbird") return "NetBird devices only";
  const auth = { sso: "HardyOS sign-in (SSO)", password: "password", pin: "PIN", none: "no sign-in in front" }[c.auth];
  return `Public, ${auth}`;
}

/** NetBird's service status in words. */
export function serviceStatus(status: string | undefined): { tone: Tone; label: string } {
  switch (status) {
    case "active":
      return { tone: "good", label: "Active" };
    case "pending":
    case "certificate_pending":
      return { tone: "warn", label: "Getting a certificate" };
    case "tunnel_not_created":
      return { tone: "warn", label: "Waiting for the tunnel" };
    case "certificate_failed":
      return { tone: "bad", label: "Certificate failed" };
    case "error":
      return { tone: "bad", label: "Error" };
    default:
      return { tone: "neutral", label: status || "Not yet" };
  }
}

/** A problem with a password or PIN typed for public sign-in ("" when fine). */
export function secretProblem(auth: string, secret: string, saved: boolean): string {
  if (auth !== "password" && auth !== "pin") return "";
  if (secret === "") return saved ? "" : auth === "password" ? "Enter a password" : "Enter a PIN";
  if (auth === "password" && secret.length < 8) return "Use at least 8 characters";
  if (auth === "pin" && !/^[0-9]{4,12}$/.test(secret)) return "A PIN is 4 to 12 digits";
  return "";
}
