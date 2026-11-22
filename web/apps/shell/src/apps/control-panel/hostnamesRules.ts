import type { HostnamesStatus } from "@hardy/api-client";
import type { Tone } from "../../ui";
import { validDomain } from "./remoteAccessRules";

/** Problems with a token and base domain before they're sent (the server checks again). */
export function tokenProblems(token: string, base: string, remoteBase: string): string[] {
  const out: string[] = [];
  const t = token.trim();
  if (t.length < 20 || t.length > 200 || /[\s"']/.test(t)) out.push("Paste the whole Cloudflare API token.");
  const b = base.trim().toLowerCase();
  if (!validDomain(b)) out.push("The base domain must look like home.example.net.");
  else if (remoteBase && b !== remoteBase) out.push(`Use Remote Access's base domain (${remoteBase}), so names are the same at home and over NetBird.`);
  return out;
}

/** The overall state in words, with a tone for its badge. */
export function hostnamesState(st: HostnamesStatus): { tone: Tone; label: string } {
  if (st.active) return { tone: "good", label: "On" };
  if (!st.token.set) return { tone: "neutral", label: "Off" };
  if (!st.settings.enabled) return { tone: "neutral", label: "Ready" };
  if (!st.certificate) return { tone: "warn", label: "No certificate" };
  return { tone: "warn", label: "Not serving" };
}

/** Days left on the certificate (negative once expired). */
export function daysLeft(notAfter: string, now = Date.now()): number {
  return Math.floor((Date.parse(notAfter) - now) / 86_400_000);
}

/** The records a router needs: every name at this server's address. */
export function routerRecords(st: HostnamesStatus, address: string): { name: string; type: "A"; value: string }[] {
  if (!address) return [];
  return st.names.map((n) => ({ name: n.host, type: "A" as const, value: address }));
}

/** dnsmasq / Pi-hole / OpenWrt style lines for the same records. */
export function dnsmasqLines(st: HostnamesStatus, address: string): string {
  return routerRecords(st, address)
    .map((r) => `address=/${r.name}/${r.value}`)
    .join("\n");
}
