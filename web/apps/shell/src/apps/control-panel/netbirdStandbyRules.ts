import type { NBStandbyStatus } from "@hardy/api-client";
import type { Tone } from "../../ui";
import { validDomain } from "./remoteAccessRules";

/** The standby's state in words, with a tone for its badge. */
export function standbyState(st: NBStandbyStatus): { tone: Tone; label: string } {
  switch (st.health.state) {
    case "takenover":
      return { tone: "accent", label: "Taken over" };
    case "ok":
      return { tone: "good", label: "In sync" };
    case "failing":
      return { tone: "warn", label: "Last copy failed" };
    case "stale":
      return { tone: "bad", label: "Out of date" };
    case "waiting":
      return { tone: "warn", label: "No copy yet" };
    default:
      return { tone: "neutral", label: "Not set up" };
  }
}

function v4Parts(s: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s.trim());
  if (!m) return null;
  const p = m.slice(1).map(Number);
  return p.every((n) => n <= 255) ? p : null;
}

/** An IPv4 address on the internet (not private, CGNAT, loopback, link-local, multicast). */
export function isPublicIPv4(s: string): boolean {
  const p = v4Parts(s);
  if (!p) return false;
  const a = p[0] ?? 0;
  const b = p[1] ?? 0;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  return true;
}

/** A global IPv6 address (rough check; the server checks exactly). */
export function isPublicIPv6(s: string): boolean {
  const t = s.trim().toLowerCase();
  if (!/^[0-9a-f:]+$/.test(t) || !t.includes(":") || t.split("::").length > 2) return false;
  return /^[23]/.test(t);
}

/** A line like "ssh-ed25519 AAAA… [comment]", optionally after a host name. */
export function looksLikeHostKey(s: string): boolean {
  const words = s.trim().split(/\s+/);
  const i = words.findIndex((w) => /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))$/.test(w));
  return i >= 0 && i <= 1 && /^AAAA[A-Za-z0-9+/=]{20,}$/.test(words[i + 1] ?? "") && !s.trim().includes("\n");
}

export interface StandbyForm {
  hostname: string;
  vpsHost: string;
  vpsPort: string;
  vpsUser: string;
  hostKey: string;
  publicIPv4: string;
  publicIPv6: string;
  intervalMinutes: string;
  connectFrom: string;
}

/** Splits "a, b c" into addresses. */
export function addressList(s: string): string[] {
  return s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

/** Problems with the settings form before it's sent (the server checks again). */
export function formProblems(f: StandbyForm): string[] {
  const out: string[] = [];
  const host = f.hostname.trim().toLowerCase().replace(/\.$/, "");
  if (!validDomain(host)) out.push("The NetBird server's name must look like vpn.example.net.");
  const vps = f.vpsHost.trim();
  if (!validDomain(vps.toLowerCase()) && !v4Parts(vps) && !/^[0-9a-fA-F:]+$/.test(vps)) out.push("The VPS address must be a host name or an IP address.");
  const port = Number(f.vpsPort || "22");
  if (!Number.isInteger(port) || port < 1 || port > 65535) out.push("The SSH port must be 1-65535.");
  if (f.vpsUser && !/^[a-z_][a-z0-9_-]{0,31}$/.test(f.vpsUser)) out.push("The VPS user must be a plain user name.");
  if (!looksLikeHostKey(f.hostKey)) out.push("Paste the VPS's host key (the line the VPS script prints, ssh-ed25519 AAAA…).");
  if (f.publicIPv4.trim() && !isPublicIPv4(f.publicIPv4)) out.push("This server's public IPv4 address must be an internet address (not 192.168.x.x, 10.x or 100.64-127.x).");
  if (f.publicIPv6.trim() && !isPublicIPv6(f.publicIPv6)) out.push("The public IPv6 address must be a global address.");
  const iv = Number(f.intervalMinutes || "15");
  if (!Number.isInteger(iv) || iv < 5 || iv > 1440) out.push("Sync every 5 to 1440 minutes.");
  if (addressList(f.connectFrom).length > 8) out.push("At most 8 addresses HardyOS connects from.");
  return out;
}

/** Why a take-over can't start yet (empty when it can). */
export function takeoverBlockers(st: NBStandbyStatus): string[] {
  const c = st.connection;
  const out: string[] = [];
  if (!c || !c.configured) return ["Set up the VPS connection first."];
  if (c.mode === "takenover") return ["HardyOS has already taken over."];
  if (!st.app.installed) out.push("Install the standby (step 3).");
  if (c.snapshots.length === 0) out.push("There is no copy of the VPS yet.");
  if (!isPublicIPv4(st.settings.publicIPv4)) out.push("Enter this server's public IPv4 address.");
  if (!st.dns.tokenSet) out.push("Save a Cloudflare token in Control Panel › Hostnames.");
  else if (st.dns.name !== c.hostname) out.push(`Let HardyOS manage ${c.hostname} in Cloudflare (step 4).`);
  else if (st.dns.adopted.some((r) => r.type === "AAAA") && !st.settings.publicIPv6) out.push(`${c.hostname} has an AAAA record: enter this server's public IPv6 address.`);
  return out;
}

/** How old the newest copy is, in words ("" without one). */
export function copyAge(st: NBStandbyStatus, now = Date.now()): string {
  const s = st.connection?.snapshots[0];
  if (!s) return "";
  const min = Math.max(0, Math.round((now - Date.parse(s.at)) / 60_000));
  if (min < 1) return "just now";
  if (min < 60) return `${min} min old`;
  const h = Math.round(min / 60);
  return h < 48 ? `${h} h old` : `${Math.round(h / 24)} days old`;
}
