import type { Disk, InstallNetwork } from "@hardy/api-client";

/** Mirrors install.MinDiskBytes on the server. */
export const MIN_BOOT_BYTES = 16 * 1024 ** 3;
export const MAX_BOOT_DISKS = 4;

/** Why a disk can't be a boot disk, or null when it can. Mirrors install.Eligible. */
export function ineligibleReason(d: Disk): string | null {
  if (d.usage === "mounted") return `In use: ${d.usageDetail}`;
  if (d.usage === "boot" && !d.pool) return "Holds the running system";
  if (d.sizeBytes < MIN_BOOT_BYTES) return "Too small (boot disks need at least 16 GB)";
  return null;
}

/** A warning shown next to an eligible disk, if any. */
export function diskWarning(d: Disk): string | null {
  if (d.usage === "pool" || d.usage === "boot") return `Member of pool ${d.pool}. It will be destroyed.`;
  if (d.usage === "has-data") return `Has data (${d.usageDetail}). It will be erased.`;
  return null;
}

/**
 * Suggests boot disks: the two smallest eligible SSDs (NVMe first) that hold
 * no pool, leaving bigger disks for data. Falls back to one disk, then to
 * the smallest eligible disks of any kind.
 */
export function suggestBootDisks(disks: Disk[]): string[] {
  const eligible = disks.filter((d) => ineligibleReason(d) === null);
  const score = (d: Disk) => (d.usage === "pool" || d.usage === "boot" ? 2 : 0) + (d.removable ? 1 : 0);
  const bySize = (a: Disk, b: Disk) => score(a) - score(b) || a.sizeBytes - b.sizeBytes;
  const flash = eligible.filter((d) => d.kind !== "hdd" && d.usage !== "pool").sort(bySize);
  // Prefer a matched pair of the same kind and similar size.
  for (const kind of ["nvme", "ssd"] as const) {
    const same = flash.filter((d) => d.kind === kind);
    if (same.length >= 2 && same[1]!.sizeBytes <= same[0]!.sizeBytes * 1.25) return [same[0]!.byId, same[1]!.byId];
  }
  if (flash.length >= 2) return [flash[0]!.byId, flash[1]!.byId];
  if (flash.length === 1) return [flash[0]!.byId];
  const any = [...eligible].sort(bySize);
  return any.slice(0, 1).map((d) => d.byId);
}

const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

export function hostnameError(h: string): string | null {
  if (!h) return "Give the server a name";
  if (!HOSTNAME_RE.test(h)) return "Lowercase letters, digits and dashes; can't start or end with a dash";
  return null;
}

const USERNAME_RE = /^[a-z][a-z0-9._-]{1,31}$/;

export function usernameError(u: string): string | null {
  if (!u) return "Choose a username";
  if (!USERNAME_RE.test(u)) return "2-32 characters: lowercase letters, digits, '.', '-' or '_', starting with a letter";
  if (["root", "hardyd", "daemon", "nobody", "bin", "sys"].includes(u)) return "That name is reserved for the system";
  return null;
}

function parseIPv4(s: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s.trim());
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((n) => n <= 255) ? parts : null;
}

function isIP(s: string): boolean {
  return parseIPv4(s) !== null || (/^[0-9a-fA-F:]+$/.test(s) && s.includes(":"));
}

/** Validates static network settings; returns field errors. */
export function networkErrors(n: InstallNetwork): Partial<Record<"interface" | "address" | "gateway" | "dns", string>> {
  if (n.mode !== "static") return {};
  const errs: Partial<Record<"interface" | "address" | "gateway" | "dns", string>> = {};
  if (!n.interface) errs.interface = "Choose the network port";
  const [ip, bitsText] = (n.address ?? "").split("/");
  const bits = Number(bitsText);
  const v4 = parseIPv4(ip ?? "");
  if (!ip || bitsText === undefined || !Number.isInteger(bits) || (v4 ? bits < 1 || bits > 31 : !isIP(ip) || bits < 1 || bits > 127)) {
    errs.address = "Use address/prefix, like 192.168.1.20/24";
  } else if (v4 && n.gateway) {
    const gw = parseIPv4(n.gateway);
    if (!gw) errs.gateway = "Not an IP address";
    else {
      const toInt = (p: number[]) => ((p[0]! << 24) | (p[1]! << 16) | (p[2]! << 8) | p[3]!) >>> 0;
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      if ((toInt(v4) & mask) !== (toInt(gw) & mask)) errs.gateway = `Must be inside ${ip}/${bits}`;
    }
  } else if (n.gateway && !isIP(n.gateway)) {
    errs.gateway = "Not an IP address";
  }
  if ((n.dns ?? []).some((d) => !isIP(d))) errs.dns = "Use IP addresses, separated by commas";
  return errs;
}

/** All IANA time zones the browser knows, with a fallback list. */
export function timeZones(): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (k: string) => string[] };
  try {
    const all = intl.supportedValuesOf?.("timeZone");
    if (all && all.length > 0) return all.includes("UTC") ? all : ["UTC", ...all];
  } catch {
    // older browsers
  }
  return ["UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles", "Europe/London", "Europe/Berlin", "Asia/Tokyo", "Australia/Sydney"];
}

export function browserTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

/** The install steps, in the order the server reports them. */
export const INSTALL_STEPS = [
  "Checking the boot disks",
  "Erasing and partitioning the boot disks",
  "Creating the boot pool",
  "Copying HardyOS onto the boot disks",
  "Applying your settings and preparing the first boot",
  "Installing the boot loader",
  "Finishing up",
] as const;

/** The extra step of a "Restore from backup" install (after the settings). */
export const RESTORE_STEP = "Bringing back the settings and the domain from the backup";

/** The steps of an install, with the restore step when restoring. */
export function installSteps(restore = false): string[] {
  const out: string[] = [...INSTALL_STEPS];
  if (restore) out.splice(out.indexOf("Installing the boot loader"), 0, RESTORE_STEP);
  return out;
}

/** Index of the step a job message belongs to (-1 when unknown). */
export function stepIndex(message: string, restore = false): number {
  return installSteps(restore).findIndex((s) => s === message);
}

/** Formats a typed code as XXXX-XXXX. */
export function formatCode(raw: string): string {
  const clean = raw.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 8);
  return clean.length > 4 ? `${clean.slice(0, 4)}-${clean.slice(4)}` : clean;
}
