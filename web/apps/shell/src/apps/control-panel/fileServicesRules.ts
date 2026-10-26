// Small helpers for File Services and the shared folder dialog's SMB
// section, kept apart so they can be tested on their own.

export type TmUnit = "GB" | "TB";

const UNIT: Record<TmUnit, number> = { GB: 1e9, TB: 1e12 };

/** The Time Machine size as the form shows it ("" = the folder's quota). */
export function tmSizeFields(bytes: number): { value: string; unit: TmUnit } {
  if (!bytes) return { value: "", unit: "GB" };
  if (bytes >= 1e12 && bytes % 1e11 === 0) return { value: String(bytes / 1e12), unit: "TB" };
  return { value: String(Math.round((bytes / 1e9) * 100) / 100), unit: "GB" };
}

/** Bytes from the form; 0 for empty, null when it isn't a number. */
export function tmSizeBytes(value: string, unit: TmUnit): number | null {
  const v = value.trim().replace(",", ".");
  if (v === "") return 0;
  if (!/^\d+(\.\d+)?$/.test(v)) return null;
  const n = Math.round(Number(v) * UNIT[unit]);
  return n > 0 ? n : null;
}

/** How a shared folder is opened: \\SERVER\Name on Windows, smb://host/Name elsewhere. */
export function smbPath(kind: "windows" | "mac" | "linux", host: string, share: string): string {
  if (kind === "windows") return `\\\\${host}\\${share}`;
  return `smb://${host}/${encodeURIComponent(share).replace(/%20/g, "%20")}`;
}

/** A Linux mount command for a shared folder (cifs-utils). */
export function linuxMount(host: string, share: string, domain: string): string {
  const dir = `/mnt/${share.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "share"}`;
  return `sudo mkdir -p ${dir}\nsudo mount -t cifs '//${host}/${share}' ${dir} -o username=YOUR_NAME,domain=${domain},uid=$(id -u),gid=$(id -g)`;
}
