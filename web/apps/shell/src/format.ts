/** Formats bytes with decimal units, the way disks are sold: 21.4 TB, 512 GB. */
export function bytes(n: number | null | undefined, digits = 1): string {
  if (n == null || !Number.isFinite(n)) return "–";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let v = n;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  const fixed = i === 0 ? String(Math.round(v)) : v.toFixed(v >= 100 ? 0 : digits);
  return `${fixed.replace(/\.0+$/, "")} ${units[i]}`;
}

/** Formats a rate in bits per second: 84 Mb/s. */
export function bitsPerSecond(bytesPerSec: number | null | undefined): string {
  if (bytesPerSec == null) return "–";
  const bits = bytesPerSec * 8;
  const units = ["b/s", "Kb/s", "Mb/s", "Gb/s"];
  let v = bits;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

/** "3 days", "5 hours", "12 minutes". */
export function duration(seconds: number | null | undefined): string {
  if (seconds == null) return "–";
  const d = Math.floor(seconds / 86_400);
  if (d >= 1) return `${d} day${d === 1 ? "" : "s"}`;
  const h = Math.floor(seconds / 3_600);
  if (h >= 1) return `${h} hour${h === 1 ? "" : "s"}`;
  const m = Math.max(1, Math.floor(seconds / 60));
  return `${m} minute${m === 1 ? "" : "s"}`;
}

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

/** "2 hours ago", "yesterday", or a date for anything older than a week. */
export function relativeTime(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "never";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "–";
  const secs = Math.round((t - now) / 1000);
  const abs = Math.abs(secs);
  if (abs < 45) return "just now";
  if (abs < 3_600) return rtf.format(Math.round(secs / 60), "minute");
  if (abs < 86_400) return rtf.format(Math.round(secs / 3_600), "hour");
  if (abs < 7 * 86_400) return rtf.format(Math.round(secs / 86_400), "day");
  return new Date(t).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

/** A full local date and time for tooltips and logs. */
export function dateTime(iso: string | null | undefined): string {
  if (!iso) return "–";
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** Initials for an avatar: "Cade Hardy" -> "CH", "cade" -> "CA". */
export function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0]![0]! + parts[1]![0]!).toUpperCase();
  return (parts[0] ?? "?").slice(0, 2).toUpperCase();
}
