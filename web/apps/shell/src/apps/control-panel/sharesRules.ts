// Shared folder rules, matching daemon/internal/shares/validate.go so the
// form can explain a mistake before anything is sent.

export const MAX_NAME = 40;
const NAME_RE = /^[\p{L}\p{N} ._()'&-]+$/u;
const RESERVED = new Set(["global", "homes", "printers", "print$", "ipc$"]);

/** Collapses spaces like the server does. */
export const cleanName = (name: string) => name.trim().split(/\s+/).filter(Boolean).join(" ");

export function nameProblem(raw: string): string | null {
  const n = cleanName(raw);
  if (n === "") return "Give the shared folder a name.";
  if ([...n].length > MAX_NAME) return `At most ${MAX_NAME} characters.`;
  if (!NAME_RE.test(n)) return "Use letters, digits, spaces and . - _ ( ) ' & only.";
  if (!/[\p{L}\p{N}]/u.test(n)) return "Use at least one letter or digit.";
  if (RESERVED.has(n.toLowerCase())) return `"${n}" is reserved for file sharing.`;
  return null;
}

/** The id the server derives from a name: "TV & Movies" -> "tv-movies". */
export function deriveId(name: string): string {
  let out = "";
  let dash = false;
  for (const ch of name.toLowerCase()) {
    if (/[a-z0-9]/.test(ch)) {
      out += ch;
      dash = false;
    } else if (!dash && out.length > 0) {
      out += "-";
      dash = true;
    }
    if (out.length >= 32) break;
  }
  return out.replace(/^-+|-+$/g, "");
}

export function idProblem(id: string): string | null {
  if (!/^[a-z0-9][a-z0-9-]{0,31}$/.test(id) || id.endsWith("-")) return "Use 1-32 lowercase letters, digits and dashes.";
  if (RESERVED.has(id)) return `"${id}" is reserved for file sharing.`;
  return null;
}

export type QuotaUnit = "GB" | "TB";
const UNIT: Record<QuotaUnit, number> = { GB: 1e9, TB: 1e12 };

/** Quota in bytes from the form (empty or 0 = none); null when it isn't a number. */
export function quotaBytes(value: string, unit: QuotaUnit): number | null {
  const v = value.trim();
  if (v === "") return 0;
  if (!/^\d+(\.\d+)?$/.test(v)) return null;
  return Math.round(Number(v) * UNIT[unit]);
}

/** The form's value and unit for a quota in bytes. */
export function quotaFields(bytes: number): { value: string; unit: QuotaUnit } {
  if (!bytes) return { value: "", unit: "GB" };
  if (bytes >= 1e12 && bytes % 1e10 === 0) return { value: String(bytes / 1e12), unit: "TB" };
  return { value: String(Math.round((bytes / 1e9) * 100) / 100), unit: "GB" };
}
