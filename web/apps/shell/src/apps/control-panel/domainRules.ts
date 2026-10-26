/** Domain name and password rules, mirroring the server so mistakes show while typing. */

export const PASSWORD_RULES = "At least 8 characters with three of: upper case, lower case, digits, symbols.";

/** Mirrors the server's rules so mistakes show while typing. */
export function passwordProblem(pw: string, username = ""): string | null {
  if (pw.length === 0) return null;
  if (pw.length < 8) return "Needs at least 8 characters.";
  const kinds = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((r) => r.test(pw)).length;
  if (kinds < 3) return "Needs three of: lower case, upper case, digits, symbols.";
  if (username.length >= 3 && pw.toLowerCase().includes(username.toLowerCase())) return "Can't contain the user name.";
  return null;
}

/** The first part of the domain, upper case, 15 characters at most. */
export function defaultShortName(domain: string): string {
  return (domain.trim().toLowerCase().split(".")[0] ?? "").toUpperCase().slice(0, 15).replace(/-+$/, "");
}

export function domainProblem(d: string): string | null {
  const v = d.trim().toLowerCase().replace(/\.$/, "");
  if (!v) return null;
  if (/\.(local|localhost|invalid|test|example)$/.test(v)) return "Names ending in .local and similar cause trouble with Macs and certificates.";
  const parts = v.split(".");
  if (parts.length < 2) return "Use at least two parts, like home.yourname.net.";
  if (parts.some((p) => !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(p))) return "Use letters, digits and dashes between the dots.";
  if (v.length > 64) return "64 characters at most.";
  return null;
}
