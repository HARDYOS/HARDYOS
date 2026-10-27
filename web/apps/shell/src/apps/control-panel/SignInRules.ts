import type { OidcClientSpec } from "@hardy/api-client";

/** One entry per line, trimmed, blanks dropped. */
export function linesToList(s: string): string[] {
  return s
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
}

export function listToLines(l?: string[]): string {
  return (l ?? []).join("\n");
}

/** A preset step's value with {clientId}, {clientSecret} and {issuer} filled in. */
export function fillStep(value: string, v: { clientId: string; clientSecret: string; issuer: string }): string {
  return value.replaceAll("{clientId}", v.clientId).replaceAll("{clientSecret}", v.clientSecret).replaceAll("{issuer}", v.issuer);
}

/** The first thing wrong with a client form (the server checks it all again), or null. */
export function validClientForm(spec: OidcClientSpec): string | null {
  if (!spec.name.trim()) return "Give the app a name.";
  if (spec.redirectUris.length === 0) return "Add at least one redirect URI.";
  for (const u of [...spec.redirectUris, ...(spec.postLogoutRedirectUris ?? [])]) {
    let url: URL;
    try {
      url = new URL(u);
    } catch {
      return `${u} isn't a full address.`;
    }
    const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
    if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback && spec.kind === "public")) {
      return `${u} must use https (plain http only for localhost, for public apps).`;
    }
    if (url.hash || u.includes("#")) return `${u} can't have a #fragment.`;
  }
  for (const g of spec.allowedGroups ?? []) {
    if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,14}\\.+$/.test(g)) return `Write the group ${g} as DOMAIN\\group.`;
  }
  return null;
}
