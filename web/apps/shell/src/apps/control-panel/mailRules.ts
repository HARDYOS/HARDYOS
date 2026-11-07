import type { MailOverview, MailRecord, MailSettings } from "@hardy/api-client";

// Client-side checks for Control Panel › Mail. hardyd and hardyd-priv
// check everything again; these only explain problems before saving.

const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const LOCAL = /^[a-z0-9]([a-z0-9._+-]{0,62}[a-z0-9])?$/;

/** Why name isn't a usable domain, or null. */
export function domainProblem(name: string): string | null {
  if (name !== name.toLowerCase()) return "Use lower case.";
  const labels = name.split(".");
  if (name.length > 253 || labels.length < 2 || !labels.every((l) => LABEL.test(l))) return "A domain looks like example.net.";
  if (/^[0-9]+$/.test(labels[labels.length - 1]!)) return "A domain ends with a name, not a number.";
  return null;
}

/** Why a is not a usable address, or null. */
export function addressProblem(a: string): string | null {
  const at = a.lastIndexOf("@");
  if (at <= 0) return "An address looks like name@example.net.";
  const local = a.slice(0, at);
  if (!LOCAL.test(local) || local.includes("..")) return "Before the @: letters, digits, “.”, “_”, “+” and “-” only.";
  return domainProblem(a.slice(at + 1));
}

/** Problems with a mailbox edit. */
export function mailboxProblems(address: string, aliases: string[], quotaMb: number): string[] {
  const out: string[] = [];
  const a = addressProblem(address);
  if (a) out.push(`The address: ${a}`);
  for (const al of aliases) {
    const p = addressProblem(al);
    if (p) out.push(`Alias ${al}: ${p}`);
    if (al === address) out.push(`Alias ${al} is the mailbox's own address.`);
    if (/^(postmaster|abuse)@/.test(al)) out.push(`Alias ${al} is kept for the postmaster.`);
  }
  if (!Number.isInteger(quotaMb) || quotaMb < 0 || quotaMb > 4 * 1024 * 1024) out.push("The size limit must be 0 (none) or a number of MB.");
  return out;
}

/** What's missing before the mail server can be turned on. */
export function settingsProblems(s: MailSettings, o: Pick<MailOverview, "domains" | "netbirdAddress" | "sesSecretSet" | "cloudflareTokenSet">): string[] {
  const out: string[] = [];
  if (!s.pool) out.push("Choose the pool mail is kept on.");
  if (!s.hostname) out.push("Set the mail server's name (like mail.example.net).");
  else if (domainProblem(s.hostname)) out.push("The mail server's name isn't a valid host name.");
  if (o.domains.length === 0) out.push("Add a mail domain (Domains & DNS).");
  if (!s.defaultDomain) out.push("Choose the domain for new mailboxes, or no mailboxes are made.");
  if (!s.vpsPeer) out.push("Enter the VPS's NetBird address.");
  if (!o.netbirdAddress) out.push("This server isn't on NetBird (Control Panel › Remote Access): the VPS can't reach it.");
  if (!s.sesAccessKeyId || !o.sesSecretSet) out.push("Without Amazon SES, mail to other servers waits in the queue.");
  if (s.tlsMode === "acme" && !o.cloudflareTokenSet) out.push("Let's Encrypt needs a Cloudflare API token.");
  return out;
}

/** A record's identity, to match a check to it. */
export function recordKey(r: Pick<MailRecord, "type" | "name" | "value">): string {
  return `${r.type} ${r.name} ${r.value}`;
}
