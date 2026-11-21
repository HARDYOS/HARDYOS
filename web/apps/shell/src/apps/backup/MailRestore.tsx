import type { BackupVersion, BackupVersionItem, MailRestoreArgs } from "@hardy/api-client";
import { useState } from "react";
import { errorMessage } from "../../api";
import { bytes, dateTime } from "../../format";
import { Alert, Button, ErrorBox, Field, Loading, Select, TextInput } from "../../ui";
import { restore, useMailContents, useMailHere } from "./backupApi";

/** A mailbox by its storage key. */
export type MailBox = { key: string; address: string };

type Scope = MailRestoreArgs["scope"];
type Mode = "copy" | "overwrite";

const scopes: { id: Scope; label: string; hint: string }[] = [
  { id: "mailbox", label: "One mailbox", hint: "Its folders and messages." },
  { id: "domain", label: "One domain", hint: "Every mailbox at the domain." },
  { id: "calendars", label: "Calendars and contacts", hint: "One person's calendars and address books." },
  { id: "all", label: "Everything", hint: "The whole mail server as it was." },
];

/** What a mail restore needs typed to go ahead ("" = nothing). */
export function mailConfirmation(a: { scope: Scope; key: string; into: string; domain: string; mode: Mode }, here: MailBox[]): string {
  if (a.scope === "all") return "mail";
  if (a.scope === "domain") return a.mode === "overwrite" ? a.domain : "";
  const live = here.find((m) => m.key === a.into)?.address ?? "";
  return a.mode === "overwrite" || a.into !== a.key ? live : "";
}

/**
 * Choose what of a mail version to put back: a mailbox (into a new
 * "Restored" folder or over it), a domain, one person's calendars and
 * contacts, or everything. Mailboxes are matched by storage key; another
 * mailbox than the version's own needs its address typed (decision 461).
 */
export function MailRestoreForm({
  version,
  here,
  webmail,
  size,
  free,
  onRestore,
}: {
  version: { mailboxes: MailBox[]; domains: string[] };
  here: { mailboxes: MailBox[]; domains: string[] };
  webmail?: boolean;
  /** The version's size and the mail storage's free space, for the estimate. */
  size?: number;
  free?: number;
  onRestore: (args: MailRestoreArgs) => Promise<void>;
}) {
  const first = version.mailboxes[0]?.key ?? "";
  const [scope, setScope] = useState<Scope>("mailbox");
  const [key, setKey] = useState(first);
  const [into, setInto] = useState(here.mailboxes.some((m) => m.key === first) ? first : (here.mailboxes[0]?.key ?? ""));
  const [domain, setDomain] = useState(version.domains.find((d) => here.domains.includes(d)) ?? version.domains[0] ?? "");
  const [mode, setMode] = useState<Mode>("copy");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const perPerson = scope === "mailbox" || scope === "calendars";
  const need = mailConfirmation({ scope, key, into, domain, mode }, here.mailboxes);
  const typed = confirm.trim();
  const confirmed = need === "" || (scope === "all" ? typed.toLowerCase() === need : typed === need);
  const ready = confirmed && (!perPerson || (key && into)) && (scope !== "domain" || here.domains.includes(domain));

  function pickKey(k: string) {
    setKey(k);
    if (here.mailboxes.some((m) => m.key === k)) setInto(k);
    setConfirm("");
  }
  async function go() {
    setBusy(true);
    setError(null);
    try {
      const args: MailRestoreArgs =
        scope === "all"
          ? { scope, confirm: typed }
          : scope === "domain"
            ? { scope, domain, mode, confirm: need ? typed : undefined }
            : { scope, key, into, mode, confirm: need ? typed : undefined };
      await onRestore(args);
      setConfirm("");
    } catch (e) {
      setError(errorMessage(e));
    }
    setBusy(false);
  }

  return (
    <form
      className="stack"
      onSubmit={(e) => {
        e.preventDefault();
        if (ready && !busy) void go();
      }}
    >
      <fieldset className="bk-mailscope">
        <legend className="field__label">What to restore</legend>
        {scopes.map((s) => (
          <label key={s.id} className={`bk-choice ${scope === s.id ? "is-on" : ""}`}>
            <input
              type="radio"
              name="mail-scope"
              checked={scope === s.id}
              onChange={() => {
                setScope(s.id);
                setConfirm("");
              }}
            />
            <span>
              <strong>{s.label}</strong>
              <span className="small muted">{s.hint}</span>
            </span>
          </label>
        ))}
      </fieldset>
      {perPerson && (
        <div className="bk-row2">
          <Field label="From the version">
            {(id) => (
              <Select id={id} value={key} onChange={(e) => pickKey(e.target.value)}>
                {version.mailboxes.map((m) => (
                  <option key={m.key} value={m.key}>
                    {m.address}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Into" hint={into !== key ? "Another mailbox: type its address below to confirm." : undefined}>
            {(id) => (
              <Select
                id={id}
                value={into}
                onChange={(e) => {
                  setInto(e.target.value);
                  setConfirm("");
                }}
              >
                {here.mailboxes.length === 0 && <option value="">No mailboxes here</option>}
                {here.mailboxes.map((m) => (
                  <option key={m.key} value={m.key}>
                    {m.address}
                    {m.key === key ? " (the same mailbox)" : ""}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
      )}
      {scope === "domain" && (
        <Field label="Domain" error={domain && !here.domains.includes(domain) ? "This mail server doesn't have that domain now; add it in Control Panel › Mail first." : null}>
          {(id) => (
            <Select
              id={id}
              value={domain}
              onChange={(e) => {
                setDomain(e.target.value);
                setConfirm("");
              }}
            >
              {version.domains.map((d) => (
                <option key={d} value={d}>
                  {d}
                </option>
              ))}
            </Select>
          )}
        </Field>
      )}
      {scope !== "all" && (
        <div className="stack" role="radiogroup" aria-label="How">
          <label className={`bk-choice ${mode === "copy" ? "is-on" : ""}`}>
            <input type="radio" name="mail-mode" checked={mode === "copy"} onChange={() => setMode("copy")} />
            <span>
              <strong>{scope === "calendars" ? "As new calendars and address books" : "Into a new folder"}</strong>
              <span className="small muted">
                {scope === "calendars"
                  ? "Each comes back next to the current ones, named “… (restored)”. Nothing current changes."
                  : "A folder “Restored <date>” with the version's folders inside. Nothing current changes."}
              </span>
            </span>
          </label>
          <label className={`bk-choice ${mode === "overwrite" ? "is-on" : ""}`}>
            <input type="radio" name="mail-mode" checked={mode === "overwrite"} onChange={() => setMode("overwrite")} />
            <span>
              <strong>Replace what's there</strong>
              <span className="small muted">
                {scope === "domain"
                  ? "Its mailboxes, their calendars and the domain's DKIM key become as in the version. "
                  : scope === "calendars"
                    ? "Their calendars and contacts become as in the version. "
                    : "The mailbox's folders and messages become as in the version; mail the version doesn't have (newer mail) stays. "}
                A snapshot of the mail is taken first, and what was there is kept for 14 days.
              </span>
            </span>
          </label>
        </div>
      )}
      {scope === "all" && (
        <Alert tone="warn" title="The whole mail server goes back">
          The mail programs stop, every mailbox, calendar, DKIM key and the spam filter's learning become as in the version{webmail ? ", and so do webmail settings" : ""},
          then the mail server starts again. Mailboxes made since stay as they are. A snapshot of the mail is taken first.
        </Alert>
      )}
      {need && (
        <Field label={`Type ${need} to confirm`}>
          {(id) => <TextInput id={id} className="input mono" value={confirm} autoComplete="off" onChange={(e) => setConfirm(e.target.value)} />}
        </Field>
      )}
      {free !== undefined && size !== undefined && size > free && (
        <Alert tone="bad" title="Probably not enough room">
          The whole version is <span className="mono">{bytes(size)}</span> and the mail storage has <span className="mono">{bytes(free)}</span> free. A single mailbox may still
          fit; the server refuses a restore that clearly doesn't.
        </Alert>
      )}
      {error && <Alert tone="bad">{error}</Alert>}
      <div className="bk-actionbar">
        <span className="small muted">
          {free !== undefined && (
            <>
              <span className="mono">{bytes(free)}</span> free on the mail storage
              {size !== undefined && (
                <>
                  {" "}
                  · the version is <span className="mono">{bytes(size)}</span>
                </>
              )}
              .{" "}
            </>
          )}
          Restores are recorded in the audit log.
        </span>
        <Button variant={need ? "danger" : "primary"} size="sm" type="submit" busy={busy} disabled={!ready}>
          Restore
        </Button>
      </div>
    </form>
  );
}

/** A cloud backup version's mail item, in the Restore tab. */
export function CloudMailRestore({
  target,
  version,
  item,
  onJob,
}: {
  target: string;
  version: BackupVersion;
  item: BackupVersionItem;
  onJob: (j: { id: string; label: string }) => void;
}) {
  const contents = useMailContents(target, item.snapshot);
  const here = useMailHere();
  return (
    <div className="stack">
      <header className="bk-detail__head">
        <div>
          <h3>Mail</h3>
          <span className="small muted">
            {dateTime(version.time)} · <span className="mono">{bytes(item.bytes)}</span>
            {item.webmail ? " · with webmail settings" : ""}
          </span>
        </div>
      </header>
      {contents.isPending || here.isPending ? (
        <Loading label="Reading what the version holds…" />
      ) : contents.isError ? (
        <ErrorBox error={contents.error} onRetry={() => contents.refetch()} />
      ) : here.isError ? (
        <ErrorBox error={here.error} onRetry={() => here.refetch()} />
      ) : here.data.mailboxes.length === 0 ? (
        <Alert tone="info" title="Set the mail server up first">
          Turn the mail server on in Control Panel › Mail, then restore into it. On a rebuilt server, Rebuild brings the whole mail server back.
        </Alert>
      ) : (
        <MailRestoreForm
          version={contents.data}
          here={here.data}
          webmail={!!item.webmail}
          size={item.bytes}
          free={here.data.freeBytes ?? undefined}
          onRestore={async (mail) => {
            const r = await restore({ target, snapshot: item.snapshot, mode: "mail", mail });
            onJob({ id: r.job.id, label: mail.scope === "all" ? "Restoring the mail server" : "Restoring mail" });
          }}
        />
      )}
    </div>
  );
}
