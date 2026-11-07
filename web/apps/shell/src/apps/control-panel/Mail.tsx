import type { Job, MailDomain, MailOverview, MailSettings, Mailbox } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../api";
import { bytes, relativeTime } from "../../format";
import { useJob } from "../../hooks/queries";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Field, Loading, PageHeader, Select, Stat, TextInput, Toggle } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { MailIcon } from "../../icons";
import { MailDomains } from "./MailDomains";
import { mailboxProblems, settingsProblems } from "./mailRules";

type Tab = "setup" | "domains" | "mailboxes" | "vps" | "sending" | "certificate" | "queue";

const TABS: [Tab, string][] = [
  ["setup", "Setup"],
  ["domains", "Domains & DNS"],
  ["mailboxes", "Mailboxes"],
  ["vps", "VPS"],
  ["sending", "Sending (SES)"],
  ["certificate", "Certificate"],
  ["queue", "Queue"],
];

export const useMailOverview = () => useQuery({ queryKey: ["mail"], queryFn: () => unwrap(api.GET("/mail")), refetchInterval: 30_000 });

/** Runs an action that may answer with a job, and follows it. */
export function useMailJob() {
  const qc = useQueryClient();
  const [jobId, setJobId] = useState<string | null>(null);
  const job = useJob(jobId);
  const state = job.data?.state;
  useEffect(() => {
    if (state === "succeeded" || state === "failed") {
      void qc.invalidateQueries({ queryKey: ["mail"] });
      if (state === "failed") toast("error", job.data?.title ?? "Mail", job.data?.error ?? "Failed");
      else toast("success", job.data?.title ?? "Done");
    }
  }, [state, qc, job.data]);
  const follow = (r: unknown) => {
    const j = (r as { job?: Job } | undefined)?.job;
    if (j?.id) setJobId(j.id);
    else void qc.invalidateQueries({ queryKey: ["mail"] });
  };
  return { follow, job: job.data, running: state === "queued" || state === "running" };
}

function ServiceBadges({ o }: { o: MailOverview }) {
  const st = o.status;
  if (!st) return <Alert tone="warn" title="The mail server's state can't be read">{o.statusError}</Alert>;
  return (
    <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
      {Object.entries(st.services)
        .filter(([u]) => o.settings.clamav || !u.startsWith("clamav"))
        .sort()
        .map(([u, s]) => (
          <Badge key={u} tone={s === "active" ? "good" : o.settings.enabled ? "bad" : "neutral"}>
            {u.replace(/\.service$/, "").replace("@hardyos-mail", "")}: {s}
          </Badge>
        ))}
    </div>
  );
}

function SetupTab({ o }: { o: MailOverview }) {
  const qc = useQueryClient();
  const { follow, running, job } = useMailJob();
  const [draft, setDraft] = useState<MailSettings | null>(null);
  const [cfToken, setCfToken] = useState("");
  const [sesSecret, setSesSecret] = useState("");
  const s: MailSettings = draft ?? o.settings;
  const edit = (p: Partial<MailSettings>) => setDraft({ ...s, ...p });
  const problems = settingsProblems(s, o);
  const save = useMutation({
    mutationFn: () =>
      unwrap(
        api.PUT("/mail/settings", {
          body: { settings: s, ...(cfToken ? { cloudflareToken: cfToken } : {}), ...(sesSecret ? { sesSecretKey: sesSecret } : {}) },
        }),
      ),
    onSuccess: (r) => {
      follow(r);
      setDraft(null);
      setCfToken("");
      setSesSecret("");
      void qc.invalidateQueries({ queryKey: ["mail"] });
    },
  });
  const st = o.status;
  return (
    <>
      <Card title="Now">
        <div className="stack">
          <div className="grid-4">
            <Stat label="Server" value={o.settings.enabled ? (st?.running ? "Running" : "Not running") : "Off"} tone={o.settings.enabled ? (st?.running ? "good" : "bad") : undefined} />
            <Stat label="Mailboxes" value={<span className="mono">{o.mailboxCount}</span>} />
            <Stat label="Mail on disk" value={<span className="mono">{bytes((st?.usedMb ?? 0) * 1024 * 1024)}</span>} />
            <Stat label="Waiting to send" value={<span className="mono">{st?.queue.length ?? 0}</span>} tone={(st?.queue.length ?? 0) > 0 ? "warn" : undefined} />
          </div>
          {o.settings.enabled && <ServiceBadges o={o} />}
          {o.publishedUrl && (
            <span className="small muted">
              Mail apps' settings and calendars are published at <span className="mono">{o.publishedUrl}</span>.
            </span>
          )}
        </div>
      </Card>
      <Card
        title="Setup"
        actions={
          <Button variant="primary" disabled={!draft && !cfToken && !sesSecret} busy={save.isPending || running} onClick={() => save.mutate()}>
            Save and apply
          </Button>
        }
      >
        <div className="stack">
          {save.error != null && <Alert tone="bad" title={errorMessage(save.error)} />}
          {job?.state === "failed" && <Alert tone="bad" title="Applying the mail settings failed">{job.error}</Alert>}
          {problems.length > 0 && s.enabled && (
            <Alert tone="warn" title="Before turning it on">
              <ul>
                {problems.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            </Alert>
          )}
          <Toggle label="Mail server" description="Receive, keep and send mail for the family's domains. Data stays on the pool when it's off." checked={!!s.enabled} onChange={(v) => edit({ enabled: v })} />
          <div className="grid-2" style={{ gap: 12 }}>
            <Field label="Keep mail on" hint="A dataset <pool>/mail; include it in your backups">
              {(id) => (
                <Select id={id} value={s.pool ?? ""} onChange={(e) => edit({ pool: e.target.value })}>
                  <option value="">Choose a pool…</option>
                  {o.pools.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label="Mail server's name" hint="Mail apps connect to it and the MX points to it, like mail.example.net">
              {(id) => <TextInput id={id} className="input mono" value={s.hostname ?? ""} placeholder="mail.example.net" onChange={(e) => edit({ hostname: e.target.value.trim().toLowerCase() })} />}
            </Field>
            <Field label="Domain for new mailboxes">
              {(id) => (
                <Select id={id} value={s.defaultDomain ?? ""} onChange={(e) => edit({ defaultDomain: e.target.value })}>
                  <option value="">{o.domains.length ? "Choose…" : "Add a domain first"}</option>
                  {o.domains.map((d) => (
                    <option key={d.name} value={d.name}>
                      {d.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label="New addresses from">
              {(id) => (
                <Select id={id} value={s.addressStyle ?? "firstname"} onChange={(e) => edit({ addressStyle: e.target.value as MailSettings["addressStyle"] })}>
                  <option value="firstname">First name (alice@)</option>
                  <option value="username">Account name (asmith@)</option>
                </Select>
              )}
            </Field>
            <Field label="Mailbox size for new accounts" hint="MB; 0 for no limit">
              {(id) => <TextInput id={id} className="input mono" inputMode="numeric" value={s.defaultQuotaMb ?? 0} onChange={(e) => edit({ defaultQuotaMb: Number(e.target.value) || 0 })} />}
            </Field>
            <Field label="Postmaster" hint="Gets postmaster@, abuse@ and DMARC reports for every domain">
              {(id) => <TextInput id={id} className="input mono" value={s.postmaster ?? ""} placeholder="you@example.net" onChange={(e) => edit({ postmaster: e.target.value.trim().toLowerCase() })} />}
            </Field>
          </div>
          <h4 className="small">The VPS</h4>
          <div className="grid-2" style={{ gap: 12 }}>
            <Field label="VPS's NetBird address" hint="Relayed mail and forwarded mail apps are accepted from this address only">
              {(id) => <TextInput id={id} className="input mono" value={s.vpsPeer ?? ""} placeholder="100.x.y.z" onChange={(e) => edit({ vpsPeer: e.target.value.trim() })} />}
            </Field>
            <Field label="VPS's public IPv4 address" hint="For the mail server's A record and the VPS check">
              {(id) => <TextInput id={id} className="input mono" value={s.vpsIpv4 ?? ""} onChange={(e) => edit({ vpsIpv4: e.target.value.trim() })} />}
            </Field>
            <Field label="VPS's public IPv6 address" hint="Optional">
              {(id) => <TextInput id={id} className="input mono" value={s.vpsIpv6 ?? ""} onChange={(e) => edit({ vpsIpv6: e.target.value.trim() })} />}
            </Field>
            <Field label="This server on NetBird">
              {(id) => <TextInput id={id} className="input mono" value={o.netbirdAddress || "not connected"} readOnly />}
            </Field>
          </div>
          <h4 className="small">Spam, viruses and limits</h4>
          <div className="grid-2" style={{ gap: 12 }}>
            <Field label="Junk from score" hint="Rspamd score from which mail goes to Junk (6 is a good start)">
              {(id) => <TextInput id={id} className="input mono" inputMode="decimal" value={s.junkScore ?? 6} onChange={(e) => edit({ junkScore: Number(e.target.value) || 0 })} />}
            </Field>
            <Field label="Largest message" hint="MB">
              {(id) => <TextInput id={id} className="input mono" inputMode="numeric" value={s.maxMessageMb ?? 50} onChange={(e) => edit({ maxMessageMb: Number(e.target.value) || 0 })} />}
            </Field>
            <Field label="Messages per person per hour" hint="Stops a stolen password from sending a flood">
              {(id) => <TextInput id={id} className="input mono" inputMode="numeric" value={s.sendPerHour ?? 200} onChange={(e) => edit({ sendPerHour: Number(e.target.value) || 0 })} />}
            </Field>
            <Field label="Notifications from" hint="HardyOS's alerts can be sent through this server from this address (Control Panel › Notifications: “HardyOS Mail”)">
              {(id) => <TextInput id={id} className="input mono" value={s.notifyFrom ?? ""} placeholder="hardyos@example.net" onChange={(e) => edit({ notifyFrom: e.target.value.trim().toLowerCase() })} />}
            </Field>
          </div>
          <Toggle label="Scan for viruses (ClamAV)" description="Uses about 1.5 GB of memory. Infected mail goes to Junk, marked." checked={!!s.clamav} onChange={(v) => edit({ clamav: v })} />
          <Toggle label="Family calendar and address book" description="Shared by everyone with a mailbox, next to their own." checked={!!s.sharedCalendar} onChange={(v) => edit({ sharedCalendar: v })} />
          <h4 className="small">Certificate and DNS</h4>
          <div className="grid-2" style={{ gap: 12 }}>
            <Field label="Certificate">
              {(id) => (
                <Select id={id} value={s.tlsMode ?? "self"} onChange={(e) => edit({ tlsMode: e.target.value as MailSettings["tlsMode"] })}>
                  <option value="acme">Let's Encrypt (DNS check through Cloudflare)</option>
                  <option value="manual">Upload my own</option>
                  <option value="self">Self-signed (testing only)</option>
                </Select>
              )}
            </Field>
            <Field label="Let's Encrypt contact" hint="Optional; expiry warnings go there">
              {(id) => <TextInput id={id} className="input mono" value={s.acmeEmail ?? ""} onChange={(e) => edit({ acmeEmail: e.target.value.trim() })} />}
            </Field>
            <Field label="Cloudflare API token" hint={o.cloudflareTokenSet ? "Saved. Leave empty to keep it." : "Zone › DNS › Edit, for your mail domains' zones only"}>
              {(id) => <TextInput id={id} type="password" autoComplete="off" value={cfToken} placeholder={o.cloudflareTokenSet ? "••••••••" : ""} onChange={(e) => setCfToken(e.target.value)} />}
            </Field>
          </div>
          {s.tlsMode === "acme" && <Toggle label="Use Let's Encrypt's staging server" description="For trying it out; staging certificates aren't trusted by devices." checked={!!s.acmeStaging} onChange={(v) => edit({ acmeStaging: v })} />}
          <h4 className="small">Sending through Amazon SES</h4>
          <div className="grid-2" style={{ gap: 12 }}>
            <Field label="AWS region" hint="Where your SES account is, like us-east-1">
              {(id) => <TextInput id={id} className="input mono" value={s.sesRegion ?? ""} onChange={(e) => edit({ sesRegion: e.target.value.trim() })} />}
            </Field>
            <Field label="Access key ID" hint="An IAM user allowed ses:SendRawEmail and the identity actions (docs/mail.md)">
              {(id) => <TextInput id={id} className="input mono" value={s.sesAccessKeyId ?? ""} onChange={(e) => edit({ sesAccessKeyId: e.target.value.trim() })} />}
            </Field>
            <Field label="Secret access key" hint={o.sesSecretSet ? "Saved. Leave empty to keep it." : "Sealed; HardyOS derives the SMTP password from it"}>
              {(id) => <TextInput id={id} type="password" autoComplete="off" value={sesSecret} placeholder={o.sesSecretSet ? "••••••••" : ""} onChange={(e) => setSesSecret(e.target.value)} />}
            </Field>
          </div>
          <Toggle label="Bounces to bounce.<domain> (custom MAIL FROM)" description="Lets SPF line up with your domain for DMARC." checked={!!s.sesMailFrom} onChange={(v) => edit({ sesMailFrom: v })} />
        </div>
      </Card>
    </>
  );
}

function MailboxDialog({ m, onClose }: { m: Mailbox; onClose: () => void }) {
  const qc = useQueryClient();
  const { follow } = useMailJob();
  const [address, setAddress] = useState(m.address);
  const [aliases, setAliases] = useState(m.aliases.join(", "));
  const [quota, setQuota] = useState(String(m.quotaMb));
  const list = aliases.split(/[\s,]+/).filter(Boolean);
  const problems = mailboxProblems(address, list, Number(quota));
  const save = useMutation({
    mutationFn: () => unwrap(api.PATCH("/mail/mailboxes/{id}", { params: { path: { id: m.id } }, body: { address, aliases: list, quotaMb: Number(quota) || 0 } })),
    onSuccess: (r) => {
      follow(r);
      void qc.invalidateQueries({ queryKey: ["mail"] });
      onClose();
    },
  });
  return (
    <Dialog
      title={`Mailbox of ${m.displayName || m.account}`}
      onClose={onClose}
      onSubmit={() => problems.length === 0 && save.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" disabled={problems.length > 0} busy={save.isPending}>
            Save
          </Button>
        </>
      }
    >
      <div className="stack">
        {save.error != null && <Alert tone="bad" title={errorMessage(save.error)} />}
        <Field label="Address" error={problems.find((p) => p.startsWith("The address"))}>
          {(id) => <TextInput id={id} className="input mono" value={address} onChange={(e) => setAddress(e.target.value.trim().toLowerCase())} />}
        </Field>
        <Field label="Aliases" hint="Other addresses that deliver here and can be sent from, separated by commas" error={problems.find((p) => p.startsWith("Alias"))}>
          {(id) => <TextInput id={id} className="input mono" value={aliases} onChange={(e) => setAliases(e.target.value.toLowerCase())} />}
        </Field>
        <Field label="Size limit" hint="MB; 0 for no limit" error={problems.find((p) => p.startsWith("The size"))}>
          {(id) => <TextInput id={id} className="input mono" inputMode="numeric" value={quota} onChange={(e) => setQuota(e.target.value)} />}
        </Field>
      </div>
    </Dialog>
  );
}

function MailboxesTab({ o }: { o: MailOverview }) {
  const qc = useQueryClient();
  const { follow, running } = useMailJob();
  const q = useQuery({ queryKey: ["mail", "mailboxes"], queryFn: () => unwrap(api.GET("/mail/mailboxes")) });
  const groups = useQuery({ queryKey: ["mail", "groups"], queryFn: () => unwrap(api.GET("/mail/groups")) });
  const [editing, setEditing] = useState<Mailbox | null>(null);
  const [deleting, setDeleting] = useState<Mailbox | null>(null);
  const [groupAddr, setGroupAddr] = useState("");
  const [groupTargets, setGroupTargets] = useState<string[]>([]);
  const toggle = useMutation({
    mutationFn: (m: Mailbox) => unwrap(api.PATCH("/mail/mailboxes/{id}", { params: { path: { id: m.id } }, body: { enabled: !m.enabled } })),
    onSuccess: follow,
    onError: (e) => toast("error", "Couldn't change the mailbox", errorMessage(e)),
  });
  const sync = useMutation({ mutationFn: () => unwrap(api.POST("/mail/mailboxes/sync")), onSuccess: follow });
  const setGroup = useMutation({
    mutationFn: () => unwrap(api.PUT("/mail/groups/{address}", { params: { path: { address: groupAddr } }, body: { targets: groupTargets } })),
    onSuccess: (r) => {
      follow(r);
      setGroupAddr("");
      setGroupTargets([]);
      void qc.invalidateQueries({ queryKey: ["mail", "groups"] });
    },
  });
  const delGroup = useMutation({
    mutationFn: (a: string) => unwrap(api.DELETE("/mail/groups/{address}", { params: { path: { address: a } } })),
    onSuccess: (r) => {
      follow(r);
      void qc.invalidateQueries({ queryKey: ["mail", "groups"] });
    },
  });
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  return (
    <>
      <Card
        title="Mailboxes"
        actions={
          <Button onClick={() => sync.mutate()} busy={sync.isPending || running} disabled={!o.settings.enabled}>
            Check for new accounts
          </Button>
        }
      >
        {q.data.length === 0 ? (
          <EmptyState icon={<MailIcon size={28} />} title="No mailboxes yet">
            Every account in Control Panel › Domain gets one when the mail server is on (a domain for new mailboxes must be set).
          </EmptyState>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Address</th>
                <th>Account</th>
                <th>Space</th>
                <th>Sign-in</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {q.data.map((m) => (
                <tr key={m.id}>
                  <td>
                    <span className="mono">{m.address}</span>
                    {m.aliases.length > 0 && <div className="small muted mono">{m.aliases.join(", ")}</div>}
                  </td>
                  <td>
                    {m.displayName || m.account}{" "}
                    {m.accountState !== "active" && <Badge tone={m.accountState === "deleted" ? "bad" : "warn"}>{m.accountState === "deleted" ? "account deleted" : "account off"}</Badge>}
                  </td>
                  <td className="mono small">
                    {bytes((m.usedKb ?? 0) * 1024)}
                    {m.quotaMb > 0 ? ` / ${bytes(m.quotaMb * 1024 * 1024)}` : ""}
                  </td>
                  <td>
                    <Toggle label={m.enabled ? "On" : "Off"} checked={m.enabled} onChange={() => toggle.mutate(m)} disabled={m.accountState !== "active"} />
                  </td>
                  <td className="row" style={{ gap: 6, justifyContent: "flex-end" }}>
                    <Button size="sm" onClick={() => setEditing(m)}>
                      Edit
                    </Button>
                    {m.accountState !== "active" && (
                      <Button size="sm" variant="danger" onClick={() => setDeleting(m)}>
                        Delete…
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <Card title="Group addresses">
        <div className="stack">
          <p className="small muted" style={{ margin: 0 }}>
            One address for several mailboxes, like family@. Everyone in the group may also send from it.
          </p>
          {(groups.data ?? []).map((g) => (
            <div key={g.address} className="row" style={{ justifyContent: "space-between" }}>
              <span>
                <span className="mono">{g.address}</span> <span className="small muted">→ {g.targets.join(", ")}</span>
              </span>
              <Button size="sm" variant="danger" onClick={() => delGroup.mutate(g.address)}>
                Remove
              </Button>
            </div>
          ))}
          <div className="grid-2" style={{ gap: 12 }}>
            <Field label="New group address">
              {(id) => <TextInput id={id} className="input mono" value={groupAddr} placeholder={`family@${o.settings.defaultDomain || "example.net"}`} onChange={(e) => setGroupAddr(e.target.value.trim().toLowerCase())} />}
            </Field>
            <div className="field">
              <span className="field__label">Delivers to</span>
              <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
                {q.data.map((m) => (
                  <label key={m.id} className="small row" style={{ gap: 4 }}>
                    <input type="checkbox" checked={groupTargets.includes(m.address)} onChange={(e) => setGroupTargets(e.target.checked ? [...groupTargets, m.address] : groupTargets.filter((t) => t !== m.address))} />
                    <span className="mono">{m.address}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>
          {setGroup.error != null && <Alert tone="bad" title={errorMessage(setGroup.error)} />}
          <div>
            <Button onClick={() => setGroup.mutate()} disabled={!groupAddr || groupTargets.length === 0} busy={setGroup.isPending}>
              Add group address
            </Button>
          </div>
        </div>
      </Card>
      {editing && <MailboxDialog m={editing} onClose={() => setEditing(null)} />}
      {deleting && (
        <ConfirmDialog
          title={`Delete ${deleting.address}?`}
          confirmLabel="Delete the mailbox and its mail"
          typeToConfirm={deleting.address}
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            const r = await unwrap(api.DELETE("/mail/mailboxes/{id}", { params: { path: { id: deleting.id } }, body: { confirm: deleting.address } }));
            follow(r);
          }}
        >
          Every message in this mailbox is deleted for good (older snapshots of the pool may still hold them). Type the address to confirm.
        </ConfirmDialog>
      )}
    </>
  );
}

function VPSTab() {
  const q = useQuery({ queryKey: ["mail", "vps"], queryFn: () => unwrap(api.GET("/mail/vps")) });
  const check = useMutation({ mutationFn: () => unwrap(api.POST("/mail/vps/check")) });
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const v = q.data;
  const download = () => {
    const url = URL.createObjectURL(new Blob([v.script], { type: "text/x-shellscript" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "hardyos-mail-relay.sh";
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <>
      <Card title="What the VPS does">
        <ul className="small" style={{ margin: 0 }}>
          <li>
            <strong>Port 25:</strong> Postfix receives mail for your domains and relays it here over NetBird (to <span className="mono">{v.homePeer || "this server"}:{v.relayPort}</span>). While home is offline it keeps mail for up to 14 days.
          </li>
          <li>
            <strong>Ports 993, 465, 587:</strong> HAProxy forwards mail apps here (to ports <span className="mono">{v.proxyPorts.join(", ")}</span>) with their real address. Encryption ends at home, so the VPS never sees passwords.
          </li>
          <li>Nothing else on the VPS changes. Run the script again after adding a domain.</li>
        </ul>
      </Card>
      <Card
        title="Run this on the VPS as root"
        actions={
          <div className="row" style={{ gap: 6 }}>
            <Button size="sm" disabled={!v.script} onClick={() => void navigator.clipboard?.writeText(v.script).then(() => toast("success", "Copied"), () => undefined)}>
              Copy
            </Button>
            <Button size="sm" disabled={!v.script} onClick={download}>
              Download
            </Button>
          </div>
        }
      >
        {v.problem ? <Alert tone="warn" title={v.problem} /> : <pre className="mail-script mono">{v.script}</pre>}
      </Card>
      <Card
        title="Check the VPS"
        actions={
          <Button variant="primary" onClick={() => check.mutate()} busy={check.isPending}>
            Check now
          </Button>
        }
      >
        {check.error != null && <Alert tone="bad" title={errorMessage(check.error)} />}
        {check.data ? (
          <ul className="mail-checks">
            {check.data.map((c) => (
              <li key={c.name}>
                <Badge tone={c.ok ? "good" : "bad"}>{c.ok ? "OK" : "Problem"}</Badge> <strong>{c.name}</strong>
                <div className="small muted">{c.detail}</div>
              </li>
            ))}
          </ul>
        ) : (
          <p className="small muted" style={{ margin: 0 }}>
            Connects to the VPS's public address like the internet would: port 25 must relay home, ports 993 and 465 must reach this server.
          </p>
        )}
      </Card>
    </>
  );
}

function SendingTab({ o }: { o: MailOverview }) {
  const enabled = !!o.settings.sesAccessKeyId && o.sesSecretSet;
  const q = useQuery({ queryKey: ["mail", "ses"], queryFn: () => unwrap(api.GET("/mail/ses")), enabled });
  if (!enabled) return <Alert tone="info" title="Enter the Amazon SES region, access key ID and secret access key in Setup.">Mail to other servers waits in the queue until sending is set up; mail between family mailboxes works without it.</Alert>;
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const s = q.data;
  return (
    <Card title="Amazon SES">
      <div className="stack">
        {s.error && <Alert tone="bad" title={s.error} />}
        {s.account && (
          <div className="grid-4">
            <Stat label="Account" value={s.account.productionAccess ? "Production" : "Sandbox"} tone={s.account.productionAccess ? "good" : "warn"} sub={s.account.productionAccess ? undefined : "Only verified recipients; request production access in AWS"} />
            <Stat label="Sending" value={s.account.sendingEnabled ? "Enabled" : "Paused"} tone={s.account.sendingEnabled ? "good" : "bad"} />
            <Stat label="Sent today" value={<span className="mono">{s.account.sentLast24Hours ?? 0}</span>} sub={`of ${s.account.max24HourSend ?? 0}`} />
          </div>
        )}
        <table className="table">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Verified</th>
              <th>DKIM</th>
              <th>MAIL FROM</th>
            </tr>
          </thead>
          <tbody>
            {o.domains.map((d) => {
              const id = s.identities[d.name];
              return (
                <tr key={d.name}>
                  <td className="mono">{d.name}</td>
                  <td>{!id?.exists ? <Badge tone="warn">not in SES</Badge> : id.verifiedForSending ? <Badge tone="good">yes</Badge> : <Badge tone="warn">waiting for DNS</Badge>}</td>
                  <td className="small">{id?.dkimStatus || "–"}</td>
                  <td className="small mono">{id?.mailFromDomain ? `${id.mailFromDomain} (${id.mailFromStatus ?? "?"})` : "–"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <span className="small muted">Add a domain to SES from Domains & DNS (“Verify with SES”), then publish the records it lists.</span>
      </div>
    </Card>
  );
}

function CertificateTab({ o }: { o: MailOverview }) {
  const { follow, running } = useMailJob();
  const [chain, setChain] = useState("");
  const [key, setKey] = useState("");
  const renew = useMutation({ mutationFn: () => unwrap(api.POST("/mail/certificate", { body: { force: true } })), onSuccess: follow });
  const upload = useMutation({
    mutationFn: () => unwrap(api.PUT("/mail/certificate", { body: { chain, key } })),
    onSuccess: (r) => {
      follow(r);
      setChain("");
      setKey("");
    },
  });
  const c = o.status?.cert;
  return (
    <>
      <Card
        title="Certificate"
        actions={
          o.settings.tlsMode === "acme" ? (
            <Button variant="primary" busy={renew.isPending || running} onClick={() => renew.mutate()}>
              Get a new one now
            </Button>
          ) : undefined
        }
      >
        {c ? (
          <div className="grid-4">
            <Stat label="For" value={<span className="mono small">{c.names?.join(", ")}</span>} />
            <Stat label="From" value={c.selfSigned ? "Self-signed" : c.issuer || "?"} tone={c.selfSigned ? "warn" : "good"} />
            <Stat label="Valid until" value={c.notAfter ? new Date(c.notAfter).toLocaleDateString() : "?"} sub={c.notAfter ? relativeTime(c.notAfter) : undefined} />
          </div>
        ) : (
          <span className="small muted">No certificate yet: one is made when the mail server is turned on.</span>
        )}
        {renew.error != null && <Alert tone="bad" title={errorMessage(renew.error)} />}
        {o.settings.tlsMode === "acme" && <p className="small muted">Let's Encrypt certificates renew by themselves 30 days before they expire.</p>}
      </Card>
      {o.settings.tlsMode === "manual" && (
        <Card title="Upload a certificate">
          <div className="stack">
            <Field label="Certificate chain (PEM)">{(id) => <textarea id={id} className="input mono" rows={6} value={chain} onChange={(e) => setChain(e.target.value)} />}</Field>
            <Field label="Private key (PEM)" hint="Goes straight to the root helper, which keeps it on the mail dataset">
              {(id) => <textarea id={id} className="input mono" rows={4} value={key} onChange={(e) => setKey(e.target.value)} />}
            </Field>
            {upload.error != null && <Alert tone="bad" title={errorMessage(upload.error)} />}
            <div>
              <Button variant="primary" disabled={!chain || !key} busy={upload.isPending || running} onClick={() => upload.mutate()}>
                Install
              </Button>
            </div>
          </div>
        </Card>
      )}
    </>
  );
}

function QueueTab() {
  const { follow, running } = useMailJob();
  const q = useQuery({ queryKey: ["mail", "queue"], queryFn: () => unwrap(api.GET("/mail/queue")), refetchInterval: 15_000 });
  const flush = useMutation({ mutationFn: () => unwrap(api.POST("/mail/queue/flush")), onSuccess: follow });
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  return (
    <Card
      title="Waiting to be delivered"
      actions={
        <Button onClick={() => flush.mutate()} busy={flush.isPending || running} disabled={q.data.length === 0}>
          Retry all now
        </Button>
      }
    >
      {q.data.length === 0 ? (
        <span className="small muted">Nothing is waiting.</span>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Since</th>
              <th>From</th>
              <th>To</th>
              <th>Why it waits</th>
            </tr>
          </thead>
          <tbody>
            {q.data.map((m) => (
              <tr key={m.id}>
                <td className="small">{relativeTime(m.arrivedAt)}</td>
                <td className="mono small">{m.sender || "(bounce)"}</td>
                <td className="mono small">{m.recipients.join(", ")}</td>
                <td className="small">{m.reason || m.queue}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

export function Mail() {
  const q = useMailOverview();
  const [tab, setTab] = useState<Tab>("setup");
  if (q.isPending) return <Loading />;
  if (q.isError) {
    if (q.error instanceof ApiFailure && q.error.status === 404) return <Alert tone="info" title="The mail server isn't available on this system." />;
    return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  }
  const o = q.data;
  return (
    <>
      <PageHeader
        title="Mail"
        subtitle="The family's mail at home: mailboxes for every domain account, webmail, calendars and contacts. Mail arrives through your VPS and leaves through Amazon SES."
        badge={o.settings.enabled ? <Badge tone={o.status?.running ? "good" : "bad"}>{o.status?.running ? "Running" : "Not running"}</Badge> : <Badge tone="neutral">Off</Badge>}
      />
      <div className="tabs" role="tablist" aria-label="Mail sections">
        {TABS.map(([id, label]) => (
          <button key={id} type="button" role="tab" className="tabs__tab" aria-selected={tab === id} onClick={() => setTab(id)}>
            {label}
          </button>
        ))}
      </div>
      <div className="stack" style={{ marginTop: 12 }}>
        {tab === "setup" && <SetupTab o={o} />}
        {tab === "domains" && <MailDomains o={o} />}
        {tab === "mailboxes" && <MailboxesTab o={o} />}
        {tab === "vps" && <VPSTab />}
        {tab === "sending" && <SendingTab o={o} />}
        {tab === "certificate" && <CertificateTab o={o} />}
        {tab === "queue" && <QueueTab />}
      </div>
    </>
  );
}

export type { MailDomain };
