import type { MailCheck, MailDomain, MailOverview, MailRecord } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { relativeTime } from "../../format";
import { ClipboardIcon } from "../../icons";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Field, Loading, Select, TextInput, Toggle } from "../../ui";
import { ConfirmDialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { useMailJob } from "./Mail";
import { domainProblem, recordKey } from "./mailRules";

function copy(text: string) {
  void navigator.clipboard?.writeText(text).then(
    () => toast("success", "Copied"),
    () => undefined,
  );
}

const statusTone = { ok: "good", missing: "bad", wrong: "bad", error: "warn" } as const;

function RecordRow({ r, check }: { r: MailRecord; check?: MailCheck }) {
  const tone = check ? (check.status === "ok" ? "good" : r.required ? statusTone[check.status] : "warn") : "neutral";
  return (
    <tr>
      <td>
        <Badge tone={tone}>{check ? check.status : "not checked"}</Badge>
      </td>
      <td className="mono small">{r.type}</td>
      <td className="mono small mail-dns-name">
        {r.name}
        {!r.required && <span className="muted"> (optional)</span>}
      </td>
      <td className="mono small mail-dns-value">
        {r.type === "MX" ? `${r.priority} ` : ""}
        {r.value}
        <button type="button" className="mail-copy" aria-label="Copy the value" onClick={() => copy(r.value)}>
          <ClipboardIcon size={14} />
        </button>
        {check && check.status !== "ok" && check.found.length > 0 && <div className="muted">found: {check.found.join(" | ")}</div>}
        {check?.detail && <div className="muted">{check.detail}</div>}
        {r.note && <div className="muted mail-note">{r.note}</div>}
      </td>
    </tr>
  );
}

function DomainDetail({ d, o, onDeleted }: { d: MailDomain; o: MailOverview; onDeleted: () => void }) {
  const qc = useQueryClient();
  const { follow, running } = useMailJob();
  const [deleting, setDeleting] = useState(false);
  const dns = useQuery({ queryKey: ["mail", "dns", d.name], queryFn: () => unwrap(api.GET("/mail/domains/{name}/dns", { params: { path: { name: d.name } } })) });
  const check = useMutation({
    mutationFn: () => unwrap(api.POST("/mail/domains/{name}/check", { params: { path: { name: d.name } } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["mail", "dns", d.name] }),
  });
  const update = useMutation({
    mutationFn: (body: { dmarcPolicy?: MailDomain["dmarcPolicy"]; mtaSts?: MailDomain["mtaSts"]; cloudflare?: boolean; rotateDkim?: boolean }) =>
      unwrap(api.PATCH("/mail/domains/{name}", { params: { path: { name: d.name } }, body })),
    onSuccess: (r) => {
      follow(r);
      void qc.invalidateQueries({ queryKey: ["mail"] });
    },
    onError: (e) => toast("error", "Couldn't change the domain", errorMessage(e)),
  });
  const publish = useMutation({ mutationFn: () => unwrap(api.POST("/mail/domains/{name}/publish", { params: { path: { name: d.name } } })), onSuccess: follow });
  const ses = useMutation({ mutationFn: () => unwrap(api.POST("/mail/domains/{name}/ses", { params: { path: { name: d.name } } })), onSuccess: follow });
  const last = check.data ?? dns.data?.lastCheck ?? d.lastCheck;
  const byKey = new Map((last?.checks ?? []).map((c) => [recordKey(c), c]));
  return (
    <Card
      title={d.name}
      actions={
        <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
          <Button size="sm" onClick={() => check.mutate()} busy={check.isPending}>
            Check DNS
          </Button>
          {o.cloudflareTokenSet && (
            <Button size="sm" onClick={() => publish.mutate()} busy={publish.isPending || running} disabled={!d.dkimPublicKey}>
              Publish in Cloudflare
            </Button>
          )}
          {o.settings.sesAccessKeyId && o.sesSecretSet && (
            <Button size="sm" onClick={() => ses.mutate()} busy={ses.isPending || running}>
              Verify with SES
            </Button>
          )}
          <Button size="sm" variant="danger" onClick={() => setDeleting(true)}>
            Remove…
          </Button>
        </div>
      }
    >
      <div className="stack">
        {last && (
          <Alert tone={last.summary.ready ? "good" : "warn"} title={last.summary.ready ? "Every required record is right" : `${last.summary.problems} required record(s) missing or wrong`}>
            Checked {relativeTime(last.at)} against public DNS{last.summary.optional > 0 ? `; ${last.summary.optional} optional record(s) not set` : ""}.
          </Alert>
        )}
        {check.error != null && <Alert tone="bad" title={errorMessage(check.error)} />}
        {publish.error != null && <Alert tone="bad" title={errorMessage(publish.error)} />}
        {ses.error != null && <Alert tone="bad" title={errorMessage(ses.error)} />}
        {Object.values(dns.data?.missing ?? {}).map((m) => (
          <Alert key={m} tone="info" title={m} />
        ))}
        <div className="grid-2" style={{ gap: 12 }}>
          <Field label="DMARC policy" hint="What receivers do with mail that pretends to be from this domain">
            {(id) => (
              <Select id={id} value={d.dmarcPolicy} onChange={(e) => update.mutate({ dmarcPolicy: e.target.value as MailDomain["dmarcPolicy"] })}>
                <option value="none">Report only (none)</option>
                <option value="quarantine">Junk it (quarantine)</option>
                <option value="reject">Refuse it (reject)</option>
              </Select>
            )}
          </Field>
          <Field label="MTA-STS" hint="Senders insist on TLS; needs the policy on https://mta-sts.<domain>">
            {(id) => (
              <Select id={id} value={d.mtaSts} onChange={(e) => update.mutate({ mtaSts: e.target.value as MailDomain["mtaSts"] })}>
                <option value="off">Off</option>
                <option value="testing">Testing (report only)</option>
                <option value="enforce">Enforce</option>
              </Select>
            )}
          </Field>
        </div>
        {o.cloudflareTokenSet && <Toggle label="Keep this domain's records in Cloudflare" checked={d.cloudflare} onChange={(v) => update.mutate({ cloudflare: v })} />}
        {dns.isPending ? (
          <Loading />
        ) : dns.isError ? (
          <ErrorBox error={dns.error} onRetry={() => dns.refetch()} />
        ) : (
          <table className="table mail-dns">
            <thead>
              <tr>
                <th>State</th>
                <th>Type</th>
                <th>Name</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              {dns.data.records.map((r) => (
                <RecordRow key={recordKey(r)} r={r} check={byKey.get(recordKey(r))} />
              ))}
            </tbody>
          </table>
        )}
        {dns.data?.mtaStsPolicy && (
          <Field label="MTA-STS policy (serve at https://mta-sts.<domain>/.well-known/mta-sts.txt)">{(id) => <textarea id={id} className="input mono" rows={4} readOnly value={dns.data.mtaStsPolicy} />}</Field>
        )}
        <div className="row" style={{ gap: 8 }}>
          <span className="small muted">
            DKIM selector <span className="mono">{d.selector}</span>.
          </span>
          <Button size="sm" onClick={() => update.mutate({ rotateDkim: true })}>
            New DKIM key
          </Button>
        </div>
      </div>
      {deleting && (
        <ConfirmDialog
          title={`Remove ${d.name}?`}
          confirmLabel="Remove the domain"
          typeToConfirm={d.name}
          onClose={() => setDeleting(false)}
          onConfirm={async () => {
            const r = await unwrap(api.DELETE("/mail/domains/{name}", { params: { path: { name: d.name } }, body: { confirm: d.name } }));
            follow(r);
            onDeleted();
          }}
        >
          Mail for this domain will be refused. Mailboxes, aliases and group addresses must not use it. Its DNS records stay where they are.
        </ConfirmDialog>
      )}
    </Card>
  );
}

export function MailDomains({ o }: { o: MailOverview }) {
  const qc = useQueryClient();
  const { follow } = useMailJob();
  const [name, setName] = useState("");
  const [selected, setSelected] = useState<string | null>(o.domains[0]?.name ?? null);
  const problem = name ? domainProblem(name) : null;
  const add = useMutation({
    mutationFn: () => unwrap(api.POST("/mail/domains", { body: { name, cloudflare: o.cloudflareTokenSet } })),
    onSuccess: (r) => {
      follow(r);
      setSelected(name.toLowerCase());
      setName("");
      void qc.invalidateQueries({ queryKey: ["mail"] });
    },
  });
  const d = o.domains.find((x) => x.name === selected);
  return (
    <>
      <Card title="Mail domains">
        <div className="stack">
          {o.domains.length === 0 ? (
            <EmptyState title="No mail domains yet">Add the domain your family's addresses end with, like example.net.</EmptyState>
          ) : (
            <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
              {o.domains.map((x) => (
                <Button key={x.name} size="sm" variant={x.name === selected ? "primary" : "secondary"} onClick={() => setSelected(x.name)}>
                  {x.name}
                  {x.lastCheck && <Badge tone={x.lastCheck.summary.ready ? "good" : "warn"}>{x.lastCheck.summary.ready ? "DNS ok" : "DNS"}</Badge>}
                </Button>
              ))}
            </div>
          )}
          <div className="row" style={{ gap: 8, alignItems: "flex-end" }}>
            <Field label="Add a domain" error={problem}>
              {(id) => <TextInput id={id} className="input mono" value={name} placeholder="example.net" onChange={(e) => setName(e.target.value.trim().toLowerCase())} />}
            </Field>
            <Button onClick={() => add.mutate()} disabled={!name || !!problem} busy={add.isPending}>
              Add
            </Button>
          </div>
          {add.error != null && <Alert tone="bad" title={errorMessage(add.error)} />}
        </div>
      </Card>
      {d && <DomainDetail key={d.name} d={d} o={o} onDeleted={() => setSelected(null)} />}
    </>
  );
}
