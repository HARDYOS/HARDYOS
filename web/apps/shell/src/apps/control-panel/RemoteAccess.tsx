import type { RemoteCheck, RemoteStatus } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { dateTime } from "../../format";
import { GlobeIcon } from "../../icons";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Field, Loading, PageHeader, Select, TextInput, Toggle } from "../../ui";
import { ConfirmDialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { PublishEditor } from "./RemoteAccessPublish";
import { STEP_LABEL, STEP_TONE, clientState, managementHost, publishSummary, serviceStatus, validDomain, validLabel, validSetupKey } from "./remoteAccessRules";
import { jobDone } from "./shareServices";

export function useRemote() {
  return useQuery({ queryKey: ["remote"], queryFn: () => unwrap(api.GET("/remote")), refetchInterval: 15000 });
}

/** Control Panel > Remote Access: NetBird on this server, and publishing the desktop and apps. */
export function RemoteAccess() {
  const remote = useRemote();
  if (remote.isPending) return <Loading />;
  if (remote.isError) return <ErrorBox error={remote.error} onRetry={() => remote.refetch()} />;
  const st = remote.data;
  const state = clientState(st.client);
  return (
    <>
      <PageHeader
        title="Remote Access"
        subtitle="Reach this server and its apps from anywhere through NetBird: its VPN for your devices, and its reverse proxy for addresses like https://jellyfin.home.example.net."
        badge={<Badge tone={state.tone}>{state.label}</Badge>}
      />
      <NetBirdCard st={st} />
      {st.client.joined && st.available && st.settings && <PublishingCard st={st} />}
      {st.client.joined && st.available && st.settings?.baseDomain && <CheckCard />}
      {st.client.joined && st.available && st.settings?.enabled && <PublishedCard st={st} />}
    </>
  );
}

// ---- the NetBird client ---------------------------------------------------

function NetBirdCard({ st }: { st: RemoteStatus }) {
  const qc = useQueryClient();
  const c = st.client;
  const [mgmt, setMgmt] = useState(st.defaultManagementUrl);
  const [key, setKey] = useState("");
  const [name, setName] = useState("nas");
  const [confirmLeave, setConfirmLeave] = useState(false);
  const join = useMutation({
    mutationFn: () => jobDone(unwrap(api.POST("/remote/join", { body: { managementUrl: mgmt.trim(), setupKey: key.trim(), hostname: name.trim() } }))),
    onSuccess: () => {
      setKey("");
      toast("success", "Joined the NetBird network");
      void qc.invalidateQueries({ queryKey: ["remote"] });
    },
  });
  const leave = useMutation({
    mutationFn: (confirm: string) => jobDone(unwrap(api.POST("/remote/leave", { body: { confirm } }))),
    onSuccess: () => {
      setConfirmLeave(false);
      toast("success", "Left the NetBird network");
      void qc.invalidateQueries({ queryKey: ["remote"] });
    },
  });

  if (!c.installed) {
    return (
      <Card title="NetBird">
        <EmptyState icon={<GlobeIcon size={30} />} title="NetBird isn't installed">
          This HardyOS build doesn't include the NetBird client. Install the latest update to get it.
        </EmptyState>
      </Card>
    );
  }

  if (!c.joined) {
    const keyOk = validSetupKey(key);
    return (
      <Card title="Join a NetBird network">
        <div className="stack">
          <span className="small muted">
            In NetBird's dashboard, make a setup key (Setup Keys › Create Setup Key; one-off is fine) and paste it here. The key is used once to sign this
            server in and isn't kept.
          </span>
          <Field label="NetBird server">{(id) => <TextInput id={id} value={mgmt} onChange={(e) => setMgmt(e.target.value)} />}</Field>
          <Field label="Setup key" error={key !== "" && !keyOk ? "That doesn't look like a setup key" : null}>
            {(id) => <TextInput id={id} type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} />}
          </Field>
          <Field label="This server's name in NetBird" error={name !== "" && !validLabel(name) ? "Letters, digits and dashes" : null}>
            {(id) => <TextInput id={id} value={name} onChange={(e) => setName(e.target.value.toLowerCase())} />}
          </Field>
          {join.isError && <Alert tone="bad">{errorMessage(join.error)}</Alert>}
          <div className="row">
            <Button variant="primary" busy={join.isPending} disabled={!keyOk || !validLabel(name) || !mgmt.startsWith("https://")} onClick={() => join.mutate()}>
              Join
            </Button>
          </div>
        </div>
      </Card>
    );
  }

  const host = managementHost(c.managementUrl ?? "");
  return (
    <Card
      title="NetBird"
      actions={
        <Button size="sm" variant="danger" onClick={() => setConfirmLeave(true)}>
          Leave
        </Button>
      }
    >
      <div className="stack">
        <dl className="kv">
          <dt>Server</dt>
          <dd className="mono">{c.managementUrl}</dd>
          <dt>This server</dt>
          <dd>
            <span className="mono">{c.ip || "—"}</span> {c.fqdn && <span className="mono muted">({c.fqdn})</span>}
          </dd>
          <dt>Peers</dt>
          <dd>
            <span className="mono">{c.peersConnected}</span> of <span className="mono">{c.peersTotal}</span> connected
          </dd>
          <dt>Interface</dt>
          <dd className="mono">{c.interface}</dd>
        </dl>
        {c.problem && <Alert tone="warn">{c.problem}</Alert>}
      </div>
      {confirmLeave && (
        <ConfirmDialog
          title="Leave the NetBird network?"
          confirmLabel="Leave"
          typeToConfirm={host}
          onConfirm={() => leave.mutateAsync(host)}
          onClose={() => setConfirmLeave(false)}
        >
          HardyOS removes its published services from NetBird, signs this server out and turns NetBird off. Devices can't reach it over NetBird any
          more.
        </ConfirmDialog>
      )}
    </Card>
  );
}

// ---- publishing settings -------------------------------------------------

function PublishingCard({ st }: { st: RemoteStatus }) {
  const qc = useQueryClient();
  const s = st.settings!;
  const [enabled, setEnabled] = useState(s.enabled);
  const [base, setBase] = useState(s.baseDomain);
  const [apiUrl, setApiUrl] = useState(s.apiUrl);
  const [desktop, setDesktop] = useState(s.desktopName);
  const [mode, setMode] = useState(s.defaultMode);
  const [shareLinks, setShareLinks] = useState(s.publicShareLinks);
  const [token, setToken] = useState("");
  const save = useMutation({
    mutationFn: (opts: { forget?: boolean }) =>
      jobDone(
        unwrap(
          api.PUT("/remote/publishing", {
            body: {
              enabled,
              baseDomain: base.trim().toLowerCase(),
              apiUrl: apiUrl.trim(),
              cluster: s.cluster,
              desktopName: desktop.trim(),
              defaultMode: mode,
              publicShareLinks: shareLinks,
              token: opts.forget ? "" : token.trim() || undefined,
            },
          }),
        ),
      ),
    onSuccess: () => {
      setToken("");
      toast("success", "Saved the publishing settings");
      void qc.invalidateQueries({ queryKey: ["remote"] });
      void qc.invalidateQueries({ queryKey: ["remote-check"] });
    },
  });
  const baseOk = base === "" || validDomain(base);
  const needsToken = enabled && !s.hasToken && token.trim() === "";
  return (
    <Card title="Publishing">
      <div className="stack">
        <span className="small muted">
          HardyOS adds, changes and removes its own services in NetBird's reverse proxy (named <span className="mono">hardyos-{s.instance || "…"}-…</span>
          ) with an access token, and never touches the others.
        </span>
        <Toggle
          label="Publish the desktop and apps"
          description="Each app with a web page gets https://<app>.<base domain>; off removes HardyOS's services from NetBird."
          checked={enabled}
          onChange={setEnabled}
        />
        <Toggle
          label="Public share links"
          description={`Share links open at https://files.${base || "<base domain>"}/s/… for people without NetBird (that address opens share links and nothing else). It is published while a link is active; on keeps it published.`}
          checked={shareLinks}
          onChange={setShareLinks}
        />
        <Field label="Base domain" hint="A custom domain in NetBird (Reverse Proxy › Custom Domains), like home.hardynetworks.net." error={!baseOk ? "A domain like home.example.net" : null}>
          {(id) => <TextInput id={id} value={base} placeholder="home.example.net" onChange={(e) => setBase(e.target.value)} />}
        </Field>
        <Field label="Desktop's name" hint={base ? `The desktop at https://${desktop || "nas"}.${base}` : undefined} error={!validLabel(desktop) ? "Letters, digits and dashes" : null}>
          {(id) => <TextInput id={id} value={desktop} onChange={(e) => setDesktop(e.target.value.toLowerCase())} />}
        </Field>
        <Field label="New apps are">
          {(id) => (
            <Select id={id} value={mode} onChange={(e) => setMode(e.target.value as typeof mode)}>
              <option value="netbird">NetBird devices only</option>
              <option value="public">Public, with HardyOS sign-in in front</option>
              <option value="off">Not published</option>
            </Select>
          )}
        </Field>
        <Field
          label="NetBird access token"
          hint={
            s.tokenUnreadable
              ? "The saved token can't be read on this server (restored from another one): paste it again."
              : s.hasToken
                ? "Saved. Paste a new one to replace it."
                : "In NetBird: Team › Service Users › Create (role Network Admin), then Create Token."
          }
        >
          {(id) => <TextInput id={id} type="password" autoComplete="off" value={token} placeholder={s.hasToken ? "••••••••" : ""} onChange={(e) => setToken(e.target.value)} />}
        </Field>
        <Field label="NetBird API address" hint="Empty: the NetBird server above.">
          {(id) => <TextInput id={id} value={apiUrl} placeholder={st.client.managementUrl} onChange={(e) => setApiUrl(e.target.value)} />}
        </Field>
        {save.isError && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
        <div className="row">
          <Button variant="primary" busy={save.isPending} disabled={!baseOk || !validLabel(desktop) || needsToken || (enabled && !base)} onClick={() => save.mutate({})}>
            Save
          </Button>
          {s.hasToken && (
            <Button variant="ghost" disabled={save.isPending} onClick={() => save.mutate({ forget: true })}>
              Remove the token
            </Button>
          )}
        </div>
      </div>
    </Card>
  );
}

// ---- setup check ---------------------------------------------------------

function CheckCard() {
  const qc = useQueryClient();
  const check = useQuery({ queryKey: ["remote-check"], queryFn: () => unwrap(api.GET("/remote/check")), staleTime: 30000 });
  const [cluster, setCluster] = useState("");
  const domain = useMutation({
    mutationFn: (action: "add" | "verify") => jobDone(unwrap(api.POST("/remote/domain", { body: { action, cluster: cluster || undefined } }))),
    onSuccess: (_, action) => {
      toast("success", action === "add" ? "Added the domain to NetBird" : "NetBird is checking the domain");
      void qc.invalidateQueries({ queryKey: ["remote-check"] });
    },
  });
  return (
    <Card
      title="Setup check"
      actions={
        <Button size="sm" variant="ghost" busy={check.isFetching} onClick={() => void check.refetch()}>
          Check again
        </Button>
      }
    >
      {check.isPending ? (
        <Loading label="Asking NetBird…" />
      ) : check.isError ? (
        <ErrorBox error={check.error} onRetry={() => check.refetch()} />
      ) : (
        <CheckView c={check.data} cluster={cluster} setCluster={setCluster} busy={domain.isPending} onDomain={(a) => domain.mutate(a)} error={domain.isError ? errorMessage(domain.error) : null} />
      )}
    </Card>
  );
}

export function CheckView({
  c,
  cluster,
  setCluster,
  busy,
  onDomain,
  error,
}: {
  c: RemoteCheck;
  cluster: string;
  setCluster: (v: string) => void;
  busy: boolean;
  onDomain: (a: "add" | "verify") => void;
  error: string | null;
}) {
  const domainStep = c.steps.find((s) => s.id === "domain");
  return (
    <div className="stack">
      <ul className="stack" style={{ listStyle: "none", padding: 0, margin: 0, gap: 8 }} aria-label="Setup check">
        {c.steps.map((s) => (
          <li key={s.id} className="row" style={{ alignItems: "flex-start", gap: 10 }}>
            <Badge tone={STEP_TONE[s.state]}>{STEP_LABEL[s.state]}</Badge>
            <span className="stack" style={{ gap: 2 }}>
              <strong className="small">{s.title}</strong>
              {s.detail && <span className="small muted">{s.detail}</span>}
            </span>
          </li>
        ))}
      </ul>
      {c.record && (
        <div className="stack" style={{ gap: 4 }}>
          <strong className="small">DNS record (Cloudflare: DNS › Records › Add record)</strong>
          <div className="table-wrap">
            <table className="table" aria-label="DNS record to add">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Name</th>
                  <th>Target</th>
                  <th>Proxy status</th>
                  <th>TTL</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="mono">{c.record.type}</td>
                  <td className="mono">{c.record.name}</td>
                  <td className="mono">{c.record.target}</td>
                  <td>{c.record.proxy} (grey cloud)</td>
                  <td>{c.record.ttl}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}
      {domainStep?.state === "bad" && (
        <div className="row" style={{ gap: 8 }}>
          {c.clusters.length > 1 && (
            <Select aria-label="Proxy cluster" value={cluster} onChange={(e) => setCluster(e.target.value)}>
              <option value="">Choose the proxy cluster…</option>
              {c.clusters.map((cl) => (
                <option key={cl.id} value={cl.address}>
                  {cl.address}
                </option>
              ))}
            </Select>
          )}
          <Button busy={busy} disabled={c.clusters.length > 1 && !cluster} onClick={() => onDomain("add")}>
            Add to NetBird
          </Button>
        </div>
      )}
      {domainStep?.state === "warn" && (
        <div className="row">
          <Button busy={busy} onClick={() => onDomain("verify")}>
            Verify
          </Button>
        </div>
      )}
      {error && <Alert tone="bad">{error}</Alert>}
    </div>
  );
}

// ---- what's published ----------------------------------------------------

function PublishedCard({ st }: { st: RemoteStatus }) {
  const qc = useQueryClient();
  const check = useQuery({ queryKey: ["remote-check"], queryFn: () => unwrap(api.GET("/remote/check")), staleTime: 30000 });
  const [editing, setEditing] = useState<string | null>(null);
  const sync = useMutation({
    mutationFn: () => jobDone(unwrap(api.POST("/remote/sync"))),
    onSuccess: () => {
      toast("success", "NetBird's services are up to date");
      void qc.invalidateQueries({ queryKey: ["remote"] });
    },
  });
  const last = st.lastSync;
  return (
    <Card
      title="Published"
      actions={
        <Button size="sm" variant="ghost" busy={sync.isPending} onClick={() => sync.mutate()}>
          Update NetBird now
        </Button>
      }
    >
      <div className="stack">
        <span className="small muted">
          HardyOS checks NetBird every 10 minutes and puts back anything changed on its services; IP and country rules you set in NetBird's dashboard
          stay. {last && <>Last checked {dateTime(last.at)}.</>}
        </span>
        {last?.problem && <Alert tone="warn">{last.problem}</Alert>}
        {st.gateway.problem && <Alert tone="bad">{st.gateway.problem}</Alert>}
        {sync.isError && <Alert tone="bad">{errorMessage(sync.error)}</Alert>}
        <ul className="stack" style={{ listStyle: "none", padding: 0, margin: 0 }} aria-label="Published">
          {st.items.map((it) => {
            const s = serviceStatus(it.status);
            return (
              <li key={it.key} className="card stack" style={{ gap: 6 }}>
                <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
                  <strong>{it.name}</strong>
                  {it.url && it.config.mode !== "off" && <span className="mono small">{it.url}</span>}
                  <Badge tone="neutral">{publishSummary(it.config)}</Badge>
                  {it.published && <Badge tone={s.tone}>{s.label}</Badge>}
                  <span className="app-card__spacer" />
                  {it.key !== "sso" && it.key !== "files" && (
                    <Button size="sm" variant="ghost" onClick={() => setEditing(editing === it.key ? null : it.key)} aria-label={`Change ${it.name}`}>
                      {editing === it.key ? "Close" : "Change"}
                    </Button>
                  )}
                </div>
                {it.error && editing !== it.key && <span className="small" style={{ color: "var(--hos-bad, #f87171)" }}>{it.error}</span>}
                {editing === it.key && (
                  <PublishEditor
                    item={it}
                    groups={check.data?.groups ?? []}
                    supportsPrivate={check.data ? check.data.supportsPrivate : undefined}
                    onSaved={() => {
                      setEditing(null);
                      void qc.invalidateQueries({ queryKey: ["remote"] });
                    }}
                  />
                )}
              </li>
            );
          })}
        </ul>
      </div>
    </Card>
  );
}
