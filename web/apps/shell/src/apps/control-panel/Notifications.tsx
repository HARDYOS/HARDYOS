import type { AlertChannel, AlertChannelConfig, AlertChannelInput, AlertRoute, AlertSecretsInput, AlertSettings } from "@hardy/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { dateTime, relativeTime } from "../../format";
import { useAlertSettings, useCategories, useChannels, useDeliveries, useRoutes } from "../../hooks/monitoring";
import { EditIcon, PlusIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, Card, ErrorBox, Field, IconButton, Loading, PageHeader, Select, TextInput, Toggle } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";

type ChannelType = AlertChannel["type"];

const TYPES: { type: ChannelType; label: string; hint: string; color: string; mark: string }[] = [
  { type: "discord", label: "Discord", hint: "A channel webhook", color: "#5865F2", mark: "D" },
  { type: "slack", label: "Slack", hint: "An incoming webhook", color: "#4A154B", mark: "S" },
  { type: "teams", label: "Microsoft Teams", hint: "A Workflows webhook", color: "#4B53BC", mark: "T" },
  { type: "smtp", label: "Email (SMTP)", hint: "Gmail, Google Workspace, SES SMTP or any mail server", color: "#0E9F75", mark: "@" },
  { type: "ses", label: "Amazon SES", hint: "Email through the SES API", color: "#D97706", mark: "A" },
  { type: "webhook", label: "Other webhook", hint: "Any public https endpoint (JSON)", color: "#475569", mark: "{}" },
];
const DESKTOP = { label: "Desktop", color: "#0B7285", mark: "◉" };

const typeInfo = (t: ChannelType) => (t === "desktop" ? { type: t, hint: "", ...DESKTOP } : TYPES.find((x) => x.type === t)!);

/** Email presets for the SMTP channel. */
const PRESETS: { id: string; label: string; cfg: Partial<AlertChannelConfig>; note: string }[] = [
  {
    id: "gmail",
    label: "Gmail / Google Workspace",
    cfg: { host: "smtp.gmail.com", port: 587, security: "starttls" },
    note: "Sign in with the full address and an app password (Google Account › Security › 2-Step Verification › App passwords), not your normal password.",
  },
  {
    id: "ses-smtp",
    label: "Amazon SES (SMTP)",
    cfg: { host: "email-smtp.us-east-1.amazonaws.com", port: 587, security: "starttls" },
    note: "Use the SMTP credentials SES creates (SES console › SMTP settings), and your region in the host name.",
  },
  { id: "other", label: "Another mail server", cfg: { port: 587, security: "starttls" }, note: "Including the family mail server, once it's set up." },
];

function channelSubtitle(c: AlertChannel): string {
  switch (c.type) {
    case "desktop":
      return "The bell in the menu bar, for administrators";
    case "smtp":
      return `${(c.config.to ?? []).join(", ")} via ${c.config.host}`;
    case "ses":
      return `${(c.config.to ?? []).join(", ")} via SES ${c.config.region}`;
    default:
      return c.config.urlHost ?? "";
  }
}

const SEVERITY_LEVELS = [
  { v: "off", label: "Off" },
  { v: "info", label: "Everything" },
  { v: "warning", label: "Warnings +" },
  { v: "critical", label: "Critical only" },
];

export function Notifications() {
  return (
    <>
      <PageHeader title="Notifications" subtitle="Where alerts go: the desktop, chat apps and email. Each alert is sent once when something goes wrong and once when it's fixed." />
      <Channels />
      <Routing />
      <SettingsCard />
      <Deliveries />
    </>
  );
}

function Channels() {
  const q = useChannels();
  const qc = useQueryClient();
  const [editing, setEditing] = useState<AlertChannel | "new" | null>(null);
  const [removing, setRemoving] = useState<AlertChannel | null>(null);
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["alert-channels"] });
    void qc.invalidateQueries({ queryKey: ["alert-routes"] });
  };
  const test = useMutation({
    mutationFn: (id: number) => unwrap(api.POST("/alerts/channels/{id}/test", { params: { path: { id } } })),
    onSuccess: (r) => {
      refresh();
      if (r.ok) toast("success", "Test alert sent", "Check that it arrived.");
      else toast("error", "The test alert didn't go out", r.error);
    },
    onError: (e) => toast("error", "Couldn't send a test", errorMessage(e)),
  });
  const toggle = useMutation({
    mutationFn: (c: AlertChannel) => unwrap(api.PATCH("/alerts/channels/{id}", { params: { path: { id: c.id } }, body: { type: c.type, name: c.name, enabled: !c.enabled, config: c.config } })),
    onSuccess: refresh,
    onError: (e) => toast("error", "Couldn't change the channel", errorMessage(e)),
  });
  const remove = useMutation({
    mutationFn: (id: number) => unwrap(api.DELETE("/alerts/channels/{id}", { params: { path: { id } } })),
    onSuccess: refresh,
  });

  return (
    <Card
      title="Channels"
      actions={
        <Button size="sm" variant="primary" onClick={() => setEditing("new")}>
          <PlusIcon size={14} /> Add channel
        </Button>
      }
    >
      {q.isPending ? (
        <Loading />
      ) : q.isError ? (
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      ) : (
        <div className="channel-grid">
          {q.data.map((c) => {
            const t = typeInfo(c.type);
            return (
              <div key={c.id} className="channel">
                <div className="channel__head">
                  <span className="channel__icon" style={{ background: t.color }} aria-hidden="true">
                    {t.mark}
                  </span>
                  <div className="channel__name">
                    <strong>{c.name}</strong>
                    <span title={channelSubtitle(c)}>{channelSubtitle(c)}</span>
                  </div>
                </div>
                <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                  {!c.enabled ? (
                    <Badge tone="neutral">Off</Badge>
                  ) : c.lastOk == null ? (
                    <Badge tone="accent">Not used yet</Badge>
                  ) : c.lastOk ? (
                    <Badge tone="good">Delivered {c.lastAt ? relativeTime(c.lastAt) : ""}</Badge>
                  ) : (
                    <Badge tone="bad">Last delivery failed</Badge>
                  )}
                </div>
                {c.lastError && (
                  <span className="small" style={{ color: "var(--hos-bad-text)" }}>
                    {c.lastError}
                  </span>
                )}
                <div className="channel__actions">
                  <Button size="sm" onClick={() => test.mutate(c.id)} busy={test.isPending && test.variables === c.id}>
                    Test
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => toggle.mutate(c)}>
                    {c.enabled ? "Turn off" : "Turn on"}
                  </Button>
                  <span style={{ flex: 1 }} />
                  {c.type !== "desktop" && (
                    <>
                      <IconButton label={`Edit ${c.name}`} onClick={() => setEditing(c)}>
                        <EditIcon size={15} />
                      </IconButton>
                      <IconButton label={`Remove ${c.name}`} onClick={() => setRemoving(c)}>
                        <TrashIcon size={15} />
                      </IconButton>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
      {editing && <ChannelDialog channel={editing === "new" ? null : editing} onClose={() => setEditing(null)} onSaved={refresh} />}
      {removing && (
        <ConfirmDialog
          title={`Remove ${removing.name}?`}
          confirmLabel="Remove"
          onConfirm={() => remove.mutateAsync(removing.id)}
          onClose={() => setRemoving(null)}
        >
          Alerts stop going there. Its saved secrets are deleted.
        </ConfirmDialog>
      )}
    </Card>
  );
}

function ChannelDialog({ channel, onClose, onSaved }: { channel: AlertChannel | null; onClose: () => void; onSaved: () => void }) {
  const [type, setType] = useState<ChannelType>(channel?.type ?? "discord");
  const [name, setName] = useState(channel?.name ?? "");
  const [cfg, setCfg] = useState<AlertChannelConfig>(channel?.config ?? {});
  const [to, setTo] = useState((channel?.config.to ?? []).join(", "));
  const [url, setUrl] = useState("");
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [preset, setPreset] = useState(channel ? "other" : "gmail");
  const set = (p: Partial<AlertChannelConfig>) => setCfg((c) => ({ ...c, ...p }));
  const isSet = (k: string) => !!channel?.secretsSet?.[k];
  const webhook = type === "discord" || type === "slack" || type === "teams" || type === "webhook";
  const t = typeInfo(type);

  useEffect(() => {
    if (!channel && type === "smtp") {
      const p = PRESETS.find((x) => x.id === preset);
      if (p) setCfg((c) => ({ ...c, ...p.cfg }));
    }
  }, [preset, type, channel]);

  const save = useMutation({
    mutationFn: () => {
      const secrets: AlertSecretsInput = {};
      if (url) secrets.url = url;
      if (password) secrets.password = password;
      if (secretKey) secrets.secretAccessKey = secretKey;
      const body: AlertChannelInput = {
        type,
        name: name.trim() || t.label,
        config: { ...cfg, to: to.split(/[\s,;]+/).filter(Boolean) },
        secrets,
      };
      return channel
        ? unwrap(api.PATCH("/alerts/channels/{id}", { params: { path: { id: channel.id } }, body }))
        : unwrap(api.POST("/alerts/channels", { body }));
    },
    onSuccess: (c) => {
      onSaved();
      toast("success", channel ? "Channel saved" : "Channel added", channel ? undefined : "Send a test to check it works. It gets warnings and critical alerts until you change routing.");
      onClose();
      void c;
    },
  });

  return (
    <Dialog
      title={channel ? `Edit ${channel.name}` : "Add a channel"}
      onClose={onClose}
      width={560}
      onSubmit={() => save.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={save.isPending}>
            {channel ? "Save" : "Add channel"}
          </Button>
        </>
      }
    >
      <div className="stack">
        {!channel && (
          <div className="type-grid" role="group" aria-label="Channel type">
            {TYPES.map((x) => (
              <button key={x.type} type="button" aria-pressed={type === x.type} onClick={() => setType(x.type)}>
                <strong>{x.label}</strong>
                <span>{x.hint}</span>
              </button>
            ))}
          </div>
        )}
        <Field label="Name" hint="How it appears in routing and the delivery log">
          {(id) => <TextInput id={id} value={name} placeholder={t.label} maxLength={64} onChange={(e) => setName(e.target.value)} />}
        </Field>

        {webhook && (
          <>
            <Field
              label="Webhook URL"
              hint={
                isSet("url")
                  ? `Saved (${channel?.config.urlHost}). Leave empty to keep it.`
                  : type === "discord"
                    ? "Discord: channel settings › Integrations › Webhooks › Copy Webhook URL"
                    : type === "slack"
                      ? "Slack: an app with Incoming Webhooks › Add New Webhook to Workspace"
                      : type === "teams"
                        ? 'Teams: the Workflows app › "Post to a channel when a webhook request is received"'
                        : "Gets a JSON object with kind, severity, title, body, link and time"
              }
            >
              {(id) => <TextInput id={id} type="password" autoComplete="off" value={url} placeholder={isSet("url") ? "••••••••" : "https://…"} onChange={(e) => setUrl(e.target.value)} />}
            </Field>
            {type === "webhook" && (
              <Toggle
                label="Allow any https host"
                description="Generic webhooks need this. Addresses on this server or your network are refused either way."
                checked={!!cfg.allowAnyHost}
                onChange={(v) => set({ allowAnyHost: v })}
              />
            )}
          </>
        )}

        {type === "smtp" && (
          <>
            {!channel && (
              <Field label="Mail service">
                {(id) => (
                  <Select id={id} value={preset} onChange={(e) => setPreset(e.target.value)}>
                    {PRESETS.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.label}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
            )}
            {!channel && <Alert tone="info">{PRESETS.find((p) => p.id === preset)?.note}</Alert>}
            <div className="grid-2" style={{ gap: 12 }}>
              <Field label="Mail server">{(id) => <TextInput id={id} value={cfg.host ?? ""} onChange={(e) => set({ host: e.target.value })} placeholder="smtp.example.com" />}</Field>
              <div className="row" style={{ gap: 12, alignItems: "flex-start" }}>
                <Field label="Port">{(id) => <TextInput id={id} className="input mono" inputMode="numeric" value={cfg.port ?? ""} onChange={(e) => set({ port: Number(e.target.value) || undefined })} />}</Field>
                <Field label="Encryption">
                  {(id) => (
                    <Select id={id} value={cfg.security ?? "starttls"} onChange={(e) => set({ security: e.target.value as AlertChannelConfig["security"] })}>
                      <option value="starttls">STARTTLS (587)</option>
                      <option value="tls">TLS (465)</option>
                      <option value="none">None (local server)</option>
                    </Select>
                  )}
                </Field>
              </div>
              <Field label="User name" hint="Usually the full email address">
                {(id) => <TextInput id={id} autoComplete="off" value={cfg.username ?? ""} onChange={(e) => set({ username: e.target.value })} />}
              </Field>
              <Field label="Password" hint={isSet("password") ? "Saved. Changing the server, port, encryption or user needs it again." : "For Gmail, an app password"}>
                {(id) => <TextInput id={id} type="password" autoComplete="new-password" value={password} placeholder={isSet("password") ? "••••••••" : ""} onChange={(e) => setPassword(e.target.value)} />}
              </Field>
            </div>
            <Toggle
              label="Allow another port"
              description="Mail servers use 25, 465, 587 or 2525. Turn this on only if yours really uses another."
              checked={!!cfg.allowAnyPort}
              onChange={(v) => set({ allowAnyPort: v })}
            />
          </>
        )}

        {type === "ses" && (
          <>
            <Alert tone="info">
              Create an IAM user allowed only <span className="mono">ses:SendEmail</span>, verify the sender address or domain in SES, and paste the user's access key here.
            </Alert>
            <div className="grid-2" style={{ gap: 12 }}>
              <Field label="Region">{(id) => <TextInput id={id} className="input mono" value={cfg.region ?? ""} placeholder="us-east-1" onChange={(e) => set({ region: e.target.value })} />}</Field>
              <Field label="Configuration set" hint="Optional">
                {(id) => <TextInput id={id} value={cfg.configurationSet ?? ""} onChange={(e) => set({ configurationSet: e.target.value })} />}
              </Field>
              <Field label="Access key ID">{(id) => <TextInput id={id} className="input mono" autoComplete="off" value={cfg.accessKeyId ?? ""} onChange={(e) => set({ accessKeyId: e.target.value })} />}</Field>
              <Field label="Secret access key" hint={isSet("secretAccessKey") ? "Saved. Leave empty to keep it." : undefined}>
                {(id) => <TextInput id={id} type="password" autoComplete="new-password" value={secretKey} placeholder={isSet("secretAccessKey") ? "••••••••" : ""} onChange={(e) => setSecretKey(e.target.value)} />}
              </Field>
            </div>
          </>
        )}

        {(type === "smtp" || type === "ses") && (
          <div className="grid-2" style={{ gap: 12 }}>
            <Field label="From" hint="An address the service lets you send from">
              {(id) => <TextInput id={id} type="email" value={cfg.from ?? ""} onChange={(e) => set({ from: e.target.value })} placeholder="nas@example.com" />}
            </Field>
            <Field label="To" hint="Separate several with commas">
              {(id) => <TextInput id={id} value={to} onChange={(e) => setTo(e.target.value)} placeholder="you@example.com" />}
            </Field>
          </div>
        )}
        {save.error != null && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      </div>
    </Dialog>
  );
}

function Routing() {
  const cats = useCategories();
  const chans = useChannels();
  const routes = useRoutes();
  const qc = useQueryClient();
  const [draft, setDraft] = useState<Record<string, string> | null>(null);
  const key = (cat: string, ch: number) => `${cat}\u0000${ch}`;
  const current = useMemo(() => {
    const m: Record<string, string> = {};
    for (const r of routes.data ?? []) m[key(r.category, r.channelId)] = r.minSeverity;
    return m;
  }, [routes.data]);
  const value = draft ?? current;
  const save = useMutation({
    mutationFn: () => {
      const list: AlertRoute[] = [];
      for (const [k, v] of Object.entries(value)) {
        if (!v || (v === "off" && k.startsWith("*\u0000"))) continue;
        const [category, ch] = k.split("\u0000");
        list.push({ category: category!, channelId: Number(ch), minSeverity: v as AlertRoute["minSeverity"] });
      }
      return unwrap(api.PUT("/alerts/routes", { body: { routes: list } }));
    },
    onSuccess: (r) => {
      qc.setQueryData(["alert-routes"], r);
      setDraft(null);
      toast("success", "Routing saved");
    },
  });
  if (cats.isPending || chans.isPending || routes.isPending) return <Card title="Routing"><Loading /></Card>;
  if (cats.isError || chans.isError || routes.isError) return <ErrorBox error={cats.error ?? chans.error ?? routes.error} />;

  return (
    <Card
      title="Routing"
      actions={
        <Button size="sm" variant="primary" disabled={!draft} busy={save.isPending} onClick={() => save.mutate()}>
          Save routing
        </Button>
      }
    >
      <p className="small muted" style={{ marginTop: 0 }}>
        For each kind of alert, how serious it must be to reach each channel. "Everything else" covers kinds not listed; a row left on its default follows it.
      </p>
      <div className="table-wrap route-grid">
        <table className="table">
          <thead>
            <tr>
              <th>Alerts</th>
              {chans.data.map((c) => (
                <th key={c.id}>{c.name}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {cats.data.map((cat) => (
              <tr key={cat.id}>
                <td>
                  {cat.label}
                  <span className="cell-sub">{cat.description}</span>
                </td>
                {chans.data.map((c) => {
                  const k = key(cat.id, c.id);
                  const inherited = cat.id !== "*" && !(k in value);
                  return (
                    <td key={c.id}>
                      <Select
                        aria-label={`${cat.label} to ${c.name}`}
                        value={inherited ? "default" : (value[k] ?? "off")}
                        onChange={(e) => {
                          const next = { ...value };
                          if (e.target.value === "default") delete next[k];
                          else next[k] = e.target.value;
                          setDraft(next);
                        }}
                      >
                        {cat.id !== "*" && <option value="default">Default ({SEVERITY_LEVELS.find((l) => l.v === (value[key("*", c.id)] ?? "off"))?.label})</option>}
                        {SEVERITY_LEVELS.map((l) => (
                          <option key={l.v} value={l.v}>
                            {l.label}
                          </option>
                        ))}
                      </Select>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {save.error != null && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
    </Card>
  );
}

function SettingsCard() {
  const q = useAlertSettings();
  const qc = useQueryClient();
  const [draft, setDraft] = useState<AlertSettings | null>(null);
  const s = draft ?? q.data;
  const save = useMutation({
    mutationFn: (b: AlertSettings) => unwrap(api.PUT("/alerts/settings", { body: b })),
    onSuccess: (r) => {
      qc.setQueryData(["alert-settings"], r);
      setDraft(null);
      toast("success", "Alert settings saved");
    },
  });
  if (q.isPending) return <Card title="Quiet hours and limits"><Loading /></Card>;
  if (q.isError || !s) return <ErrorBox error={q.error} />;
  const edit = (p: Partial<AlertSettings>) => setDraft({ ...s, ...p });
  const quiet = (p: Partial<AlertSettings["quietHours"]>) => edit({ quietHours: { ...s.quietHours, ...p } });
  return (
    <Card
      title="Quiet hours and limits"
      actions={
        <Button size="sm" variant="primary" disabled={!draft} busy={save.isPending} onClick={() => save.mutate(s)}>
          Save
        </Button>
      }
    >
      <div className="stack">
        <Toggle
          label="Quiet hours"
          description="Hold alerts for chat and email at night and send one summary in the morning. The desktop always shows them."
          checked={s.quietHours.enabled}
          onChange={(v) => quiet({ enabled: v })}
        />
        {s.quietHours.enabled && (
          <div className="row" style={{ gap: 12, flexWrap: "wrap", alignItems: "flex-start" }}>
            <Field label="From">{(id) => <TextInput id={id} type="time" value={s.quietHours.start} onChange={(e) => quiet({ start: e.target.value })} />}</Field>
            <Field label="Until">{(id) => <TextInput id={id} type="time" value={s.quietHours.end} onChange={(e) => quiet({ end: e.target.value })} />}</Field>
            <Field label="Still send at once">
              {(id) => (
                <Select id={id} value={s.quietHours.allow} onChange={(e) => quiet({ allow: e.target.value as "warning" | "critical" })}>
                  <option value="critical">Critical alerts</option>
                  <option value="warning">Warnings and critical alerts</option>
                </Select>
              )}
            </Field>
          </div>
        )}
        <div className="row" style={{ gap: 12, flexWrap: "wrap", alignItems: "flex-start" }}>
          <Field label="Ignore repeats for" hint="Minutes; the same alert again is dropped">
            {(id) => <TextInput id={id} className="input mono" inputMode="numeric" value={s.dedupMinutes} onChange={(e) => edit({ dedupMinutes: Number(e.target.value) || 0 })} />}
          </Field>
          <Field label="At most per hour" hint="Per alert and channel; critical ones twice as many">
            {(id) => <TextInput id={id} className="input mono" inputMode="numeric" value={s.maxPerHour} onChange={(e) => edit({ maxPerHour: Number(e.target.value) || 1 })} />}
          </Field>
          <Field label="Server address for links" hint="Messages link here, e.g. https://nas.example.com">
            {(id) => <TextInput id={id} value={s.serverUrl} placeholder="https://…" onChange={(e) => edit({ serverUrl: e.target.value })} />}
          </Field>
        </div>
        {save.error != null && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      </div>
    </Card>
  );
}

const STATUS_TONE = { sent: "good", failed: "bad", held: "accent", suppressed: "neutral" } as const;

function Deliveries() {
  const q = useDeliveries();
  const chans = useChannels();
  const names = new Map((chans.data ?? []).map((c) => [c.id, c.name]));
  return (
    <Card title="Recent deliveries">
      {q.isPending ? (
        <Loading />
      ) : q.isError ? (
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      ) : q.data.length === 0 ? (
        <p className="small muted">Nothing sent to a chat app or email yet.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>When</th>
                <th>Channel</th>
                <th>Alert</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {q.data.map((d) => (
                <tr key={d.id}>
                  <td title={dateTime(d.at)}>{relativeTime(d.at)}</td>
                  <td>{names.get(d.channelId) ?? `#${d.channelId}`}</td>
                  <td>
                    {d.title}
                    <span className="cell-sub mono">
                      {d.severity} · {d.kind}
                    </span>
                  </td>
                  <td>
                    <Badge tone={STATUS_TONE[d.status]}>{d.status}</Badge>
                    {d.detail && <span className="cell-sub">{d.detail}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
