import type { OidcClient, OidcClientSpec, OidcPreset, OidcStatus } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { dateTime } from "../../format";
import { EditIcon, KeyIcon, PlusIcon, RefreshIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, Card, ErrorBox, Field, IconButton, Loading, PageHeader, Select, TextInput, Toggle } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { fillStep, linesToList, listToLines, validClientForm } from "./SignInRules";

const useStatus = () => useQuery({ queryKey: ["oidc"], queryFn: () => unwrap(api.GET("/oidc")) });
const useClients = () => useQuery({ queryKey: ["oidc", "clients"], queryFn: () => unwrap(api.GET("/oidc/clients")) });

/** Control Panel > Sign-in (OIDC): HardyOS as the sign-in provider for NetBird and other apps. */
export function SignIn() {
  const status = useStatus();
  const clients = useClients();
  const qc = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<OidcClient | null>(null);
  const [deleting, setDeleting] = useState<OidcClient | null>(null);
  const [revoking, setRevoking] = useState<OidcClient | null>(null);
  const [shown, setShown] = useState<{ client: OidcClient; secret?: string; preset?: OidcPreset } | null>(null);
  const refresh = () => void qc.invalidateQueries({ queryKey: ["oidc"] });

  const newSecret = useMutation({
    mutationFn: (c: OidcClient) => unwrap(api.POST("/oidc/clients/{id}/secret", { params: { path: { id: c.id } } })),
    onSuccess: (r, c) => setShown({ client: c, secret: r.secret }),
    onError: (e) => toast("error", "Couldn't make a new secret", errorMessage(e)),
  });

  return (
    <>
      <PageHeader
        title="Sign-in (OIDC)"
        subtitle="HardyOS signs people in to other apps with their domain accounts: NetBird first, and through it the sign-in in front of public apps."
        actions={
          <Button variant="primary" onClick={() => setAdding(true)}>
            <PlusIcon size={16} /> Add app
          </Button>
        }
      />
      {status.isPending ? (
        <Loading />
      ) : status.isError ? (
        <ErrorBox error={status.error} onRetry={() => status.refetch()} />
      ) : (
        <IssuerCard status={status.data} onChanged={refresh} />
      )}

      <Card title="Apps">
        {clients.isPending ? (
          <Loading />
        ) : clients.isError ? (
          <ErrorBox error={clients.error} onRetry={() => clients.refetch()} />
        ) : clients.data.clients.length === 0 ? (
          <p className="muted small">No apps yet. Add NetBird to sign in to it with your HardyOS account.</p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>App</th>
                  <th>Kind</th>
                  <th>Who may sign in</th>
                  <th className="actions">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {clients.data.clients.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <strong>{c.name}</strong>
                      <span className="cell-sub mono">{c.id}</span>
                      <div className="row" style={{ marginTop: 4 }}>
                        {c.managedBy && <Badge tone="info">Kept by Remote Access</Badge>}
                        {c.disabled && <Badge tone="warn">Off</Badge>}
                        {!c.firstParty && <Badge tone="neutral">Asks for consent</Badge>}
                      </div>
                    </td>
                    <td>{c.kind === "public" ? "Public (PKCE)" : "Confidential"}</td>
                    <td>{c.allowedGroups.length ? c.allowedGroups.join(", ") : "Everyone"}</td>
                    <td className="actions">
                      {!c.managedBy && (
                        <>
                          <IconButton label={`Edit ${c.name}`} onClick={() => setEditing(c)}>
                            <EditIcon size={16} />
                          </IconButton>
                          {c.kind === "confidential" && (
                            <IconButton label={`New secret for ${c.name}`} onClick={() => newSecret.mutate(c)}>
                              <KeyIcon size={16} />
                            </IconButton>
                          )}
                        </>
                      )}
                      <IconButton label={`Sign everyone out of ${c.name}`} onClick={() => setRevoking(c)}>
                        <RefreshIcon size={16} />
                      </IconButton>
                      {!c.managedBy && (
                        <IconButton label={`Remove ${c.name}`} onClick={() => setDeleting(c)}>
                          <TrashIcon size={16} />
                        </IconButton>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {status.data && <KeysCard status={status.data} onChanged={refresh} />}

      {adding && (
        <ClientDialog
          onClose={() => setAdding(false)}
          onSaved={(client, secret, preset) => {
            setAdding(false);
            refresh();
            setShown({ client, secret, preset });
          }}
        />
      )}
      {editing && (
        <ClientDialog
          client={editing}
          onClose={() => setEditing(null)}
          onSaved={(client, secret) => {
            setEditing(null);
            refresh();
            if (secret) setShown({ client, secret });
            else toast("success", `${client.name} saved`);
          }}
        />
      )}
      {shown && status.data && <SetupDialog {...shown} issuer={status.data.issuer} onClose={() => setShown(null)} onChanged={refresh} />}
      {deleting && (
        <ConfirmDialog
          title={`Remove ${deleting.name}?`}
          confirmLabel="Remove"
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            await unwrap(api.DELETE("/oidc/clients/{id}", { params: { path: { id: deleting.id } } }));
            refresh();
            toast("success", `${deleting.name} removed`);
          }}
        >
          Nobody can sign in to {deleting.name} with HardyOS any more, and everyone signed in there is signed out.
        </ConfirmDialog>
      )}
      {revoking && (
        <ConfirmDialog
          title={`Sign everyone out of ${revoking.name}?`}
          confirmLabel="Sign everyone out"
          onClose={() => setRevoking(null)}
          onConfirm={async () => {
            const r = await unwrap(api.POST("/oidc/clients/{id}/revoke", { params: { path: { id: revoking.id } } }));
            toast("success", `${r.revoked} sign-in${r.revoked === 1 ? "" : "s"} ended`);
          }}
        >
          Every token {revoking.name} holds stops working. People sign in again the next time {revoking.name} asks.
        </ConfirmDialog>
      )}
    </>
  );
}

function Copyable({ value, label }: { value: string; label: string }) {
  return (
    <span className="row" style={{ flexWrap: "nowrap", gap: 6 }}>
      <span className="mono" style={{ overflowWrap: "anywhere" }}>
        {value}
      </span>
      <Button
        size="sm"
        variant="ghost"
        aria-label={`Copy ${label}`}
        onClick={() =>
          void navigator.clipboard?.writeText(value).then(
            () => toast("success", `${label} copied`),
            () => toast("error", "Couldn't copy", "Select the text and copy it yourself."),
          )
        }
      >
        Copy
      </Button>
    </span>
  );
}

function IssuerCard({ status, onChanged }: { status: OidcStatus; onChanged: () => void }) {
  const [editing, setEditing] = useState(false);
  const local = useMutation({
    mutationFn: (on: boolean) => unwrap(api.PATCH("/oidc", { body: { localAccounts: on } })),
    onSuccess: onChanged,
    onError: (e) => toast("error", "Couldn't change the setting", errorMessage(e)),
  });
  const admins = useMutation({
    mutationFn: (on: boolean) => unwrap(api.PATCH("/oidc", { body: { publicAdmins: on } })),
    onSuccess: onChanged,
    onError: (e) => toast("error", "Couldn't change the setting", errorMessage(e)),
  });
  return (
    <Card title="Issuer" actions={<Button onClick={() => setEditing(true)}>Change</Button>}>
      <div className="stack">
        <dl className="kv">
          <dt>Issuer</dt>
          <dd>
            <Copyable value={status.issuer} label="Issuer" />
          </dd>
          <dt>Discovery</dt>
          <dd>
            <Copyable value={status.discovery} label="Discovery address" />
          </dd>
        </dl>
        <p className="small muted">
          {status.issuerChosen
            ? "Chosen by an administrator."
            : status.issuer.endsWith("/oidc")
              ? "On the desktop's own address until Remote Access has a base domain; then it moves to sso.<base domain>, which NetBird's proxy publishes on the internet."
              : "Its own address under Remote Access's base domain, published on the internet by NetBird's proxy (the desktop can stay NetBird-only)."}{" "}
          Apps are set up with this address: changing it means setting them up again.
        </p>
        <Toggle
          label="HardyOS accounts may sign in to apps"
          description="Off: only domain accounts. The local administrator is a recovery account and usually shouldn't be used for apps."
          checked={status.localAccounts}
          disabled={local.isPending}
          onChange={(v) => local.mutate(v)}
        />
        <Toggle
          label="Administrators can sign in through public SSO"
          description="Off: from the internet (sso.<base domain> through NetBird's proxy) an administrator's sign-in is refused like a wrong password. Sign in at home or over NetBird instead."
          checked={status.publicAdmins}
          disabled={admins.isPending}
          onChange={(v) => admins.mutate(v)}
        />
      </div>
      {editing && <IssuerDialog status={status} onClose={() => setEditing(false)} onChanged={onChanged} />}
    </Card>
  );
}

function IssuerDialog({ status, onClose, onChanged }: { status: OidcStatus; onClose: () => void; onChanged: () => void }) {
  const [value, setValue] = useState(status.issuerChosen ? status.issuer : "");
  const save = useMutation({
    mutationFn: (issuer: string) => unwrap(api.PATCH("/oidc", { body: { issuer } })),
    onSuccess: () => {
      onChanged();
      onClose();
    },
  });
  return (
    <Dialog
      title="Issuer"
      description="Leave it empty to follow Remote Access. Otherwise a host of its own (https://sso.example.net) or the desktop's address with /oidc."
      onClose={onClose}
      onSubmit={() => save.mutate(value.trim())}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={save.isPending}>
            Save
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label="Issuer URL" hint={`Empty: ${status.derivedIssuer}`}>
          {(id) => <TextInput id={id} value={value} placeholder={status.derivedIssuer} onChange={(e) => setValue(e.target.value)} spellCheck={false} />}
        </Field>
        {save.isError && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      </div>
    </Dialog>
  );
}

function ClientDialog({
  client,
  onClose,
  onSaved,
}: {
  client?: OidcClient;
  onClose: () => void;
  onSaved: (c: OidcClient, secret?: string, preset?: OidcPreset) => void;
}) {
  const [netbird, setNetbird] = useState("https://vpn.hardynetworks.net");
  const presets = useQuery({
    queryKey: ["oidc", "presets", netbird],
    queryFn: () => unwrap(api.GET("/oidc/presets", { params: { query: { netbirdUrl: netbird } } })),
    enabled: !client,
  });
  const [presetId, setPresetId] = useState(client ? "" : "netbird");
  const preset = presets.data?.presets.find((p) => p.id === presetId);
  const [form, setForm] = useState({
    name: client?.name ?? "",
    kind: client?.kind ?? "confidential",
    redirects: listToLines(client?.redirectUris),
    logouts: listToLines(client?.postLogoutRedirectUris),
    groups: listToLines(client?.allowedGroups),
    firstParty: client?.firstParty ?? true,
    disabled: client?.disabled ?? false,
  });
  const usingPreset = !client && preset;
  const spec: OidcClientSpec = usingPreset
    ? { ...preset.client, allowedGroups: linesToList(form.groups) }
    : {
        name: form.name,
        kind: form.kind as OidcClientSpec["kind"],
        redirectUris: linesToList(form.redirects),
        postLogoutRedirectUris: linesToList(form.logouts),
        allowedGroups: linesToList(form.groups),
        firstParty: form.firstParty,
        preset: client?.preset ?? "",
        disabled: form.disabled,
      };
  const problem = validClientForm(spec);
  const save = useMutation({
    mutationFn: () =>
      client
        ? unwrap(api.PATCH("/oidc/clients/{id}", { params: { path: { id: client.id } }, body: spec }))
        : unwrap(api.POST("/oidc/clients", { body: spec })),
    onSuccess: (r) => onSaved(r.client, r.secret, usingPreset ? preset : undefined),
  });
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });

  return (
    <Dialog
      title={client ? `Edit ${client.name}` : "Add an app"}
      width={600}
      onClose={onClose}
      onSubmit={() => !problem && save.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={!!problem} busy={save.isPending}>
            {client ? "Save" : "Add"}
          </Button>
        </>
      }
    >
      <div className="stack">
        {!client && (
          <Field label="App">
            {(id) => (
              <Select id={id} value={presetId} onChange={(e) => setPresetId(e.target.value)}>
                <option value="netbird">NetBird</option>
                <option value="netbird-proxy">NetBird reverse proxy SSO (HardyOS as NetBird's only identity provider)</option>
                <option value="">Another app</option>
              </Select>
            )}
          </Field>
        )}
        {usingPreset ? (
          <>
            <p className="small muted">{preset.description}</p>
            <Field label="NetBird's address" hint="The dashboard and management address of your NetBird server.">
              {(id) => <TextInput id={id} value={netbird} onChange={(e) => setNetbird(e.target.value)} spellCheck={false} />}
            </Field>
          </>
        ) : (
          !client || !client.managedBy ? (
            <>
              <Field label="Name">{(id) => <TextInput id={id} value={form.name} onChange={set("name")} maxLength={64} />}</Field>
              <Field label="Kind" hint="Public apps (in a browser or on a device) can't keep a secret; they must use PKCE.">
                {(id) => (
                  <Select id={id} value={form.kind} onChange={set("kind")}>
                    <option value="confidential">Confidential (a server with a secret)</option>
                    <option value="public">Public (PKCE, no secret)</option>
                  </Select>
                )}
              </Field>
              <Field label="Redirect URIs" hint="One per line, exactly as the app sends them.">
                {(id) => <textarea id={id} className="input" rows={3} value={form.redirects} onChange={set("redirects")} spellCheck={false} />}
              </Field>
              <Field label="Sign-out redirect URIs" hint="Optional, one per line.">
                {(id) => <textarea id={id} className="input" rows={2} value={form.logouts} onChange={set("logouts")} spellCheck={false} />}
              </Field>
              <Toggle
                label="Set up by me for this server (no consent screen)"
                description="Off: people are asked once whether the app may see their name, email and groups."
                checked={form.firstParty}
                onChange={(v) => setForm({ ...form, firstParty: v })}
              />
              {client && <Toggle label="Turned off" description="Nobody can sign in; everyone signed in is signed out." checked={form.disabled} onChange={(v) => setForm({ ...form, disabled: v })} />}
            </>
          ) : null
        )}
        <Field label="Who may sign in" hint="Domain groups, one per line (HOME\Family). Empty: every domain account.">
          {(id) => <textarea id={id} className="input" rows={2} value={form.groups} onChange={set("groups")} spellCheck={false} />}
        </Field>
        {problem && form.name + form.redirects !== "" && <p className="small muted">{problem}</p>}
        {save.isError && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      </div>
    </Dialog>
  );
}

/** Shows a new client's ID and secret (once) and what to paste where in the app. */
function SetupDialog({
  client,
  secret,
  preset,
  issuer,
  onClose,
  onChanged,
}: {
  client: OidcClient;
  secret?: string;
  preset?: OidcPreset;
  issuer: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [redirect, setRedirect] = useState("");
  const vals = { clientId: client.id, clientSecret: secret ?? "(the secret shown when it was made)", issuer };
  const addRedirect = useMutation({
    mutationFn: () =>
      unwrap(
        api.PATCH("/oidc/clients/{id}", {
          params: { path: { id: client.id } },
          body: {
            name: client.name,
            kind: client.kind,
            redirectUris: [redirect.trim()],
            postLogoutRedirectUris: client.postLogoutRedirectUris,
            allowedGroups: client.allowedGroups,
            firstParty: client.firstParty,
            preset: client.preset,
            disabled: client.disabled,
          },
        }),
      ),
    onSuccess: () => {
      onChanged();
      toast("success", "Redirect URL saved", "Finish in NetBird and try signing in.");
      onClose();
    },
  });
  const redirectOK = !!preset?.redirectFromApp && redirect.trim().startsWith(preset.redirectFromApp);
  return (
    <Dialog
      title={preset ? `Set up ${preset.name}` : `${client.name}: client details`}
      width={640}
      onClose={onClose}
      footer={
        preset?.redirectFromApp ? (
          <>
            <Button onClick={onClose}>Later</Button>
            <Button variant="primary" disabled={!redirectOK} busy={addRedirect.isPending} onClick={() => addRedirect.mutate()}>
              Save the redirect URL
            </Button>
          </>
        ) : (
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        )
      }
    >
      <div className="stack">
        {secret && <Alert tone="warn">Copy the client secret now: it isn't shown again (HardyOS keeps only a hash). You can make a new one later.</Alert>}
        <dl className="kv">
          <dt>Client ID</dt>
          <dd>
            <Copyable value={client.id} label="Client ID" />
          </dd>
          {secret && (
            <>
              <dt>Client secret</dt>
              <dd>
                <Copyable value={secret} label="Client secret" />
              </dd>
            </>
          )}
          <dt>Issuer</dt>
          <dd>
            <Copyable value={issuer} label="Issuer" />
          </dd>
        </dl>
        {preset && (
          <>
            <h3 className="section-label">In NetBird</h3>
            <ol className="steps">
              {preset.steps.map((s, i) => (
                <li key={i}>
                  <span>{s.where}</span>
                  {s.field && (
                    <div className="row" style={{ gap: 6 }}>
                      <strong>{s.field}:</strong> {s.value && <Copyable value={fillStep(s.value, vals)} label={s.field} />}
                    </div>
                  )}
                </li>
              ))}
            </ol>
            {preset.redirectFromApp && (
              <Field label="Redirect URL NetBird shows" hint={`It starts with ${preset.redirectFromApp}`} error={redirect && !redirectOK ? "That isn't NetBird's redirect URL for this server" : null}>
                {(id) => <TextInput id={id} value={redirect} onChange={(e) => setRedirect(e.target.value)} spellCheck={false} placeholder={`${preset.redirectFromApp}…`} />}
              </Field>
            )}
            {preset.notes.map((n, i) => (
              <p key={i} className="small muted">
                {n}
              </p>
            ))}
          </>
        )}
        {addRedirect.isError && <Alert tone="bad">{errorMessage(addRedirect.error)}</Alert>}
      </div>
    </Dialog>
  );
}

function KeysCard({ status, onChanged }: { status: OidcStatus; onChanged: () => void }) {
  const [confirm, setConfirm] = useState(false);
  return (
    <Card title="Signing keys" actions={<Button onClick={() => setConfirm(true)}>Rotate now</Button>}>
      <p className="small muted">
        ID tokens are signed with RS256. A new key is published a day before it signs, signs for 30 days and stays published 2 days after. The private keys are
        encrypted with a key only the root helper has; settings backups with keys bring them back.
      </p>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Key</th>
              <th>State</th>
              <th>Since</th>
            </tr>
          </thead>
          <tbody>
            {status.keys.map((k) => (
              <tr key={k.id}>
                <td className="mono">{k.id}</td>
                <td>
                  <Badge tone={k.state === "active" ? "good" : k.state === "next" ? "info" : "neutral"}>
                    {k.state === "active" ? "Signing" : k.state === "next" ? "Next" : "Retired"}
                  </Badge>
                </td>
                <td className="small">{dateTime(k.state === "retired" ? (k.retiredAt ?? k.createdAt) : (k.activatedAt ?? k.createdAt))}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {confirm && (
        <ConfirmDialog
          title="Rotate the signing key now?"
          confirmLabel="Rotate"
          danger={false}
          onClose={() => setConfirm(false)}
          onConfirm={async () => {
            await unwrap(api.POST("/oidc/keys/rotate"));
            onChanged();
            toast("success", "A new key signs now");
          }}
        >
          The next key starts signing at once. Apps that cached the old key list fetch the new one; the current key stays published for 2 days.
        </ConfirmDialog>
      )}
    </Card>
  );
}
