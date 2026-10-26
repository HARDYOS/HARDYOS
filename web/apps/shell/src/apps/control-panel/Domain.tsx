import type { DomainConfig, DomainController, DomainStatus, DomainSuggestion } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ReactNode, useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { dateTime } from "../../format";
import { DomainIcon, EditIcon, PlayIcon, StopIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Field, IconButton, Loading, PageHeader, TextInput } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { JobProgress } from "../shared";
import { DomainGroups, DomainUsers } from "./DomainDirectory";
import { defaultShortName, domainProblem, PASSWORD_RULES, passwordProblem } from "./domainRules";

export const useDomain = () =>
  useQuery({ queryKey: ["domain"], queryFn: () => unwrap(api.GET("/domain")), refetchInterval: 15_000 });

type Tab = "overview" | "users" | "groups";

export function Domain() {
  const status = useDomain();
  const [tab, setTab] = useState<Tab>("overview");
  if (status.isPending) return <Loading />;
  if (status.isError) return <ErrorBox error={status.error} onRetry={() => status.refetch()} />;
  const st = status.data;

  if (!st.available) {
    return (
      <>
        <PageHeader title="Domain" subtitle="One sign-in for every computer and app in the house." />
        <Alert tone="warn" title="Not available in this build">
          This HardyOS build doesn't include the domain controller. Install the latest update to get it.
        </Alert>
      </>
    );
  }
  if (!st.provisioned || !st.config) return <Setup onDone={() => void status.refetch()} />;

  return (
    <>
      <PageHeader
        title="Domain"
        subtitle={
          <>
            <span className="mono">{st.config.domain}</span>: one sign-in for every Windows PC and, later, every app.
          </>
        }
        badge={<HealthBadge st={st} />}
      />
      <div className="tabs" role="tablist" aria-label="Domain sections">
        {(
          [
            ["overview", "Overview"],
            ["users", "Users"],
            ["groups", "Groups"],
          ] as const
        ).map(([id, label]) => (
          <button key={id} type="button" role="tab" className="tabs__tab" aria-selected={tab === id} onClick={() => setTab(id)}>
            {label}
          </button>
        ))}
      </div>
      {tab === "overview" && <Overview st={st} />}
      {tab === "users" && <DomainUsers />}
      {tab === "groups" && <DomainGroups />}
    </>
  );
}

function HealthBadge({ st }: { st: DomainStatus }) {
  if (!st.config?.enabled) return <Badge tone="neutral">Stopped</Badge>;
  if (st.running && st.responding) return <Badge tone="good">Running</Badge>;
  if (st.running) return <Badge tone="warn">Starting</Badge>;
  return <Badge tone="bad">Not running</Badge>;
}

const ip = (cidr: string) => cidr.split("/")[0] ?? cidr;

// ---- setup -------------------------------------------------------------

type Mode = "create" | "join";

function Setup({ onDone }: { onDone: () => void }) {
  const [mode, setMode] = useState<Mode | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);

  return (
    <>
      <PageHeader title="Domain" subtitle="One sign-in for every computer and app in the house." />
      {jobId ? (
        <Card title={mode === "join" ? "Joining the domain" : "Creating the domain"}>
          <JobProgress
            id={jobId}
            onDone={(j) => {
              if (j.state === "succeeded") {
                toast("success", mode === "join" ? "This server is now a domain controller too" : "The domain is ready", mode === "join" ? undefined : "Add the family's accounts next.");
                onDone();
              }
            }}
          />
          <div style={{ marginTop: 12 }}>
            <Button size="sm" onClick={() => setJobId(null)}>
              Back to the settings
            </Button>
          </div>
        </Card>
      ) : mode ? (
        <SetupForm mode={mode} onStarted={setJobId} onCancel={() => setMode(null)} />
      ) : (
        <Card>
          <EmptyState icon={<DomainIcon size={30} />} title="No domain on this server">
            A domain gives everyone one account that works on every Windows PC in the house, on the NAS's shared folders and, later, in every app.
            HardyOS runs it as an Active Directory domain controller with its own address on your network.
          </EmptyState>
          <div className="grid-2" style={{ marginTop: 8 }}>
            <ChoiceCard
              title="Create a new domain"
              body="Start the family's domain on this server."
              action={
                <Button variant="primary" onClick={() => setMode("create")}>
                  Create a domain
                </Button>
              }
            />
            <ChoiceCard
              title="Join an existing domain"
              body="Another HardyOS server already runs the domain: make this one a second domain controller, so sign-ins and DNS keep working when either is off."
              action={<Button onClick={() => setMode("join")}>Join a domain</Button>}
            />
          </div>
        </Card>
      )}
    </>
  );
}

function ChoiceCard({ title, body, action }: { title: string; body: string; action: ReactNode }) {
  return (
    <div className="stack" style={{ gap: 8, padding: 16, borderRadius: 12, background: "var(--hos-surface)" }}>
      <strong>{title}</strong>
      <span className="small muted">{body}</span>
      <div>{action}</div>
    </div>
  );
}

function SetupForm({ mode, onStarted, onCancel }: { mode: Mode; onStarted: (jobId: string) => void; onCancel: () => void }) {
  const suggest = useQuery({ queryKey: ["domain", "suggest"], queryFn: () => unwrap(api.GET("/domain/suggest")), staleTime: Infinity });
  if (suggest.isPending) return <Loading label="Looking at your network…" />;
  if (suggest.isError) return <ErrorBox error={suggest.error} onRetry={() => suggest.refetch()} />;
  return <SetupFields mode={mode} sug={suggest.data} onStarted={onStarted} onCancel={onCancel} />;
}

function SetupFields({ mode, sug, onStarted, onCancel }: { mode: Mode; sug: DomainSuggestion; onStarted: (jobId: string) => void; onCancel: () => void }) {
  const joining = mode === "join";
  const [domain, setDomain] = useState("");
  const [short, setShort] = useState("");
  const [shortEdited, setShortEdited] = useState(false);
  const [existing, setExisting] = useState("");
  const [address, setAddress] = useState(sug.address ? ip(sug.address) : "");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [advanced, setAdvanced] = useState(false);
  const [gateway, setGateway] = useState(sug.gateway);
  const [dns, setDns] = useState(sug.dns.join(", "));

  const shortName = shortEdited ? short : defaultShortName(domain);
  const dProblem = domainProblem(domain);
  const pProblem = joining ? null : passwordProblem(password, "Administrator");
  const mismatch = !joining && confirm.length > 0 && confirm !== password;
  const existingProblem = existing && !/^\d{1,3}(\.\d{1,3}){3}$/.test(existing.trim()) ? "Enter its address, like 192.168.1.20." : null;
  const ready =
    domain.trim() !== "" &&
    !dProblem &&
    address.trim() !== "" &&
    password !== "" &&
    (joining ? existing.trim() !== "" && !existingProblem : !pProblem && confirm === password);
  const forwarders = dns
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);

  const start = useMutation({
    mutationFn: () =>
      joining
        ? unwrap(
            api.POST("/domain/join", {
              body: { domain: domain.trim(), existing: existing.trim(), adminPassword: password, address: address.trim(), gateway: gateway.trim() || undefined, forwarders },
            }),
          )
        : unwrap(
            api.POST("/domain", {
              body: { domain: domain.trim(), netbios: shortName || undefined, adminPassword: password, address: address.trim(), gateway: gateway.trim() || undefined, forwarders },
            }),
          ),
    onSuccess: (r) => onStarted(r.job.id),
  });

  return (
    <form
      className="stack"
      onSubmit={(e) => {
        e.preventDefault();
        if (ready) start.mutate();
      }}
    >
      <Card title={joining ? "The domain to join" : "Name"}>
        <div className="stack">
          <Field
            label="Domain name"
            error={dProblem}
            hint={
              joining
                ? "Exactly as it was created on the other server, like home.yourname.net."
                : "A subdomain of a domain you own, like home.yourname.net. It only exists inside your network. Choose carefully: once computers join, changing it means joining them again."
            }
          >
            {(id) => (
              <TextInput id={id} value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="home.yourname.net" autoCapitalize="none" spellCheck={false} autoFocus />
            )}
          </Field>
          {joining ? (
            <Field label="An existing domain controller's address" error={existingProblem} hint="Shown on the other server's Domain page.">
              {(id) => <TextInput id={id} value={existing} onChange={(e) => setExisting(e.target.value)} className="input mono" spellCheck={false} placeholder="192.168.1.20" />}
            </Field>
          ) : (
            <Field
              label="Short name"
              hint={
                <>
                  Windows shows accounts as <span className="mono">{shortName || "SHORT"}\username</span>. Up to 15 letters, digits or dashes.
                </>
              }
            >
              {(id) => (
                <TextInput
                  id={id}
                  value={shortName}
                  onChange={(e) => {
                    setShortEdited(true);
                    setShort(e.target.value.toUpperCase());
                  }}
                  maxLength={15}
                  spellCheck={false}
                />
              )}
            </Field>
          )}
        </div>
      </Card>

      <Card title={joining ? "This domain controller" : "Network"}>
        <div className="stack">
          <Field
            label={joining ? "This server's domain controller address" : "Domain controller address"}
            hint={
              <>
                Its own address on your network (the NAS is <span className="mono">{ip(sug.hostAddress)}</span>). Pick one outside your router's DHCP
                range, or reserve it in the router.
                {sug.address ? " This one looked free just now." : " HardyOS couldn't find a free one by itself."}
              </>
            }
          >
            {(id) => <TextInput id={id} value={address} onChange={(e) => setAddress(e.target.value)} className="input mono" spellCheck={false} />}
          </Field>
          {advanced ? (
            <div className="grid-2">
              <Field label="Gateway" hint="Your router">
                {(id) => <TextInput id={id} value={gateway} onChange={(e) => setGateway(e.target.value)} className="input mono" />}
              </Field>
              <Field label="DNS servers for the internet" hint="Where the domain sends lookups for other names; two at most">
                {(id) => <TextInput id={id} value={dns} onChange={(e) => setDns(e.target.value)} className="input mono" />}
              </Field>
            </div>
          ) : (
            <div>
              <Button size="sm" variant="ghost" onClick={() => setAdvanced(true)}>
                Gateway and DNS…
              </Button>
            </div>
          )}
        </div>
      </Card>

      <Card title="Administrator">
        <div className="stack">
          <p className="small muted" style={{ margin: 0 }}>
            {joining ? (
              <>
                The domain's <span className="mono">Administrator</span> password, set when the domain was created. It's used once, to copy the
                domain, and isn't kept.
              </>
            ) : (
              <>
                The domain's own <span className="mono">Administrator</span> account, used to join computers to the domain. Keep this password
                somewhere safe.
              </>
            )}
          </p>
          {joining ? (
            <Field label="Administrator password">
              {(id) => <TextInput id={id} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="off" />}
            </Field>
          ) : (
            <div className="grid-2">
              <Field label="Password" error={pProblem} hint={PASSWORD_RULES}>
                {(id) => <TextInput id={id} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />}
              </Field>
              <Field label="Password again" error={mismatch ? "The passwords don't match." : null}>
                {(id) => <TextInput id={id} type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />}
              </Field>
            </div>
          )}
        </div>
      </Card>

      {start.error && <Alert tone="bad">{errorMessage(start.error)}</Alert>}
      <div className="row">
        <Button type="submit" variant="primary" busy={start.isPending} disabled={!ready}>
          {joining ? "Join the domain" : "Create the domain"}
        </Button>
        <Button onClick={onCancel}>Cancel</Button>
      </div>
    </form>
  );
}

// ---- overview ----------------------------------------------------------

function Overview({ st }: { st: DomainStatus }) {
  const qc = useQueryClient();
  const c = st.config!;
  const others = c.others ?? [];
  const [editingDNS, setEditingDNS] = useState(false);
  const [removing, setRemoving] = useState<DomainController | null>(null);
  const [job, setJob] = useState<string | null>(null);
  const enable = useMutation({
    mutationFn: (enabled: boolean) => unwrap(api.PUT("/domain/enabled", { body: { enabled } })),
    onSuccess: (s) => {
      qc.setQueryData(["domain"], s);
      toast("success", s.config?.enabled ? "The domain controller is running" : "The domain controller is stopped");
    },
    onError: (e) => toast("error", "Couldn't change the domain controller", errorMessage(e)),
  });
  const dnsServers = [ip(c.address), ...others.map((o) => o.address).filter(Boolean)];

  return (
    <>
      {st.problem && c.enabled && <Alert tone={st.running ? "warn" : "bad"}>{st.problem}</Alert>}
      {job && (
        <Card>
          <JobProgress
            id={job}
            onDone={() => {
              void qc.invalidateQueries({ queryKey: ["domain"] });
            }}
          />
        </Card>
      )}
      <div className="grid-2">
        <Card
          title="This domain controller"
          actions={
            c.enabled ? (
              <Button size="sm" onClick={() => enable.mutate(false)} busy={enable.isPending}>
                <StopIcon size={14} /> Stop
              </Button>
            ) : (
              <Button size="sm" variant="primary" onClick={() => enable.mutate(true)} busy={enable.isPending}>
                <PlayIcon size={14} /> Start
              </Button>
            )
          }
        >
          <dl className="kv">
            <dt>Domain</dt>
            <dd className="mono">{c.domain}</dd>
            <dt>Short name</dt>
            <dd className="mono">{c.netbios}</dd>
            <dt>Name</dt>
            <dd className="mono">{c.dcName}</dd>
            <dt>Address</dt>
            <dd className="mono">{ip(c.address)}</dd>
            <dt>On port</dt>
            <dd className="mono">{c.parent}</dd>
            <dt>Internet DNS</dt>
            <dd className="row" style={{ gap: 6 }}>
              <span className="mono">{c.forwarders.join(", ") || "None"}</span>
              <IconButton label="Change the internet DNS servers" onClick={() => setEditingDNS(true)}>
                <EditIcon size={14} />
              </IconButton>
            </dd>
            <dt>{c.joined ? "Joined" : "Created"}</dt>
            <dd>{dateTime(c.createdAt)}</dd>
          </dl>
        </Card>
        <Card title="Domain controllers">
          <div className="stack" style={{ gap: 10 }}>
            <DCRow name={c.dcName} address={ip(c.address)} badge={<Badge tone="accent">This server</Badge>} />
            {others.map((o) => (
              <DCRow
                key={o.name || o.address}
                name={o.name || "Finding its name…"}
                address={o.address}
                action={
                  o.name ? (
                    <IconButton label={`Remove ${o.name} (gone for good)`} onClick={() => setRemoving(o)}>
                      <TrashIcon size={15} />
                    </IconButton>
                  ) : undefined
                }
              />
            ))}
            {others.length === 0 && (
              <p className="small muted" style={{ margin: 0 }}>
                This is the only domain controller. To keep sign-ins and DNS working when this server is off, open <strong>Control Panel → Domain</strong> on
                a second HardyOS server and choose <strong>Join an existing domain</strong> with address <span className="mono">{ip(c.address)}</span>.
              </p>
            )}
          </div>
        </Card>
      </div>
      <div className="grid-2">
        <Card title="DNS for your network">
          <p className="small" style={{ marginTop: 0 }}>
            Devices find the domain through its DNS. In your router's DHCP settings, set the DNS servers to:
          </p>
          <div className="row" style={{ gap: 8, marginBottom: 10 }}>
            {dnsServers.map((s, i) => (
              <Badge key={s} tone="neutral">
                <span className="mono">
                  DNS {i + 1}: {s}
                </span>
              </Badge>
            ))}
          </div>
          <p className="small muted" style={{ margin: 0 }}>
            Every device then uses the domain without setting anything by hand. The domain answers internet names too, through{" "}
            <span className="mono">{c.forwarders.join(", ") || "its DNS servers"}</span>. This NAS already uses it.
          </p>
        </Card>
        <Card title="Join a Windows PC">
          <ol className="steps">
            <Step>
              Make sure the PC uses <span className="mono">{ip(c.address)}</span> for DNS (through the router, as on the left, or in its network settings).
            </Step>
            <Step>
              Open <strong>Settings → System → About → Domain or workgroup</strong>, choose <strong>Domain</strong> and enter{" "}
              <span className="mono">{c.domain}</span>.
            </Step>
            <Step>
              Sign in with <span className="mono">Administrator</span> and the domain's Administrator password, then restart.
            </Step>
            <Step>
              Family members sign in as <span className="mono">{c.netbios}\username</span> with the accounts on the Users tab.
            </Step>
          </ol>
          <p className="small muted" style={{ margin: "10px 0 0" }}>
            Windows Pro, Education or Enterprise can join a domain; Windows Home can't.
          </p>
        </Card>
      </div>
      <LeaveOrDelete c={c} onJob={setJob} />
      {editingDNS && <ForwardersDialog c={c} onClose={() => setEditingDNS(false)} />}
      {removing && (
        <ConfirmDialog
          title={`Remove ${removing.name}?`}
          confirmLabel="Remove it"
          typeToConfirm={removing.name}
          onClose={() => setRemoving(null)}
          onConfirm={async () => {
            const r = await unwrap(api.POST("/domain/controllers/remove", { body: { name: removing.name, confirm: removing.name } }));
            setJob(r.job.id);
          }}
        >
          <p>
            Only for a domain controller that's <strong>gone for good</strong> (its server died or was wiped). This server takes over its roles and
            the domain forgets it. A controller that's just turned off comes back by itself; don't remove it.
          </p>
        </ConfirmDialog>
      )}
    </>
  );
}

function DCRow({ name, address, badge, action }: { name: string; address: string; badge?: ReactNode; action?: ReactNode }) {
  return (
    <div className="row row--between" style={{ flexWrap: "nowrap" }}>
      <div style={{ minWidth: 0 }}>
        <div className="row" style={{ gap: 8 }}>
          <strong className="mono">{name}</strong>
          {badge}
        </div>
        <span className="cell-sub mono">{address || "address unknown"}</span>
      </div>
      {action}
    </div>
  );
}

function LeaveOrDelete({ c, onJob }: { c: DomainConfig; onJob: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const shared = (c.others ?? []).length > 0;
  return (
    <Card title={shared ? "Remove this server from the domain" : "Delete the domain"}>
      <div className="row row--between">
        <p className="small muted" style={{ margin: 0, maxWidth: 560 }}>
          {shared ? (
            <>
              The other domain controllers keep the domain and every account. This server stops being a domain controller and its copy is deleted.
            </>
          ) : (
            <>
              Deletes every account, group and joined computer in <span className="mono">{c.domain}</span>. Computers that joined it must be taken
              out of the domain by hand. This can't be undone.
            </>
          )}
        </p>
        <Button variant="danger" onClick={() => setOpen(true)}>
          <TrashIcon size={15} /> {shared ? "Remove this server" : "Delete domain"}
        </Button>
      </div>
      {open && !shared && (
        <ConfirmDialog
          title={`Delete ${c.domain}?`}
          confirmLabel="Delete the domain"
          typeToConfirm={c.domain}
          onClose={() => setOpen(false)}
          onConfirm={async () => {
            const r = await unwrap(api.DELETE("/domain", { body: { confirm: c.domain } }));
            onJob(r.job.id);
          }}
        >
          <p>Every account, group and joined computer in the domain is deleted for good. Type the domain name to confirm.</p>
        </ConfirmDialog>
      )}
      {open && shared && <LeaveDialog c={c} onJob={onJob} onClose={() => setOpen(false)} />}
    </Card>
  );
}

function LeaveDialog({ c, onJob, onClose }: { c: DomainConfig; onJob: (id: string) => void; onClose: () => void }) {
  const [password, setPassword] = useState("");
  const leave = useMutation({
    mutationFn: () => unwrap(api.POST("/domain/leave", { body: { adminPassword: password } })),
    onSuccess: (r) => {
      onJob(r.job.id);
      onClose();
    },
  });
  return (
    <Dialog
      title={`Remove ${c.dcName} from the domain?`}
      description="The other domain controllers keep the domain; roles this one held move to them."
      onClose={onClose}
      onSubmit={() => password && leave.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="danger" busy={leave.isPending} disabled={!password}>
            Remove this server
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label="The domain's Administrator password">
          {(id) => <TextInput id={id} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="off" />}
        </Field>
        {leave.error && <Alert tone="bad">{errorMessage(leave.error)}</Alert>}
      </div>
    </Dialog>
  );
}

function ForwardersDialog({ c, onClose }: { c: DomainConfig; onClose: () => void }) {
  const qc = useQueryClient();
  const [text, setText] = useState(c.forwarders.join(", "));
  const list = text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  const save = useMutation({
    mutationFn: () => unwrap(api.PUT("/domain/forwarders", { body: { forwarders: list } })),
    onSuccess: (s) => {
      qc.setQueryData(["domain"], s);
      toast("success", "Internet DNS servers changed");
      onClose();
    },
  });
  return (
    <Dialog
      title="Internet DNS servers"
      description="Where the domain sends lookups for names outside it, like your router or 9.9.9.9. The domain controller restarts to use them (a few seconds)."
      onClose={onClose}
      onSubmit={() => list.length > 0 && save.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={save.isPending} disabled={list.length === 0 || list.length > 2}>
            Save
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label="DNS servers" hint="One or two addresses, separated by commas" error={list.length > 2 ? "Two at most." : null}>
          {(id) => <TextInput id={id} value={text} onChange={(e) => setText(e.target.value)} className="input mono" />}
        </Field>
        {save.error && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      </div>
    </Dialog>
  );
}

function Step({ children }: { children: ReactNode }) {
  return <li>{children}</li>;
}

