import type { DomainStatus, DomainSuggestion } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ReactNode, useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { dateTime } from "../../format";
import { DomainIcon, PlayIcon, StopIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Field, Loading, PageHeader, TextInput } from "../../ui";
import { ConfirmDialog } from "../../ui/Dialog";
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

// ---- setup -------------------------------------------------------------

function Setup({ onDone }: { onDone: () => void }) {
  const [started, setStarted] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);

  return (
    <>
      <PageHeader title="Domain" subtitle="One sign-in for every computer and app in the house." />
      {jobId ? (
        <Card title="Creating the domain">
          <JobProgress
            id={jobId}
            onDone={(j) => {
              if (j.state === "succeeded") {
                toast("success", "The domain is ready", "Add the family's accounts next.");
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
      ) : started ? (
        <SetupForm onStarted={setJobId} onCancel={() => setStarted(false)} />
      ) : (
        <Card>
          <EmptyState
            icon={<DomainIcon size={30} />}
            title="No domain yet"
            action={
              <Button variant="primary" onClick={() => setStarted(true)}>
                Set up a domain
              </Button>
            }
          >
            A domain gives everyone one account that works on every Windows PC in the house, on the NAS's shared folders and, later, in every app.
            HardyOS runs it as an Active Directory domain controller with its own address on your network.
          </EmptyState>
        </Card>
      )}
    </>
  );
}

function SetupForm({ onStarted, onCancel }: { onStarted: (jobId: string) => void; onCancel: () => void }) {
  const suggest = useQuery({ queryKey: ["domain", "suggest"], queryFn: () => unwrap(api.GET("/domain/suggest")), staleTime: Infinity });
  if (suggest.isPending) return <Loading label="Looking at your network…" />;
  if (suggest.isError) return <ErrorBox error={suggest.error} onRetry={() => suggest.refetch()} />;
  return <SetupFields sug={suggest.data} onStarted={onStarted} onCancel={onCancel} />;
}

function SetupFields({ sug, onStarted, onCancel }: { sug: DomainSuggestion; onStarted: (jobId: string) => void; onCancel: () => void }) {
  const [domain, setDomain] = useState("");
  const [short, setShort] = useState("");
  const [shortEdited, setShortEdited] = useState(false);
  const [address, setAddress] = useState(sug.address ? sug.address.split("/")[0]! : "");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [advanced, setAdvanced] = useState(false);
  const [gateway, setGateway] = useState(sug.gateway);
  const [dns, setDns] = useState(sug.dns.join(", "));

  const shortName = shortEdited ? short : defaultShortName(domain);
  const dProblem = domainProblem(domain);
  const pProblem = passwordProblem(password, "Administrator");
  const mismatch = confirm.length > 0 && confirm !== password;
  const ready = domain.trim() !== "" && !dProblem && address.trim() !== "" && password !== "" && !pProblem && confirm === password;

  const create = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/domain", {
          body: {
            domain: domain.trim(),
            netbios: shortName || undefined,
            adminPassword: password,
            address: address.trim(),
            gateway: gateway.trim() || undefined,
            forwarders: dns
              .split(/[\s,]+/)
              .map((s) => s.trim())
              .filter(Boolean),
          },
        }),
      ),
    onSuccess: (r) => onStarted(r.job.id),
  });

  return (
    <form
      className="stack"
      onSubmit={(e) => {
        e.preventDefault();
        if (ready) create.mutate();
      }}
    >
      <Card title="Name">
        <div className="stack">
          <Field
            label="Domain name"
            error={dProblem}
            hint="A subdomain of a domain you own, like home.yourname.net. It only exists inside your network. Choose carefully: once computers join, changing it means joining them again."
          >
            {(id) => (
              <TextInput
                id={id}
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="home.yourname.net"
                autoCapitalize="none"
                spellCheck={false}
                autoFocus
              />
            )}
          </Field>
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
        </div>
      </Card>

      <Card title="Network">
        <div className="stack">
          <Field
            label="Domain controller address"
            hint={
              <>
                Its own address on your network ({sug.hostAddress && <span className="mono">NAS is {sug.hostAddress.split("/")[0]}</span>}). Pick one
                outside your router's DHCP range, or reserve it in the router.
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
            The domain's own <span className="mono">Administrator</span> account, used to join computers to the domain. Keep this password
            somewhere safe.
          </p>
          <div className="grid-2">
            <Field label="Password" error={pProblem} hint={PASSWORD_RULES}>
              {(id) => <TextInput id={id} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />}
            </Field>
            <Field label="Password again" error={mismatch ? "The passwords don't match." : null}>
              {(id) => <TextInput id={id} type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />}
            </Field>
          </div>
        </div>
      </Card>

      {create.error && <Alert tone="bad">{errorMessage(create.error)}</Alert>}
      <div className="row">
        <Button type="submit" variant="primary" busy={create.isPending} disabled={!ready}>
          Create the domain
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
  const [deleting, setDeleting] = useState(false);
  const [deleteJob, setDeleteJob] = useState<string | null>(null);
  const enable = useMutation({
    mutationFn: (enabled: boolean) => unwrap(api.PUT("/domain/enabled", { body: { enabled } })),
    onSuccess: (s) => {
      qc.setQueryData(["domain"], s);
      toast("success", s.config?.enabled ? "The domain controller is running" : "The domain controller is stopped");
    },
    onError: (e) => toast("error", "Couldn't change the domain controller", errorMessage(e)),
  });
  const ip = c.address.split("/")[0];

  return (
    <>
      {st.problem && c.enabled && <Alert tone={st.running ? "warn" : "bad"}>{st.problem}</Alert>}
      <div className="grid-2">
        <Card
          title="Domain controller"
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
            <dt>Controller</dt>
            <dd className="mono">{c.dcName}</dd>
            <dt>Address</dt>
            <dd className="mono">{ip}</dd>
            <dt>On port</dt>
            <dd className="mono">{c.parent}</dd>
            <dt>Internet DNS</dt>
            <dd className="mono">{c.forwarders.join(", ") || "None"}</dd>
            <dt>Created</dt>
            <dd>{dateTime(c.createdAt)}</dd>
          </dl>
        </Card>
        <Card title="Join a Windows PC">
          <ol className="steps">
            <Step>
              Set the PC's DNS server to <span className="mono">{ip}</span> (or set it once in your router's DHCP settings for every device).
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
      <Card title="Delete the domain">
        {deleteJob ? (
          <JobProgress
            id={deleteJob}
            onDone={() => {
              void qc.invalidateQueries({ queryKey: ["domain"] });
            }}
          />
        ) : (
          <div className="row row--between">
            <p className="small muted" style={{ margin: 0, maxWidth: 560 }}>
              Deletes every account, group and joined computer in <span className="mono">{c.domain}</span>. Computers that joined it must be
              taken out of the domain by hand. This can't be undone.
            </p>
            <Button variant="danger" onClick={() => setDeleting(true)}>
              <TrashIcon size={15} /> Delete domain
            </Button>
          </div>
        )}
      </Card>
      {deleting && (
        <ConfirmDialog
          title={`Delete ${c.domain}?`}
          confirmLabel="Delete the domain"
          typeToConfirm={c.domain}
          onClose={() => setDeleting(false)}
          onConfirm={async () => {
            const r = await unwrap(api.DELETE("/domain", { body: { confirm: c.domain } }));
            setDeleteJob(r.job.id);
          }}
        >
          <p>Every account, group and joined computer in the domain is deleted for good. Type the domain name to confirm.</p>
        </ConfirmDialog>
      )}
    </>
  );
}

function Step({ children }: { children: ReactNode }) {
  return <li>{children}</li>;
}
