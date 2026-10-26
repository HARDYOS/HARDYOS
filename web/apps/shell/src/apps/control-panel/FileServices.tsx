import type { FileServicesStatus } from "@hardy/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { dateTime } from "../../format";
import { useDataPools } from "../../hooks/queries";
import { ShareIcon } from "../../icons";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Field, Loading, PageHeader, Select, TextInput, Toggle } from "../../ui";
import { ConfirmDialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { JobProgress } from "../shared";
import { linuxMount, smbPath } from "./fileServicesRules";
import { useFileServices } from "./ShareSMBSection";
import { jobDone } from "./shareServices";

/** Control Panel > File Services: the SMB file server and how to connect. */
export function FileServices({ admin }: { admin: boolean }) {
  const files = useFileServices();
  if (files.isPending) return <Loading />;
  if (files.isError) return <ErrorBox error={files.error} onRetry={() => files.refetch()} />;
  const st = files.data;
  return (
    <>
      <PageHeader
        title="File Services"
        subtitle="Open the shared folders from Windows PCs, Macs and Linux, and back up Macs with Time Machine."
        badge={<HealthBadge st={st} />}
      />
      {!st.available ? (
        <Alert tone="warn" title="Not available in this build">
          This HardyOS build doesn't include the SMB file server. Install the latest update to get it.
        </Alert>
      ) : !st.joined ? (
        admin ? (
          <JoinCard st={st} onDone={() => void files.refetch()} />
        ) : (
          <Card>
            <EmptyState icon={<ShareIcon size={30} />} title="File sharing isn't set up yet">
              An administrator needs to connect this server to the domain first.
            </EmptyState>
          </Card>
        )
      ) : (
        <>
          {admin && st.problem && <Alert tone="warn">{st.problem}</Alert>}
          {admin && <ServerCard st={st} onDone={() => void files.refetch()} />}
          {admin && <HomesCard st={st} />}
          <HowToConnect st={st} />
        </>
      )}
    </>
  );
}

function HealthBadge({ st }: { st: FileServicesStatus }) {
  if (!st.available || !st.joined) return <Badge tone="neutral">Off</Badge>;
  if (!st.settings.smbEnabled) return <Badge tone="neutral">SMB off</Badge>;
  if (st.running && st.winbind) return <Badge tone="good">Sharing</Badge>;
  return <Badge tone="warn">Needs attention</Badge>;
}

// ---- joining -----------------------------------------------------------

function JoinCard({ st, onDone }: { st: FileServicesStatus; onDone: () => void }) {
  const own = st.localDomain !== "";
  const [domain, setDomain] = useState(st.localDomain);
  const [user, setUser] = useState("Administrator");
  const [password, setPassword] = useState("");
  const [jobId, setJobId] = useState<string | null>(null);
  const start = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/files/join", {
          body: { domain: own && domain === st.localDomain ? undefined : domain.trim(), adminUser: user.trim() || undefined, adminPassword: password },
        }),
      ),
    onSuccess: (r) => {
      setPassword("");
      setJobId(r.job.id);
    },
  });
  if (jobId) {
    return (
      <Card title="Joining the domain">
        <JobProgress
          id={jobId}
          onDone={(j) => {
            if (j.state === "succeeded") {
              toast("success", "The shared folders can be opened from computers now");
              onDone();
            }
          }}
        />
        <div style={{ marginTop: 12 }}>
          <Button size="sm" onClick={() => setJobId(null)}>
            Back
          </Button>
        </div>
      </Card>
    );
  }
  const ready = domain.trim() !== "" && password !== "";
  return (
    <Card title="Join the domain">
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) start.mutate();
        }}
      >
        <span className="small muted">
          Family members open the shared folders with their domain account. This server joins the domain as its file server, named{" "}
          <span className="mono">{st.serverName}</span>.
          {own ? " This server runs the domain itself, so this takes a few seconds." : " The domain must be reachable: this server needs to use its DNS servers."}
        </span>
        <Field label="Domain" hint={own ? "This server's own domain." : "Its DNS name, like home.yourname.net."}>
          {(id) => <TextInput id={id} className="input mono" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="home.yourname.net" spellCheck={false} />}
        </Field>
        {!own && (
          <Field label="Administrator account">
            {(id) => <TextInput id={id} value={user} onChange={(e) => setUser(e.target.value)} autoComplete="username" />}
          </Field>
        )}
        <Field label="Password" hint="Used once to add this server to the domain; it isn't kept.">
          {(id) => <TextInput id={id} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />}
        </Field>
        {start.isError && <Alert tone="bad">{errorMessage(start.error)}</Alert>}
        <div>
          <Button type="submit" variant="primary" disabled={!ready} busy={start.isPending}>
            Join the domain
          </Button>
        </div>
      </form>
    </Card>
  );
}

// ---- the server --------------------------------------------------------

function ServerCard({ st, onDone }: { st: FileServicesStatus; onDone: () => void }) {
  const qc = useQueryClient();
  const [leaving, setLeaving] = useState(false);
  const [password, setPassword] = useState("");
  const toggle = useMutation({
    mutationFn: (on: boolean) => jobDone(unwrap(api.PATCH("/files/settings", { body: { smbEnabled: on } }))),
    onSuccess: (_, on) => {
      toast("success", on ? "SMB sharing is on" : "SMB sharing is off");
      void qc.invalidateQueries({ queryKey: ["files"] });
    },
  });
  const shared = st.shares.filter((s) => s.available);
  return (
    <Card title="SMB file server">
      <div className="stack">
        <div className="grid-2">
          <div className="stack" style={{ gap: 2 }}>
            <span className="small muted">Domain</span>
            <span className="mono">{st.domain?.domain}</span>
          </div>
          <div className="stack" style={{ gap: 2 }}>
            <span className="small muted">Server name</span>
            <span className="mono">{st.serverName}</span>
          </div>
          <div className="stack" style={{ gap: 2 }}>
            <span className="small muted">Sign-ins</span>
            <span>{st.winbind ? <Badge tone="good">The domain answers</Badge> : <Badge tone="bad">Can't reach the domain</Badge>}</span>
          </div>
          <div className="stack" style={{ gap: 2 }}>
            <span className="small muted">Shared folders offered</span>
            <span className="mono">{shared.length}</span>
          </div>
        </div>
        {st.joinedAt && <span className="small muted">Joined {dateTime(st.joinedAt)}.</span>}
        <Toggle
          label="SMB sharing"
          description="Windows PCs and Macs can open the shared folders that have SMB on. Turning it off stops sharing all of them."
          checked={st.settings.smbEnabled}
          disabled={toggle.isPending}
          onChange={(v) => toggle.mutate(v)}
        />
        {toggle.isError && <Alert tone="bad">{errorMessage(toggle.error)}</Alert>}
        <div>
          <Button variant="danger" size="sm" onClick={() => setLeaving(true)}>
            Leave the domain
          </Button>
        </div>
      </div>
      {leaving && (
        <ConfirmDialog
          title={`Leave ${st.domain?.domain}?`}
          confirmLabel="Leave the domain"
          onClose={() => {
            setLeaving(false);
            setPassword("");
          }}
          onConfirm={async () => {
            await jobDone(
              unwrap(api.POST("/files/leave", { body: { confirm: true, adminPassword: password || undefined } })),
            );
            toast("success", "This server left the domain");
            onDone();
          }}
        >
          <div className="stack">
            <span>Computers can't open the shared folders any more until this server joins again. The files and their permissions stay.</span>
            <Field label="Administrator password (optional)" hint="With it, this server's computer account is removed from the domain too.">
              {(id) => <TextInput id={id} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />}
            </Field>
          </div>
        </ConfirmDialog>
      )}
    </Card>
  );
}

function HomesCard({ st }: { st: FileServicesStatus }) {
  const qc = useQueryClient();
  const pools = useDataPools(true);
  const h = st.settings.homes;
  const [enabled, setEnabled] = useState(h.enabled);
  const [pool, setPool] = useState(h.pool);
  const [quota, setQuota] = useState(h.quotaBytes ? String(Math.round(h.quotaBytes / 1e9)) : "");
  const names = pools.data?.map((p) => p.name) ?? [];
  const poolNow = pool || names[0] || "";
  const qGB = quota.trim() === "" ? 0 : Number(quota);
  const qProblem = quota.trim() !== "" && (!Number.isFinite(qGB) || qGB <= 0) ? "Enter a number of GB, or leave it empty for no limit." : null;
  const changed = enabled !== h.enabled || (enabled && (poolNow !== h.pool || Math.round(qGB * 1e9) !== h.quotaBytes));
  const save = useMutation({
    mutationFn: () => jobDone(unwrap(api.PATCH("/files/settings", { body: { homes: { enabled, pool: enabled ? poolNow : h.pool, quotaBytes: Math.round(qGB * 1e9) } } }))),
    onSuccess: () => {
      toast("success", enabled ? "Home folders are on" : "Home folders are off");
      void qc.invalidateQueries({ queryKey: ["files"] });
    },
  });
  return (
    <Card title="Home folders">
      <div className="stack">
        <Toggle
          label="A home folder for everyone"
          description="Each domain account gets its own private folder, which shows as their name on the network and as Home in the File Manager."
          checked={enabled}
          onChange={setEnabled}
        />
        {enabled && (
          <div className="grid-2">
            <Field label="Pool" hint={h.enabled && h.pool ? "Home folders stay where they were made; a new pool is used for new accounts." : undefined}>
              {(id) => (
                <Select id={id} value={poolNow} onChange={(e) => setPool(e.target.value)}>
                  {names.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label="Quota for each (GB)" error={qProblem} hint="Leave empty for no limit.">
              {(id) => <TextInput id={id} className="input mono" inputMode="decimal" value={quota} onChange={(e) => setQuota(e.target.value)} placeholder="No limit" />}
            </Field>
          </div>
        )}
        {enabled && names.length === 0 && <Alert tone="warn">Create a pool in Storage first.</Alert>}
        {save.isError && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
        {changed && (
          <div>
            <Button variant="primary" size="sm" disabled={!!qProblem || (enabled && !poolNow)} busy={save.isPending} onClick={() => save.mutate()}>
              Save
            </Button>
          </div>
        )}
      </div>
    </Card>
  );
}

// ---- how to connect ----------------------------------------------------

function HowToConnect({ st }: { st: FileServicesStatus }) {
  const shares = st.shares.filter((s) => s.available);
  const first = shares[0]?.name ?? "Media";
  const host = st.hostName || st.serverName.toLowerCase();
  const ip = st.addresses[0];
  const nb = st.domain?.netbios ?? "HOME";
  const tm = shares.filter((s) => s.timeMachine);
  return (
    <Card title="How to connect">
      <div className="stack">
        {!st.settings.smbEnabled && <Alert tone="info">SMB sharing is off right now.</Alert>}
        <div className="stack" style={{ gap: 4 }}>
          <strong className="small">Windows</strong>
          <span className="small">
            In File Explorer's address bar type <span className="mono">{smbPath("windows", st.serverName, first)}</span>, or right-click This PC › Map network
            drive. Sign in as <span className="mono">{nb}\yourname</span> (PCs joined to the domain sign in by themselves).
          </span>
        </div>
        <div className="stack" style={{ gap: 4 }}>
          <strong className="small">Mac</strong>
          <span className="small">
            In Finder choose Go › Connect to Server and enter <span className="mono">{smbPath("mac", host, first)}</span>
            {ip && (
              <>
                {" "}
                (or <span className="mono">{smbPath("mac", ip, first)}</span>)
              </>
            )}
            . The server also shows up under Network in the sidebar.
          </span>
        </div>
        <div className="stack" style={{ gap: 4 }}>
          <strong className="small">Linux</strong>
          <span className="small">
            File managers open <span className="mono">{smbPath("linux", host, first)}</span>. From a terminal (cifs-utils):
          </span>
          <pre className="log-view" aria-label="Linux mount command">
            {linuxMount(host, first, nb)}
          </pre>
        </div>
        <div className="stack" style={{ gap: 4 }}>
          <strong className="small">Time Machine</strong>
          <span className="small">
            {tm.length > 0 ? (
              <>
                On a Mac open System Settings › General › Time Machine › Add Backup Disk and pick{" "}
                <span className="mono">{tm.map((s) => s.name).join(", ")}</span> on {st.serverName}.
              </>
            ) : (
              "Turn Time Machine on for a shared folder (Shared Folders › Edit) to back up Macs to it."
            )}
          </span>
        </div>
        {shares.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Shared folder</th>
                  <th>Windows</th>
                  <th>Mac and Linux</th>
                </tr>
              </thead>
              <tbody>
                {shares.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <strong>{s.name}</strong>
                      <div className="row" style={{ gap: 6, marginTop: 4 }}>
                        {s.timeMachine && <Badge tone="info">Time Machine</Badge>}
                        {s.previousVersions && <Badge tone="neutral">Previous Versions</Badge>}
                        {s.guest && <Badge tone="neutral">Guests can read</Badge>}
                      </div>
                    </td>
                    <td className="mono small">{smbPath("windows", st.serverName, s.name)}</td>
                    <td className="mono small">{smbPath("mac", host, s.name)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {st.settings.homes.enabled && (
          <span className="small muted">
            Your home folder: <span className="mono">{smbPath("windows", st.serverName, "yourname")}</span>.
          </span>
        )}
      </div>
    </Card>
  );
}
