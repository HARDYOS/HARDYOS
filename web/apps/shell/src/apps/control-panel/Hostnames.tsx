import type { HostnamesStatus } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { dateTime, relativeTime } from "../../format";
import { Alert, Badge, Button, Card, ErrorBox, Field, Loading, PageHeader, Select, Stat, TextInput, Toggle } from "../../ui";
import { ConfirmDialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { daysLeft, dnsmasqLines, hostnamesState, routerRecords, tokenProblems } from "./hostnamesRules";
import { jobDone } from "./shareServices";

const KEY = ["hostnames"];

function useHostnames() {
  return useQuery({ queryKey: KEY, queryFn: () => unwrap(api.GET("/hostnames")), refetchInterval: 20000 });
}

/** Control Panel › Hostnames: apps at their own names under the base domain, with a trusted certificate. */
export function Hostnames() {
  const q = useHostnames();
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const st = q.data;
  const state = hostnamesState(st);
  return (
    <>
      <PageHeader
        title="Hostnames"
        subtitle="Give every app its own address, like https://photos.home.example.net, with a certificate browsers trust. Each app then runs on its own origin, apart from the desktop."
        badge={<Badge tone={state.tone}>{state.label}</Badge>}
      />
      {st.problem && <Alert tone="warn">{st.problem}</Alert>}
      <TokenCard st={st} />
      {st.token.set && <OnCard st={st} />}
      {st.token.set && <CertificateCard st={st} />}
      {st.names.length > 0 && <NamesCard st={st} />}
      {st.token.set && <LANCard st={st} />}
    </>
  );
}

function TokenCard({ st }: { st: HostnamesStatus }) {
  const qc = useQueryClient();
  const [token, setToken] = useState("");
  const [base, setBase] = useState(st.token.base || st.remoteBase);
  const [confirm, setConfirm] = useState(false);
  const problems = token ? tokenProblems(token, base, st.remoteBase) : [];
  const save = useMutation({
    mutationFn: () => jobDone(unwrap(api.PUT("/hostnames/token", { body: { token: token.trim(), base: base.trim().toLowerCase() } }))),
    onSuccess: () => {
      setToken("");
      toast("success", "Cloudflare token saved", "Cloudflare accepted it.");
      void qc.invalidateQueries({ queryKey: KEY });
    },
  });
  const verify = useMutation({
    mutationFn: () => jobDone(unwrap(api.POST("/hostnames/token/verify"))),
    onSuccess: () => {
      toast("success", "The token still works");
      void qc.invalidateQueries({ queryKey: KEY });
    },
    onError: (e) => {
      toast("error", "Cloudflare refused the token", errorMessage(e));
      void qc.invalidateQueries({ queryKey: KEY });
    },
  });
  return (
    <Card title="Cloudflare token">
      <p className="small muted">
        Create an API token in Cloudflare (My Profile › API Tokens) with only <strong>Zone › DNS › Edit</strong>, limited to the zone your base domain
        is in. HardyOS uses it to prove the domain is yours to Let&apos;s Encrypt. Only the system&apos;s root helper keeps it, encrypted; it is never
        shown again.
      </p>
      {st.token.set ? (
        <div className="grid-3">
          <Stat label="Token" value="Set" tone={st.token.problem ? "bad" : "good"} sub={`last verified ${relativeTime(st.token.verifiedAt)}`} />
          <Stat label="Base domain" value={<span className="mono">{st.token.base}</span>} />
          <Stat label="Cloudflare zone" value={<span className="mono">{st.token.zone}</span>} />
        </div>
      ) : (
        <Alert tone="info">Without a token apps keep opening on the server&apos;s own address and ports, with its self-signed certificate.</Alert>
      )}
      {st.token.problem && <Alert tone="bad">{st.token.problem}</Alert>}
      <Field label="Base domain" hint={st.remoteBase ? "Remote Access's base domain: names are the same at home and over NetBird." : "Apps become https://<app>.<base>."}>
        {(id) => <TextInput id={id} value={base} placeholder="home.example.net" onChange={(e) => setBase(e.target.value)} />}
      </Field>
      <Field label={st.token.set ? "New token" : "API token"} error={problems[0]}>
        {(id) => <TextInput id={id} type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} />}
      </Field>
      {save.error != null && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      <div className="row">
        <Button variant="primary" busy={save.isPending} disabled={!token || problems.length > 0} onClick={() => save.mutate()}>
          {st.token.set ? "Replace token" : "Save token"}
        </Button>
        {st.token.set && (
          <Button busy={verify.isPending} onClick={() => verify.mutate()}>
            Check again
          </Button>
        )}
        {st.token.set && (
          <Button variant="ghost" onClick={() => setConfirm(true)}>
            Forget token
          </Button>
        )}
      </div>
      {confirm && (
        <ConfirmDialog
          title="Forget the Cloudflare token?"
          confirmLabel="Forget token"
          typeToConfirm={st.token.base}
          onClose={() => setConfirm(false)}
          onConfirm={async () => {
            await jobDone(unwrap(api.DELETE("/hostnames/token", { body: { confirm: st.token.base } })));
            setConfirm(false);
            toast("success", "Token forgotten", "Apps are back on the server's own address.");
            void qc.invalidateQueries({ queryKey: KEY });
          }}
        >
          The certificate is removed and apps open on the server&apos;s address and ports again. DNS records stay in Cloudflare.
        </ConfirmDialog>
      )}
    </Card>
  );
}

function OnCard({ st }: { st: HostnamesStatus }) {
  const qc = useQueryClient();
  const [email, setEmail] = useState(st.settings.email);
  const [staging, setStaging] = useState(st.settings.staging);
  const save = useMutation({
    mutationFn: (enabled: boolean) => jobDone(unwrap(api.PUT("/hostnames/settings", { body: { enabled, email: email.trim(), staging } }))),
    onSuccess: (_, enabled) => {
      toast("success", enabled ? "Hostnames are on" : "Hostnames are off");
      void qc.invalidateQueries({ queryKey: KEY });
    },
    onError: (e) => {
      toast("error", "Couldn't save", errorMessage(e));
      void qc.invalidateQueries({ queryKey: KEY });
    },
  });
  return (
    <Card title="Serve apps at their hostnames">
      <Toggle
        label="Use hostnames"
        description="Turning on gets the certificate first (about a minute). Old addresses then send people to the new ones."
        checked={st.settings.enabled}
        disabled={save.isPending}
        onChange={(v) => save.mutate(v)}
      />
      <Field label="Contact email for Let's Encrypt" hint="Optional: warnings if renewing ever stops working.">
        {(id) => <TextInput id={id} type="email" value={email} onChange={(e) => setEmail(e.target.value)} />}
      </Field>
      <Toggle label="Test certificate (staging)" description="Untrusted certificates from Let's Encrypt's test server, for trying the setup." checked={staging} onChange={setStaging} />
      <div className="row">
        <Button busy={save.isPending} onClick={() => save.mutate(st.settings.enabled)}>
          Save
        </Button>
      </div>
    </Card>
  );
}

function CertificateCard({ st }: { st: HostnamesStatus }) {
  const qc = useQueryClient();
  const issue = useMutation({
    mutationFn: () => jobDone(unwrap(api.POST("/hostnames/certificate"))),
    onSuccess: () => {
      toast("success", "Certificate renewed");
      void qc.invalidateQueries({ queryKey: KEY });
    },
    onError: (e) => {
      toast("error", "Let's Encrypt didn't issue a certificate", errorMessage(e));
      void qc.invalidateQueries({ queryKey: KEY });
    },
  });
  const c = st.certificate;
  const left = c ? daysLeft(c.notAfter) : 0;
  return (
    <Card
      title="Certificate"
      actions={
        <Button size="sm" busy={issue.isPending} onClick={() => issue.mutate()}>
          {c ? "Renew now" : "Get certificate"}
        </Button>
      }
    >
      {c ? (
        <div className="grid-3">
          <Stat label="For" value={<span className="mono">{c.names.join(", ")}</span>} sub={c.issuer} />
          <Stat label="Valid until" value={dateTime(c.notAfter)} tone={left > 30 ? "good" : left > 7 ? "warn" : "bad"} sub={<span className="mono">{left} days</span>} />
          <Stat label="Renews" value={dateTime(c.renewsAt)} sub="by itself, 30 days before it expires" />
        </div>
      ) : (
        <p className="small muted">No certificate yet.</p>
      )}
      {st.lastError && (
        <Alert tone="bad" title={`Last try failed ${relativeTime(st.lastError.at)}`}>
          {st.lastError.error}
        </Alert>
      )}
    </Card>
  );
}

function NamesCard({ st }: { st: HostnamesStatus }) {
  return (
    <Card title="Names">
      <table className="table">
        <thead>
          <tr>
            <th>Address</th>
            <th>Opens</th>
          </tr>
        </thead>
        <tbody>
          {st.names.map((n) => (
            <tr key={n.label}>
              <td className="mono">{st.active ? <a href={`https://${n.host}/`} target="_blank" rel="noreferrer">{`https://${n.host}`}</a> : `https://${n.host}`}</td>
              <td>{n.what}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {st.active && st.desktopUrl && !location.host.startsWith(st.desktopUrl.replace("https://", "")) && (
        <Alert tone="info" title="Use the desktop at its own name">
          Apps open at their hostnames when the desktop itself is used at <a href={st.desktopUrl}>{st.desktopUrl}</a>. At this address they keep opening on
          their ports.
        </Alert>
      )}
    </Card>
  );
}

function LANCard({ st }: { st: HostnamesStatus }) {
  const qc = useQueryClient();
  const [addr, setAddr] = useState(st.lan.addresses[0] ?? "");
  const lan = useMutation({
    mutationFn: (remove: boolean) => jobDone(unwrap(api.POST("/hostnames/lan", { body: { remove, address: addr } }))),
    onSuccess: (_, remove) => {
      toast("success", remove ? "Removed from the domain's DNS" : "Added to the domain's DNS");
      void qc.invalidateQueries({ queryKey: KEY });
    },
    onError: (e) => toast("error", "Couldn't change the domain's DNS", errorMessage(e)),
  });
  const records = routerRecords(st, addr);
  return (
    <Card title="Finding the names at home">
      <p className="small muted">
        Public DNS sends these names to NetBird&apos;s proxy (Remote Access). At home, devices should reach this server directly: pick one of these.
      </p>
      <Field label="This server's address">
        {(id) => (
          <Select id={id} value={addr} onChange={(e) => setAddr(e.target.value)}>
            {st.lan.addresses.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <h3 className="small">This server&apos;s domain DNS</h3>
      {st.lan.domainDns ? (
        <>
          <p className="small muted">
            Devices that use the <span className="mono">{st.lan.domain}</span> domain controller for DNS find the names by themselves once they&apos;re added.
            Names another record already uses are left alone.
          </p>
          <div className="row">
            <Button variant="primary" busy={lan.isPending} disabled={!addr} onClick={() => lan.mutate(false)}>
              Add the names
            </Button>
            <Button variant="ghost" busy={lan.isPending} onClick={() => lan.mutate(true)}>
              Remove them
            </Button>
          </div>
        </>
      ) : (
        <p className="small muted">No domain controller runs on this server (Control Panel › Domain).</p>
      )}
      <h3 className="small">Your router&apos;s DNS</h3>
      <p className="small muted">Add these records as local DNS entries (in Pi-hole, OpenWrt or dnsmasq, the lines below do the same):</p>
      <table className="table">
        <tbody>
          {records.map((r) => (
            <tr key={r.name}>
              <td className="mono">{r.name}</td>
              <td>{r.type}</td>
              <td className="mono">{r.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <pre className="mono small">{dnsmasqLines(st, addr)}</pre>
      {st.lan.netbirdIp && (
        <p className="small muted">
          Over NetBird, the same names work at this server&apos;s NetBird address <span className="mono">{st.lan.netbirdIp}</span> for devices whose DNS
          points them there.
        </p>
      )}
    </Card>
  );
}
