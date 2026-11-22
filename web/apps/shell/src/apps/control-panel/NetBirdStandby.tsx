import type { NBStandbyDNSPreview, NBStandbyStatus, NBStandbyVPSStatus } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { bytes, dateTime, relativeTime } from "../../format";
import { Alert, Badge, Button, Card, ErrorBox, Field, Loading, PageHeader, Stat, TextInput, Toggle } from "../../ui";
import { ConfirmDialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { addressList, copyAge, formProblems, type StandbyForm, standbyState, takeoverBlockers } from "./netbirdStandbyRules";
import { jobDone } from "./shareServices";

const KEY = ["netbird-standby"];

function useStandby() {
  return useQuery({ queryKey: KEY, queryFn: () => unwrap(api.GET("/netbird-standby")), refetchInterval: 15000 });
}

/** Control Panel › NetBird Standby: a stopped copy of the VPS's NetBird server, taken over by hand. */
export function NetBirdStandby() {
  const q = useStandby();
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const st = q.data;
  const state = standbyState(st);
  const taken = st.connection?.mode === "takenover";
  return (
    <>
      <PageHeader
        title="NetBird Standby"
        subtitle="This server keeps a copy of your VPS's NetBird server, stopped. If the VPS goes down, take over with one click: NetBird's name then points here until you hand it back."
        badge={<Badge tone={state.tone}>{state.label}</Badge>}
      />
      {st.problem && <Alert tone="bad">{st.problem}</Alert>}
      {st.versionNote && <Alert tone={st.versionNewer ? "warn" : "info"}>{st.versionNote}</Alert>}
      {taken ? <TakenOverCard st={st} /> : null}
      <ConnectionCard st={st} />
      {st.connection?.configured && !taken && <ScriptCard />}
      {st.connection?.hostname && <AppCard st={st} />}
      {st.connection?.hostname && <DNSCard st={st} />}
      {st.connection?.configured && <SyncCard st={st} />}
      <PortsCard st={st} />
      {st.connection?.configured && !taken && <TakeoverCard st={st} />}
      {st.connection?.configured && !taken && <ForgetCard st={st} />}
    </>
  );
}

function formOf(st: NBStandbyStatus): StandbyForm {
  const c = st.connection;
  return {
    hostname: c?.hostname ?? "",
    vpsHost: c?.vpsHost ?? "",
    vpsPort: String(c?.vpsPort || 22),
    vpsUser: c?.vpsUser || "hardyos-standby",
    hostKey: c?.hostKey ?? "",
    publicIPv4: c?.publicIPv4 ?? st.settings.publicIPv4,
    publicIPv6: c?.publicIPv6 ?? st.settings.publicIPv6,
    intervalMinutes: String(st.settings.intervalMinutes || 15),
    connectFrom: (st.settings.connectFrom.length ? st.settings.connectFrom : st.clientIp ? [st.clientIp] : []).join(", "),
  };
}

function ConnectionCard({ st }: { st: NBStandbyStatus }) {
  const qc = useQueryClient();
  const [f, setF] = useState<StandbyForm>(() => formOf(st));
  const [autoSync, setAutoSync] = useState(st.settings.autoSync);
  const [addressConfirm, setAddressConfirm] = useState("");
  const addressChanged = (c0: typeof st.connection) =>
    !!c0 && (f.publicIPv4.trim() !== (c0.publicIPv4 ?? "") || f.publicIPv6.trim() !== (c0.publicIPv6 ?? ""));
  const needsConfirm = addressChanged(st.connection);
  const problems = formProblems(f);
  const confirmOK = !needsConfirm || addressConfirm.trim().toLowerCase() === f.hostname.trim().toLowerCase();
  const taken = st.connection?.mode === "takenover";
  const save = useMutation({
    mutationFn: (newKey: boolean) =>
      jobDone(
        unwrap(
          api.PUT("/netbird-standby/settings", {
            body: {
              hostname: f.hostname.trim().toLowerCase(),
              vpsHost: f.vpsHost.trim(),
              vpsPort: Number(f.vpsPort || "22"),
              vpsUser: f.vpsUser.trim(),
              hostKey: f.hostKey.trim(),
              newKey,
              addressConfirm: addressConfirm.trim(),
              settings: {
                intervalMinutes: Number(f.intervalMinutes || "15"),
                autoSync,
                publicIPv4: f.publicIPv4.trim(),
                publicIPv6: f.publicIPv6.trim(),
                connectFrom: addressList(f.connectFrom),
              },
            },
          }),
        ),
      ),
    onSuccess: (_, newKey) => {
      toast("success", newKey ? "New key made" : "Saved", newKey ? "Run the VPS script again so the VPS knows it." : undefined);
      void qc.invalidateQueries({ queryKey: KEY });
    },
    onError: (e) => toast("error", "Couldn't save", errorMessage(e)),
  });
  const set = (k: keyof StandbyForm) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const c = st.connection;
  return (
    <Card title="1. The VPS and this server">
      <p className="small muted">
        HardyOS reads the VPS over SSH with a key only it holds, which the VPS lets run one fixed command (copy the NetBird server, report its status and,
        if you allow it, take the state back). Nothing else can run on the VPS with it.
      </p>
      <div className="grid-2">
        <Field label="NetBird server's name" hint="The name peers connect to, for example vpn.example.net.">
          {(id) => <TextInput id={id} value={f.hostname} placeholder="vpn.example.net" onChange={set("hostname")} disabled={taken} />}
        </Field>
        <Field label="VPS address for SSH" hint="Its NetBird address works too.">
          {(id) => <TextInput id={id} value={f.vpsHost} placeholder="vps.example.net" onChange={set("vpsHost")} disabled={taken} />}
        </Field>
        <Field label="SSH port">{(id) => <TextInput id={id} inputMode="numeric" className="mono" value={f.vpsPort} onChange={set("vpsPort")} disabled={taken} />}</Field>
        <Field label="VPS user" hint="Made by the VPS script.">
          {(id) => <TextInput id={id} value={f.vpsUser} onChange={set("vpsUser")} disabled={taken} />}
        </Field>
      </div>
      <Field label="VPS host key" hint="The VPS script prints it at the end (or: ssh-keyscan -t ed25519 <vps>). HardyOS refuses any other key.">
        {(id) => <TextInput id={id} className="mono" value={f.hostKey} placeholder="ssh-ed25519 AAAA…" onChange={set("hostKey")} disabled={taken} />}
      </Field>
      <div className="grid-2">
        <Field label="This server's public IPv4 address" hint="Where your router forwards the NetBird ports. DNS points here on a take-over.">
          {(id) => <TextInput id={id} className="mono" value={f.publicIPv4} placeholder="203.0.113.5" onChange={set("publicIPv4")} />}
        </Field>
        <Field label="Public IPv6 address (optional)" hint="Needed if the name has an AAAA record.">
          {(id) => <TextInput id={id} className="mono" value={f.publicIPv6} onChange={set("publicIPv6")} />}
        </Field>
        <Field label="Copy every (minutes)" hint="5 to 1440.">
          {(id) => <TextInput id={id} inputMode="numeric" className="mono" value={f.intervalMinutes} onChange={set("intervalMinutes")} />}
        </Field>
        <Field label="HardyOS connects from" hint="The VPS accepts the key only from these addresses (this server's NetBird or public address). Empty: from anywhere.">
          {(id) => <TextInput id={id} className="mono" value={f.connectFrom} onChange={set("connectFrom")} />}
        </Field>
      </div>
      <Toggle label="Copy automatically" description="Off: only when you press Copy now." checked={autoSync} onChange={setAutoSync} />
      {needsConfirm && (
        <Field
          label={`Type ${f.hostname || "the NetBird name"} to change the public address`}
          hint="On a take-over DNS can point the NetBird name only at this address, so changing it needs the name typed."
        >
          {(id) => <TextInput id={id} value={addressConfirm} autoComplete="off" onChange={(e) => setAddressConfirm(e.target.value)} />}
        </Field>
      )}
      {problems.length > 0 && f.hostname && <Alert tone="warn">{problems[0]}</Alert>}
      {c?.publicKey && (
        <div className="grid-2">
          <Stat label="HardyOS's key" value={<span className="mono small">{c.publicKey.slice(0, 32)}…</span>} sub={c.keyCreated ? `made ${relativeTime(c.keyCreated)}` : undefined} />
          <Stat label="VPS host key" value={<span className="mono small">{c.hostKeyFingerprint || "—"}</span>} />
        </div>
      )}
      <div className="row">
        <Button variant="primary" busy={save.isPending} disabled={problems.length > 0 || !confirmOK} onClick={() => save.mutate(false)}>
          Save
        </Button>
        {c?.publicKey && !taken && (
          <Button variant="ghost" busy={save.isPending} disabled={problems.length > 0 || !confirmOK} onClick={() => save.mutate(true)}>
            Make a new key
          </Button>
        )}
      </div>
    </Card>
  );
}

function ScriptCard() {
  const [script, setScript] = useState("");
  const [fingerprint, setFingerprint] = useState("");
  const [vps, setVPS] = useState<NBStandbyVPSStatus | null>(null);
  const load = useMutation({
    mutationFn: () => unwrap(api.GET("/netbird-standby/script")),
    onSuccess: (r) => {
      setScript(r.script);
      setFingerprint(r.fingerprint);
    },
    onError: (e) => toast("error", "No script", errorMessage(e)),
  });
  const check = useMutation({
    mutationFn: () => unwrap(api.GET("/netbird-standby/vps")),
    onSuccess: (r) => setVPS(r),
    onError: (e) => {
      setVPS(null);
      toast("error", "The VPS didn't answer", errorMessage(e));
    },
  });
  const download = () => {
    const url = URL.createObjectURL(new Blob([script], { type: "text/x-shellscript" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "hardyos-standby.sh";
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <Card title="2. Set up the VPS">
      <p className="small muted">
        Run this script on the VPS as root, once (and again after a new key). Add <span className="mono">--allow-handback</span> to let HardyOS stop the
        VPS&apos;s server on a take-over and hand state back; without it HardyOS can only read. Paste the host key it prints above.
      </p>
      <p className="small muted">
        The script prints the fingerprint of the key it installed. Compare it with{" "}
        <span className="mono">sudo hardyctl netbird-standby fingerprint</span> on this server&apos;s console (not only with this page){fingerprint ? (
          <>
            : <span className="mono">{fingerprint}</span>
          </>
        ) : null}
        .
      </p>
      <div className="row">
        <Button busy={load.isPending} onClick={() => load.mutate()}>
          {script ? "Reload script" : "Show the script"}
        </Button>
        {script && <Button onClick={download}>Download</Button>}
        {script && <Button onClick={() => void navigator.clipboard?.writeText(script).then(() => toast("success", "Copied"))}>Copy</Button>}
        <Button variant="ghost" busy={check.isPending} onClick={() => check.mutate()}>
          Check the VPS
        </Button>
      </div>
      {vps && (
        <div className="grid-3">
          <Stat label="NetBird on the VPS" value={vps.running ? "Running" : "Stopped"} tone={vps.running ? "good" : "bad"} sub={vps.version ? <span className="mono">{vps.version}</span> : undefined} />
          <Stat
            label="Hand back"
            value={!vps.handbackInstalled ? "Not installed" : vps.restoreAllowed ? "Armed" : "Not armed"}
            tone={vps.restoreAllowed ? "good" : "warn"}
            sub={
              vps.restoreAllowed
                ? `until ${dateTime(vps.restoreArmedUntil)}`
                : vps.fenced
                  ? `fenced (stopped by HardyOS)${vps.fencedUntil ? ` until ${dateTime(vps.fencedUntil)} unless renewed` : ""}`
                  : undefined
            }
          />
          <Stat label="Name" value={<span className="mono">{vps.hostname || "—"}</span>} />
        </div>
      )}
      {script && <pre className="mono small" style={{ maxHeight: 280, overflow: "auto" }}>{script}</pre>}
    </Card>
  );
}

function AppCard({ st }: { st: NBStandbyStatus }) {
  const qc = useQueryClient();
  const install = useMutation({
    mutationFn: () => jobDone(unwrap(api.POST("/netbird-standby/install", { body: {} }))),
    onSuccess: () => {
      toast("success", "The standby is installed", "It stays stopped until a take-over.");
      void qc.invalidateQueries({ queryKey: KEY });
    },
    onError: (e) => toast("error", "Couldn't install the standby", errorMessage(e)),
  });
  return (
    <Card title="3. The standby server">
      <p className="small muted">
        NetBird&apos;s own server, dashboard and Traefik ({st.standbyVersion}), the same as on the VPS. Installed but stopped: it starts only on a
        take-over.
      </p>
      {st.app.installed ? (
        <div className="grid-3">
          <Stat label="App" value="Installed" tone="good" sub={<span className="mono">{st.app.version}</span>} />
          <Stat label="State" value={st.app.state} tone={st.app.state === "running" ? "accent" : "neutral"} />
          <Stat label="Ports" value={st.connection?.networkOpen ? "Open" : "Closed"} tone={st.connection?.networkOpen ? "accent" : "neutral"} sub="closed unless taken over" />
        </div>
      ) : (
        <Button variant="primary" busy={install.isPending} disabled={st.connection?.mode === "takenover"} onClick={() => install.mutate()}>
          Install the standby
        </Button>
      )}
    </Card>
  );
}

function DNSCard({ st }: { st: NBStandbyStatus }) {
  const qc = useQueryClient();
  const host = st.connection?.hostname ?? "";
  const [preview, setPreview] = useState<NBStandbyDNSPreview | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [token, setToken] = useState("");
  const [rebind, setRebind] = useState(false);
  const look = useMutation({
    mutationFn: () => unwrap(api.GET("/netbird-standby/dns", { params: { query: { name: host } } })),
    onSuccess: setPreview,
    onError: (e) => toast("error", "Couldn't look the name up", errorMessage(e)),
  });
  const adopted = st.dns.name === host && host !== "";
  return (
    <Card title="4. NetBird's name in Cloudflare">
      {!st.dns.tokenSet ? (
        <Alert tone="info">Save a Cloudflare token in Control Panel › Hostnames first. A take-over changes {host}&apos;s record with it.</Alert>
      ) : !st.dns.inZone ? (
        <Alert tone="bad">
          {host} isn&apos;t in the Cloudflare zone {st.dns.zone} the token is for: HardyOS can&apos;t change its DNS.
        </Alert>
      ) : adopted ? (
        <>
          <p className="small muted">HardyOS may change these records of {host} on a take-over and puts them back exactly on hand-back. Nothing else in the zone.</p>
          <RecordTable records={st.dns.adopted} />
          {st.dns.bound && (
            <p className="small muted">
              Allowed for <span className="mono">{[st.dns.bound.ipv4, st.dns.bound.ipv6].filter(Boolean).join(", ")}</span> with the VPS{" "}
              <span className="mono">
                {st.dns.bound.vpsHost}:{st.dns.bound.vpsPort}
              </span>{" "}
              (host key <span className="mono">{st.dns.bound.hostKeyFingerprint}</span>).
            </p>
          )}
          {st.dns.needsRebind && (
            <Alert tone="warn">
              This server&apos;s public address or the VPS changed since {host} was allowed: a take-over is refused until you confirm the new values with the
              Cloudflare token (or run <span className="mono">sudo hardyctl netbird-standby rebind</span> on this server&apos;s console).
              <div className="row">
                <Button variant="primary" onClick={() => setRebind(true)}>
                  Confirm the new values
                </Button>
              </div>
            </Alert>
          )}
        </>
      ) : (
        <>
          <p className="small muted">
            {st.dns.inBase
              ? `${host} is under the hostnames' base domain.`
              : `${host} isn't under the hostnames' base domain (${st.dns.base}), so HardyOS may change it only after you allow exactly this one name.`}{" "}
            Look at its records now; HardyOS remembers them to put them back.
          </p>
          <div className="row">
            <Button busy={look.isPending} onClick={() => look.mutate()}>
              Look up {host}
            </Button>
            {preview?.adoptable && (
              <Button variant="primary" onClick={() => setConfirm(true)}>
                Let HardyOS manage it
              </Button>
            )}
          </div>
          {preview && <RecordTable records={preview.records} />}
          {preview?.problem && <Alert tone="warn">{preview.problem}</Alert>}
        </>
      )}
      {rebind && (
        <ConfirmDialog
          title={`Allow the new values for ${host}?`}
          confirmLabel="Allow"
          danger={false}
          canConfirm={token.trim().length >= 20}
          onClose={() => {
            setRebind(false);
            setToken("");
          }}
          onConfirm={async () => {
            await jobDone(unwrap(api.POST("/netbird-standby/dns/rebind", { body: { token: token.trim() } })));
            setToken("");
            toast("success", `The new values are allowed for ${host}`);
            void qc.invalidateQueries({ queryKey: KEY });
          }}
        >
          On a take-over HardyOS will point {host} at {[st.settings.publicIPv4, st.settings.publicIPv6].filter(Boolean).join(", ") || "this server"} and copy from{" "}
          {st.connection?.vpsHost} (host key <span className="mono">{st.connection?.hostKeyFingerprint}</span>). Check these are yours.
          <Field label="Cloudflare token, pasted again" hint="The one saved in Control Panel › Hostnames: this step needs the person who holds it.">
            {(id) => <TextInput id={id} type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} />}
          </Field>
        </ConfirmDialog>
      )}
      {confirm && preview && (
        <ConfirmDialog
          title={`Let HardyOS manage ${host}?`}
          confirmLabel="Allow"
          danger={false}
          typeToConfirm={host}
          canConfirm={token.trim().length >= 20}
          onClose={() => {
            setConfirm(false);
            setToken("");
          }}
          onConfirm={async () => {
            await jobDone(
              unwrap(api.POST("/netbird-standby/dns", { body: { name: host, confirm: host, ids: preview.records.map((r) => r.id), token: token.trim() } })),
            );
            setToken("");
            toast("success", `HardyOS manages ${host}`);
            void qc.invalidateQueries({ queryKey: KEY });
          }}
        >
          On a take-over HardyOS points these records at this server ({st.settings.publicIPv4 || "its public address"}) with a 60-second TTL, and on hand-back
          sets them back to what they are now. No other record in {st.dns.zone} can be changed.
          <Field label="Cloudflare token, pasted again" hint="The one saved in Control Panel › Hostnames: this step needs the person who holds it.">
            {(id) => <TextInput id={id} type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} />}
          </Field>
        </ConfirmDialog>
      )}
    </Card>
  );
}

function RecordTable({ records }: { records: { id: string; type: string; content: string; ttl: number; proxied: boolean }[] }) {
  if (records.length === 0) return <p className="small muted">No records.</p>;
  return (
    <table className="table">
      <thead>
        <tr>
          <th>Type</th>
          <th>Points to</th>
          <th>TTL</th>
          <th>Proxied</th>
        </tr>
      </thead>
      <tbody>
        {records.map((r) => (
          <tr key={r.id}>
            <td>{r.type}</td>
            <td className="mono">{r.content}</td>
            <td className="mono">{r.ttl === 1 ? "auto" : r.ttl}</td>
            <td>{r.proxied ? "Yes" : "No"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SyncCard({ st }: { st: NBStandbyStatus }) {
  const qc = useQueryClient();
  const sync = useMutation({
    mutationFn: () => jobDone(unwrap(api.POST("/netbird-standby/sync"))),
    onSuccess: () => {
      toast("success", "Copied the VPS");
      void qc.invalidateQueries({ queryKey: KEY });
    },
    onError: (e) => {
      toast("error", "The copy failed", errorMessage(e));
      void qc.invalidateQueries({ queryKey: KEY });
    },
  });
  const c = st.connection;
  const s = c?.snapshots[0];
  const taken = c?.mode === "takenover";
  return (
    <Card
      title="Copies of the VPS"
      actions={
        !taken && (
          <Button size="sm" busy={sync.isPending} onClick={() => sync.mutate()}>
            Copy now
          </Button>
        )
      }
    >
      <div className="grid-3">
        <Stat label="Newest copy" value={s ? copyAge(st) : "None"} tone={st.health.stale ? "bad" : s ? "good" : "warn"} sub={s ? dateTime(s.at) : undefined} />
        <Stat label="Size" value={<span className="mono">{s ? bytes(s.info.bytes) : "—"}</span>} sub={s ? `${s.info.peers} peers, ${s.info.setupKeys} setup keys` : undefined} />
        <Stat
          label="VPS version"
          value={<span className="mono">{s?.info.version || "—"}</span>}
          sub={s?.info.certNotAfter ? `certificate until ${dateTime(s.info.certNotAfter)}` : undefined}
          tone={st.versionNewer ? "warn" : undefined}
        />
      </div>
      {st.health.problem && <Alert tone={st.health.stale ? "bad" : "warn"}>{st.health.problem}</Alert>}
      {st.health.stale && <Alert tone="bad">No good copy for over {st.health.staleAfterMinutes} minutes: a take-over now brings back older peers and settings.</Alert>}
      {!taken && st.health.nextSync && st.settings.autoSync && <p className="small muted">Next copy {relativeTime(st.health.nextSync)}.</p>}
      {s?.info.warnings.map((w) => (
        <Alert key={w} tone="info">
          {w}
        </Alert>
      ))}
      {st.history.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>When</th>
              <th>Result</th>
              <th>Size</th>
            </tr>
          </thead>
          <tbody>
            {st.history.slice(0, 8).map((h) => (
              <tr key={h.startedAt + h.finishedAt}>
                <td>{relativeTime(h.startedAt)}</td>
                <td>{h.ok ? <Badge tone="good">Copied</Badge> : <span className="small">{h.error}</span>}</td>
                <td className="mono">{h.ok ? bytes(h.bytes) : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

function PortsCard({ st }: { st: NBStandbyStatus }) {
  return (
    <Card title="Router port forwards">
      <p className="small muted">
        Peers reach the standby from the internet only through your router. HardyOS can&apos;t change it: add these forwards to this server&apos;s LAN
        address. They stay closed on this server (firewall) until a take-over.
      </p>
      <table className="table">
        <thead>
          <tr>
            <th>Protocol</th>
            <th>Public port</th>
            <th>To this server</th>
            <th>For</th>
          </tr>
        </thead>
        <tbody>
          {st.portForwards.map((p) => (
            <tr key={p.protocol + p.public}>
              <td>{p.protocol}</td>
              <td className="mono">{p.public}</td>
              <td className="mono">{p.internal}</td>
              <td>{p.purpose}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="small muted">This server itself and the apps on it reach the standby locally during a take-over, without the router.</p>
    </Card>
  );
}

function TakeoverCard({ st }: { st: NBStandbyStatus }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [acceptVersion, setAcceptVersion] = useState(false);
  const [acceptAlive, setAcceptAlive] = useState(false);
  const host = st.connection?.hostname ?? "";
  const blockers = takeoverBlockers(st);
  return (
    <Card title="Take over">
      <p className="small muted">
        Only when the VPS is down (or you&apos;re moving NetBird here). HardyOS stops copying, starts the standby with the newest copy ({copyAge(st) || "none"}),
        opens its ports and points {host} at {st.connection?.publicIPv4 || "this server"}. If the VPS still answers, HardyOS stops its NetBird server first
        (fence), so peers drop their old connections and come here.
      </p>
      {blockers.map((b) => (
        <Alert key={b} tone="warn">
          {b}
        </Alert>
      ))}
      <Button variant="danger" disabled={blockers.length > 0} onClick={() => setOpen(true)}>
        Take over
      </Button>
      {open && (
        <ConfirmDialog
          title={`Take over ${host}?`}
          confirmLabel="Take over"
          typeToConfirm={host}
          canConfirm={!st.versionNewer || acceptVersion}
          onClose={() => setOpen(false)}
          onConfirm={async () => {
            await jobDone(unwrap(api.POST("/netbird-standby/takeover", { body: { confirm: host, acceptVersion, acceptVpsAlive: acceptAlive } })));
            toast("success", "HardyOS has taken over", `${host} points at this server now.`);
            void qc.invalidateQueries({ queryKey: KEY });
          }}
        >
          <p>
            NetBird has one server at a time. While HardyOS runs it, changes made on the VPS are lost on hand-back, and if the VPS comes back on its own, peers
            that still use its old address talk to a stale copy. Hand back from here when the VPS is healthy.
          </p>
          {st.versionNewer && (
            <label className="row small">
              <input type="checkbox" checked={acceptVersion} onChange={(e) => setAcceptVersion(e.target.checked)} />
              The VPS runs a newer NetBird than the standby; take over anyway.
            </label>
          )}
          <label className="row small">
            <input type="checkbox" checked={acceptAlive} onChange={(e) => setAcceptAlive(e.target.checked)} />
            If the VPS still works, stop its NetBird server and take over anyway (otherwise HardyOS stops when the VPS answers).
          </label>
        </ConfirmDialog>
      )}
    </Card>
  );
}

function TakenOverCard({ st }: { st: NBStandbyStatus }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [ack, setAck] = useState(false);
  const [discard, setDiscard] = useState(false);
  const host = st.connection?.hostname ?? "";
  const t = st.takeover;
  return (
    <Card title={`HardyOS runs ${host}`}>
      <div className="grid-3">
        <Stat label="Since" value={t ? relativeTime(t.at) : st.connection?.takenOverAt ? relativeTime(st.connection.takenOverAt) : "—"} sub={t?.by ? `by ${t.by}` : undefined} />
        <Stat
          label="Peers connected"
          value={<span className="mono">{t && t.peersTotal > 0 ? `${t.peersConnected} / ${t.peersTotal}` : "—"}</span>}
          sub={t?.peersProblem || (t?.peersCheckedAt ? `checked ${relativeTime(t.peersCheckedAt)}` : undefined)}
        />
        <Stat label="Copy used" value={t ? dateTime(t.snapshotAt) : "—"} sub={t ? (t.finalSync ? "a last copy right before" : "the newest saved copy") : undefined} />
      </div>
      <div className="grid-3">
        <Stat label="This server's NetBird" value={st.clientConnected ? "Connected" : "Not connected"} tone={st.clientConnected ? "good" : "warn"} sub="through the local standby" />
        <Stat label="DNS" value={t?.dnsChanged ? "Points here" : "Unchanged"} tone={t?.dnsChanged ? "accent" : "warn"} sub={<span className="mono">{t?.ipv4}</span>} />
        <Stat
          label="VPS"
          value={t?.fenced ? "Fenced" : "Not fenced"}
          tone={t?.fenced ? "good" : "warn"}
          sub={
            t?.handedBack
              ? "state handed back; finish with Hand back"
              : t?.fenced && t.fenceRenewed
                ? `renewed ${dateTime(t.fenceRenewed)}; it ends 2 h after the last renewal`
                : undefined
          }
        />
        <Stat label="Standby" value={st.app.state || "—"} tone={st.app.state === "running" ? "good" : "bad"} />
      </div>
      {t?.notes.map((n) => (
        <Alert key={n} tone="info">
          {n}
        </Alert>
      ))}
      <Button variant="primary" onClick={() => setOpen(true)}>
        Hand back to the VPS
      </Button>
      {open && (
        <ConfirmDialog
          title={`Hand ${host} back to the VPS?`}
          confirmLabel="Hand back"
          typeToConfirm={host}
          canConfirm={ack}
          onClose={() => setOpen(false)}
          onConfirm={async () => {
            await jobDone(unwrap(api.POST("/netbird-standby/handback", { body: { confirm: host, acceptSplitBrain: ack, discard } })));
            toast("success", "The VPS runs NetBird again");
            void qc.invalidateQueries({ queryKey: KEY });
          }}
        >
          <p>
            First arm the hand-back on the VPS, as root: <span className="mono">hardyos-netbird-standby-root arm-restore 2h</span>. Then the standby stops
            (peers drop for a minute), its state goes to the VPS (which checks it, keeps a backup of its own and rolls back by itself if its server doesn&apos;t
            come up), {host} points back at the VPS and HardyOS starts copying again. The VPS refuses new or changed owners, admins, access tokens or sign-in
            tables (the IdP rotates its signing keys every few hours, so a long take-over usually needs this) unless armed with{" "}
            <span className="mono">--allow-new-admins</span>.
          </p>
          <label className="row small">
            <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
            Anything changed on the VPS since the take-over is replaced by the standby&apos;s state.
          </label>
          <label className="row small">
            <input type="checkbox" checked={discard} onChange={(e) => setDiscard(e.target.checked)} />
            Don&apos;t send the standby&apos;s state: the VPS keeps its own, and peers or settings added here are lost.
          </label>
        </ConfirmDialog>
      )}
    </Card>
  );
}

function ForgetCard({ st }: { st: NBStandbyStatus }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const host = st.connection?.hostname ?? "";
  return (
    <Card title="Forget the standby">
      <p className="small muted">Removes the VPS connection, HardyOS&apos;s key and every copy. The app stays installed (remove it in the App Store).</p>
      <Button variant="ghost" onClick={() => setOpen(true)}>
        Forget
      </Button>
      {open && (
        <ConfirmDialog
          title="Forget the NetBird standby?"
          confirmLabel="Forget"
          typeToConfirm={host}
          onClose={() => setOpen(false)}
          onConfirm={async () => {
            await jobDone(unwrap(api.DELETE("/netbird-standby", { body: { confirm: host } })));
            toast("success", "Forgotten");
            void qc.invalidateQueries({ queryKey: KEY });
          }}
        >
          Every saved copy is deleted. Remove the hardyos-standby user on the VPS with the script&apos;s --uninstall.
        </ConfirmDialog>
      )}
    </Card>
  );
}
