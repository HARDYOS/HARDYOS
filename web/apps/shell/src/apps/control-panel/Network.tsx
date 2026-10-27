import type {
  LiveInterface,
  NetworkAddressing,
  NetworkBond,
  NetworkConfig,
  NetworkStatus,
  NetworkVLAN,
} from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../api";
import { dateTime } from "../../format";
import { PlusIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, Card, ErrorBox, Field, IconButton, Loading, PageHeader, Select, TextInput } from "../../ui";
import { Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { JobProgress } from "../shared";

type Mode = NetworkAddressing["mode"];
const POLICIES: { id: NetworkBond["policy"]; label: string; hint: string }[] = [
  { id: "active-backup", label: "Failover", hint: "One port carries traffic, the next takes over if it fails. Works with any switch." },
  { id: "802.3ad", label: "Link aggregation (LACP)", hint: "All ports share traffic. The switch ports must be set up as an LACP group." },
  { id: "balance-alb", label: "Load balancing", hint: "Ports share traffic without any switch setup." },
];

export function useNetworkStatus(enabled = true) {
  return useQuery({
    queryKey: ["network"],
    queryFn: () => unwrap(api.GET("/network")),
    enabled,
    refetchInterval: (q) => (q.state.data?.pending ? 3_000 : 30_000),
  });
}

/** Seconds until the deadline, ticking. */
function useCountdown(deadline?: string) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!deadline) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [deadline]);
  return deadline ? Math.max(0, Math.round((new Date(deadline).getTime() - now) / 1000)) : 0;
}

const mmss = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;

/** Keep-or-undo prompt for a network change; also shown on the desktop. */
export function PendingNetwork({ pending }: { pending: NonNullable<NetworkStatus["pending"]> }) {
  const qc = useQueryClient();
  const left = useCountdown(pending.deadline);
  const done = () => void qc.invalidateQueries({ queryKey: ["network"] });
  const keep = useMutation({
    mutationFn: () => unwrap(api.POST("/network/confirm")),
    onSuccess: () => {
      toast("success", "Network settings saved");
      done();
    },
  });
  const undo = useMutation({
    mutationFn: () => unwrap(api.POST("/network/revert")),
    onSuccess: () => {
      toast("success", "The previous network settings are back");
      done();
    },
  });
  return (
    <Alert
      tone="warn"
      title="Keep the new network settings?"
      action={
        <div className="row">
          <Button variant="ghost" busy={undo.isPending} disabled={keep.isPending} onClick={() => undo.mutate()}>
            Undo
          </Button>
          <Button variant="primary" busy={keep.isPending} disabled={undo.isPending} onClick={() => keep.mutate()}>
            Keep settings
          </Button>
        </div>
      }
    >
      You're connected, so they work from here. Unless you keep them, the previous settings come back in{" "}
      <strong className="mono">{mmss(left)}</strong>.
      {(keep.error || undo.error) != null && <span className="field__error"> {errorMessage(keep.error ?? undo.error)}</span>}
    </Alert>
  );
}

export function Network() {
  const status = useNetworkStatus();
  const [draft, setDraft] = useState<NetworkConfig | null>(null);
  const [reviewing, setReviewing] = useState(false);

  if (status.isPending) return <Loading />;
  if (status.isError) return <ErrorBox error={status.error} onRetry={() => status.refetch()} />;
  const st = status.data;
  const cfg = draft ?? st.config;
  const dirty = draft !== null && JSON.stringify(draft) !== JSON.stringify(st.config);
  const edit = (fn: (c: NetworkConfig) => NetworkConfig) => setDraft(fn(structuredClone(cfg)));

  return (
    <>
      <PageHeader
        title="Network"
        subtitle="How the server connects: its name, addresses, bonded ports and VLANs."
        actions={
          <>
            {dirty && (
              <Button variant="ghost" onClick={() => setDraft(null)}>
                Discard changes
              </Button>
            )}
            <Button variant="primary" disabled={!dirty || st.pending != null} onClick={() => setReviewing(true)}>
              Apply…
            </Button>
          </>
        }
      />
      {st.pending && <PendingNetwork pending={st.pending} />}
      {st.lastRevert && !st.pending && (
        <Alert tone="info" title="The last network change was undone">
          {st.lastRevert.reason} <span className="muted">({dateTime(st.lastRevert.at)})</span>
        </Alert>
      )}
      <NowCard st={st} />

      <Card title="General">
        <div className="grid-3">
          <Field label="Server name" hint="Lowercase letters, digits and dashes.">
            {(id) => (
              <TextInput id={id} value={cfg.hostname} onChange={(e) => edit((c) => ({ ...c, hostname: e.target.value }))} />
            )}
          </Field>
          <ListField
            label="DNS servers"
            hint="Leave empty to use the ones DHCP provides."
            value={cfg.dns}
            onChange={(dns) => edit((c) => ({ ...c, dns }))}
          />
          <ListField
            label="Search domains"
            hint="Optional, like home.arpa"
            value={cfg.search}
            onChange={(search) => edit((c) => ({ ...c, search }))}
          />
        </div>
      </Card>

      <Card title="Ports">
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Port</th>
                <th>Link</th>
                <th>Address</th>
              </tr>
            </thead>
            <tbody>
              {cfg.interfaces.map((it, i) => {
                const bond = cfg.bonds.find((b) => b.members.includes(it.name));
                const bridge = (cfg.bridges ?? []).find((b) => b.port === it.name);
                return (
                  <tr key={it.name}>
                    <td>
                      <strong className="mono">{it.name}</strong>
                    </td>
                    <td>
                      <LinkState live={st.live.find((l) => l.name === it.name)} />
                    </td>
                    <td>
                      {bond ? (
                        <span className="muted small">Part of {bond.name}</span>
                      ) : bridge ? (
                        <span className="muted small">Under the bridge {bridge.name}, which has its address</span>
                      ) : (
                        <AddressingEditor
                          name={it.name}
                          value={it}
                          canVLAN={cfg.vlans.some((v) => v.parent === it.name)}
                          onChange={(a) => edit((c) => ({ ...c, interfaces: c.interfaces.map((x, j) => (j === i ? { ...x, ...a } : x)) }))}
                        />
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>

      <BondsCard cfg={cfg} live={st.live} edit={edit} />
      <BridgesCard cfg={cfg} edit={edit} />
      <VLANsCard cfg={cfg} live={st.live} edit={edit} />

      {reviewing && (
        <ApplyDialog
          st={st}
          cfg={cfg}
          onClose={() => setReviewing(false)}
          onApplied={() => {
            setDraft(null);
          }}
        />
      )}
    </>
  );
}

/** Bridges put virtual machines on the home network; the first VM that
 * needs one creates it. Removing one gives its address back to the port. */
function BridgesCard({ cfg, edit }: { cfg: NetworkConfig; edit: (fn: (c: NetworkConfig) => NetworkConfig) => void }) {
  const bridges = cfg.bridges ?? [];
  if (bridges.length === 0) return null;
  return (
    <Card title="Bridges for virtual machines">
      <p className="small muted" style={{ marginTop: 0 }}>
        Virtual machines plug into a bridge to be on your network like any other computer. The bridge has the server's address.
      </p>
      <div className="stack">
        {bridges.map((br, i) => (
          <div key={br.name} className="row" style={{ alignItems: "flex-start", gap: 12, flexWrap: "wrap" }}>
            <div className="stack" style={{ gap: 2, minWidth: 140 }}>
              <strong className="mono">{br.name}</strong>
              <span className="small muted">over {br.port}</span>
            </div>
            <AddressingEditor
              name={br.name}
              value={br}
              canVLAN={cfg.vlans.some((v) => v.parent === br.name)}
              onChange={(a) => edit((c) => ({ ...c, bridges: (c.bridges ?? []).map((x, j) => (j === i ? { ...x, ...a } : x)) }))}
            />
            <IconButton
              label={`Remove ${br.name}`}
              title={`Remove ${br.name}: VMs on the home network lose their connection until it's back`}
              onClick={() => edit((c) => ({ ...c, bridges: (c.bridges ?? []).filter((_, j) => j !== i) }))}
            >
              <TrashIcon size={16} />
            </IconButton>
          </div>
        ))}
      </div>
    </Card>
  );
}

function NowCard({ st }: { st: NetworkStatus }) {
  const addrs = st.live.flatMap((l) => (l.kind === "other" ? [] : l.addresses.map((a) => ({ iface: l.name, addr: a }))));
  return (
    <Card title="Right now">
      <div className="grid-3">
        <div className="stack" style={{ gap: 4 }}>
          <span className="small muted">Addresses</span>
          {addrs.length === 0 ? (
            <span>None yet</span>
          ) : (
            addrs.map((a) => (
              <span key={a.iface + a.addr} className="mono">
                {a.addr.split("/")[0]} <span className="muted small">on {a.iface}</span>
              </span>
            ))
          )}
        </div>
        <div className="stack" style={{ gap: 4 }}>
          <span className="small muted">Gateway</span>
          <span className="mono">{st.gateway || "None"}</span>
        </div>
        <div className="stack" style={{ gap: 4 }}>
          <span className="small muted">DNS servers</span>
          <span className="mono">{st.dns.length ? st.dns.join(", ") : "None"}</span>
        </div>
      </div>
    </Card>
  );
}

function LinkState({ live }: { live?: LiveInterface }) {
  if (!live) return <Badge tone="neutral">not found</Badge>;
  if (!live.carrier) return <Badge tone="neutral">no cable</Badge>;
  const speed = live.speedMbps >= 1000 ? `${live.speedMbps / 1000} Gb/s` : live.speedMbps ? `${live.speedMbps} Mb/s` : "connected";
  return (
    <div>
      <Badge tone="good">{speed}</Badge>
      <span className="cell-sub mono">{live.mac}</span>
    </div>
  );
}

function ListField({ label, hint, value, onChange }: { label: string; hint: string; value: string[]; onChange: (v: string[]) => void }) {
  // Edit as text so typing a separator doesn't fight the list.
  const [text, setText] = useState(value.join(", "));
  const joined = value.join(", ");
  useEffect(() => {
    // Follow outside changes (like Discard) without fighting the typing.
    setText((t) => (t.split(/[\s,]+/).filter(Boolean).join(", ") === joined ? t : joined));
  }, [joined]);
  return (
    <Field label={label} hint={hint}>
      {(id) => (
        <TextInput
          id={id}
          value={text}
          placeholder="Separate with commas"
          onChange={(e) => {
            setText(e.target.value);
            onChange(
              e.target.value
                .split(/[\s,]+/)
                .map((s) => s.trim())
                .filter(Boolean),
            );
          }}
        />
      )}
    </Field>
  );
}

function AddressingEditor({
  name,
  value,
  onChange,
  canVLAN,
}: {
  name: string;
  value: NetworkAddressing;
  onChange: (a: NetworkAddressing) => void;
  canVLAN?: boolean;
}) {
  const set = (patch: Partial<NetworkAddressing>) => onChange({ ...value, ...patch });
  return (
    <div className="row" style={{ alignItems: "flex-start", gap: 8 }}>
      <Select
        aria-label={`How ${name} gets its address`}
        value={value.mode}
        onChange={(e) => {
          const mode = e.target.value as Mode;
          onChange(mode === "static" ? { mode, address: value.address ?? "", gateway: value.gateway ?? "", mtu: value.mtu } : { mode, mtu: value.mtu });
        }}
        style={{ width: 150 }}
      >
        <option value="dhcp">Automatic (DHCP)</option>
        <option value="static">Fixed address</option>
        <option value="off">{canVLAN ? "No address (VLANs only)" : "Off"}</option>
      </Select>
      {value.mode === "static" && (
        <>
          <TextInput
            aria-label={`${name} address`}
            placeholder="192.168.1.20/24"
            value={value.address ?? ""}
            onChange={(e) => set({ address: e.target.value })}
            style={{ width: 170 }}
          />
          <TextInput
            aria-label={`${name} gateway`}
            placeholder="Gateway (optional)"
            value={value.gateway ?? ""}
            onChange={(e) => set({ gateway: e.target.value || undefined })}
            style={{ width: 150 }}
          />
        </>
      )}
      <TextInput
        aria-label={`${name} MTU`}
        type="number"
        placeholder="MTU 1500"
        value={value.mtu || ""}
        onChange={(e) => set({ mtu: Number(e.target.value) || undefined })}
        style={{ width: 110 }}
      />
    </div>
  );
}

function BondsCard({ cfg, live, edit }: { cfg: NetworkConfig; live: LiveInterface[]; edit: (fn: (c: NetworkConfig) => NetworkConfig) => void }) {
  const add = () =>
    edit((c) => {
      let n = 0;
      while (c.bonds.some((b) => b.name === `bond${n}`)) n++;
      return { ...c, bonds: [...c.bonds, { name: `bond${n}`, members: [], policy: "active-backup", mode: "dhcp" }] };
    });
  const setBond = (i: number, b: NetworkBond) =>
    edit((c) => {
      const bonds = c.bonds.map((x, j) => (j === i ? b : x));
      // A port joining a bond loses its own address.
      const interfaces = c.interfaces.map((it) => (b.members.includes(it.name) ? { ...it, mode: "member" as Mode, address: undefined, gateway: undefined } : it.mode === "member" && !bonds.some((x) => x.members.includes(it.name)) ? { ...it, mode: "off" as Mode } : it));
      return { ...c, bonds, interfaces };
    });
  const remove = (i: number) =>
    edit((c) => {
      const gone = c.bonds[i];
      if (!gone) return c;
      return {
        ...c,
        bonds: c.bonds.filter((_, j) => j !== i),
        vlans: c.vlans.filter((v) => v.parent !== gone.name),
        interfaces: c.interfaces.map((it) => (gone.members.includes(it.name) ? { ...it, mode: "off" as Mode } : it)),
      };
    });
  return (
    <Card
      title="Bonds"
      actions={
        <Button size="sm" onClick={add} disabled={cfg.interfaces.length < 2}>
          <PlusIcon size={14} /> Add bond
        </Button>
      }
    >
      {cfg.bonds.length === 0 ? (
        <p className="small muted" style={{ margin: 0 }}>
          A bond joins two or more ports into one connection, for failover or more bandwidth.
        </p>
      ) : (
        <div className="stack">
          {cfg.bonds.map((b, i) => (
            <div key={b.name} className="stack" style={{ gap: 8, paddingBottom: 12, borderBottom: "1px solid var(--hos-border)" }}>
              <div className="row row--between">
                <div className="row">
                  <strong className="mono">{b.name}</strong>
                  <LinkState live={live.find((l) => l.name === b.name)} />
                </div>
                <IconButton label={`Remove ${b.name}`} onClick={() => remove(i)}>
                  <TrashIcon size={15} />
                </IconButton>
              </div>
              <div className="row" style={{ gap: 14 }}>
                <span className="small muted">Ports</span>
                {cfg.interfaces.map((it) => {
                  const other = cfg.bonds.find((x, j) => j !== i && x.members.includes(it.name));
                  return (
                    <label key={it.name} className="row small" style={{ gap: 6, opacity: other ? 0.5 : 1 }}>
                      <input
                        type="checkbox"
                        disabled={!!other}
                        checked={b.members.includes(it.name)}
                        onChange={(e) =>
                          setBond(i, { ...b, members: e.target.checked ? [...b.members, it.name].sort() : b.members.filter((m) => m !== it.name) })
                        }
                      />
                      <span className="mono">{it.name}</span>
                    </label>
                  );
                })}
              </div>
              <Field label="Mode" hint={POLICIES.find((p) => p.id === b.policy)?.hint}>
                {(id) => (
                  <Select id={id} value={b.policy} onChange={(e) => setBond(i, { ...b, policy: e.target.value as NetworkBond["policy"] })} style={{ maxWidth: 280 }}>
                    {POLICIES.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.label}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              {(cfg.bridges ?? []).some((br) => br.port === b.name) ? (
                <span className="muted small">Under a bridge, which has its address</span>
              ) : (
                <AddressingEditor name={b.name} value={b} canVLAN={cfg.vlans.some((v) => v.parent === b.name)} onChange={(a) => setBond(i, { ...b, ...a })} />
              )}
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

function VLANsCard({ cfg, live, edit }: { cfg: NetworkConfig; live: LiveInterface[]; edit: (fn: (c: NetworkConfig) => NetworkConfig) => void }) {
  const parents = [...cfg.interfaces.filter((it) => it.mode !== "member").map((it) => it.name), ...cfg.bonds.map((b) => b.name)];
  const add = () => edit((c) => (parents[0] ? { ...c, vlans: [...c.vlans, { parent: parents[0], id: 10, mode: "dhcp" }] } : c));
  const setVLAN = (i: number, v: NetworkVLAN) => edit((c) => ({ ...c, vlans: c.vlans.map((x, j) => (j === i ? v : x)) }));
  return (
    <Card
      title="VLANs"
      actions={
        <Button size="sm" onClick={add} disabled={parents.length === 0}>
          <PlusIcon size={14} /> Add VLAN
        </Button>
      }
    >
      {cfg.vlans.length === 0 ? (
        <p className="small muted" style={{ margin: 0 }}>
          A VLAN puts the server on a tagged network that shares a port, like a separate network for cameras or guests.
        </p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>On</th>
                <th>VLAN ID</th>
                <th>Link</th>
                <th>Address</th>
                <th className="actions">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {cfg.vlans.map((v, i) => (
                <tr key={i}>
                  <td>
                    <Select aria-label="Port or bond" value={v.parent} onChange={(e) => setVLAN(i, { ...v, parent: e.target.value })} style={{ width: 120 }}>
                      {parents.map((p) => (
                        <option key={p} value={p}>
                          {p}
                        </option>
                      ))}
                    </Select>
                  </td>
                  <td>
                    <TextInput aria-label="VLAN ID" type="number" min={1} max={4094} value={v.id} onChange={(e) => setVLAN(i, { ...v, id: Number(e.target.value) })} style={{ width: 90 }} />
                  </td>
                  <td>
                    <LinkState live={live.find((l) => l.name === `${v.parent}.${v.id}`)} />
                  </td>
                  <td>
                    <AddressingEditor name={`VLAN ${v.id}`} value={v} onChange={(a) => setVLAN(i, { ...v, ...a })} />
                  </td>
                  <td className="actions">
                    <IconButton label={`Remove VLAN ${v.id}`} onClick={() => edit((c) => ({ ...c, vlans: c.vlans.filter((_, j) => j !== i) }))}>
                      <TrashIcon size={15} />
                    </IconButton>
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

/** Fixed addresses in a config. */
function staticAddresses(c: NetworkConfig): string[] {
  return [...c.interfaces, ...c.bonds, ...c.vlans].flatMap((a) => (a.mode === "static" && a.address ? [a.address.split("/")[0] ?? a.address] : []));
}

function ApplyDialog({ st, cfg, onClose, onApplied }: { st: NetworkStatus; cfg: NetworkConfig; onClose: () => void; onApplied: () => void }) {
  const qc = useQueryClient();
  const [jobId, setJobId] = useState<string | null>(null);
  const [lost, setLost] = useState(false);
  const apply = useMutation({
    mutationFn: () => unwrap(api.PUT("/network", { body: cfg })),
    onSuccess: (r) => {
      setJobId(r.job.id);
      onApplied();
    },
  });

  // Where will this page be after the change?
  const host = window.location.hostname;
  const hostIface = st.live.find((l) => l.addresses.some((a) => a.split("/")[0] === host))?.name;
  const newStatic = staticAddresses(cfg);
  const ifaceChanges = (() => {
    if (!hostIface) return false;
    const was = [...st.config.interfaces, ...st.config.bonds, ...st.config.vlans.map((v) => ({ ...v, name: `${v.parent}.${v.id}` }))].find((x) => x.name === hostIface);
    const now = [...cfg.interfaces, ...cfg.bonds, ...cfg.vlans.map((v) => ({ ...v, name: `${v.parent}.${v.id}` }))].find((x) => x.name === hostIface);
    return JSON.stringify(was) !== JSON.stringify(now);
  })();
  const moves = ifaceChanges && !newStatic.includes(host);

  // While the network restarts, this page may lose the server for a moment.
  useEffect(() => {
    if (!jobId) return;
    const t = setInterval(() => {
      fetch("/api/v1/health", { cache: "no-store" })
        .then(() => setLost(false))
        .catch(() => setLost(true));
    }, 3000);
    return () => clearInterval(t);
  }, [jobId]);

  const details = apply.error instanceof ApiFailure ? apply.error.details : [];
  return (
    <Dialog
      title="Apply network settings?"
      onClose={onClose}
      width={560}
      footer={
        jobId ? (
          <Button onClick={onClose}>Close</Button>
        ) : (
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" busy={apply.isPending} onClick={() => apply.mutate()}>
              Apply
            </Button>
          </>
        )
      }
    >
      {!jobId && (
        <div className="stack">
          <p style={{ margin: 0 }}>
            The network restarts, so connections drop for a few seconds. You then have <strong>3 minutes</strong> to keep the new
            settings; otherwise the current ones come back by themselves.
          </p>
          {moves && (
            <Alert tone="warn" title="This page will lose the server">
              {newStatic.length > 0 ? (
                <>
                  After the change, open{" "}
                  {newStatic.map((a, i) => (
                    <span key={a}>
                      {i > 0 && " or "}
                      <strong className="mono">https://{a}</strong>
                    </span>
                  ))}{" "}
                  and choose <strong>Keep settings</strong> there.
                </>
              ) : (
                <>The server will get a new address from DHCP. Find it on the server's screen or your router, sign in there and choose Keep settings.</>
              )}
            </Alert>
          )}
          {apply.error != null && (
            <Alert tone="bad" title={errorMessage(apply.error)}>
              {details.length > 0 && (
                <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
                  {details.map((d) => (
                    <li key={d}>{d}</li>
                  ))}
                </ul>
              )}
            </Alert>
          )}
        </div>
      )}
      {jobId && (
        <div className="stack">
          <JobProgress
            id={jobId}
            onDone={(j) => {
              void qc.invalidateQueries({ queryKey: ["network"] });
              if (j.state === "succeeded") onClose();
            }}
          />
          {lost && (
            <Alert tone="info">
              {moves && newStatic.length > 0
                ? `Waiting for the server… If it doesn't come back here, open https://${newStatic[0]} and keep the settings there.`
                : "Waiting for the server to come back…"}
            </Alert>
          )}
        </div>
      )}
    </Dialog>
  );
}
