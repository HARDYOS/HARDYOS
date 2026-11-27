import type { Job, VM, VMStreamingAccount, VMStreamingPending, VMStreamingStatus } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../api";
import { ExternalIcon, GamepadIcon, KeyIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, Card, Field, IconButton, Loading, TextInput, Toggle } from "../../ui";
import { Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";

// Game streaming (decisions 400-409): Sunshine inside a gaming VM, set up
// by HardyOS, played with Moonlight on the home network and, published to
// NetBird devices only, away from home.

export const streamingKey = (id: string) => ["vms", id, "streaming"] as const;

export const useStreaming = (id: string, running: boolean) =>
  useQuery<VMStreamingStatus>({
    queryKey: streamingKey(id),
    queryFn: () => unwrap(api.GET("/vms/{id}/streaming", { params: { path: { id } } })),
    refetchInterval: running ? 5_000 : 30_000,
  });

/** A 4-digit Moonlight PIN. */
export const pinOK = (pin: string) => /^[0-9]{4}$/.test(pin);
/** A device name Sunshine and HardyOS accept. */
export const deviceNameOK = (name: string) => /^[\p{L}\p{N} ._'()-]{1,64}$/u.test(name.trim());

/** "47984, 47989, 48010" with runs as ranges. */
export function portSummary(ports: number[]): string {
  const s = [...new Set(ports)].sort((a, b) => a - b);
  const runs: number[][] = [];
  for (const p of s) {
    const last = runs[runs.length - 1];
    if (last && last[last.length - 1] === p - 1) last.push(p);
    else runs.push([p]);
  }
  return runs.flatMap((r) => (r.length >= 3 ? [`${r[0]}–${r[r.length - 1]}`] : r.map(String))).join(", ");
}

export function StreamingPanel({ vm, onJob }: { vm: VM; onJob: (j: Job) => void }) {
  const running = vm.state === "running";
  const { data: st, error, isLoading } = useStreaming(vm.id, running);
  const title = (
    <span className="row" style={{ gap: 8 }}>
      <GamepadIcon size={16} /> Game streaming
    </span>
  );
  if (isLoading) {
    return (
      <Card title={title}>
        <Loading label="Asking Sunshine…" />
      </Card>
    );
  }
  if (error || !st) {
    return (
      <Card title={title}>
        <Alert tone="bad">{errorMessage(error)}</Alert>
      </Card>
    );
  }
  if (!st.setUp) return <ManualStreaming vm={vm} st={st} />;
  return (
    <Card
      title={title}
      actions={
        st.reachable ? <Badge tone="good">Sunshine is running</Badge> : <Badge tone={running ? "warn" : "neutral"}>{running ? "Sunshine not reachable" : "VM off"}</Badge>
      }
    >
      <div className="stack">
        {st.installPending && (
          <Alert tone="info" title="Windows is installing">
            Sunshine and the virtual display are installed at the first sign-in, from the HardyOS streaming disc. Watch the VM's screen; pairing works once it's done.
          </Alert>
        )}
        {st.problem && !st.installPending && running && <Alert tone="warn">{st.problem}</Alert>}
        <div className="grid-2">
          <div className="stack" style={{ gap: 4 }}>
            <span className="small muted">On the home network</span>
            <span className="mono">{st.address || "—"}</span>
            <span className="small muted">Moonlight usually finds the VM by itself; otherwise add this address.</span>
          </div>
          <div className="stack" style={{ gap: 4 }}>
            <span className="small muted">Away from home (NetBird)</span>
            <span className="mono">{st.remote && st.netbirdAddress ? (st.moonlight ?? st.netbirdAddress) : "—"}</span>
            <span className="small muted">
              {st.remote ? (st.forwarding ? "Forwarding now, to your NetBird devices only." : "On; forwarding starts while the VM runs and NetBird is connected.") : "Off."}
            </span>
          </div>
        </div>
        <RemoteToggle vm={vm} st={st} onJob={onJob} />
        <PairDevice vm={vm} st={st} onJob={onJob} />
        <DeviceList vm={vm} st={st} onJob={onJob} />
        <SunshineAccount vm={vm} st={st} />
        <DriverGuidance />
      </div>
    </Card>
  );
}

function RemoteToggle({ vm, st, onJob }: { vm: VM; st: VMStreamingStatus; onJob: (j: Job) => void }) {
  const [busy, setBusy] = useState(false);
  const [chosen, setChosen] = useState<string[]>(st.peers);
  const [open, setOpen] = useState(false);
  const put = async (enabled: boolean, peers: string[]) => {
    setBusy(true);
    try {
      const r = await unwrap(api.PUT("/vms/{id}/streaming/remote", { params: { path: { id: vm.id } }, body: enabled ? { enabled, peers } : { enabled } }));
      onJob(r.job);
      setOpen(false);
    } catch (e) {
      toast("error", "Not changed", errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const toggle = (ip: string) => setChosen((c) => (c.includes(ip) ? c.filter((x) => x !== ip) : [...c, ip]));
  return (
    <div className="stack" style={{ gap: 8 }}>
      <Toggle
        label="Play away from home over NetBird"
        description={`Forwards only Sunshine's streaming ports (TCP ${portSummary(st.ports.tcp)}, UDP ${portSummary(st.ports.udp)}) from this server's NetBird address to this VM, for the NetBird devices you choose; never from the internet. Sunshine's web page stays in the VM. Several VMs can be published: each gets its own ports, and Sunshine in the VM is moved to them (add the address with its port in Moonlight).`}
        checked={st.remote || open}
        disabled={busy}
        onChange={(v) => (v ? setOpen(true) : void put(false, []))}
      />
      {(open || st.remote) && (
        <div className="stack" style={{ gap: 6 }}>
          <span className="small muted">
            Which devices may stream{st.netbirdKernel ? " (NetBird's access policies don't apply to these forwarded ports: only the devices ticked here get through)" : ""}:
          </span>
          {st.netbirdPeers.length === 0 ? (
            <span className="small muted">This server sees no NetBird devices right now.</span>
          ) : (
            <ul className="list" aria-label="NetBird devices">
              {st.netbirdPeers.map((p) => (
                <li key={p.ip}>
                  <label className="row" style={{ gap: 8 }}>
                    <input type="checkbox" disabled={p.proxy || busy} checked={chosen.includes(p.ip)} onChange={() => toggle(p.ip)} aria-label={p.name || p.ip} />
                    <span>
                      {p.name || p.ip} <span className="small muted mono">{p.ip}</span> {p.proxy && <Badge tone="neutral">NetBird's reverse proxy</Badge>}
                    </span>
                  </label>
                </li>
              ))}
            </ul>
          )}
          <div>
            <Button variant="primary" disabled={busy || chosen.length === 0} onClick={() => void put(true, chosen)}>
              {st.remote ? "Save devices" : "Publish to these devices"}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function PairDevice({ vm, st, onJob }: { vm: VM; st: VMStreamingStatus; onJob: (j: Job) => void }) {
  const [pairing, setPairing] = useState<VMStreamingPending | null>(null);
  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="row row--between">
        <strong>Pair a device</strong>
      </div>
      {st.waiting.length === 0 ? (
        <p className="small muted" style={{ margin: 0 }}>
          In{" "}
          <a href="https://moonlight-stream.org" target="_blank" rel="noreferrer">
            Moonlight <ExternalIcon size={11} />
          </a>
          , pick this VM (or add <span className="mono">{st.remote && st.netbirdAddress ? (st.moonlight ?? st.netbirdAddress) : st.address || "its address"}</span>). Moonlight shows a PIN and the
          device appears here; enter the PIN to pair it.
        </p>
      ) : (
        <ul className="list" aria-label="Devices waiting to pair">
          {st.waiting.map((p) => (
            <li key={p.id} className="row row--between">
              <span>
                {p.name || "A Moonlight device"} <span className="small muted mono">{p.address}</span>{" "}
                {p.viaNetBird && <Badge tone="warn">Through NetBird</Badge>}
              </span>
              <Button variant="primary" onClick={() => setPairing(p)}>
                Enter its PIN
              </Button>
            </li>
          ))}
        </ul>
      )}
      {pairing && <PairDialog vm={vm} pending={pairing} onClose={() => setPairing(null)} onJob={onJob} />}
    </div>
  );
}

function PairDialog({ vm, pending, onClose, onJob }: { vm: VM; pending: VMStreamingPending; onClose: () => void; onJob: (j: Job) => void }) {
  const [pin, setPin] = useState("");
  const [name, setName] = useState(pending.name || "");
  const [busy, setBusy] = useState(false);
  const [confirmRemote, setConfirmRemote] = useState(false);
  const ok = pinOK(pin) && deviceNameOK(name) && (!pending.viaNetBird || confirmRemote);
  const submit = async () => {
    if (!ok) return;
    setBusy(true);
    try {
      const r = await unwrap(api.POST("/vms/{id}/streaming/pair", { params: { path: { id: vm.id } }, body: { pairingId: pending.id, pin, name: name.trim(), ...(pending.viaNetBird ? { confirmRemote: true } : {}) } }));
      onJob(r.job);
      onClose();
    } catch (e) {
      toast("error", "Not paired", errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      title="Pair a Moonlight device"
      description="Type the 4 digits Moonlight shows. HardyOS gives them to Sunshine in the VM."
      onClose={onClose}
      onSubmit={submit}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" disabled={!ok || busy}>
            Pair
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label="PIN">
          {(id) => (
            <TextInput
              id={id}
              className="input mono"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={4}
              value={pin}
              onChange={(e) => setPin(e.target.value.replace(/\D/g, ""))}
            />
          )}
        </Field>
        <Field label="Device name" hint="How it's listed here and in Sunshine.">
          {(id) => <TextInput id={id} maxLength={64} value={name} onChange={(e) => setName(e.target.value)} />}
        </Field>
        {pending.viaNetBird && (
          <>
            <Alert tone="warn">
              This device reached Sunshine through NetBird, so HardyOS can't tell it apart from your other NetBird devices. Pairing at home is safer.
            </Alert>
            <Toggle label="It's my device: pair it anyway" checked={confirmRemote} onChange={setConfirmRemote} />
          </>
        )}
      </div>
    </Dialog>
  );
}

function DeviceList({ vm, st, onJob }: { vm: VM; st: VMStreamingStatus; onJob: (j: Job) => void }) {
  const unpair = async (uuid: string, name: string) => {
    try {
      const r = await unwrap(api.POST("/vms/{id}/streaming/unpair", { params: { path: { id: vm.id } }, body: { uuid } }));
      onJob(r.job);
    } catch (e) {
      toast("error", `${name} not unpaired`, errorMessage(e));
    }
  };
  if (!st.reachable) return null;
  return (
    <div className="stack" style={{ gap: 8 }}>
      <strong>Paired devices</strong>
      {st.devices.length === 0 ? (
        <p className="small muted" style={{ margin: 0 }}>
          None yet.
        </p>
      ) : (
        <ul className="list" aria-label="Paired devices">
          {st.devices.map((d) => (
            <li key={d.uuid} className="row row--between">
              <span>
                {d.name || "Unnamed device"} {!d.enabled && <Badge tone="neutral">Turned off</Badge>}
              </span>
              <IconButton label={`Unpair ${d.name || "the device"}`} onClick={() => void unpair(d.uuid, d.name)}>
                <TrashIcon size={15} />
              </IconButton>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function SunshineAccount({ vm, st }: { vm: VM; st: VMStreamingStatus }) {
  const [asking, setAsking] = useState(false);
  const [password, setPassword] = useState("");
  const [shown, setShown] = useState<VMStreamingAccount | null>(null);
  const [problem, setProblem] = useState("");
  const reveal = async () => {
    setProblem("");
    try {
      const acct = await unwrap(api.POST("/vms/{id}/streaming/reveal", { params: { path: { id: vm.id } }, body: { password } }));
      setShown(acct);
      setAsking(false);
      setPassword("");
    } catch (e) {
      setProblem(e instanceof ApiFailure && e.code === "bad_credentials" ? "That password isn't right." : errorMessage(e));
    }
  };
  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="row row--between">
        <span>
          <strong>Sunshine's own page</strong>{" "}
          <span className="small muted">
            (https://localhost:47990 inside the VM; it answers nowhere else but HardyOS) · account{" "}
            <span className="mono">{st.user}</span>
          </span>
        </span>
        {st.accountKept && !shown && (
          <Button onClick={() => setAsking(true)}>
            <KeyIcon size={14} /> Show the password
          </Button>
        )}
      </div>
      {shown && (
        <Alert tone="info" title="Sunshine's account" action={<Button onClick={() => setShown(null)}>Hide</Button>}>
          <span className="mono">{shown.user}</span> · <span className="mono">{shown.password}</span>
        </Alert>
      )}
      {asking && (
        <Dialog
          title="Show Sunshine's password"
          description="Type your own HardyOS password. Every time the password is shown is logged."
          onClose={() => setAsking(false)}
          onSubmit={reveal}
          footer={
            <>
              <Button onClick={() => setAsking(false)}>Cancel</Button>
              <Button variant="primary" type="submit" disabled={!password}>
                Show
              </Button>
            </>
          }
        >
          <Field label="Your password">
            {(id) => <TextInput id={id} type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />}
          </Field>
          {problem && <Alert tone="bad">{problem}</Alert>}
        </Dialog>
      )}
    </div>
  );
}

function DriverGuidance() {
  return (
    <div className="tip">
      <span>
        Install your graphics card's own driver in Windows (from NVIDIA, AMD or Intel; the VM's screen works until then). HardyOS doesn't install, patch or unlock graphics
        drivers: no vGPU unlocks and no licence workarounds. Once the driver runs, Sunshine streams from the card; the virtual display gives it a screen without a monitor
        or dummy plug.
      </span>
    </div>
  );
}

/** A GPU VM HardyOS didn't set up: the steps by hand. */
function ManualStreaming({ vm, st }: { vm: VM; st: VMStreamingStatus }) {
  const addr = st.address || vm.addresses[0];
  return (
    <Card
      title={
        <span className="row" style={{ gap: 8 }}>
          <GamepadIcon size={16} /> Game streaming
        </span>
      }
    >
      <div className="stack">
        <p className="small" style={{ margin: 0 }}>
          Play this VM's games on a TV, laptop or phone with Moonlight, streamed from Sunshine inside the VM. HardyOS sets this up by itself for new gaming VMs (Set up game
          streaming in the wizard); for this one, by hand:
        </p>
        <ol className="small" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
          <li>
            In the VM, install the graphics card's driver, then{" "}
            <a href="https://github.com/LizardByte/Sunshine/releases" target="_blank" rel="noreferrer">
              Sunshine <ExternalIcon size={11} />
            </a>
            .
          </li>
          <li>Open Sunshine's page in the VM (https://localhost:47990) and set a user name and password.</li>
          <li>
            Install{" "}
            <a href="https://moonlight-stream.org" target="_blank" rel="noreferrer">
              Moonlight <ExternalIcon size={11} />
            </a>{" "}
            on the device you play on and add the VM by its address: <strong className="mono">{addr ?? "(start the VM to see it)"}</strong>
          </li>
        </ol>
        <DriverGuidance />
      </div>
    </Card>
  );
}
