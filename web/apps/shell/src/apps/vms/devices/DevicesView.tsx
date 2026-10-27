import type { DeviceInventory, GPUInfo, NvidiaStatus, VGPUUpload } from "@hardy/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type ChangeEvent, useState } from "react";
import { api, errorMessage, unwrap } from "../../../api";
import { dateTime } from "../../../format";
import { CheckIcon, CpuIcon, RestartIcon, TrashIcon, UploadIcon } from "../../../icons";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Loading, PageHeader, Progress } from "../../../ui";
import { ConfirmDialog, Dialog } from "../../../ui/Dialog";
import { RestartOverlay } from "../../../ui/RestartOverlay";
import { JobProgress } from "../../shared";
import { OwnerBadge } from "./DevicePicker";
import { gpuName, uploadVGPUDriver, useDevices, useNvidia, vram } from "./deviceApi";
import "./devices.css";

type Accepted = { job: { id: string } };

/** The Devices view: GPUs and who has them, NVIDIA setup, IOMMU, USB. */
export function DevicesView() {
  const qc = useQueryClient();
  const inv = useDevices();
  const [restarting, setRestarting] = useState(false);
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["devices"] });
    void qc.invalidateQueries({ queryKey: ["devices-nvidia"] });
  };
  const reboot = useMutation({ mutationFn: () => unwrap(api.POST("/system/reboot")), onSuccess: () => setRestarting(true) });
  if (restarting) return <RestartOverlay />;
  if (inv.isPending) return <Loading />;
  if (inv.isError) return <ErrorBox error={inv.error} onRetry={() => inv.refetch()} />;
  const d = inv.data;
  const nvidia = d.gpus.some((g) => g.vendor === "nvidia");
  return (
    <>
      <PageHeader title="Devices" subtitle="Graphics cards, USB and PCI devices: what Docker apps use, and what virtual machines can have." />
      {d.stuck.length > 0 && <StuckAlert inv={d} onDone={refresh} />}
      <IOMMUCard inv={d} onDone={refresh} onRestart={() => reboot.mutate()} />
      <Card title="Graphics cards">
        {d.gpus.length === 0 ? (
          <EmptyState icon={<CpuIcon size={28} />} title="No graphics card found">
            Video and photo work in apps uses the processor.
          </EmptyState>
        ) : (
          <div className="stack">
            {d.gpus.map((g) => (
              <GPUCard key={g.address} gpu={g} onDone={refresh} />
            ))}
          </div>
        )}
      </Card>
      {nvidia && <NvidiaSetup onRestart={() => reboot.mutate()} onChanged={refresh} />}
      {nvidia && <VGPUDriverCard onChanged={refresh} />}
      <div className="grid-2">
        <GroupsCard inv={d} />
        <USBCard inv={d} />
      </div>
    </>
  );
}

function StuckAlert({ inv, onDone }: { inv: DeviceInventory; onDone: () => void }) {
  const [job, setJob] = useState<string | null>(null);
  const retry = useMutation({ mutationFn: () => unwrap(api.POST("/devices/reconcile")), onSuccess: (r) => setJob((r as Accepted).job.id) });
  return (
    <Alert
      tone="warn"
      title="A device didn't come back from a VM"
      action={
        <Button size="sm" busy={retry.isPending} onClick={() => retry.mutate()}>
          Try again
        </Button>
      }
    >
      {inv.stuck.map((s) => (
        <p key={s.address} style={{ margin: "4px 0" }}>
          {s.message}
        </p>
      ))}
      {job && <JobProgress id={job} onDone={onDone} />}
    </Alert>
  );
}

function IOMMUCard({ inv, onDone, onRestart }: { inv: DeviceInventory; onDone: () => void; onRestart: () => void }) {
  const io = inv.iommu;
  const [job, setJob] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const enable = useMutation({ mutationFn: () => unwrap(api.POST("/devices/iommu/enable")), onSuccess: (r) => setJob((r as Accepted).job.id) });
  const restart = io.restartNeeded || done;
  return (
    <Card
      title="Passthrough (IOMMU)"
      actions={io.enabled ? <Badge tone="good">On</Badge> : restart ? <Badge tone="warn">Restart needed</Badge> : <Badge tone="neutral">Off</Badge>}
    >
      <p className="small" style={{ margin: 0 }}>
        {io.message}
      </p>
      {io.canTurnOn && !job && (
        <div className="row">
          <Button variant="primary" busy={enable.isPending} onClick={() => enable.mutate()}>
            Turn on IOMMU
          </Button>
          <span className="small muted">
            Adds <span className="mono">{io.flags.join(" ")}</span> to the boot settings on every boot disk. Takes effect after a restart.
          </span>
        </div>
      )}
      {enable.error != null && <Alert tone="bad">{errorMessage(enable.error)}</Alert>}
      {job && (
        <JobProgress
          id={job}
          onDone={(j) => {
            if (j.state === "succeeded") setDone(true);
            onDone();
          }}
        />
      )}
      {restart && !io.enabled && (
        <Button onClick={onRestart}>
          <RestartIcon size={14} /> Restart now
        </Button>
      )}
      {io.kernelArgs.length > 0 && (
        <p className="small muted" style={{ margin: 0 }}>
          Extra boot settings: <span className="mono">{io.kernelArgs.join(" ")}</span>
        </p>
      )}
    </Card>
  );
}

function GPUCard({ gpu: g, onDone }: { gpu: GPUInfo; onDone: () => void }) {
  const [job, setJob] = useState<string | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const sriov = useMutation({
    mutationFn: (vfs: number) => unwrap(api.POST("/devices/gpus/{address}/sriov", { params: { path: { address: g.address } }, body: { vfs } })),
    onSuccess: (r) => setJob((r as Accepted).job.id),
  });
  const v = g.vgpu;
  return (
    <div className="devcard" aria-label={gpuName(g)}>
      <div className="row row--between">
        <div>
          <strong>{gpuName(g)}</strong>
          <span className="small muted"> {[vram(g), g.address, g.driver ? `driver ${g.driver}` : "no driver"].filter(Boolean).join(" · ")}</span>
        </div>
        <OwnerBadge gpu={g} />
      </div>
      {g.functions.length > 1 && (
        <p className="small muted" style={{ margin: 0 }}>
          {g.functions.length} parts: {g.functions.map((f) => f.kind).join(", ")}
          {g.iommuGroup != null && ` · IOMMU group ${g.iommuGroup}`}
        </p>
      )}
      {g.users.length > 0 && (
        <p className="small" style={{ margin: 0 }}>
          In use now by {[...new Set(g.users.map((u) => (u.app ? `the app ${u.app}` : u.process)))].join(", ")}.
        </p>
      )}
      {g.assigned.length > 0 && (
        <p className="small muted" style={{ margin: 0 }}>
          Set up for {g.assigned.length === 1 ? "the VM" : "the VMs"} {g.assigned.join(", ")}: it moves to the VM while it runs and comes back to Docker apps when it stops.
        </p>
      )}
      {g.problem && (
        <p className="small muted" style={{ margin: 0 }}>
          {g.problem}
        </p>
      )}
      {g.hints.length > 0 && (
        <ul className="devcard__hints small">
          {g.hints.map((h) => (
            <li key={h}>{h}</li>
          ))}
        </ul>
      )}
      {v && (
        <div className="devcard__vgpu">
          <div className="row row--between">
            <span className="section-label">vGPU slices</span>
            {(v.mode === "sriov-vf" || (v.mode === "nvidia-vf" && v.maxVfs > 0)) && (
              <Button size="sm" busy={sriov.isPending} onClick={() => sriov.mutate(v.vfs > 0 ? 0 : v.maxVfs)}>
                {v.vfs > 0 ? "Turn slices off" : "Turn on slices"}
              </Button>
            )}
          </div>
          {v.note && <p className="small muted">{v.note}</p>}
          {v.types.map((t) => {
            const max = t.maxInstances || t.available;
            const used = Math.max(0, max - t.available);
            return (
              <div key={t.id} className="devcard__type">
                <div className="row row--between small">
                  <span>
                    {t.name}
                    {t.framebufferMb > 0 && <span className="muted"> · {Math.round(t.framebufferMb / 1024)} GB each</span>}
                  </span>
                  <span className="mono">{max > 0 ? `${t.available} of ${max} free` : `${t.available} free`}</span>
                </div>
                {max > 0 && <Progress value={(used / max) * 100} label={`${t.name} slices in use`} />}
              </div>
            );
          })}
          {v.instances.length > 0 && (
            <ul className="devlist">
              {v.instances.map((i) => (
                <li key={i.id} className="row row--between">
                  <span className="small">
                    <span className="mono">{i.id}</span> · {i.type} · {i.vm ? `VM ${i.vm}` : "not used by a running VM"}
                  </span>
                  {!i.vm && (
                    <Button size="sm" variant="ghost" onClick={() => setRemoving(i.id)}>
                      <TrashIcon size={14} /> Remove
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {sriov.error != null && <Alert tone="bad">{errorMessage(sriov.error)}</Alert>}
      {job && <JobProgress id={job} onDone={onDone} />}
      {removing && (
        <ConfirmDialog
          title="Remove this vGPU slice?"
          confirmLabel="Remove"
          onClose={() => setRemoving(null)}
          onConfirm={async () => {
            const r = await unwrap(api.POST("/devices/slices/{id}/remove", { params: { path: { id: removing } } }));
            setJob((r as Accepted).job.id);
          }}
        >
          No running VM uses it. A VM that has a slice of this type gets a new one the next time it starts.
        </ConfirmDialog>
      )}
    </div>
  );
}

/** NVIDIA driver setup: get the packages, read the licence, agree, install. */
export function NvidiaSetup({ onRestart, onChanged }: { onRestart: () => void; onChanged: () => void }) {
  const [job, setJob] = useState<string | null>(null);
  const st = useNvidia(job !== null);
  const [licence, setLicence] = useState(false);
  const [removing, setRemoving] = useState(false);
  const prepare = useMutation({ mutationFn: () => unwrap(api.POST("/devices/nvidia/prepare")), onSuccess: (r) => setJob((r as Accepted).job.id) });
  const finished = () => {
    setJob(null);
    void st.refetch();
    onChanged();
  };
  if (st.isPending) return null;
  if (st.isError) return <ErrorBox error={st.error} onRetry={() => st.refetch()} />;
  const s = st.data;
  const task = s.task;
  const lastFailed = !job && task && task.state === "failed" && task.kind.startsWith("nvidia");
  return (
    <Card title="NVIDIA driver for Docker apps" actions={<NvidiaBadge s={s} />}>
      {s.installed ? (
        <>
          <p className="small" style={{ margin: 0 }}>
            {s.loaded
              ? `NVIDIA's driver ${s.version} is running${s.toolkit ? " with the container toolkit" : ""}. Docker apps (Jellyfin, Plex, Immich, AI apps) can use NVIDIA cards that aren't with a VM.`
              : "NVIDIA's driver is installed. Restart the server to start using it."}
          </p>
          {s.consent && (
            <p className="small muted" style={{ margin: 0 }}>
              Licence agreed to by {s.consent.by} on {dateTime(s.consent.at)} (driver {s.consent.version}). HardyOS rebuilds it for every new version before installing an update.
            </p>
          )}
          <div className="row">
            {s.restartNeeded && (
              <Button variant="primary" onClick={onRestart}>
                <RestartIcon size={14} /> Restart now
              </Button>
            )}
            <Button variant="ghost" disabled={job !== null} onClick={() => setRemoving(true)}>
              <TrashIcon size={14} /> Remove the driver
            </Button>
          </div>
        </>
      ) : s.vgpu?.installed ? (
        <p className="small muted" style={{ margin: 0 }}>
          NVIDIA's vGPU host driver is installed instead (below). It splits supported cards for VMs; Docker apps can't use NVIDIA cards with it.
        </p>
      ) : (
        <>
          <p className="small" style={{ margin: 0 }}>
            HardyOS can install NVIDIA's driver so Docker apps can use your NVIDIA card for video transcoding and AI. It comes from Debian's non-free packages and NVIDIA's
            container toolkit, and is built for this server's kernel. You'll see NVIDIA's licence before anything is installed.
          </p>
          <div className="row">
            {s.licence ? (
              <Button variant="primary" disabled={job !== null} onClick={() => setLicence(true)}>
                Read NVIDIA's licence and install
              </Button>
            ) : (
              <Button variant="primary" busy={prepare.isPending} disabled={job !== null} onClick={() => prepare.mutate()}>
                Get the NVIDIA driver
              </Button>
            )}
            <span className="small muted">Packages: {s.packages.length}. Downloads about 400 MB.</span>
          </div>
        </>
      )}
      {prepare.error != null && <Alert tone="bad">{errorMessage(prepare.error)}</Alert>}
      {job && <JobProgress id={job} onDone={finished} />}
      {job && task?.state === "running" && <TaskLog log={task.log} />}
      {lastFailed && (
        <Alert tone="bad" title="The last NVIDIA driver step failed">
          {task.error}
          <TaskLog log={task.log} />
        </Alert>
      )}
      {licence && <LicenceDialog onClose={() => setLicence(false)} onStarted={(id) => setJob(id)} />}
      {removing && (
        <ConfirmDialog
          title="Remove the NVIDIA driver?"
          confirmLabel="Remove"
          onClose={() => setRemoving(false)}
          onConfirm={async () => {
            const r = await unwrap(api.POST("/devices/nvidia/remove", { body: { confirm: true } }));
            setJob((r as Accepted).job.id);
          }}
        >
          Docker apps stop using NVIDIA cards (they keep working without them). VMs can still be given the card. A restart finishes the removal.
        </ConfirmDialog>
      )}
    </Card>
  );
}

function NvidiaBadge({ s }: { s: NvidiaStatus }) {
  if (s.installed && s.loaded) return <Badge tone="good">Running</Badge>;
  if (s.restartNeeded) return <Badge tone="warn">Restart needed</Badge>;
  if (s.installed) return <Badge tone="info">Installed</Badge>;
  return <Badge tone="neutral">Not installed</Badge>;
}

function TaskLog({ log }: { log: string }) {
  if (!log) return null;
  return (
    <details className="devlog">
      <summary>Show the log</summary>
      <pre>{log}</pre>
    </details>
  );
}

/** NVIDIA's licence, from the packages; installing needs a ticked box. */
export function LicenceDialog({ onClose, onStarted }: { onClose: () => void; onStarted: (job: string) => void }) {
  const [agree, setAgree] = useState(false);
  const [text, setText] = useState<{ text: string; sha256: string; version: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useMutation({
    mutationFn: () => unwrap(api.GET("/devices/nvidia/licence")),
    onSuccess: (r) => setText({ text: r.text, sha256: r.licence.sha256, version: r.licence.version }),
    onError: (e) => setError(errorMessage(e)),
  });
  const install = useMutation({
    mutationFn: () => unwrap(api.POST("/devices/nvidia/install", { body: { licenceSha256: text!.sha256, accept: true } })),
    onSuccess: (r) => {
      onStarted((r as Accepted).job.id);
      onClose();
    },
  });
  if (!text && !load.isPending && !error) load.mutate();
  return (
    <Dialog
      title="NVIDIA's licence"
      description={text ? `NVIDIA driver ${text.version}, from Debian's non-free packages. Read it, then agree to install.` : undefined}
      width={640}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!agree || !text} busy={install.isPending} onClick={() => install.mutate()}>
            Agree and install
          </Button>
        </>
      }
    >
      {error && <Alert tone="bad">{error}</Alert>}
      {!text && !error && <Loading label="Reading the licence…" />}
      {text && (
        <>
          <pre className="devlicence" tabIndex={0} aria-label="Licence text">
            {text.text}
          </pre>
          <label className="row" style={{ flexWrap: "nowrap", marginTop: 10 }}>
            <input type="checkbox" checked={agree} onChange={(e) => setAgree(e.target.checked)} />
            <span>I have read NVIDIA's licence and agree to it.</span>
          </label>
        </>
      )}
      {install.error != null && <Alert tone="bad">{errorMessage(install.error)}</Alert>}
    </Dialog>
  );
}

/** NVIDIA's official vGPU host driver, uploaded by the admin. */
export function VGPUDriverCard({ onChanged }: { onChanged: () => void }) {
  const st = useNvidia();
  const [up, setUp] = useState<VGPUUpload | null>(null);
  const [pct, setPct] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [accept, setAccept] = useState(false);
  const [replace, setReplace] = useState(false);
  const [job, setJob] = useState<string | null>(null);
  const [removing, setRemoving] = useState(false);
  const install = useMutation({
    mutationFn: () =>
      unwrap(api.POST("/devices/vgpu-driver/install", { body: { upload: up!.upload, sha256: up!.sha256, fileName: up!.fileName, accept: true, replaceDriver: replace } })),
    onSuccess: (r) => {
      setJob((r as Accepted).job.id);
      setUp(null);
    },
  });
  if (st.isPending || st.isError) return null;
  const s = st.data;
  const pick = async (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    e.target.value = "";
    if (!f) return;
    setError(null);
    setPct(0);
    try {
      setUp(await uploadVGPUDriver(f, setPct));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setPct(null);
    }
  };
  return (
    <Card title="vGPU slices with NVIDIA's vGPU software" actions={s.vgpu?.installed ? <Badge tone="good">Installed</Badge> : undefined}>
      {s.vgpu?.installed ? (
        <>
          <p className="small" style={{ margin: 0 }}>
            NVIDIA vGPU host driver {s.vgpu.version} ({s.vgpuHostDriver ? "running" : "restart to start it"}). Cards NVIDIA supports for vGPU show their slice types above.
          </p>
          <Button variant="ghost" onClick={() => setRemoving(true)}>
            <TrashIcon size={14} /> Remove the vGPU driver
          </Button>
        </>
      ) : (
        <>
          <p className="small" style={{ margin: 0 }}>
            Split a supported NVIDIA card (data-center cards and some RTX workstation cards) between several VMs. This needs NVIDIA's vGPU software, licensed from
            NVIDIA: download the KVM host driver (<span className="mono">NVIDIA-Linux-x86_64-…-vgpu-kvm.run</span>) from NVIDIA's licensing portal and upload it here.
            Cards NVIDIA doesn't support for vGPU can still go to a VM whole.
          </p>
          {!up && (
            <label className="btn btn--secondary btn--md" style={{ alignSelf: "flex-start" }}>
              <UploadIcon size={14} /> Upload the vGPU host driver
              <input type="file" accept=".run" hidden onChange={pick} aria-label="vGPU host driver file" />
            </label>
          )}
          {pct !== null && <Progress value={pct} label="Uploading the driver" />}
          {up && (
            <div className="stack" style={{ gap: 8 }}>
              <p className="small" style={{ margin: 0 }}>
                <CheckIcon size={14} /> {up.fileName} (version {up.version})
                <br />
                <span className="muted">
                  SHA-256 <span className="mono">{up.sha256}</span>: compare it with NVIDIA's checksum.
                </span>
              </p>
              <label className="row" style={{ flexWrap: "nowrap" }}>
                <input type="checkbox" checked={accept} onChange={(e) => setAccept(e.target.checked)} />
                <span className="small">I have a licence for NVIDIA vGPU software and agree to the licence in NVIDIA's installer.</span>
              </label>
              {s.installed && (
                <label className="row" style={{ flexWrap: "nowrap" }}>
                  <input type="checkbox" checked={replace} onChange={(e) => setReplace(e.target.checked)} />
                  <span className="small">Remove the NVIDIA driver for Docker apps first (they can't be installed together).</span>
                </label>
              )}
              <div className="row">
                <Button variant="primary" disabled={!accept || (s.installed && !replace)} busy={install.isPending} onClick={() => install.mutate()}>
                  Install
                </Button>
                <Button variant="ghost" onClick={() => setUp(null)}>
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </>
      )}
      {(error || install.error != null) && <Alert tone="bad">{error ?? errorMessage(install.error)}</Alert>}
      {job && (
        <JobProgress
          id={job}
          onDone={() => {
            setJob(null);
            void st.refetch();
            onChanged();
          }}
        />
      )}
      {removing && (
        <ConfirmDialog
          title="Remove NVIDIA's vGPU host driver?"
          confirmLabel="Remove"
          onClose={() => setRemoving(false)}
          onConfirm={async () => {
            const r = await unwrap(api.POST("/devices/vgpu-driver/remove", { body: { confirm: true } }));
            setJob((r as Accepted).job.id);
          }}
        >
          VMs with vGPU slices won't start until it's installed again. A restart finishes the removal.
        </ConfirmDialog>
      )}
    </Card>
  );
}

function GroupsCard({ inv }: { inv: DeviceInventory }) {
  const shared = inv.groups.filter((g) => g.devices.length > 1);
  return (
    <Card title="IOMMU groups">
      {inv.groups.length === 0 ? (
        <p className="small muted" style={{ margin: 0 }}>
          No groups: IOMMU is off.
        </p>
      ) : (
        <>
          <p className="small muted" style={{ margin: 0 }}>
            Devices in one group can only go to a VM together. {inv.groups.length} groups; {shared.length} hold more than one device.
          </p>
          <ul className="devlist">
            {shared.map((g) => (
              <li key={g.id} className="small">
                {g.explanation}
              </li>
            ))}
          </ul>
        </>
      )}
    </Card>
  );
}

function USBCard({ inv }: { inv: DeviceInventory }) {
  return (
    <Card title="USB devices">
      {inv.usb.length === 0 ? (
        <p className="small muted" style={{ margin: 0 }}>
          Nothing plugged in.
        </p>
      ) : (
        <ul className="devlist">
          {inv.usb.map((u) => (
            <li key={u.port} className="small">
              {u.product || `${u.vendorId}:${u.productId}`}
              <span className="cell-sub">
                {[u.manufacturer, `port ${u.port}`, u.hub ? "hub" : "", u.owner ? `VM ${u.owner}` : "", u.critical].filter(Boolean).join(" · ")}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
