import type { Disk, InstallCheck, InstallNetwork, InstallerHardware, InstallerStatus, Job } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, type ReactNode, useEffect, useMemo, useState } from "react";
import { api, errorMessage, unwrap } from "../api";
import { bytes } from "../format";
import { AlertIcon, CheckIcon, CpuIcon, DiskIcon, LockIcon, LogoIcon, NetworkIcon, RestartIcon } from "../icons";
import { Alert, Badge, Button, Field, Loading, Progress, Select, Spinner, TextInput } from "../ui";
import {
  INSTALL_STEPS,
  MAX_BOOT_DISKS,
  browserTimeZone,
  diskWarning,
  formatCode,
  hostnameError,
  ineligibleReason,
  networkErrors,
  stepIndex,
  suggestBootDisks,
  timeZones,
  usernameError,
} from "./logic";
import "./installer.css";

/** The live ISO's web installer. Shown instead of the desktop when hardyd runs in installer mode. */
export function Installer({ status }: { status: InstallerStatus }) {
  if (!status.unlocked) return <UnlockScreen />;
  const job = status.job;
  if (job && !isDone(job)) return <Installing job={job} />;
  if (job?.state === "succeeded") return <Finished job={job} />;
  return <Wizard version={status.version ?? ""} lastFailure={job?.state === "failed" ? job : undefined} />;
}

const isDone = (j: Job) => j.state === "succeeded" || j.state === "failed" || j.state === "cancelled";

/** Polls the installer status; fast while an install runs. */
export function useInstallerStatus() {
  return useQuery({
    queryKey: ["installer"],
    queryFn: () => unwrap(api.GET("/installer")),
    refetchInterval: (q) => {
      const j = q.state.data?.job;
      return j && !isDone(j) ? 1000 : false;
    },
    staleTime: Infinity,
  });
}

/* ---------- Unlock ---------- */

function UnlockScreen() {
  const qc = useQueryClient();
  const [code, setCode] = useState("");
  const unlock = useMutation({
    mutationFn: () => unwrap(api.POST("/installer/unlock", { body: { code } })),
    onSuccess: (st) => qc.setQueryData(["installer"], st),
    onError: () => setCode(""),
  });
  function submit(e: FormEvent) {
    e.preventDefault();
    if (code.replace("-", "").length === 8) unlock.mutate();
  }
  return (
    <div className="lock-screen wallpaper">
      <div className="setup-intro">
        <LogoIcon size={40} />
        <h1>Install HardyOS</h1>
        <p>To make sure it's you, enter the code shown on the server's screen. Connect a monitor if you don't see one.</p>
      </div>
      <form className="lock-card glass" onSubmit={submit} aria-label="Unlock the installer">
        <div className="lock-card__avatar" aria-hidden="true">
          <LockIcon size={28} />
        </div>
        <Field label="Installer code">
          {(id) => (
            <TextInput
              id={id}
              className="input inst-code"
              value={code}
              onChange={(e) => setCode(formatCode(e.target.value))}
              placeholder="XXXX-XXXX"
              autoComplete="one-time-code"
              autoCapitalize="characters"
              spellCheck={false}
              autoFocus
            />
          )}
        </Field>
        {unlock.error && <Alert tone="bad">{errorMessage(unlock.error)}</Alert>}
        <Button type="submit" variant="primary" className="btn--block btn--lg" busy={unlock.isPending} disabled={code.length !== 9}>
          Continue
        </Button>
      </form>
    </div>
  );
}

/* ---------- Wizard ---------- */

type StepId = "welcome" | "disks" | "settings" | "account" | "review";
const STEPS: { id: StepId; label: string }[] = [
  { id: "welcome", label: "Welcome" },
  { id: "disks", label: "Boot disks" },
  { id: "settings", label: "Name and network" },
  { id: "account", label: "Administrator" },
  { id: "review", label: "Review and install" },
];

interface Form {
  disks: string[];
  hostname: string;
  timezone: string;
  network: InstallNetwork;
  dnsText: string;
  displayName: string;
  username: string;
  password: string;
  confirm: string;
}

function Wizard({ version, lastFailure }: { version: string; lastFailure?: Job }) {
  const hw = useQuery({ queryKey: ["installer-hw"], queryFn: () => unwrap(api.GET("/installer/hardware")), staleTime: Infinity });
  const [step, setStep] = useState<StepId>(lastFailure ? "review" : "welcome");
  const [form, setForm] = useState<Form>({
    disks: [],
    hostname: "hardyos",
    timezone: browserTimeZone(),
    network: { mode: "dhcp" },
    dnsText: "",
    displayName: "",
    username: "",
    password: "",
    confirm: "",
  });
  const [suggested, setSuggested] = useState(false);
  useEffect(() => {
    if (hw.data && !suggested) {
      setSuggested(true);
      setForm((f) => ({ ...f, disks: f.disks.length ? f.disks : suggestBootDisks(hw.data.disks) }));
    }
  }, [hw.data, suggested]);

  const set = (patch: Partial<Form>) => setForm((f) => ({ ...f, ...patch }));
  const network: InstallNetwork =
    form.network.mode === "static"
      ? { ...form.network, dns: form.dnsText.split(/[\s,]+/).filter(Boolean) }
      : { mode: "dhcp" };

  const errors = {
    disks: form.disks.length === 0 ? "Choose at least one boot disk" : null,
    hostname: hostnameError(form.hostname),
    network: networkErrors(network),
    username: usernameError(form.username),
    password: form.password.length < 10 ? "At least 10 characters" : null,
    confirm: form.confirm !== form.password ? "The passwords don't match" : null,
  };
  const valid: Record<StepId, boolean> = {
    welcome: true,
    disks: !errors.disks,
    settings: !errors.hostname && Object.keys(errors.network).length === 0,
    account: !errors.username && !errors.password && !errors.confirm,
    review: true,
  };
  const idx = STEPS.findIndex((s) => s.id === step);
  const reachable = (i: number) => STEPS.slice(0, i).every((s) => valid[s.id]);

  return (
    <div className="inst wallpaper">
      <div className="inst__panel glass">
        <aside className="inst__rail">
          <div className="inst__brand">
            <LogoIcon size={26} />
            <div>
              <strong>HardyOS</strong>
              <span>{version ? `Installer · ${version}` : "Installer"}</span>
            </div>
          </div>
          <ol className="inst__steps" aria-label="Install steps">
            {STEPS.map((s, i) => (
              <li key={s.id}>
                <button
                  type="button"
                  className={`inst__step ${s.id === step ? "is-current" : ""} ${i < idx ? "is-done" : ""}`}
                  aria-current={s.id === step ? "step" : undefined}
                  disabled={!reachable(i)}
                  onClick={() => setStep(s.id)}
                >
                  <span className="inst__step-num">{i < idx ? <CheckIcon size={13} /> : i + 1}</span>
                  {s.label}
                </button>
              </li>
            ))}
          </ol>
        </aside>
        <main className="inst__main">
          {hw.isPending ? (
            <Loading label="Looking at your hardware…" />
          ) : hw.isError ? (
            <Alert tone="bad" title="Couldn't read the hardware" action={<Button onClick={() => hw.refetch()}>Try again</Button>}>
              {errorMessage(hw.error)}
            </Alert>
          ) : step === "welcome" ? (
            <Welcome hw={hw.data} version={version} />
          ) : step === "disks" ? (
            <DisksStep hw={hw.data} selected={form.disks} onChange={(disks) => set({ disks })} />
          ) : step === "settings" ? (
            <SettingsStep hw={hw.data} form={form} set={set} errors={errors} />
          ) : step === "account" ? (
            <AccountStep form={form} set={set} errors={errors} />
          ) : (
            <ReviewStep hw={hw.data} form={form} network={network} lastFailure={lastFailure} onEdit={setStep} />
          )}
          {step !== "review" && !hw.isPending && !hw.isError && (
            <footer className="inst__footer">
              {idx > 0 && <Button onClick={() => setStep(STEPS[idx - 1]!.id)}>Back</Button>}
              <Button variant="primary" disabled={!valid[step]} onClick={() => setStep(STEPS[idx + 1]!.id)}>
                Continue
              </Button>
            </footer>
          )}
        </main>
      </div>
    </div>
  );
}

function StepHeader({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <header className="inst__header">
      <h1>{title}</h1>
      {children && <p>{children}</p>}
    </header>
  );
}

function Welcome({ hw, version }: { hw: InstallerHardware; version: string }) {
  const nicsWithIP = hw.nics.filter((n) => n.addresses.length > 0);
  return (
    <>
      <StepHeader title={`Install HardyOS${version ? ` ${version}` : ""}`}>
        This puts HardyOS on one or two small disks (the boot disks). Your data goes on separate disks in a storage pool you
        create afterwards, so the system can be reinstalled or updated without touching it.
      </StepHeader>
      <div className="inst__facts">
        <Fact icon={<CpuIcon size={18} />} label="Processor" value={hw.cpu || "Unknown"} />
        <Fact icon={<CpuIcon size={18} />} label="Memory" value={`${Math.round(hw.memBytes / 1024 ** 3)} GB`} />
        <Fact icon={<DiskIcon size={18} />} label="Disks" value={`${hw.disks.length} found`} />
        <Fact
          icon={<NetworkIcon size={18} />}
          label="Network"
          value={nicsWithIP.length ? nicsWithIP.map((n) => `${n.name} ${n.addresses[0]}`).join(", ") : "No address yet"}
        />
      </div>
      {hw.virtual && (
        <Alert tone="info" title="Running in a virtual machine">
          That's fine for trying HardyOS. Give each virtual disk a SATA or NVMe controller so it has a stable ID.
        </Alert>
      )}
      <p className="small muted">It takes about 5–15 minutes. You'll choose disks and settings first; nothing is changed until the last step.</p>
    </>
  );
}

function Fact({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="inst__fact">
      <span className="inst__fact-icon">{icon}</span>
      <span className="inst__fact-label">{label}</span>
      <span className="inst__fact-value">{value}</span>
    </div>
  );
}

function DisksStep({ hw, selected, onChange }: { hw: InstallerHardware; selected: string[]; onChange: (d: string[]) => void }) {
  const toggle = (d: Disk) => {
    if (selected.includes(d.byId)) onChange(selected.filter((x) => x !== d.byId));
    else if (selected.length < MAX_BOOT_DISKS) onChange([...selected, d.byId]);
  };
  const sizes = hw.disks.filter((d) => selected.includes(d.byId)).map((d) => d.sizeBytes);
  return (
    <>
      <StepHeader title="Choose the boot disks">
        Pick one or two small SSDs. With two, HardyOS mirrors itself so the server keeps running if one fails. Everything on
        the disks you pick is erased.
      </StepHeader>
      <div className="inst__disks" role="group" aria-label="Disks">
        {hw.disks.map((d) => {
          const reason = ineligibleReason(d);
          const warn = diskWarning(d);
          const on = selected.includes(d.byId);
          return (
            <label key={d.byId} className={`inst__disk ${on ? "is-on" : ""} ${reason ? "is-off" : ""}`}>
              <input type="checkbox" checked={on} disabled={!!reason || (!on && selected.length >= MAX_BOOT_DISKS)} onChange={() => toggle(d)} />
              <span className="inst__disk-icon">
                <DiskIcon size={20} />
              </span>
              <span className="inst__disk-main">
                <span className="inst__disk-name">
                  {d.model || d.name} <Badge tone="neutral">{d.kind.toUpperCase()}</Badge>
                  {d.removable && <Badge tone="neutral">USB</Badge>}
                </span>
                <span className="inst__disk-sub mono">{d.name} · {d.serial || d.byId.replace("/dev/disk/by-id/", "")}</span>
                {(reason || warn) && <span className={`inst__disk-note ${reason ? "" : "is-warn"}`}>{reason ?? warn}</span>}
              </span>
              <span className="inst__disk-size mono">{bytes(d.sizeBytes, 0)}</span>
            </label>
          );
        })}
        {hw.disks.length === 0 && <Alert tone="bad" title="No disks found">Check the cables or the disk controller settings.</Alert>}
      </div>
      {selected.length === 1 && (
        <Alert tone="info">With one boot disk, a disk failure means reinstalling HardyOS. Your data pool isn't affected either way.</Alert>
      )}
      {selected.length >= 2 && (
        <Alert tone="good">
          Mirrored across {selected.length} disks · {bytes(Math.min(...sizes), 0)} usable
        </Alert>
      )}
    </>
  );
}

type Errors = {
  hostname: string | null;
  network: ReturnType<typeof networkErrors>;
  username: string | null;
  password: string | null;
  confirm: string | null;
};

function SettingsStep({ hw, form, set, errors }: { hw: InstallerHardware; form: Form; set: (p: Partial<Form>) => void; errors: Errors }) {
  const zones = useMemo(timeZones, []);
  const net = form.network;
  const setNet = (patch: Partial<InstallNetwork>) => set({ network: { ...net, ...patch } });
  return (
    <>
      <StepHeader title="Name and network">The name is how the server shows up on your network.</StepHeader>
      <div className="stack">
        <div className="grid-2">
          <Field label="Server name" hint="Lowercase letters, digits and dashes" error={form.hostname ? errors.hostname : null}>
            {(id) => <TextInput id={id} value={form.hostname} onChange={(e) => set({ hostname: e.target.value.toLowerCase() })} spellCheck={false} />}
          </Field>
          <Field label="Time zone">
            {(id) => (
              <Select id={id} value={form.timezone} onChange={(e) => set({ timezone: e.target.value })}>
                {zones.map((z) => (
                  <option key={z}>{z}</option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <fieldset className="inst__choice">
          <legend>Network address</legend>
          <label className={`inst__radio ${net.mode === "dhcp" ? "is-on" : ""}`}>
            <input type="radio" name="netmode" checked={net.mode === "dhcp"} onChange={() => setNet({ mode: "dhcp" })} />
            <span>
              <strong>Automatic (DHCP)</strong>
              <span className="small muted">Recommended. Reserve the address in your router so it doesn't change.</span>
            </span>
          </label>
          <label className={`inst__radio ${net.mode === "static" ? "is-on" : ""}`}>
            <input
              type="radio"
              name="netmode"
              checked={net.mode === "static"}
              onChange={() => {
                const first = hw.nics.find((n) => n.addresses.length) ?? hw.nics[0];
                const v4 = first?.addresses.find((a) => a.includes("."));
                setNet({ mode: "static", interface: net.interface || first?.name || "", address: net.address || v4 || "" });
              }}
            />
            <span>
              <strong>Fixed address</strong>
              <span className="small muted">Set the address yourself.</span>
            </span>
          </label>
        </fieldset>
        {net.mode === "static" && (
          <div className="grid-2">
            <Field label="Network port" error={errors.network.interface}>
              {(id) => (
                <Select id={id} value={net.interface ?? ""} onChange={(e) => setNet({ interface: e.target.value })}>
                  <option value="">Choose…</option>
                  {hw.nics.map((n) => (
                    <option key={n.name} value={n.name}>
                      {n.name} {n.up ? `· connected${n.speedMbps > 0 ? ` ${n.speedMbps} Mb/s` : ""}` : "· no cable"}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label="Address" hint="With prefix length, like 192.168.1.20/24" error={net.address ? errors.network.address : null}>
              {(id) => <TextInput id={id} className="input mono" value={net.address ?? ""} onChange={(e) => setNet({ address: e.target.value.trim() })} />}
            </Field>
            <Field label="Gateway" hint="Usually your router" error={errors.network.gateway}>
              {(id) => <TextInput id={id} className="input mono" value={net.gateway ?? ""} onChange={(e) => setNet({ gateway: e.target.value.trim() })} />}
            </Field>
            <Field label="DNS servers" hint="Comma-separated" error={errors.network.dns}>
              {(id) => <TextInput id={id} className="input mono" value={form.dnsText} onChange={(e) => set({ dnsText: e.target.value })} placeholder="1.1.1.1, 9.9.9.9" />}
            </Field>
          </div>
        )}
      </div>
    </>
  );
}

function AccountStep({ form, set, errors }: { form: Form; set: (p: Partial<Form>) => void; errors: Errors }) {
  return (
    <>
      <StepHeader title="Create the administrator">
        You'll sign in with this account after the first start. It stays a local account, so it always works, even if other
        sign-in methods are down.
      </StepHeader>
      <div className="stack inst__narrow">
        <Field label="Your name" hint="Shown in the menu bar">
          {(id) => <TextInput id={id} value={form.displayName} onChange={(e) => set({ displayName: e.target.value })} autoComplete="name" />}
        </Field>
        <Field label="Username" error={form.username ? errors.username : null}>
          {(id) => (
            <TextInput id={id} value={form.username} onChange={(e) => set({ username: e.target.value.toLowerCase() })} autoComplete="username" autoCapitalize="none" spellCheck={false} />
          )}
        </Field>
        <Field label="Password" hint="At least 10 characters" error={form.password ? errors.password : null}>
          {(id) => <TextInput id={id} type="password" value={form.password} onChange={(e) => set({ password: e.target.value })} autoComplete="new-password" />}
        </Field>
        <Field label="Repeat password" error={form.confirm ? errors.confirm : null}>
          {(id) => <TextInput id={id} type="password" value={form.confirm} onChange={(e) => set({ confirm: e.target.value })} autoComplete="new-password" />}
        </Field>
      </div>
    </>
  );
}

function ReviewStep({
  hw,
  form,
  network,
  lastFailure,
  onEdit,
}: {
  hw: InstallerHardware;
  form: Form;
  network: InstallNetwork;
  lastFailure?: Job;
  onEdit: (s: StepId) => void;
}) {
  const qc = useQueryClient();
  const [typed, setTyped] = useState("");
  const plan = { disks: form.disks, hostname: form.hostname, timezone: form.timezone, network };
  const check = useQuery({
    queryKey: ["installer-check", plan],
    queryFn: () => unwrap(api.POST("/installer/check", { body: { plan } })),
    staleTime: 0,
    retry: false,
  });
  const install = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/installer/install", {
          body: {
            plan,
            admin: { username: form.username, displayName: form.displayName, password: form.password },
            confirmWipe: true,
          },
        }),
      ),
    onSuccess: (job) => {
      qc.setQueryData<InstallerStatus>(["installer"], (st) => ({ ...(st ?? { active: true, unlocked: true }), job }));
      void qc.invalidateQueries({ queryKey: ["installer"] });
    },
  });
  const diskInfo = (id: string): Disk | undefined => hw.disks.find((d) => d.byId === id);
  const ready = typed.trim().toUpperCase() === "ERASE" && check.isSuccess;

  return (
    <>
      <StepHeader title="Review and install">Check the summary. Installing erases the boot disks below.</StepHeader>
      {lastFailure && (
        <Alert tone="bad" title="The last attempt failed">
          {lastFailure.error || "Unknown error"}. Nothing else was changed; you can try again.
        </Alert>
      )}
      <dl className="inst__summary">
        <SummaryRow label="Boot disks" onEdit={() => onEdit("disks")}>
          {form.disks.length > 1 ? `Mirror of ${form.disks.length} disks` : "Single disk"}
          <ul className="inst__summary-disks">
            {form.disks.map((id) => {
              const d = diskInfo(id);
              const warnings = (check.data as InstallCheck | undefined)?.disks.find((c) => c.disk.byId === id)?.warnings ?? [];
              return (
                <li key={id}>
                  <span>
                    {d?.model || d?.name || id} <span className="mono muted">{d ? bytes(d.sizeBytes, 0) : ""}</span>
                  </span>
                  {warnings.map((w) => (
                    <span key={w} className="inst__warn">
                      <AlertIcon size={13} /> {w}
                    </span>
                  ))}
                </li>
              );
            })}
          </ul>
        </SummaryRow>
        <SummaryRow label="Server name" onEdit={() => onEdit("settings")}>
          <span className="mono">{form.hostname}</span>
        </SummaryRow>
        <SummaryRow label="Time zone" onEdit={() => onEdit("settings")}>
          {form.timezone}
        </SummaryRow>
        <SummaryRow label="Network" onEdit={() => onEdit("settings")}>
          {network.mode === "dhcp" ? (
            "Automatic (DHCP) on every port"
          ) : (
            <span className="mono">
              {network.interface} {network.address}
              {network.gateway ? ` via ${network.gateway}` : ""}
            </span>
          )}
        </SummaryRow>
        <SummaryRow label="Administrator" onEdit={() => onEdit("account")}>
          {form.displayName ? `${form.displayName} (${form.username})` : form.username}
        </SummaryRow>
      </dl>
      {check.isPending && <Loading label="Checking the disks…" />}
      {check.isError && <Alert tone="bad" title="This plan won't work">{errorMessage(check.error)}</Alert>}
      <div className="inst__confirm">
        <Field label='Type ERASE to confirm' hint="Everything on the boot disks will be deleted">
          {(id) => <TextInput id={id} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />}
        </Field>
      </div>
      {install.error && <Alert tone="bad">{errorMessage(install.error)}</Alert>}
      <footer className="inst__footer">
        <Button onClick={() => onEdit("account")}>Back</Button>
        <Button variant="danger" disabled={!ready} busy={install.isPending} onClick={() => install.mutate()}>
          Erase disks and install
        </Button>
      </footer>
    </>
  );
}

function SummaryRow({ label, onEdit, children }: { label: string; onEdit: () => void; children: ReactNode }) {
  return (
    <div className="inst__summary-row">
      <dt>{label}</dt>
      <dd>{children}</dd>
      <Button size="sm" variant="ghost" onClick={onEdit} aria-label={`Change ${label.toLowerCase()}`}>
        Change
      </Button>
    </div>
  );
}

/* ---------- Progress and done ---------- */

function useElapsed(since?: string | null) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  if (!since) return "";
  const s = Math.max(0, Math.floor((now - Date.parse(since)) / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

function Installing({ job }: { job: Job }) {
  const current = stepIndex(job.message ?? "");
  const elapsed = useElapsed(job.startedAt ?? job.createdAt);
  return (
    <div className="lock-screen wallpaper">
      <div className="inst__progress glass" aria-live="polite">
        <LogoIcon size={36} />
        <h1>Installing HardyOS</h1>
        <p className="muted">Keep the server on. This takes about 5–15 minutes.</p>
        <Progress value={job.progress ?? 0} label="Install progress" />
        <div className="inst__progress-meta small muted">
          <span>{Math.round(job.progress ?? 0)}%</span>
          <span className="mono">{elapsed}</span>
        </div>
        <ol className="inst__progress-steps">
          {INSTALL_STEPS.map((s, i) => (
            <li key={s} className={i < current ? "is-done" : i === current ? "is-current" : ""}>
              <span className="inst__progress-dot">{i < current ? <CheckIcon size={12} /> : i === current ? <Spinner size={12} /> : null}</span>
              {s}
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}

function Finished({ job }: { job: Job }) {
  const [rebooting, setRebooting] = useState(false);
  const reboot = useMutation({
    mutationFn: () => unwrap(api.POST("/installer/reboot")),
    onSuccess: () => setRebooting(true),
  });
  const result = (job.result ?? {}) as { hostname?: string };

  // After the restart the installed system answers on the same address; go
  // to its sign-in screen as soon as it does.
  useEffect(() => {
    if (!rebooting) return;
    let sawDown = false;
    const t = setInterval(async () => {
      try {
        const r = await fetch("/api/v1/installer", { cache: "no-store" });
        const st = (await r.json()) as InstallerStatus;
        if (!st.active) window.location.assign("/");
        else if (sawDown) window.location.reload();
      } catch {
        sawDown = true;
      }
    }, 4000);
    return () => clearInterval(t);
  }, [rebooting]);

  return (
    <div className="lock-screen wallpaper">
      <div className="inst__progress glass">
        <span className="inst__done-badge">
          <CheckIcon size={26} />
        </span>
        <h1>HardyOS is installed</h1>
        {rebooting ? (
          <>
            <p className="muted">
              Restarting. This page opens the sign-in screen when the server is back, usually within two minutes.
            </p>
            <Loading label="Waiting for the server…" />
            <p className="small muted">
              If nothing happens, open https://{result.hostname || "<server address>"} or the address shown on the server's screen.
            </p>
          </>
        ) : (
          <>
            <p className="muted">Remove the USB stick you installed from, then restart. You'll sign in with the administrator account you just created.</p>
            {reboot.error && <Alert tone="bad">{errorMessage(reboot.error)}</Alert>}
            <Button variant="primary" className="btn--lg" busy={reboot.isPending} onClick={() => reboot.mutate()}>
              <RestartIcon size={16} /> Restart now
            </Button>
          </>
        )}
      </div>
    </div>
  );
}
