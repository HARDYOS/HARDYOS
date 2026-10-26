import type { AppInstallRequest, AppPackage, AppPackageRef, AppPlan, AppShareChoice } from "@hardy/api-client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../api";
import { AlertIcon } from "../../icons";
import { Alert, Button, ErrorBox, Field, Loading, Select, TextInput, Toggle } from "../../ui";
import { Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { JobProgress } from "../shared";
import { AppIcon, SourceBadge, appNotes, untrusted, useShares } from "./common";
import {
  AccessEditor,
  type AccessDraft,
  LimitsFields,
  type LimitsDraft,
  PermissionsPicker,
  SharesPicker,
  accessProblem,
  accessValue,
  defaultShareChoices,
  limitsProblem,
  limitsValue,
} from "./parts";

export function InstallDialog({
  pkgRef,
  plan: given,
  onClose,
  onInstalled,
}: {
  pkgRef: AppPackageRef;
  /** A plan already made (Create an app returns one). */
  plan?: AppPlan;
  onClose: () => void;
  onInstalled: () => void;
}) {
  const qc = useQueryClient();
  const plan = useQuery({
    queryKey: ["apps", "plan", pkgRef.source, pkgRef.ref, pkgRef.catalogId ?? 0],
    queryFn: () => unwrap(api.POST("/apps/plan", { body: pkgRef })),
    staleTime: 0,
    gcTime: 0,
    enabled: !given,
  });
  const [job, setJob] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const data = given ?? plan.data;

  if (!data) {
    return (
      <Dialog title="Install an app" onClose={onClose}>
        {plan.isError ? <ErrorBox error={plan.error} onRetry={() => plan.refetch()} /> : <Loading label="Checking the package…" />}
      </Dialog>
    );
  }
  const pkg = data.package;

  if (job) {
    return (
      <Dialog
        title={`Installing ${pkg.name}`}
        description="Downloading the app can take a few minutes. You can close this window; the install keeps going."
        onClose={onClose}
        footer={<Button onClick={failed ? () => setJob(null) : onClose}>{failed ? "Back" : "Close"}</Button>}
      >
        <JobProgress
          id={job}
          onDone={(j) => {
            void qc.invalidateQueries({ queryKey: ["apps"] });
            if (j.state === "succeeded") {
              toast("success", `${pkg.name} is ready`, appNotes(j));
              onInstalled();
            } else {
              setFailed(true);
            }
          }}
        />
      </Dialog>
    );
  }
  return <InstallForm plan={data} onClose={onClose} onStarted={setJob} />;
}

type Step = "settings" | "folders" | "permissions" | "access";
const STEP_LABEL: Record<Step, string> = { settings: "Settings", folders: "Shared folders", permissions: "Permissions", access: "Who can use it" };

const portProblem = (v: string) => {
  const n = Number(v);
  return Number.isInteger(n) && n >= 1024 && n <= 65535 ? null : "Use a port from 1024 to 65535";
};

function InstallForm({ plan, onClose, onStarted }: { plan: AppPlan; onClose: () => void; onStarted: (job: string) => void }) {
  const pkg = plan.package;
  const reinstall = plan.installed || plan.keptData;
  const steps: Step[] = ["settings", ...(pkg.shares.length > 0 ? (["folders"] as Step[]) : []), "permissions", "access"];
  const [step, setStep] = useState<Step>("settings");
  const [pool, setPool] = useState(plan.enginePool || plan.pools[0] || "");
  const [ports, setPorts] = useState<Record<string, string>>(() =>
    Object.fromEntries(pkg.ports.map((pt) => [pt.name, String(plan.ports[pt.name] ?? pt.default)])),
  );
  // On a reinstall, blank settings keep what the app has now.
  const [settings, setSettings] = useState<Record<string, string>>(() =>
    Object.fromEntries(pkg.settings.map((s) => [s.env, reinstall ? "" : s.default])),
  );
  const shares = useShares(pkg.shares.length > 0);
  const [choices, setChoices] = useState<Record<string, AppShareChoice> | null>(null);
  const shareChoices = choices ?? (shares.data ? defaultShareChoices(pkg.shares, shares.data) : {});
  const [grants, setGrants] = useState<string[]>([]);
  const [limits, setLimits] = useState<LimitsDraft>({ memoryMB: "", cpus: "" });
  const [access, setAccess] = useState<AccessDraft>({ everyone: true, principals: [] });
  const [replaceOk, setReplaceOk] = useState(false);
  const [busy, setBusy] = useState(false);
  const [problems, setProblems] = useState<string[]>([]);

  const missing = pkg.settings.filter((s) => s.required && !reinstall && !settings[s.env]?.trim());
  const stepReady: Record<Step, boolean> = {
    settings: !!pool && (pkg.fixedPorts || pkg.ports.every((pt) => !portProblem(ports[pt.name] ?? ""))) && missing.length === 0,
    folders: pkg.shares.every((m) => !m.required || !!shareChoices[m.name]?.share),
    permissions: !untrusted(pkg) || pkg.grants.every((g) => grants.includes(g.grant)),
    access: !accessProblem(access) && !limitsProblem(limits),
  };
  const index = steps.indexOf(step);
  const last = index === steps.length - 1;
  const allReady = steps.every((s) => stepReady[s]) && plan.available && (!plan.replaceSourceRequired || replaceOk);

  async function submit() {
    if (!last) {
      if (stepReady[step]) setStep(steps[index + 1]!);
      return;
    }
    if (!allReady) return;
    setBusy(true);
    setProblems([]);
    try {
      const chosen: Record<string, string> = {};
      for (const s of pkg.settings) {
        const v = settings[s.env] ?? "";
        if (v !== "" || !reinstall) chosen[s.env] = v;
      }
      const body: AppInstallRequest = {
        source: pkg.source,
        ref: pkg.ref,
        catalogId: pkg.source === "imported" ? pkg.catalogId : undefined,
        replaceSource: plan.replaceSourceRequired ? replaceOk : undefined,
        pool: plan.enginePool ? undefined : pool,
        ports: Object.fromEntries(Object.entries(ports).map(([k, v]) => [k, Number(v)])),
        settings: chosen,
      };
      if (pkg.shares.length > 0) body.shares = shareChoices;
      if (untrusted(pkg) && grants.length > 0) body.grants = grants;
      const l = limitsValue(limits);
      if (l.memoryMB > 0 || l.cpus > 0) body.limits = l;
      if (!access.everyone) body.access = accessValue(access);
      const r = await unwrap(api.POST("/apps/install", { body }));
      onStarted(r.job.id);
    } catch (err) {
      setProblems(err instanceof ApiFailure && err.details.length > 0 ? err.details : [errorMessage(err)]);
      setBusy(false);
    }
  }

  return (
    <Dialog
      title={reinstall ? `Reinstall ${pkg.name}` : `Install ${pkg.name}`}
      onClose={onClose}
      onSubmit={submit}
      width={640}
      footer={
        <>
          {index > 0 ? <Button onClick={() => setStep(steps[index - 1]!)}>Back</Button> : <Button onClick={onClose}>Cancel</Button>}
          <Button type="submit" variant="primary" disabled={last ? !allReady : !stepReady[step]} busy={busy}>
            {last ? (reinstall ? "Reinstall" : "Install") : "Next"}
          </Button>
        </>
      }
    >
      <div className="stack install">
        <div className="install__head">
          <AppIcon src={pkg.icon} name={pkg.name} size={56} />
          <div>
            <div className="install__name">{pkg.name}</div>
            <div className="small muted row" style={{ gap: 6 }}>
              <span className="mono">{pkg.version}</span>
              {pkg.publisher && <span>· {pkg.publisher}</span>}
              <SourceBadge source={pkg.source} sourceName={pkg.sourceName} />
              {pkg.source === "imported" && pkg.sourceName && <span>from {pkg.sourceName}</span>}
            </div>
          </div>
        </div>
        <ol className="install__steps" aria-label="Steps">
          {steps.map((s, i) => (
            <li key={s} aria-current={s === step ? "step" : undefined} className={i < index ? "is-done" : undefined}>
              <span className="mono">{i + 1}</span> {STEP_LABEL[s]}
            </li>
          ))}
        </ol>

        {plan.replaceSourceRequired && <ReplaceSourceWarning plan={plan} value={replaceOk} onChange={setReplaceOk} />}

        {step === "settings" && <SettingsStep plan={plan} pool={pool} setPool={setPool} ports={ports} setPorts={setPorts} settings={settings} setSettings={setSettings} />}
        {step === "folders" && (
          <>
            <p className="small muted" style={{ margin: 0 }}>
              Choose which of your shared folders {pkg.name} can use. It gets its own account on the server, so it only sees the folders you pick here.
            </p>
            <SharesPicker mounts={pkg.shares} value={shareChoices} onChange={setChoices} />
          </>
        )}
        {step === "permissions" && <PermissionsPicker pkg={pkg} value={grants} onChange={setGrants} />}
        {step === "access" && (
          <>
            <section className="install__section" aria-label="Who can use it">
              <h3>Who can use it</h3>
              <AccessEditor draft={access} onChange={setAccess} />
            </section>
            <details className="install__advanced">
              <summary>Advanced: resource limits</summary>
              <p className="small muted">Cap how much memory and processor time {pkg.name} may use, so it can't slow the rest of the server down.</p>
              <LimitsFields value={limits} onChange={setLimits} />
            </details>
          </>
        )}

        {problems.length > 0 && (
          <Alert tone="bad" title={problems.length === 1 ? "Can't install yet" : "Can't install yet:"}>
            {problems.length === 1 ? (
              problems[0]
            ) : (
              <ul className="install__problems">
                {problems.map((pr) => (
                  <li key={pr}>{pr}</li>
                ))}
              </ul>
            )}
          </Alert>
        )}
      </div>
    </Dialog>
  );
}

function sourceWords(source: string, name?: string): string {
  switch (source) {
    case "catalog":
      return "HardyOS's catalog";
    case "imported":
      return name ? `the ${name} catalog` : "an imported catalog";
    case "upload":
      return "an uploaded package";
    case "custom":
      return "a Compose file (Create an app)";
  }
  return "somewhere HardyOS can't tell";
}

/** The installed app with this id came from somewhere else: say so, and make the admin tick it. */
function ReplaceSourceWarning({ plan, value, onChange }: { plan: AppPlan; value: boolean; onChange: (v: boolean) => void }) {
  const pkg = plan.package;
  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="grant-warning" role="alert">
        <AlertIcon size={15} />
        <span>
          {pkg.name} ({pkg.id}) is {plan.installed ? "installed" : "kept"} from {sourceWords(plan.installedSource, plan.installedSourceName)}. This package is
          from {sourceWords(pkg.source, pkg.sourceName)}, and it would take over that app's data and passwords. Only go on if you trust it with them.
        </span>
      </div>
      <div className="grant-list">
        <label>
          <input type="checkbox" checked={value} onChange={(e) => onChange(e.target.checked)} />
          <span>Replace the installed {pkg.name} with this one, giving it the data and passwords</span>
        </label>
      </div>
    </div>
  );
}

function SettingsStep({
  plan,
  pool,
  setPool,
  ports,
  setPorts,
  settings,
  setSettings,
}: {
  plan: AppPlan;
  pool: string;
  setPool: (v: string) => void;
  ports: Record<string, string>;
  setPorts: (v: Record<string, string>) => void;
  settings: Record<string, string>;
  setSettings: (v: Record<string, string>) => void;
}) {
  const pkg = plan.package;
  const reinstall = plan.installed || plan.keptData;
  return (
    <>
      {pkg.description && <p className="install__desc">{pkg.description}</p>}
      {plan.installed && (
        <Alert tone="info" title={`${pkg.name} ${plan.installedVersion} is installed`}>
          Reinstalling keeps its data and passwords. Leave a setting blank to keep its current value.
        </Alert>
      )}
      {plan.keptData && (
        <Alert tone="info" title="Picks up the data you kept">
          {pkg.name} was removed before with its data kept. Installing it again uses that data and its passwords.
        </Alert>
      )}
      {!plan.available && <Alert tone="warn" title="This build doesn't include Docker" />}
      {plan.problem && <Alert tone="bad" title="Apps can't run right now">{plan.problem}</Alert>}

      {!plan.enginePool && (
        <Field label="Pool for apps" hint="Docker and every app keep their data here, in datasets you can snapshot. All apps share this pool.">
          {(fid) =>
            plan.pools.length === 0 ? (
              <Alert tone="warn" title="No pool yet">Create a pool in Storage Manager first.</Alert>
            ) : (
              <Select id={fid} value={pool} onChange={(e) => setPool(e.target.value)}>
                {plan.pools.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </Select>
            )
          }
        </Field>
      )}

      {pkg.ports.length > 0 && <PortFields pkg={pkg} ports={ports} setPorts={setPorts} />}

      {pkg.settings.map((s) => (
        <SettingField key={s.env} setting={s} value={settings[s.env] ?? ""} keep={reinstall} onChange={(v) => setSettings({ ...settings, [s.env]: v })} />
      ))}
    </>
  );
}

export function PortFields({ pkg, ports, setPorts }: { pkg: AppPackage; ports: Record<string, string>; setPorts: (v: Record<string, string>) => void }) {
  return (
    <div className="grid-2">
      {pkg.ports.map((pt) => (
        <Field
          key={pt.name}
          label={pt.label}
          hint={pkg.fixedPorts ? "Fixed: the app uses the server's network directly" : pt.web ? "Where the app's website opens" : `${pt.protocol.toUpperCase()} port on this server`}
          error={pkg.fixedPorts ? null : portProblem(ports[pt.name] ?? "")}
        >
          {(fid) => (
            <TextInput
              id={fid}
              className="input mono"
              inputMode="numeric"
              readOnly={pkg.fixedPorts}
              value={ports[pt.name] ?? ""}
              onChange={(e) => setPorts({ ...ports, [pt.name]: e.target.value.replace(/[^0-9]/g, "") })}
            />
          )}
        </Field>
      ))}
    </div>
  );
}

export { portProblem };

/** One of the app's settings. With keep, blank keeps the current value. */
export function SettingField({
  setting: s,
  value,
  keep: keepAll,
  onChange,
  isSet,
  editing,
}: {
  setting: AppPackage["settings"][number];
  value: string;
  keep: boolean;
  onChange: (v: string) => void;
  isSet?: boolean;
  /** The settings screen: values are filled in; only passwords keep when blank. */
  editing?: boolean;
}) {
  const keep = editing ? s.type === "password" : keepAll;
  if (editing && s.type !== "password" && s.type !== "boolean") {
    return (
      <Field label={s.label} hint={s.help || undefined}>
        {(fid) =>
          s.type === "select" ? (
            <Select id={fid} value={value} onChange={(e) => onChange(e.target.value)}>
              {s.options.map((o) => (
                <option key={o} value={o}>
                  {o}
                </option>
              ))}
            </Select>
          ) : (
            <TextInput id={fid} className={s.type === "number" ? "input mono" : "input"} value={value} onChange={(e) => onChange(e.target.value)} />
          )
        }
      </Field>
    );
  }
  if (editing && s.type === "password") {
    return (
      <Field label={s.label} hint={s.help || undefined}>
        {(fid) => (
          <TextInput id={fid} type="password" autoComplete="new-password" placeholder={isSet === false ? "Not set" : "Keep current password"} value={value} onChange={(e) => onChange(e.target.value)} />
        )}
      </Field>
    );
  }
  if (editing && s.type === "boolean") {
    return <Toggle label={s.label} description={s.help || undefined} checked={value === "true"} onChange={(v) => onChange(v ? "true" : "false")} />;
  }
  if (s.type === "boolean" && keep) {
    return (
      <Field label={s.label} hint={s.help || undefined}>
        {(fid) => (
          <Select id={fid} value={value} onChange={(e) => onChange(e.target.value)}>
            <option value="">Keep current</option>
            <option value="true">On</option>
            <option value="false">Off</option>
          </Select>
        )}
      </Field>
    );
  }
  if (s.type === "boolean") {
    const on = value === "" ? s.default === "true" : value === "true";
    return <Toggle label={s.label} description={s.help || undefined} checked={on} onChange={(v) => onChange(v ? "true" : "false")} />;
  }
  const placeholder = keep ? (s.type === "password" ? (isSet === false ? "Not set" : "Keep current password") : "Keep current") : undefined;
  return (
    <Field label={s.required && !keep ? s.label : `${s.label}${keep ? "" : " (optional)"}`} hint={s.help || undefined}>
      {(fid) =>
        s.type === "select" ? (
          <Select id={fid} value={value} onChange={(e) => onChange(e.target.value)}>
            {keep && <option value="">Keep current</option>}
            {s.options.map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
          </Select>
        ) : (
          <TextInput
            id={fid}
            type={s.type === "password" ? "password" : "text"}
            inputMode={s.type === "number" ? "numeric" : undefined}
            className={s.type === "number" ? "input mono" : "input"}
            autoComplete={s.type === "password" ? "new-password" : "off"}
            placeholder={placeholder}
            value={value}
            onChange={(e) => onChange(s.type === "number" ? e.target.value.replace(/[^0-9.]/g, "") : e.target.value)}
          />
        )
      }
    </Field>
  );
}
