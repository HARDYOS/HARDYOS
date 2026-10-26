import type { AppEntryGrant, AppLimits, AppPackage, AppPrincipal, AppShareChoice, AppShareMount } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api, unwrap } from "../../api";
import { AlertIcon, PlusIcon, TrashIcon } from "../../icons";
import { Alert, Button, Field, Loading, Select, TextInput, Toggle } from "../../ui";
import { type Share, useShares } from "./common";

// ---- shared folders ---------------------------------------------------------

/** The default choice for each of a package's shares: its suggestion when that folder exists. */
export function defaultShareChoices(mounts: AppShareMount[], shares: Share[]): Record<string, AppShareChoice> {
  const ids = new Set(shares.map((s) => s.id));
  return Object.fromEntries(
    mounts.map((m) => [m.name, { share: m.suggest && ids.has(m.suggest) ? m.suggest : "", path: "", access: m.access }]),
  );
}

export function SharesPicker({
  mounts,
  value,
  onChange,
}: {
  mounts: AppShareMount[];
  value: Record<string, AppShareChoice>;
  onChange: (v: Record<string, AppShareChoice>) => void;
}) {
  const shares = useShares();
  if (shares.isPending) return <Loading label="Finding shared folders…" />;
  const list = shares.data ?? [];
  return (
    <div className="stack">
      {shares.isError && (
        <Alert tone="warn" title="Couldn't list the shared folders">
          You can still install the app and give it folders later in its settings.
        </Alert>
      )}
      {!shares.isError && list.length === 0 && (
        <Alert tone="info" title="No shared folders yet">
          Create some in Control Panel › Shared Folders, then give them to the app in its settings.
        </Alert>
      )}
      {mounts.map((m) => (
        <ShareRow key={m.name} mount={m} shares={list} value={value[m.name] ?? { share: "", path: "", access: m.access }} onChange={(c) => onChange({ ...value, [m.name]: c })} />
      ))}
    </div>
  );
}

function ShareRow({ mount: m, shares, value, onChange }: { mount: AppShareMount; shares: Share[]; value: AppShareChoice; onChange: (c: AppShareChoice) => void }) {
  const access = value.access ?? m.access;
  // Apps get whole shared folders: a subfolder could be swapped for a link
  // by the app itself (security review), so path is always "".
  return (
    <section className="install__section" aria-label={m.label}>
      <div className="row row--between">
        <h3>{m.label}</h3>
        <span className="small muted">{m.access === "write" ? "Can read and change files" : "Can only read files"}</span>
      </div>
      {m.help && <p className="small muted">{m.help}</p>}
      <Field label={`Shared folder for ${m.label}`} error={m.required && !value.share ? "Choose a shared folder" : null} hint="The app sees the whole folder">
        {(fid) => (
          <Select id={fid} value={value.share} onChange={(e) => onChange({ ...value, share: e.target.value, path: "" })}>
            <option value="">{m.required ? "Choose…" : "None"}</option>
            {shares.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {m.access === "write" && value.share && (
        <Toggle
          label="Only let it read"
          description="The app can see the files but not change or delete them."
          checked={access === "read"}
          onChange={(ro) => onChange({ ...value, access: ro ? "read" : "write" })}
        />
      )}
    </section>
  );
}

// ---- permissions ------------------------------------------------------------

/**
 * What the app may do beyond its own folder. Catalog apps: labelled. Anything
 * else: every extra permission is an unticked checkbox with a red warning.
 */
export function PermissionsPicker({ pkg, value, onChange }: { pkg: AppPackage; value: string[]; onChange: (v: string[]) => void }) {
  const catalog = pkg.source === "catalog";
  return (
    <section className="install__section" aria-label="What it can do">
      <h3>What it can do</h3>
      {pkg.grants.length === 0 ? (
        <p className="small muted">Runs in its own containers. It can only see its own folder, the shared folders you give it and its ports.</p>
      ) : catalog ? (
        <>
          <p className="small muted">Besides its own folder and ports, {pkg.name} uses:</p>
          <ul className="install__perms">
            {pkg.grants.map((g) => (
              <li key={g.grant}>
                <AlertIcon size={13} /> {g.label}
              </li>
            ))}
          </ul>
        </>
      ) : (
        <GrantChecks grants={pkg.grants} value={value} onChange={onChange} name={pkg.name} />
      )}
      {pkg.images.length > 0 && (
        <p className="small muted">
          Software:{" "}
          {pkg.images.map((img, i) => (
            <span key={img}>
              {i > 0 && ", "}
              <span className="mono">{img}</span>
            </span>
          ))}
        </p>
      )}
    </section>
  );
}

export function GrantChecks({ grants, value, onChange, name }: { grants: AppEntryGrant[]; value: string[]; onChange: (v: string[]) => void; name: string }) {
  const set = new Set(value);
  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="grant-warning" role="alert">
        <AlertIcon size={15} />
        <span>
          {name} isn't from HardyOS's catalog, so nobody has checked it. It asks for more than a plain app gets. Only allow these if you trust whoever made
          it: it can't be installed without them.
        </span>
      </div>
      <div className="grant-list">
        {grants.map((g) => (
          <label key={g.grant}>
            <input
              type="checkbox"
              checked={set.has(g.grant)}
              onChange={(e) => onChange(e.target.checked ? [...value, g.grant] : value.filter((x) => x !== g.grant))}
            />
            <span>{g.label}</span>
          </label>
        ))}
      </div>
    </div>
  );
}

// ---- limits -------------------------------------------------------------------

export interface LimitsDraft {
  memoryMB: string;
  cpus: string;
}

export const limitsDraft = (l?: AppLimits | null): LimitsDraft => ({
  memoryMB: l && l.memoryMB > 0 ? String(l.memoryMB) : "",
  cpus: l && l.cpus > 0 ? String(l.cpus) : "",
});

export function limitsProblem(d: LimitsDraft): string | null {
  const m = d.memoryMB === "" ? 0 : Number(d.memoryMB);
  const c = d.cpus === "" ? 0 : Number(d.cpus);
  if (!Number.isInteger(m) || m < 0 || (m > 0 && m < 64)) return "Memory: leave empty for no limit, or at least 64 MB";
  if (!Number.isFinite(c) || c < 0 || c > 1024) return "CPUs: leave empty for no limit, or a number like 1.5";
  return null;
}

export const limitsValue = (d: LimitsDraft): AppLimits => ({ memoryMB: d.memoryMB === "" ? 0 : Number(d.memoryMB), cpus: d.cpus === "" ? 0 : Number(d.cpus) });

export function LimitsFields({ value, onChange }: { value: LimitsDraft; onChange: (v: LimitsDraft) => void }) {
  const problem = limitsProblem(value);
  return (
    <div className="stack" style={{ gap: 6 }}>
      <div className="grid-2">
        <Field label="Memory limit (MB)" hint="Empty: no limit">
          {(fid) => (
            <TextInput id={fid} className="input mono" inputMode="numeric" value={value.memoryMB} onChange={(e) => onChange({ ...value, memoryMB: e.target.value.replace(/[^0-9]/g, "") })} />
          )}
        </Field>
        <Field label="CPU limit (CPUs)" hint="Empty: no limit. 0.5 is half a CPU">
          {(fid) => (
            <TextInput id={fid} className="input mono" inputMode="decimal" value={value.cpus} onChange={(e) => onChange({ ...value, cpus: e.target.value.replace(/[^0-9.]/g, "") })} />
          )}
        </Field>
      </div>
      {problem && (
        <span className="field__error" role="alert">
          {problem}
        </span>
      )}
    </div>
  );
}

// ---- who can use it -----------------------------------------------------------

const principalKey = (p: AppPrincipal) => `${p.kind}:${p.name.toLowerCase()}`;

/** Who may use an app, as edited: everyone, or the chosen people and groups. */
export interface AccessDraft {
  everyone: boolean;
  principals: AppPrincipal[];
}

export const accessDraft = (list: AppPrincipal[]): AccessDraft => ({ everyone: list.length === 0, principals: list });
/** What to send: an empty list means everyone. */
export const accessValue = (d: AccessDraft): AppPrincipal[] => (d.everyone ? [] : d.principals);
export const accessProblem = (d: AccessDraft): string | null =>
  !d.everyone && d.principals.length === 0 ? "Choose at least one person or group, or let everyone use it" : null;

/** Who may use an app. */
export function AccessEditor({ draft, onChange }: { draft: AccessDraft; onChange: (v: AccessDraft) => void }) {
  const everyone = draft.everyone;
  const value = draft.principals;
  const users = useQuery({ queryKey: ["users"], queryFn: () => unwrap(api.GET("/users")), staleTime: 60_000 });
  const domain = useQuery({ queryKey: ["domain"], queryFn: () => unwrap(api.GET("/domain")), retry: false, staleTime: 60_000 });
  const netbios = domain.data?.provisioned ? (domain.data.config?.netbios ?? "") : "";
  const dUsers = useQuery({ queryKey: ["domain", "users"], queryFn: () => unwrap(api.GET("/domain/users")), enabled: !!netbios, retry: false });
  const dGroups = useQuery({ queryKey: ["domain", "groups"], queryFn: () => unwrap(api.GET("/domain/groups")), enabled: !!netbios, retry: false });
  const [manual, setManual] = useState("");
  const [manualKind, setManualKind] = useState<"user" | "group">("group");
  const chosen = new Set(value.map(principalKey));

  const set = (principals: AppPrincipal[]) => onChange({ everyone: false, principals });
  const toggle = (p: AppPrincipal, on: boolean) => set(on ? [...value, p] : value.filter((x) => principalKey(x) !== principalKey(p)));
  const options: { label: string; items: AppPrincipal[] }[] = [
    { label: "HardyOS accounts", items: (users.data ?? []).filter((u) => !u.disabled).map((u) => ({ kind: "user", name: u.username })) },
  ];
  if (netbios) {
    options.push(
      { label: `Groups in ${netbios}`, items: (dGroups.data?.groups ?? []).map((g) => ({ kind: "group", name: `${netbios}\\${g.name}` })) },
      { label: `People in ${netbios}`, items: (dUsers.data?.users ?? []).filter((u) => u.enabled).map((u) => ({ kind: "user", name: `${netbios}\\${u.username}` })) },
    );
  }
  const known = new Set(options.flatMap((o) => o.items.map(principalKey)));
  const extra = value.filter((p) => !known.has(principalKey(p)));
  const manualOk = /^[A-Za-z0-9][A-Za-z0-9-]{0,14}\\[^\\/:*?"<>|]{1,64}$/.test(manual.trim());

  return (
    <div className="stack" style={{ gap: 10 }}>
      <Toggle
        label="Everyone signed in to HardyOS"
        description="Administrators can always use every app."
        checked={everyone}
        onChange={(on) => onChange({ everyone: on, principals: value })}
      />
      {!everyone && (
      <div className="stack" style={{ gap: 8 }} aria-label="People and groups">
        {options.map((o) =>
          o.items.length === 0 ? null : (
            <fieldset key={o.label} className="access-group">
              <legend className="small muted">{o.label}</legend>
              <div className="check-list">
                {o.items.map((p) => (
                  <label key={principalKey(p)}>
                    <input type="checkbox" checked={chosen.has(principalKey(p))} onChange={(e) => toggle(p, e.target.checked)} />
                    <span>{p.name}</span>
                  </label>
                ))}
              </div>
            </fieldset>
          ),
        )}
        {extra.length > 0 && (
          <ul className="access-extra">
            {extra.map((p) => (
              <li key={principalKey(p)}>
                <span className="mono small">{p.name}</span> <span className="muted small">({p.kind})</span>
                <Button size="sm" variant="ghost" aria-label={`Remove ${p.name}`} onClick={() => toggle(p, false)}>
                  <TrashIcon size={13} />
                </Button>
              </li>
            ))}
          </ul>
        )}
        <div className="row access-add">
          <Select aria-label="Kind" value={manualKind} onChange={(e) => setManualKind(e.target.value as "user" | "group")}>
            <option value="group">Domain group</option>
            <option value="user">Domain user</option>
          </Select>
          <TextInput aria-label="Domain name" placeholder={netbios ? `${netbios}\\Family` : "HOME\\Family"} value={manual} onChange={(e) => setManual(e.target.value)} />
          <Button
            size="sm"
            disabled={!manualOk}
            onClick={() => {
              const p: AppPrincipal = { kind: manualKind, name: manual.trim() };
              if (!chosen.has(principalKey(p))) set([...value, p]);
              setManual("");
            }}
          >
            <PlusIcon size={13} /> Add
          </Button>
        </div>
        {accessProblem(draft) && <p className="field__error">{accessProblem(draft)}</p>}
      </div>
      )}
    </div>
  );
}
