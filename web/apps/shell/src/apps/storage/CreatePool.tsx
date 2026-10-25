import type { Disk, PoolSpec, Recommendation, VdevSpec } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { bytes } from "../../format";
import { useHardware } from "../../hooks/queries";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Field, Loading, PageHeader, Select, TextInput, Toggle } from "../../ui";
import { JobProgress } from "../shared";

type Role = "data" | "special" | "log" | "cache" | "spare" | "none";
type Layout = VdevSpec["type"];

const ROLE_LABEL: Record<Role, string> = {
  data: "Data",
  special: "Special (metadata)",
  log: "Log (SLOG)",
  cache: "Read cache (L2ARC)",
  spare: "Hot spare",
  none: "Don't use",
};

const MIN_DISKS: Record<Layout, number> = { stripe: 1, mirror: 2, raidz1: 3, raidz2: 4, raidz3: 5 };
const PARITY: Record<Layout, (n: number) => number> = {
  stripe: () => 0,
  mirror: (n) => n - 1,
  raidz1: () => 1,
  raidz2: () => 2,
  raidz3: () => 3,
};
const LAYOUT_LABEL: Record<Layout, string> = {
  stripe: "Stripe (no redundancy)",
  mirror: "Mirror (full copies)",
  raidz1: "RAIDZ1 (1 parity disk)",
  raidz2: "RAIDZ2 (2 parity disks)",
  raidz3: "RAIDZ3 (3 parity disks)",
};

/** Default layout for n data disks, following the HardyOS table. */
export function defaultLayout(n: number): Layout {
  if (n <= 1) return "stripe";
  if (n <= 3) return "mirror";
  if (n <= 5) return "raidz1";
  if (n <= 11) return "raidz2";
  return "raidz2";
}

/** Builds a pool spec from per-disk roles and a data layout. */
export function buildSpec(name: string, roles: Record<string, Role>, layout: Layout, encrypt: boolean): { spec: PoolSpec; problems: string[] } {
  const by = (r: Role) => Object.entries(roles).filter(([, role]) => role === r).map(([id]) => id);
  const data = by("data");
  const special = by("special");
  const log = by("log");
  const problems: string[] = [];
  if (data.length === 0) problems.push("Pick at least one data disk.");
  else if (data.length < MIN_DISKS[layout]) problems.push(`${LAYOUT_LABEL[layout]} needs at least ${MIN_DISKS[layout]} data disks.`);
  if (special.length === 1) problems.push("The special vdev must be mirrored: pick two or more disks for it, or none.");
  const spec: PoolSpec = {
    name,
    encrypt,
    data: layout === "stripe" ? data.map((d) => ({ type: "stripe", disks: [d] })) : [{ type: layout, disks: data }],
  };
  if (special.length >= 2) spec.special = { type: "mirror", disks: special };
  if (log.length === 1) spec.log = { type: "stripe", disks: log };
  if (log.length >= 2) spec.log = { type: "mirror", disks: log };
  const cache = by("cache");
  const spares = by("spare");
  if (cache.length) spec.cache = cache;
  if (spares.length) spec.spares = spares;
  return { spec, problems };
}

function rolesFromRecommendation(rec: Recommendation, usable: Disk[]): Record<string, Role> {
  const roles: Record<string, Role> = {};
  for (const d of usable) roles[d.byId] = "none";
  rec.spec.data.forEach((v) => v.disks.forEach((d) => (roles[d] = "data")));
  rec.spec.special?.disks.forEach((d) => (roles[d] = "special"));
  rec.spec.log?.disks.forEach((d) => (roles[d] = "log"));
  rec.spec.cache?.forEach((d) => (roles[d] = "cache"));
  rec.spec.spares?.forEach((d) => (roles[d] = "spare"));
  return roles;
}

export function CreatePool({ onCreated }: { onCreated: (pool: string) => void }) {
  const qc = useQueryClient();
  const hw = useHardware();
  const [name, setName] = useState("tank");
  const [step, setStep] = useState<"plan" | "confirm" | "running">("plan");
  const [roles, setRoles] = useState<Record<string, Role>>({});
  const [layout, setLayout] = useState<Layout>("raidz2");
  const [customized, setCustomized] = useState(false);
  const [encrypt, setEncrypt] = useState(false);
  const [typed, setTyped] = useState("");
  const [jobId, setJobId] = useState<string | null>(null);

  const rec = useQuery({
    queryKey: ["recommendation"],
    queryFn: () => unwrap(api.GET("/storage/recommendation", { params: { query: { name: "tank" } } })),
    staleTime: 30_000,
    retry: false,
  });
  const usable = useMemo(() => (hw.data?.disks ?? []).filter((d) => (d.usage === "free" || d.usage === "has-data") && !d.removable), [hw.data]);

  useEffect(() => {
    if (rec.data && usable.length && Object.keys(roles).length === 0) {
      setRoles(rolesFromRecommendation(rec.data, usable));
      setLayout(rec.data.spec.data[0]?.type ?? "raidz2");
    }
  }, [rec.data, usable, roles]);

  const built = useMemo(() => {
    if (!customized && rec.data) return { spec: { ...rec.data.spec, name, encrypt }, problems: [] as string[] };
    return buildSpec(name, roles, layout, encrypt);
  }, [customized, rec.data, name, roles, layout, encrypt]);

  const dataDisks = usable.filter((d) => roles[d.byId] === "data");
  const minSize = dataDisks.length ? Math.min(...dataDisks.map((d) => d.sizeBytes)) : 0;
  const usableBytes = built.spec.data.reduce((sum, v) => {
    const n = v.disks.length;
    const stores = v.type === "mirror" || v.type === "stripe" ? 1 : n - PARITY[v.type](n);
    return sum + stores * minSize;
  }, 0);
  const survives = built.spec.data[0] ? PARITY[built.spec.data[0].type](built.spec.data[0].disks.length) : 0;
  const nameValid = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(name);
  const toErase = built.spec.data.flatMap((v) => v.disks).concat(built.spec.special?.disks ?? [], built.spec.log?.disks ?? [], built.spec.cache ?? [], built.spec.spares ?? []);

  const create = useMutation({
    mutationFn: () => unwrap(api.POST("/storage/pools", { body: { spec: built.spec, confirmWipe: true } })),
    onSuccess: (r) => {
      setJobId(r.job.id);
      setStep("running");
    },
  });

  if (hw.isPending || rec.isPending) return <Loading label="Looking at your disks…" />;
  if (hw.isError) return <ErrorBox error={hw.error} onRetry={() => hw.refetch()} />;
  if (usable.length === 0) {
    return (
      <>
        <PageHeader title="Create a pool" />
        <Card>
          <EmptyState title="No unused disks">All disks are already in a pool, hold the system, or are removable. Add a disk to create a new pool.</EmptyState>
        </Card>
      </>
    );
  }

  const setRole = (id: string, r: Role) => {
    setCustomized(true);
    const next = { ...roles, [id]: r };
    setRoles(next);
    const n = Object.values(next).filter((x) => x === "data").length;
    if (n < MIN_DISKS[layout]) setLayout(defaultLayout(n));
  };
  const layoutOptions = (Object.keys(MIN_DISKS) as Layout[]).filter((l) => dataDisks.length >= MIN_DISKS[l]);

  if (step === "running" && jobId) {
    return (
      <>
        <PageHeader title={`Creating ${name}`} subtitle="Erasing disks, building the pool and setting up standard folders and schedules." />
        <Card>
          <JobProgress
            id={jobId}
            onDone={(job) => {
              void qc.invalidateQueries({ queryKey: ["pools"] });
              void qc.invalidateQueries({ queryKey: ["hardware"] });
              if (job.state === "succeeded") onCreated(name);
              else setStep("plan");
            }}
          />
        </Card>
      </>
    );
  }

  if (step === "confirm") {
    return (
      <>
        <PageHeader title={`Create ${name}?`} subtitle="Check the disks below. Everything on them will be erased." />
        <Card title={`${toErase.length} disk${toErase.length === 1 ? "" : "s"} will be erased`}>
          <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
            {toErase.map((id) => {
              const d = usable.find((x) => x.byId === id);
              return (
                <li key={id}>
                  <strong>{d?.name}</strong> · {d ? bytes(d.sizeBytes, 0) : ""} {d?.model} · {ROLE_LABEL[roles[id] ?? "data"]}
                  {d?.usage === "has-data" && <Badge tone="warn">has data: {d.usageDetail}</Badge>}
                </li>
              );
            })}
          </ul>
          <Field label={`Type ${name} to confirm`}>
            {(id) => <TextInput id={id} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />}
          </Field>
          {create.error && <Alert tone="bad">{errorMessage(create.error)}</Alert>}
          <div className="row">
            <Button onClick={() => setStep("plan")}>Back</Button>
            <Button variant="danger" disabled={typed !== name} busy={create.isPending} onClick={() => create.mutate()}>
              Erase disks and create {name}
            </Button>
          </div>
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader title="Create a pool" subtitle="HardyOS suggested a layout for your disks. Change any disk's role if you want something different." />

      {rec.isError ? (
        <Alert tone="warn">{errorMessage(rec.error)}</Alert>
      ) : (
        rec.data &&
        !customized && (
          <Card title="Suggested layout">
            <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.6 }}>
              {rec.data.explanation.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          </Card>
        )
      )}

      <div className="grid-3">
        <Field label="Pool name" error={!nameValid ? "Letters, digits, '_', '.', '-', starting with a letter" : null} hint="Shown in Storage Manager and used in folder paths">
          {(id) => <TextInput id={id} value={name} onChange={(e) => setName(e.target.value)} spellCheck={false} />}
        </Field>
        <Field label="Data layout" hint={customized ? undefined : "From the suggestion"}>
          {(id) => (
            <Select
              id={id}
              value={built.spec.data[0]?.type ?? layout}
              onChange={(e) => {
                setCustomized(true);
                setLayout(e.target.value as Layout);
              }}
            >
              {(layoutOptions.length ? layoutOptions : (["stripe"] as Layout[])).map((l) => (
                <option key={l} value={l}>
                  {LAYOUT_LABEL[l]}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <div className="stat">
          <span className="stat__label">Usable space (estimate)</span>
          <span className="stat__value mono">{bytes(usableBytes)}</span>
          <span className="stat__sub">{survives > 0 ? `Survives ${survives} disk failure${survives > 1 ? "s" : ""} per group` : "No redundancy"}</span>
        </div>
      </div>

      <div className="table-wrap">
        <table className="table wizard-disks">
          <thead>
            <tr>
              <th>Disk</th>
              <th>Type</th>
              <th className="num">Size</th>
              <th>Current state</th>
              <th>Role in the pool</th>
            </tr>
          </thead>
          <tbody>
            {usable.map((d) => (
              <tr key={d.byId}>
                <td>
                  <strong className="mono">{d.name}</strong>
                  <span className="cell-sub">{d.model || d.byId.replace("/dev/disk/by-id/", "")}</span>
                </td>
                <td>{d.kind.toUpperCase()}</td>
                <td className="num">{bytes(d.sizeBytes, 0)}</td>
                <td>{d.usage === "free" ? <Badge tone="good">blank</Badge> : <Badge tone="warn">has data</Badge>}</td>
                <td style={{ minWidth: 190 }}>
                  <Select aria-label={`Role for ${d.name}`} value={roles[d.byId] ?? "none"} onChange={(e) => setRole(d.byId, e.target.value as Role)}>
                    {(Object.keys(ROLE_LABEL) as Role[]).map((r) => (
                      <option key={r} value={r}>
                        {ROLE_LABEL[r]}
                      </option>
                    ))}
                  </Select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Toggle
        label="Encrypt the pool"
        description="Protects the data if disks are removed from the server. The key is stored on the boot drive so the pool unlocks automatically."
        checked={encrypt}
        onChange={setEncrypt}
      />

      {built.problems.map((p) => (
        <Alert key={p} tone="bad">
          {p}
        </Alert>
      ))}
      {(!customized ? (rec.data?.warnings ?? []) : []).concat(built.spec.data.length === 1 && built.spec.data[0]!.type === "stripe" ? ["A single disk has no redundancy: if it fails, everything on the pool is lost."] : []).map((w) => (
        <Alert key={w} tone="warn">
          {w}
        </Alert>
      ))}

      <div className="row">
        <Button variant="primary" disabled={built.problems.length > 0 || !nameValid} onClick={() => { setTyped(""); setStep("confirm"); }}>
          Review and create
        </Button>
        {customized && rec.data && (
          <Button
            variant="ghost"
            onClick={() => {
              setCustomized(false);
              setRoles(rolesFromRecommendation(rec.data!, usable));
              setLayout(rec.data!.spec.data[0]?.type ?? "raidz2");
            }}
          >
            Use the suggestion again
          </Button>
        )}
      </div>
    </>
  );
}
