import type { Disk, DiskHealth, PoolStatus, Scan, Vdev } from "@hardy/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { bytes, relativeTime } from "../../format";
import { useDatasets, useDiskHealth, useHardware, usePools, usePoolStatus } from "../../hooks/queries";
import { AlertIcon, PauseIcon, PlayIcon, StopIcon } from "../../icons";
import { Alert, Badge, Button, Card, ErrorBox, Field, Loading, PageHeader, Progress, Select, Stat } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { JobProgress } from "../shared";
import { healthTone } from "./StorageManager";

const CLASS_LABEL: Record<string, string> = {
  data: "Data",
  special: "Special",
  log: "Log (SLOG)",
  cache: "Cache (L2ARC)",
  spare: "Spare",
  dedup: "Dedup",
};
const CLASS_HINT: Record<string, string> = {
  special: "Metadata and small files",
  log: "Synchronous writes",
  cache: "Read cache · safe to lose",
  spare: "Replaces a failed disk",
};

function layoutLabel(v: Vdev): string {
  switch (v.type) {
    case "raidz1":
    case "raidz2":
    case "raidz3": {
      const n = v.children.length;
      const parity = Number(v.type.slice(-1));
      return `${v.type.toUpperCase()} · survives ${parity} of ${n}`;
    }
    case "mirror":
      return `Mirror · survives ${v.children.length - 1}`;
    case "disk":
      return v.class === "data" ? "Single disk · no redundancy" : "Single disk";
    default:
      return v.type;
  }
}

export function leafDisks(v: Vdev): Vdev[] {
  if (v.type === "disk" || v.type === "file") return [v];
  return v.children.flatMap(leafDisks);
}

export function stateTone(s: string) {
  if (s === "ONLINE" || s === "AVAIL") return "good" as const;
  if (s === "DEGRADED" || s === "OFFLINE" || s === "INUSE") return "warn" as const;
  return "bad" as const;
}

function scanSummary(scan: Scan): string {
  if (scan.kind === "none") return "Never scrubbed";
  const what = scan.kind === "scrub" ? "Scrub" : scan.kind === "resilver" ? "Resilver" : "Expansion";
  if (scan.state === "running") return `${what} running`;
  if (scan.state === "paused") return `${what} paused`;
  if (scan.state === "finished") return `${what} ${scan.finishedAt ? relativeTime(scan.finishedAt) : "finished"}`;
  return `${what} ${scan.state}`;
}

export function PoolDetail({ pool, onGone }: { pool: string; onGone: () => void }) {
  const qc = useQueryClient();
  const pools = usePools();
  const [running, setRunning] = useState(false);
  const status = usePoolStatus(pool, running);
  const hw = useHardware();
  const health = useDiskHealth();
  const root = useDatasets(pool);
  const [replacing, setReplacing] = useState<Vdev | null>(null);
  const [expanding, setExpanding] = useState<Vdev | null>(null);
  const [destroying, setDestroying] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);

  const st = status.data;
  const isRunning = !!st && (st.scan.state === "running" || st.expand?.state === "running");
  if (isRunning !== running) setRunning(isRunning);

  const row = pools.data?.find((p) => p.name === pool);
  const disksById = useMemo(() => new Map((hw.data?.disks ?? []).map((d) => [d.byId, d])), [hw.data]);
  const healthById = useMemo(() => new Map((health.data ?? []).map((h) => [h.byId, h])), [health.data]);
  const freeDisks = (hw.data?.disks ?? []).filter((d) => (d.usage === "free" || d.usage === "has-data") && !d.removable);

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["pool", pool] });
    void qc.invalidateQueries({ queryKey: ["pools"] });
  };
  const scrub = useMutation({
    mutationFn: (action: "start" | "pause" | "stop") => unwrap(api.POST("/storage/pools/{pool}/scrub", { params: { path: { pool } }, body: { action } })),
    onSuccess: (s) => {
      qc.setQueryData(["pool", pool], s);
      refresh();
    },
    onError: (err) => toast("error", "Scrub", errorMessage(err)),
  });
  const clear = useMutation({
    mutationFn: () => unwrap(api.POST("/storage/pools/{pool}/clear", { params: { path: { pool } } })),
    onSuccess: (s) => {
      qc.setQueryData(["pool", pool], s);
      toast("success", "Error counters cleared");
    },
  });

  if (status.isPending) return <Loading />;
  if (status.isError) return <ErrorBox error={status.error} onRetry={() => status.refetch()} />;
  if (!st) return null;

  const errors = st.groups.flatMap(leafDisks).reduce((n, d) => n + d.read + d.write + d.checksum, 0);
  const dataGroups = st.groups.filter((g) => g.class === "data");
  const rootDs = root.data?.find((d) => d.name === pool);
  const scrubState = st.scan.kind === "scrub" ? st.scan.state : "none";
  const describe = dataGroups.length
    ? `${dataGroups.length > 1 ? `${dataGroups.length} × ` : ""}${layoutLabel(dataGroups[0]!)}`
    : "No data vdevs";
  const warnings: { disk: Disk | undefined; health: DiskHealth }[] = [];
  for (const d of st.groups.flatMap(leafDisks)) {
    const h = healthById.get(d.disk);
    if (h && (h.health === "warning" || h.health === "failing")) warnings.push({ disk: disksById.get(d.disk), health: h });
  }

  return (
    <>
      <PageHeader
        title={pool}
        badge={<Badge tone={healthTone(st.state)}>{st.state.toLowerCase()}</Badge>}
        subtitle={`${describe}${rootDs?.encryption && rootDs.encryption !== "off" ? " · encrypted" : ""}`}
        actions={
          <>
            {scrubState === "running" ? (
              <>
                <Button onClick={() => scrub.mutate("pause")} busy={scrub.isPending && scrub.variables === "pause"}>
                  <PauseIcon size={14} /> Pause scrub
                </Button>
                <Button onClick={() => scrub.mutate("stop")} busy={scrub.isPending && scrub.variables === "stop"}>
                  <StopIcon size={14} /> Stop
                </Button>
              </>
            ) : (
              <Button onClick={() => scrub.mutate("start")} busy={scrub.isPending} disabled={st.scan.kind === "resilver" && st.scan.state === "running"}>
                <PlayIcon size={14} /> {scrubState === "paused" ? "Resume scrub" : "Scrub now"}
              </Button>
            )}
            {errors > 0 && (
              <Button onClick={() => clear.mutate()} busy={clear.isPending}>
                Clear errors
              </Button>
            )}
          </>
        }
      />

      {st.state !== "ONLINE" && (st.status || st.action) && (
        <Alert tone={st.state === "DEGRADED" ? "warn" : "bad"} title={st.status}>
          {st.action}
        </Alert>
      )}

      {row && (
        <Card>
          <div className="capacity">
            <div className="row" style={{ alignItems: "baseline" }}>
              <span className="capacity__num">{bytes(row.allocBytes)}</span>
              <span className="small muted">used of {bytes(row.sizeBytes)} raw capacity</span>
              <span className="grow" />
              <span className="mono small">{row.capacityPct}%</span>
            </div>
            <div className="capacity__bar" role="img" aria-label={`${row.capacityPct}% used`}>
              <div style={{ width: `${row.capacityPct}%`, background: row.capacityPct > 85 ? "var(--hos-warn)" : "var(--hos-accent)" }} />
            </div>
            <div className="legend">
              <span>
                <span className="swatch" style={{ background: "var(--hos-accent)" }} /> Used {bytes(row.allocBytes)}
              </span>
              <span>
                <span className="swatch" style={{ background: "rgba(255,255,255,0.2)" }} /> Free {bytes(row.freeBytes)}
              </span>
              {rootDs && (
                <span>
                  Usable now {bytes(rootDs.availBytes)} after redundancy
                </span>
              )}
            </div>
          </div>
        </Card>
      )}

      <div className="grid-4">
        <Stat label="Errors" value={<span className="mono">{errors}</span>} tone={errors ? "warn" : "good"} sub="Read, write, checksum" />
        <Stat label="Last check" value={<span style={{ fontSize: 15 }}>{scanSummary(st.scan)}</span>} sub={st.scan.errors != null ? `${st.scan.errors} errors found` : undefined} />
        <Stat label="Compression" value={<span className="mono">{rootDs?.compressRatio ?? "–"}</span>} sub={rootDs?.compression} />
        <Stat label="Fragmentation" value={<span className="mono">{row?.fragmentation != null ? `${row.fragmentation}%` : "–"}</span>} sub="Free-space fragmentation" />
      </div>

      {(st.scan.state === "running" || st.scan.state === "paused") && <ScanCard scan={st.scan} />}
      {st.expand && st.expand.state === "running" && <ScanCard scan={st.expand} />}
      {jobId && (
        <Card title="Operation in progress">
          <JobProgress id={jobId} onDone={() => refresh()} />
        </Card>
      )}

      {warnings.map(({ disk, health: h }) => (
        <Alert key={h.byId} tone={h.health === "failing" ? "bad" : "warn"} title={`${disk?.name ?? h.byId}: ${h.health}`}>
          {h.reasons.join("; ")}. {h.health === "failing" ? "Replace this disk soon." : "Keep an eye on it."}
        </Alert>
      ))}

      <Card title="Layout" actions={<span className="small muted">{st.groups.flatMap(leafDisks).length} devices</span>}>
        {st.groups.map((g, i) => (
          <div key={`${g.name}-${i}`} className="stack" style={{ gap: 14 }}>
            {i > 0 && st.groups[i - 1]!.class !== g.class && <div className="divider" />}
            <VdevRow
              vdev={g}
              disksById={disksById}
              healthById={healthById}
              onReplace={setReplacing}
              onExpand={g.class === "data" && /^raidz|^mirror/.test(g.type) && freeDisks.length > 0 ? () => setExpanding(g) : undefined}
            />
          </div>
        ))}
      </Card>

      <Card title="Danger zone">
        <div className="row row--between">
          <div>
            <strong>Destroy this pool</strong>
            <span className="cell-sub">Erases every file, folder and snapshot on {pool}. This can't be undone.</span>
          </div>
          <Button variant="danger" onClick={() => setDestroying(true)}>
            Destroy pool
          </Button>
        </div>
      </Card>

      {replacing && (
        <DiskPickerDialog
          title={`Replace ${shortName(replacing)}`}
          description="Pick the new disk. It will be erased, and the pool rebuilds the missing data onto it (resilvering). The pool stays usable meanwhile."
          disks={freeDisks}
          confirmLabel="Replace disk"
          onClose={() => setReplacing(null)}
          onPick={async (disk) => {
            const r = await unwrap(api.POST("/storage/pools/{pool}/replace", { params: { path: { pool } }, body: { old: replacing.name, disk: disk.byId, confirmWipe: true } }));
            setJobId(r.job.id);
          }}
        />
      )}
      {expanding && (
        <DiskPickerDialog
          title={`Add a disk to ${expanding.name}`}
          description={
            expanding.type === "mirror"
              ? "The new disk becomes another copy in this mirror."
              : "RAIDZ expansion adds one disk to this group and spreads the data across it. It takes a while but the pool stays usable."
          }
          disks={freeDisks}
          confirmLabel="Add disk"
          onClose={() => setExpanding(null)}
          onPick={async (disk) => {
            const r = await unwrap(api.POST("/storage/pools/{pool}/attach", { params: { path: { pool } }, body: { target: expanding.name, disk: disk.byId, confirmWipe: true } }));
            setJobId(r.job.id);
          }}
        />
      )}
      {destroying && (
        <ConfirmDialog
          title={`Destroy ${pool}?`}
          confirmLabel="Destroy pool"
          typeToConfirm={pool}
          onClose={() => setDestroying(false)}
          onConfirm={async () => {
            await unwrap(api.DELETE("/storage/pools/{pool}", { params: { path: { pool } }, body: { confirmName: pool } }));
            toast("success", `Destroyed ${pool}`);
            await qc.invalidateQueries({ queryKey: ["pools"] });
            onGone();
          }}
        >
          <p>Every file, folder, app dataset, VM disk and snapshot on <strong>{pool}</strong> will be erased permanently.</p>
        </ConfirmDialog>
      )}
    </>
  );
}

export function shortName(v: Vdev) {
  const n = v.disk || v.name;
  return n.replace("/dev/disk/by-id/", "");
}

export function ScanCard({ scan }: { scan: Scan }) {
  const label = scan.kind === "scrub" ? "Scrubbing" : scan.kind === "resilver" ? "Resilvering" : "Expanding";
  return (
    <Card title={`${label}${scan.state === "paused" ? " (paused)" : ""}`}>
      <div className="row row--between small">
        <span className="muted">{scan.remaining ? `${scan.remaining} to go` : scan.kind === "scrub" ? "Checking every block against its checksum" : "Working"}</span>
        <span className="mono">{scan.percent != null ? `${scan.percent.toFixed(1)}%` : ""}</span>
      </div>
      <Progress value={scan.percent ?? 0} label={label} />
    </Card>
  );
}

function VdevRow({
  vdev,
  disksById,
  healthById,
  onReplace,
  onExpand,
}: {
  vdev: Vdev;
  disksById: Map<string, Disk>;
  healthById: Map<string, DiskHealth>;
  onReplace: (v: Vdev) => void;
  onExpand?: () => void;
}) {
  const leaves = leafDisks(vdev);
  return (
    <div className="vdev-group">
      <div className="vdev-group__label">
        <strong>{CLASS_LABEL[vdev.class] ?? vdev.class}</strong>
        <span>{vdev.type === "disk" ? CLASS_HINT[vdev.class] ?? layoutLabel(vdev) : layoutLabel(vdev)}</span>
        {vdev.type !== "disk" && <span className="mono">{vdev.name}</span>}
        {onExpand && (
          <Button size="sm" variant="ghost" onClick={onExpand} style={{ alignSelf: "flex-start", paddingLeft: 0 }}>
            + Add disk
          </Button>
        )}
      </div>
      <div className="disk-chips">
        {leaves.map((d) => {
          const disk = disksById.get(d.disk);
          const h = healthById.get(d.disk);
          const errs = d.read + d.write + d.checksum;
          const tone = d.state !== "ONLINE" && d.state !== "AVAIL" ? stateTone(d.state) : h?.health === "failing" ? "bad" : h?.health === "warning" || errs > 0 ? "warn" : "good";
          const canReplace = vdev.class === "data" || vdev.class === "special";
          return (
            <div key={d.name} className={`disk-chip ${tone === "warn" ? "disk-chip--warn" : tone === "bad" ? "disk-chip--bad" : ""}`}>
              <div className="disk-chip__name">
                <span title={d.disk || d.name}>{disk?.name ?? shortName(d)}</span>
                <span className={`dot dot--${tone}`} aria-label={d.state.toLowerCase()} />
              </div>
              <span className="disk-chip__sub">
                {disk ? `${bytes(disk.sizeBytes, 0)} ${disk.kind.toUpperCase()}` : d.state.toLowerCase()}
                {h?.temperatureC != null ? ` · ${h.temperatureC} °C` : ""}
              </span>
              {(errs > 0 || d.note || d.state !== "ONLINE") && (
                <span className="disk-chip__sub" style={{ color: tone === "good" ? undefined : "var(--hos-warn-text)" }}>
                  {d.state !== "ONLINE" ? d.state.toLowerCase() : ""} {errs > 0 ? `${errs} errors` : ""} {d.note}
                </span>
              )}
              {canReplace && (tone !== "good" || d.state !== "ONLINE") && (
                <Button size="sm" variant="ghost" style={{ alignSelf: "flex-start", padding: 0, height: 22 }} onClick={() => onReplace(d)}>
                  <AlertIcon size={12} /> Replace
                </Button>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function DiskPickerDialog({
  title,
  description,
  disks,
  confirmLabel,
  onPick,
  onClose,
}: {
  title: string;
  description: string;
  disks: Disk[];
  confirmLabel: string;
  onPick: (d: Disk) => Promise<void>;
  onClose: () => void;
}) {
  const [byId, setById] = useState(disks[0]?.byId ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const disk = disks.find((d) => d.byId === byId);
  return (
    <Dialog
      title={title}
      description={description}
      onClose={onClose}
      onSubmit={async () => {
        if (!disk) return;
        setBusy(true);
        setError(null);
        try {
          await onPick(disk);
          onClose();
        } catch (err) {
          setError(errorMessage(err));
          setBusy(false);
        }
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="danger" busy={busy} disabled={!disk}>
            Erase and {confirmLabel.toLowerCase()}
          </Button>
        </>
      }
    >
      <div className="stack">
        {disks.length === 0 ? (
          <Alert tone="warn">No unused disks. Install a new disk, then try again.</Alert>
        ) : (
          <Field label="New disk">
            {(id) => (
              <Select id={id} value={byId} onChange={(e) => setById(e.target.value)}>
                {disks.map((d) => (
                  <option key={d.byId} value={d.byId}>
                    {d.name} · {bytes(d.sizeBytes, 0)} {d.kind.toUpperCase()} · {d.model || "unknown model"}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        )}
        {disk?.usage === "has-data" && <Alert tone="warn">This disk has existing data ({disk.usageDetail}). It will be erased.</Alert>}
        {error && <Alert tone="bad">{error}</Alert>}
      </div>
    </Dialog>
  );
}

export type { PoolStatus };
