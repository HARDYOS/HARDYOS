import type { Pool, Vdev } from "@hardy/api-client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, unwrap } from "../../api";
import { bytes } from "../../format";
import { PlusIcon } from "../../icons";
import { Alert, Badge, Button, Card, Progress } from "../../ui";
import { ConfirmDialog } from "../../ui/Dialog";
import { JobProgress } from "../shared";
import { DiskPickerDialog, leafDisks, ScanCard, shortName, stateTone } from "./PoolDetail";
import { healthTone } from "./StorageManager";

const useBootDisks = () =>
  useQuery({
    queryKey: ["boot-disks"],
    queryFn: () => unwrap(api.GET("/storage/boot")),
    refetchInterval: (q) => (q.state.data?.status.scan.state === "running" ? 5_000 : 60_000),
    retry: false,
  });

/** The system pool: HardyOS itself, mirrored across the boot disks. */
export function SystemPoolCard({ pool }: { pool: Pool }) {
  const qc = useQueryClient();
  const boot = useBootDisks();
  const [replacing, setReplacing] = useState<Vdev | null>(null);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<Vdev | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["boot-disks"] });
    void qc.invalidateQueries({ queryKey: ["pools"] });
  };

  const b = boot.data;
  const leaves = b ? (b.status.root?.children ?? []).flatMap(leafDisks) : [];
  const working = leaves.filter((v) => v.state === "ONLINE");
  const single = b != null && b.disks.length === 1;

  return (
    <Card
      title="System pool"
      actions={
        b && b.disks.length < 4 ? (
          <Button size="sm" onClick={() => setAdding(true)} disabled={jobId !== null}>
            <PlusIcon size={14} /> Add a boot disk
          </Button>
        ) : undefined
      }
    >
      <div className="row row--between">
        <span className="small muted">
          <span className="mono">{pool.name}</span> holds HardyOS itself on the boot disks. Updates manage what's on it; the disks are
          managed here.
        </span>
        <Badge tone={healthTone(pool.health)}>{pool.health.toLowerCase()}</Badge>
      </div>
      <Progress value={pool.capacityPct} label={`${pool.name} ${pool.capacityPct}% full`} tone={pool.capacityPct > 85 ? "warn" : "accent"} />
      <span className="small muted">
        {bytes(pool.allocBytes)} used of {bytes(pool.sizeBytes)}
      </span>

      {boot.isError && <span className="small muted">Boot disks can't be managed on this system (it wasn't installed with the HardyOS installer).</span>}
      {single && (
        <Alert tone="warn" title="Only one boot disk">
          If it fails, HardyOS won't start until it's reinstalled. Add a second disk to mirror it; your data pools aren't affected either way.
        </Alert>
      )}
      {b && working.length < leaves.length && (
        <Alert tone="bad" title="A boot disk has failed">
          HardyOS is still running from the other {working.length === 1 ? "disk" : "disks"}. Replace the failed one with a new disk of at least{" "}
          {bytes(b.minBytes, 0)} to restore the mirror.
        </Alert>
      )}
      {b && (b.status.scan.state === "running" || b.status.scan.state === "paused") && b.status.scan.kind === "resilver" && <ScanCard scan={b.status.scan} />}
      {jobId && (
        <JobProgress
          id={jobId}
          onDone={() => {
            setJobId(null);
            refresh();
          }}
        />
      )}

      {leaves.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Boot disk</th>
                <th>State</th>
                <th className="actions">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {leaves.map((v) => {
                const ok = v.state === "ONLINE";
                return (
                  <tr key={v.name}>
                    <td>
                      <span className="mono small">{ok ? shortName(v) : v.note.replace(/^was \/dev\/disk\/by-id\//, "") || v.name}</span>
                      {!ok && <span className="cell-sub">{v.note.startsWith("was") ? "missing" : "not working"}</span>}
                    </td>
                    <td>
                      <Badge tone={stateTone(v.state)}>{v.state.toLowerCase()}</Badge>
                    </td>
                    <td className="actions">
                      <div className="row" style={{ justifyContent: "flex-end", gap: 6 }}>
                        <Button size="sm" disabled={jobId !== null} onClick={() => setReplacing(v)}>
                          Replace…
                        </Button>
                        {!ok && working.length > 0 && (
                          <Button size="sm" variant="ghost" disabled={jobId !== null} onClick={() => setRemoving(v)}>
                            Remove
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {replacing && b && (
        <DiskPickerDialog
          title="Replace a boot disk"
          description="Pick the new disk. It's erased, gets the same partitions as the other boot disks, joins the mirror and gets the boot loader, so the server can start from it."
          disks={b.candidates}
          confirmLabel="Replace"
          onPick={async (d) => {
            const r = await unwrap(api.POST("/storage/boot/replace", { body: { old: replacing.name, disk: d.byId, confirmWipe: true } }));
            setJobId((r.job as { id: string }).id);
          }}
          onClose={() => setReplacing(null)}
        />
      )}
      {adding && b && (
        <DiskPickerDialog
          title="Add a boot disk"
          description="The new disk is erased and becomes a copy of the boot disks, so HardyOS keeps running if one of them fails."
          disks={b.candidates}
          confirmLabel="Add"
          onPick={async (d) => {
            const r = await unwrap(api.POST("/storage/boot/attach", { body: { disk: d.byId, confirmWipe: true } }));
            setJobId((r.job as { id: string }).id);
          }}
          onClose={() => setAdding(false)}
        />
      )}
      {removing && (
        <ConfirmDialog
          title="Remove the failed boot disk?"
          confirmLabel="Remove"
          onConfirm={async () => {
            const r = await unwrap(api.POST("/storage/boot/detach", { body: { device: removing.name } }));
            setJobId((r.job as { id: string }).id);
          }}
          onClose={() => setRemoving(null)}
        >
          It's taken out of the mirror and the boot list. Do this when you won't replace it; the server then runs with one boot disk fewer.
        </ConfirmDialog>
      )}
    </Card>
  );
}
