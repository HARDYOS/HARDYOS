// "Make highly available" (Phase 10, docs/plans/make-ha.md): the button on
// a VM's page and an app's details, and its dialog. The workload stops for
// the final copy only; this server's copy is kept for a day after it ran
// from cluster storage.
import type { Job } from "@hardy/api-client";
import { useState } from "react";
import { errorMessage } from "../../../api";
import { bytes } from "../../../format";
import { Alert, Badge, Button, Field, Loading, Select, TextInput } from "../../../ui";
import { Dialog } from "../../../ui/Dialog";
import { CONVERSION_PHASE, type WorkloadKind, makeHA, useClusterPlacement, useConvertCheck, useHAStatus } from "./haApi";

/** "Make highly available…" for a VM or app on this server's own storage in a cluster; nothing otherwise. */
export function MakeHAButton({ kind, id, name, onJob, disabled }: { kind: WorkloadKind; id: string; name: string; onJob: (j: Job) => void; disabled?: boolean }) {
  const st = useHAStatus(15_000);
  const placed = useClusterPlacement(kind, id);
  const [open, setOpen] = useState(false);
  if (!st.data?.member || placed) return null;
  return (
    <>
      <Button onClick={() => setOpen(true)} disabled={disabled} title="Move it to cluster storage so it restarts on another server when this one fails">
        Make highly available…
      </Button>
      {open && <MakeHADialog kind={kind} id={id} name={name} onClose={() => setOpen(false)} onJob={onJob} />}
    </>
  );
}

export function MakeHADialog({ kind, id, name, onClose, onJob }: { kind: WorkloadKind; id: string; name: string; onClose: () => void; onJob: (j: Job) => void }) {
  const [cpu, setCpu] = useState<"baseline" | "keep">("baseline");
  const q = useConvertCheck(kind, id, cpu);
  const [priority, setPriority] = useState("50");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const r = q.data;
  const resume = !!r?.open && r.open.direction === "ha";
  const prio = Number.parseInt(priority, 10);
  const prioOK = Number.isInteger(prio) && prio >= 1 && prio <= 100;
  const blocked = !!r && r.problems.length > 0 && !(resume && ["park", "register", "attach", "start"].includes(r.open!.phase));
  const ready = !!r && !blocked && prioOK && (confirm === name || confirm === id);

  async function submit() {
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      onJob(await makeHA(kind, id, { priority: prio, cpu: kind === "vm" ? cpu : undefined, confirm }));
      onClose();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <Dialog
      title={resume ? `Resume making ${name} highly available` : `Make ${name} highly available`}
      onClose={onClose}
      onSubmit={submit}
      width={560}
      description="Its storage and snapshots move to the storage server. When the server running it fails, it restarts on another one."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" busy={busy} disabled={!ready}>
            {resume ? "Resume" : "Make highly available"}
          </Button>
        </>
      }
    >
      {q.isLoading && <Loading />}
      {q.error && <Alert tone="bad">{errorMessage(q.error)}</Alert>}
      {r && (
        <>
          {resume && (
            <Alert tone="warn" title="An earlier try didn't finish">
              It stopped at “{CONVERSION_PHASE[r.open!.phase] ?? r.open!.phase}”{r.open!.problem ? `: ${r.open!.problem}` : ""}. Resuming carries on from
              there; what was copied already isn't copied again.
            </Alert>
          )}
          {r.problems.length > 0 && (
            <Alert tone="bad" title="It can't be made highly available now">
              <ul className="list">
                {r.problems.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            </Alert>
          )}
          <dl className="kv">
            <dt>Storage</dt>
            <dd>
              <span className="mono">{bytes(r.sizeBytes)}</span> from <span className="mono">{r.localPool || "—"}</span> to the storage server's{" "}
              <span className="mono">{r.storagePool || "—"}</span>, with every snapshot
            </dd>
            <dt>Downtime</dt>
            <dd>
              {r.running
                ? "It keeps running while most of it is copied, then shuts down for the final copy of what changed, and starts from cluster storage."
                : "It is off, and stays off; start it whenever you like."}
            </dd>
            {kind === "app" && r.mode && (
              <>
                <dt>Data</dt>
                <dd>
                  {r.mode === "block" ? <Badge tone="accent">Block volume</Badge> : <Badge tone="neutral">Folder (NFS)</Badge>} {r.modeReason}
                </dd>
              </>
            )}
            {(r.shares ?? []).length > 0 && (
              <>
                <dt>Shared folders</dt>
                <dd>
                  {(r.shares ?? []).map((s) => (
                    <div key={s.id}>
                      {s.name} <span className="mono muted">{bytes(s.sizeBytes)}</span> {s.write ? <Badge tone="neutral">read and write</Badge> : <Badge tone="neutral">read only</Badge>}
                    </div>
                  ))}
                  <span className="small muted">
                    They move to the storage server with it and become its shared folders there, with the same names, permissions and settings: every server
                    can then give them to {name}. Nobody can use them on this server during the final copy.
                  </span>
                </dd>
              </>
            )}
            <dt>This server's copy</dt>
            <dd>Kept, unused, until it has run from cluster storage, then for 24 hours (you can delete it sooner).</dd>
          </dl>
          {(r.notes ?? []).length > 0 && (
            <Alert tone="warn" title="For the people using its shared folders">
              <ul className="list">
                {(r.notes ?? []).map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            </Alert>
          )}
          <Field label="Priority" hint="Higher recovers first when a server fails (1-100).">
            {(fid) => <TextInput id={fid} value={priority} onChange={(e) => setPriority(e.target.value)} inputMode="numeric" />}
          </Field>
          {kind === "vm" && (
            <Field label="Processor">
              {(fid) => (
                <Select id={fid} value={cpu} onChange={(e) => setCpu(e.target.value as "baseline" | "keep")} disabled={!r.cpuBaseline}>
                  <option value="baseline">The cluster's CPU model{r.cpuBaseline ? ` (${r.cpuBaseline})` : ""}: moves live between any servers</option>
                  <option value="keep">Keep its own setting{r.cpuModel ? ` (${r.cpuModel})` : " (this server's exact CPU)"}</option>
                </Select>
              )}
            </Field>
          )}
          <Field label={`Type ${name} to confirm`}>
            {(fid) => <TextInput id={fid} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />}
          </Field>
          {error && <Alert tone="bad">{error}</Alert>}
        </>
      )}
    </Dialog>
  );
}
