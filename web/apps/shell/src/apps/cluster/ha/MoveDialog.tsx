// The Move dialog, shared by the Virtual Machines app, the App Store and
// the cluster's HA page.
import type { Job } from "@hardy/api-client";
import { useState } from "react";
import { errorMessage } from "../../../api";
import { Alert, Badge, Button, Field, Loading, Select, TextInput } from "../../../ui";
import { Dialog } from "../../../ui/Dialog";
import { type WorkloadKind, moveWorkload, useMoveCandidates } from "./haApi";

export function MoveDialog({
  kind,
  id,
  name,
  onClose,
  onJob,
}: {
  kind: WorkloadKind;
  id: string;
  name: string;
  onClose: () => void;
  onJob: (j: Job) => void;
}) {
  const q = useMoveCandidates(kind, id);
  const [to, setTo] = useState("");
  const [live, setLive] = useState(true);
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const c = q.data;
  const forced = !!c && (c.pinned || c.ownerDown);
  const canLive = !!c?.live;
  const mode = canLive && live ? "live" : "offline";
  const needsTarget = !!c?.pinned;
  const ready = !!c && (!forced || confirm === c.placement.name) && (!needsTarget || to !== "");

  async function submit() {
    if (!c || !ready) return;
    setBusy(true);
    setError(null);
    try {
      const job = await moveWorkload({ kind, id, to: to || undefined, mode, generation: c.placement.generation, confirm: forced ? confirm : undefined });
      onJob(job);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  const title = c?.ownerDown ? `Start ${name} on another server` : `Move ${name}`;
  return (
    <Dialog
      title={title}
      onClose={onClose}
      onSubmit={submit}
      width={520}
      description={
        c?.ownerDown
          ? `Its server ${c.placement.owner} is down. It starts elsewhere from the same storage once the storage server has cut ${c.placement.owner} off.`
          : "It keeps its storage: only the server that runs it changes."
      }
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" busy={busy} disabled={!ready}>
            {c?.ownerDown ? "Start elsewhere" : mode === "live" ? "Move live" : "Move"}
          </Button>
        </>
      }
    >
      {q.isLoading && <Loading />}
      {q.error && <Alert tone="bad">{errorMessage(q.error)}</Alert>}
      {c && (
        <>
          <Field label="To">
            {(fid) => (<Select id={fid} value={to} onChange={(e) => setTo(e.target.value)}>
              {!needsTarget && <option value="">Let HardyOS choose</option>}
              {needsTarget && <option value="">Choose a server…</option>}
              {c.candidates.map((n) => (
                <option key={n.id} value={n.id} disabled={!n.fits}>
                  {n.name}
                  {n.fits ? "" : ` (${n.reason})`}
                </option>
              ))}
            </Select>)}
          </Field>
          {kind === "vm" && !c.ownerDown && (
            <Field label="How">
              {(fid) => (<Select id={fid} value={mode} onChange={(e) => setLive(e.target.value === "live")} disabled={!canLive}>
                <option value="live">Live: it keeps running (memory is copied over the storage network)</option>
                <option value="offline">Offline: shut down, then start on the new server</option>
              </Select>)}
            </Field>
          )}
          {!canLive && c.liveReason && kind === "vm" && (
            <p className="muted">
              <Badge tone="neutral">Offline only</Badge> {c.liveReason}.
            </p>
          )}
          {kind === "app" && <p className="muted">Apps stop for a moment while they move; their published address follows them.</p>}
          {c.pinned && (
            <Alert tone="warn" title="Passthrough devices">
              {name} uses devices of {c.placement.owner} (a GPU or USB device). The server you choose checks that it has the same devices before
              anything stops; it can't be highly available or move live.
            </Alert>
          )}
          {forced && (
            <Field label={`Type ${c.placement.name} to confirm`}>
              {(fid) => <TextInput id={fid} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />}
            </Field>
          )}
          {error && <Alert tone="bad">{error}</Alert>}
        </>
      )}
    </Dialog>
  );
}
