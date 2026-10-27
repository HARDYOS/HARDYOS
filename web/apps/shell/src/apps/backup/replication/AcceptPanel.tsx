import type { ReplicationPairingCode, ReplicationSource } from "@hardy/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../../api";
import { bytes, dateTime, relativeTime } from "../../../format";
import { ClipboardIcon, EditIcon, KeyIcon, TrashIcon } from "../../../icons";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Field, Loading, Select, TextInput, Toggle } from "../../../ui";
import { Dialog } from "../../../ui/Dialog";
import { toast } from "../../../ui/toasts";
import { KIND_LABEL, snapshotTime, usePoolNames, useReceive } from "./replicationApi";
import "./replication.css";

const GiB = 2 ** 30;

/**
 * Accept from another server: one-time pairing codes, the servers that
 * send here with their replicas' sizes, quotas, and deleting what a server
 * sent. Replicas are never mounted or shared here.
 */
export function AcceptPanel() {
  const rc = useReceive();
  const qc = useQueryClient();
  const refresh = () => void qc.invalidateQueries({ queryKey: ["replication-receive"] });
  const [making, setMaking] = useState(false);
  const [code, setCode] = useState<ReplicationPairingCode | null>(null);
  const [editing, setEditing] = useState<ReplicationSource | null>(null);
  const [deleting, setDeleting] = useState<ReplicationSource | null>(null);
  const close = useMutation({
    mutationFn: () => unwrap(api.DELETE("/replication/receive/pairing")),
    onSuccess: () => {
      setCode(null);
      setTimeout(refresh, 500);
    },
  });
  if (rc.isPending) return <Loading />;
  if (rc.isError) return <ErrorBox error={rc.error} onRetry={() => rc.refetch()} />;
  const st = rc.data;
  return (
    <div className="repl stack">
      <Card
        title="Accept from another server"
        actions={
          <Button variant="primary" size="sm" onClick={() => setMaking(true)}>
            <KeyIcon size={14} /> Make a pairing code…
          </Button>
        }
      >
        <p className="small muted" style={{ marginTop: 0 }}>
          Another HardyOS server can keep its replicas here. They live in <span className="mono">&lt;pool&gt;/replicas</span>, read only, never mounted
          or shared, and a server can only add to its own (it can't delete them). Other servers connect to{" "}
          <span className="mono">
            {st.hostname}:{st.port}
          </span>{" "}
          over your network or NetBird.
        </p>
        {st.addresses.length > 0 && (
          <div className="row small" style={{ flexWrap: "wrap" }} aria-label="This server's addresses">
            {st.addresses.map((a) => (
              <span key={a.address} className="mono">
                {a.address}
                {a.netbird && <Badge tone="accent">NetBird</Badge>}
              </span>
            ))}
          </div>
        )}
        <div className="row small">
          <Badge tone={st.receiving ? "good" : "neutral"}>{st.receiving ? "accepting connections" : "not accepting"}</Badge>
          <span className="muted">
            This server's key: <span className="mono">{st.pin.slice(0, 16)}…</span>
          </span>
        </div>
        {code && (
          <div className="repl-code" role="status">
            <span className="small muted">Enter this code on the other server (Replication › Pair with a server) before {dateTime(code.expiresAt)}:</span>
            <div className="row">
              <span className="repl-code__value mono">{code.code}</span>
              <Button
                size="sm"
                variant="ghost"
                aria-label="Copy the code"
                onClick={() => void navigator.clipboard?.writeText(code.code).then(() => toast("success", "Copied"), () => undefined)}
              >
                <ClipboardIcon size={14} />
              </Button>
            </div>
          </div>
        )}
        {!code && st.pairing && (
          <Alert tone="info" title="A pairing code is open" action={<Button size="sm" busy={close.isPending} onClick={() => close.mutate()}>Close it</Button>}>
            For a server sending to {st.pairing.pool}, until {dateTime(st.pairing.expiresAt)}. It's shown only once; make a new one if it's lost.
          </Alert>
        )}
        {code && (
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <Button size="sm" variant="ghost" busy={close.isPending} onClick={() => close.mutate()}>
              Close the code
            </Button>
          </div>
        )}
        {st.problem && <Alert tone="warn">{st.problem}</Alert>}
      </Card>

      <Card title="Servers sending here">
        {st.sources.length === 0 ? (
          <EmptyState title="None yet">Make a pairing code and enter it on the server that should send its replicas here.</EmptyState>
        ) : (
          <div className="stack">
            {st.sources.map((s) => (
              <div key={s.id} className="repl-task">
                <div className="row row--between">
                  <div>
                    <strong>{s.name}</strong>
                    <div className="small muted">
                      On {s.pool} · {bytes(s.usedBytes)}
                      {s.quotaBytes > 0 ? ` of ${bytes(s.quotaBytes)}` : ", no limit"} · keeps at least {s.minKeep} snapshots of each · last seen{" "}
                      {s.lastSeenAt ? relativeTime(s.lastSeenAt) : "never"}
                    </div>
                  </div>
                  <div className="row">
                    <Button size="sm" variant="ghost" aria-label={`Limits for ${s.name}`} onClick={() => setEditing(s)}>
                      <EditIcon size={14} />
                    </Button>
                    <Button size="sm" variant="ghost" aria-label={`Delete ${s.name}'s replicas`} onClick={() => setDeleting(s)}>
                      <TrashIcon size={14} />
                    </Button>
                  </div>
                </div>
                {s.replicas.length > 0 && (
                  <div className="table-wrap">
                    <table className="table">
                      <thead>
                        <tr>
                          <th>Replica</th>
                          <th>Kind</th>
                          <th className="num">Size</th>
                          <th>Newest</th>
                        </tr>
                      </thead>
                      <tbody>
                        {s.replicas.map((r) => (
                          <tr key={r.kind + r.id}>
                            <td>
                              {r.name} {r.partial && <Badge tone="warn">transfer to finish</Badge>}
                            </td>
                            <td>{KIND_LABEL[r.kind]}</td>
                            <td className="num mono">{bytes(r.usedBytes)}</td>
                            <td>
                              {r.lastSnapshot ? relativeTime(snapshotTime(r.lastSnapshot)) : "—"} <span className="small muted">({r.snapshots})</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>
      {making && (
        <PairingDialog
          onClose={() => setMaking(false)}
          onMade={(c) => {
            setCode(c);
            setMaking(false);
            setTimeout(refresh, 500);
          }}
        />
      )}
      {editing && <LimitsDialog source={editing} onClose={() => setEditing(null)} onDone={refresh} />}
      {deleting && <DeleteSourceDialog source={deleting} onClose={() => setDeleting(null)} onDone={refresh} />}
    </div>
  );
}

function PairingDialog({ onClose, onMade }: { onClose: () => void; onMade: (c: ReplicationPairingCode) => void }) {
  const pools = usePoolNames();
  const [pool, setPool] = useState("");
  const [quotaGB, setQuotaGB] = useState(0);
  const [minKeep, setMinKeep] = useState(3);
  const chosen = pool || pools.data?.[0] || "";
  const make = useMutation({
    mutationFn: () =>
      unwrap(api.POST("/replication/receive/pairing", { body: { pool: chosen, quotaBytes: Math.max(0, Math.round(quotaGB * GiB)), minKeep } })),
    onSuccess: onMade,
  });
  return (
    <Dialog
      title="Make a pairing code"
      description="The code works once, for 30 minutes. The server that uses it may then send replicas here, into the pool you choose."
      onClose={onClose}
      onSubmit={() => make.mutate()}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" busy={make.isPending} disabled={!chosen || minKeep < 1}>
            Make code
          </Button>
        </>
      }
    >
      <div className="stack">
        {pools.isError && <ErrorBox error={pools.error} />}
        <Field label="Keep its replicas on">
          {(id) => (
            <Select id={id} value={chosen} onChange={(e) => setPool(e.target.value)}>
              {(pools.data ?? []).map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <div className="grid-2">
          <Field label="Space limit (GiB)" hint="0 for no limit">
            {(id) => <TextInput id={id} type="number" min={0} value={quotaGB} onChange={(e) => setQuotaGB(Number(e.target.value))} />}
          </Field>
          <Field label="Snapshots kept at least" hint="Per item, whatever the sending server asks.">
            {(id) => <TextInput id={id} type="number" min={1} max={1000} value={minKeep} onChange={(e) => setMinKeep(Number(e.target.value))} />}
          </Field>
        </div>
        {make.isError && <Alert tone="bad">{errorMessage(make.error)}</Alert>}
      </div>
    </Dialog>
  );
}

function LimitsDialog({ source, onClose, onDone }: { source: ReplicationSource; onClose: () => void; onDone: () => void }) {
  const [quotaGB, setQuotaGB] = useState(Math.round((source.quotaBytes / GiB) * 10) / 10);
  const [minKeep, setMinKeep] = useState(source.minKeep);
  const save = useMutation({
    mutationFn: () =>
      unwrap(
        api.PATCH("/replication/receive/sources/{id}", {
          params: { path: { id: source.id } },
          body: { quotaBytes: Math.max(0, Math.round(quotaGB * GiB)), minKeep },
        }),
      ),
    onSuccess: () => {
      setTimeout(onDone, 500);
      onClose();
    },
  });
  return (
    <Dialog
      title={`Limits for ${source.name}`}
      onClose={onClose}
      onSubmit={() => save.mutate()}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" busy={save.isPending} disabled={minKeep < 1}>
            Save
          </Button>
        </>
      }
    >
      <div className="grid-2">
        <Field label="Space limit (GiB)" hint="0 for no limit; applies from the next transfer">
          {(id) => <TextInput id={id} type="number" min={0} value={quotaGB} onChange={(e) => setQuotaGB(Number(e.target.value))} />}
        </Field>
        <Field label="Snapshots kept at least">
          {(id) => <TextInput id={id} type="number" min={1} max={1000} value={minKeep} onChange={(e) => setMinKeep(Number(e.target.value))} />}
        </Field>
      </div>
      {save.isError && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
    </Dialog>
  );
}

function DeleteSourceDialog({ source, onClose, onDone }: { source: ReplicationSource; onClose: () => void; onDone: () => void }) {
  const [typed, setTyped] = useState("");
  const [deleteReplicas, setDeleteReplicas] = useState(true);
  const del = useMutation({
    mutationFn: () =>
      unwrap(api.DELETE("/replication/receive/sources/{id}", { params: { path: { id: source.id } }, body: { confirm: typed, deleteReplicas } })),
    onSuccess: () => {
      toast("info", deleteReplicas ? `Deleting ${source.name}'s replicas` : `No longer receiving from ${source.name}`);
      setTimeout(onDone, 800);
      onClose();
    },
  });
  return (
    <Dialog
      title={`Stop receiving from ${source.name}?`}
      onClose={onClose}
      onSubmit={() => typed === source.name && del.mutate()}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="danger" type="submit" busy={del.isPending} disabled={typed !== source.name}>
            {deleteReplicas ? "Delete replicas" : "Stop receiving"}
          </Button>
        </>
      }
    >
      <div className="stack">
        <p style={{ margin: 0 }}>
          {source.name} can't send here any more, and it has to be paired again to start over. Its replicas use {bytes(source.usedBytes)} on {source.pool}.
        </p>
        <Toggle
          label="Delete its replicas"
          description="Everything it sent, every snapshot, gone for good."
          checked={deleteReplicas}
          onChange={setDeleteReplicas}
        />
        <Field label={`Type ${source.name} to confirm`}>
          {(id) => <TextInput id={id} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />}
        </Field>
        {del.isError && <Alert tone="bad">{errorMessage(del.error)}</Alert>}
      </div>
    </Dialog>
  );
}
